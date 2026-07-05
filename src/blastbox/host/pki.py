"""In-process PKI for worker mTLS: a private CA that issues server certs (for workers) and client
certs (for the dispatcher), so the HTTP transport can run over mutually-authenticated TLS without
anyone hand-rolling openssl.

The dispatcher owns a long-lived CA (``ensure_ca`` -> ``BLASTBOX_PKI_DIR/ca.{crt,key}``). Workers get
a short-lived **server** cert SAN-pinned to their address; the dispatcher gets a **client** cert. Both
sides trust only the CA, so:
  * a worker will only complete a handshake for a client presenting a CA-signed cert (the dispatcher) --
    an "allowed caller" list enforced by cryptography, not a firewall guess;
  * the dispatcher will only talk to a worker whose server cert the CA signed and whose SAN matches.

For disposable workers the private key must never ride a channel in the clear: the worker generates its
own keypair at boot and sends a CSR; the dispatcher ``sign_csr``-s it (Phase 2). Everything here is
pure ``cryptography`` -- no shelling to openssl.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_CN = "blastbox-worker-ca"
_UTC = datetime.timezone.utc


def _now() -> datetime.datetime:
    return datetime.datetime.now(_UTC)


def _san_list(sans: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for s in sans:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            out.append(x509.DNSName(s))
    return out


@dataclass
class IssuedCert:
    """A leaf cert + its private key, both PEM. ``write`` drops them next to each other."""

    cert_pem: bytes
    key_pem: bytes

    def write(self, dir: Path, name: str) -> tuple[Path, Path]:
        dir = Path(dir)
        dir.mkdir(parents=True, exist_ok=True)
        crt, key = dir / f"{name}.crt", dir / f"{name}.key"
        crt.write_bytes(self.cert_pem)
        key.write_bytes(self.key_pem)
        os.chmod(key, 0o600)
        return crt, key


class CertAuthority:
    """A CA that signs short-lived worker/dispatcher leaf certs. Hold the key only on the dispatcher."""

    def __init__(self, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
        self._cert = cert
        self._key = key

    @property
    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _sign(self, subject_cn: str, pub_key, sans: list[str], *,
              server: bool, client: bool, days: int) -> x509.Certificate:
        eku = []
        if server:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(self._cert.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        )
        san = _san_list(sans)
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
        return builder.sign(self._key, hashes.SHA256())

    def issue_server(self, sans: list[str], *, cn: str | None = None, days: int = 30) -> IssuedCert:
        """A worker's server cert, SAN-pinned to its IP/host(s)."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._sign(cn or (sans[0] if sans else "worker"), key.public_key(), sans,
                          server=True, client=False, days=days)
        return IssuedCert(cert.public_bytes(serialization.Encoding.PEM), _key_pem(key))

    def issue_client(self, cn: str = "dispatcher", *, days: int = 30) -> IssuedCert:
        """The dispatcher's client cert (presented for mTLS)."""
        key = ec.generate_private_key(ec.SECP256R1())
        cert = self._sign(cn, key.public_key(), [], server=False, client=True, days=days)
        return IssuedCert(cert.public_bytes(serialization.Encoding.PEM), _key_pem(key))

    def sign_csr(self, csr_pem: bytes, *, days: int = 2) -> bytes:
        """Sign a worker-generated CSR (Phase 2: the worker's key never leaves the box). SANs are taken
        from the CSR; a bad signature is rejected. Returns the server cert PEM."""
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")
        cn = "worker"
        for attr in csr.subject:
            if attr.oid == NameOID.COMMON_NAME:
                cn = str(attr.value)
        sans: list[str] = []
        try:
            ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(g.value) for g in ext.value]
        except x509.ExtensionNotFound:
            pass
        cert = self._sign(cn, csr.public_key(), sans, server=True, client=False, days=days)
        return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _generate_ca(cn: str = _CA_CN, days: int = 3650) -> CertAuthority:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return CertAuthority(cert, key)


def load_ca(pki_dir: Path) -> CertAuthority:
    pki_dir = Path(pki_dir)
    cert = x509.load_pem_x509_certificate((pki_dir / "ca.crt").read_bytes())
    key = serialization.load_pem_private_key((pki_dir / "ca.key").read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return CertAuthority(cert, key)


def ensure_ca(pki_dir: Path) -> CertAuthority:
    """Load the CA from ``pki_dir`` (``ca.crt`` + ``ca.key``) or generate + persist a new one (key 0600)."""
    pki_dir = Path(pki_dir)
    if (pki_dir / "ca.crt").exists() and (pki_dir / "ca.key").exists():
        return load_ca(pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca = _generate_ca()
    (pki_dir / "ca.crt").write_bytes(ca.cert_pem)
    (pki_dir / "ca.key").write_bytes(ca.key_pem)
    os.chmod(pki_dir / "ca.key", 0o600)
    return ca


# SSL context builders moved to ``blastbox.tls`` (stdlib-only, so the worker can use them without
# pulling ``cryptography``). Re-exported here for callers that already import from ``pki``.
from blastbox.tls import client_ssl_context, server_ssl_context  # noqa: E402,F401
