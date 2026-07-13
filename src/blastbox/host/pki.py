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


def _write_private(path: Path, data: bytes) -> None:
    """Write a private key at 0600 -- enforced via fchmod so an EXISTING (possibly looser-perm) file
    being overwritten is also tightened (the O_CREAT mode only applies on creation)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:   # closes fd on any error below
        os.fchmod(fd, 0o600)
        fh.write(data)


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
        _write_private(key, self.key_pem)
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
        if not sans:
            # a SAN-less server cert passes signing but fails TLS hostname/IP verification later --
            # reject at signing time (workers are reached by IP/URL through client_ssl_context).
            raise ValueError("server CSR has no SubjectAlternativeName; refusing to issue a SAN-less server cert")
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
    # guard against a partial restore / interrupted rotation: a key that doesn't match ca.crt would mint
    # leaf certs signed by the wrong CA (fail TLS against the published ca.crt).
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != cert.public_key().public_bytes(*spki):
        raise RuntimeError(f"CA key does not match ca.crt in {pki_dir} (partial/mismatched CA state)")
    return CertAuthority(cert, key)


def ensure_ca(pki_dir: Path) -> CertAuthority:
    """Load the CA from ``pki_dir`` (``ca.crt`` + ``ca.key``) or generate + persist a new one (key 0600).
    Refuses a **partial** state (only one of the two present) rather than silently rotating the CA --
    a fresh CA would invalidate every cert it already signed."""
    pki_dir = Path(pki_dir)
    crt, key = pki_dir / "ca.crt", pki_dir / "ca.key"
    if crt.exists() and key.exists():
        return load_ca(pki_dir)
    if crt.exists() or key.exists():
        raise RuntimeError(
            f"partial CA state in {pki_dir} (have {'ca.crt' if crt.exists() else 'ca.key'}, "
            "missing the other) -- refusing to rotate the CA; restore or clear both files"
        )
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca = _generate_ca()
    crt.write_bytes(ca.cert_pem)
    _write_private(key, ca.key_pem)
    return ca


def import_ca(pki_dir: Path, cert_pem: bytes, key_pem: bytes) -> CertAuthority:
    """Install an EXTERNALLY-generated CA (``cert_pem`` + ``key_pem``) into ``pki_dir``, so several
    hosts / a shared worker pool issue and trust leaves under **one** root -- the failover / multi-
    dispatcher case, where each host's own ``ensure_ca`` would mint a *different* CA and the servers
    would not trust each other's certs. Generate the CA once (e.g. ``_generate_ca`` on an offline box),
    then ``import_ca`` it wherever certs are issued or verified.

    Validates that the key matches the cert and that it IS a CA cert, writes ``ca.key`` 0600, and
    **refuses to overwrite a *different* CA** already in ``pki_dir`` (a silent rotation would invalidate
    every cert the old CA signed -- same stance as ``ensure_ca``'s partial-state refusal). Re-importing
    the SAME CA is idempotent."""
    pki_dir = Path(pki_dir)
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("CA key must be an EC private key")
    # the key must match the cert -- else every leaf we sign would fail TLS against the published ca.crt
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != cert.public_key().public_bytes(*spki):
        raise ValueError("CA key does not match the CA cert")
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if not is_ca:
        raise ValueError("imported cert is not a CA (BasicConstraints ca=True required)")
    crt_path, key_path = pki_dir / "ca.crt", pki_dir / "ca.key"
    have_crt, have_key = crt_path.exists(), key_path.exists()
    if have_crt != have_key:
        # mirror ensure_ca: refuse a partial CA state rather than silently completing it
        raise RuntimeError(
            f"partial CA state in {pki_dir} (have {'ca.crt' if have_crt else 'ca.key'}, missing the "
            "other) -- clear both before importing")
    if have_crt:  # both present: only the SAME CA may be re-imported (never a silent rotation)
        existing = x509.load_pem_x509_certificate(crt_path.read_bytes())
        if existing.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise RuntimeError(
                f"a different CA already exists in {pki_dir} -- refusing to overwrite it (would "
                "invalidate every cert it signed); clear ca.crt/ca.key first to replace it")
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca = CertAuthority(cert, key)
    crt_path.write_bytes(ca.cert_pem)          # normalize to the CA's own canonical PEM
    _write_private(key_path, ca.key_pem)       # (re)writes the validated pair -- heals a tampered key
    return ca


# SSL context builders moved to ``blastbox.tls`` (stdlib-only, so the worker can use them without
# pulling ``cryptography``). Re-exported here for callers that already import from ``pki``.
from blastbox.tls import client_ssl_context, server_ssl_context  # noqa: E402,F401
