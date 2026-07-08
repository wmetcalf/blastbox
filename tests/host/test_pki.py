"""Unit tests for the in-process worker-mTLS PKI (real TLS handshakes, no network beyond loopback)."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blastbox.host.pki import (
    CertAuthority,
    _generate_ca,
    client_ssl_context,
    ensure_ca,
    server_ssl_context,
)


# --------------------------------------------------------------- CA lifecycle

def test_ensure_ca_generates_then_reloads_same(tmp_path):
    ca1 = ensure_ca(tmp_path)
    assert (tmp_path / "ca.crt").exists() and (tmp_path / "ca.key").exists()
    assert oct((tmp_path / "ca.key").stat().st_mode)[-3:] == "600"
    ca2 = ensure_ca(tmp_path)                      # idempotent -> same CA loaded, not regenerated
    assert ca1.cert_pem == ca2.cert_pem


def test_ensure_ca_refuses_partial_state(tmp_path):
    ensure_ca(tmp_path)
    (tmp_path / "ca.key").unlink()                 # crt present, key gone -> partial
    with pytest.raises(RuntimeError):
        ensure_ca(tmp_path)                         # must NOT silently rotate the CA


def test_issued_private_key_is_0600(tmp_path):
    _, key = _generate_ca().issue_client("d").write(tmp_path, "d")
    assert oct(key.stat().st_mode)[-3:] == "600"


def test_ca_is_a_ca_cert():
    ca = _generate_ca()
    cert = x509.load_pem_x509_certificate(ca.cert_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True


# --------------------------------------------------------------- leaf issuance

def test_issue_server_has_server_eku_and_san():
    ca = _generate_ca()
    issued = ca.issue_server(["10.0.0.7", "worker.internal"])
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "worker.internal" in [g.value for g in san if isinstance(g, x509.DNSName)]


def test_issue_client_has_client_eku():
    ca = _generate_ca()
    cert = x509.load_pem_x509_certificate(ca.issue_client("dispatcher").cert_pem)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "dispatcher"


def test_sign_csr_signs_and_rejects_bad(tmp_path):
    ca = _generate_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "w1")]))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("10.0.0.9"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = ca.sign_csr(csr.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.issuer == x509.load_pem_x509_certificate(ca.cert_pem).subject
    # tamper -> invalid signature rejected
    with pytest.raises(ValueError):
        ca.sign_csr(b"-----BEGIN CERTIFICATE REQUEST-----\nbogus\n-----END CERTIFICATE REQUEST-----\n")


# --------------------------------------------------------------- real mTLS handshake

def _handshake(server_ctx: ssl.SSLContext, client_ctx: ssl.SSLContext, server_hostname: str) -> dict:
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    out: dict = {}

    def _server() -> None:
        try:
            conn, _ = lsock.accept()
            with server_ctx.wrap_socket(conn, server_side=True) as s:
                out["peer_cert"] = s.getpeercert()
        except Exception as e:  # noqa: BLE001
            out["server_error"] = type(e).__name__

    t = threading.Thread(target=_server, daemon=True)
    t.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with client_ctx.wrap_socket(raw, server_hostname=server_hostname):
                out["client_ok"] = True
    except Exception as e:  # noqa: BLE001
        out["client_error"] = type(e).__name__
    t.join(5)
    lsock.close()
    return out


def _ctxs(ca: CertAuthority, tmp_path, *, client_ca: CertAuthority | None = None):
    srv = ca.issue_server(["127.0.0.1"])
    scrt, skey = srv.write(tmp_path, "server")
    (tmp_path / "ca.crt").write_bytes(ca.cert_pem)
    server_ctx = server_ssl_context(str(scrt), str(skey), client_ca_file=str(tmp_path / "ca.crt"))
    signer = client_ca or ca
    cli = signer.issue_client("dispatcher")
    ccrt, ckey = cli.write(tmp_path, "client")
    (tmp_path / "trust.crt").write_bytes(ca.cert_pem)
    client_ctx = client_ssl_context(str(tmp_path / "trust.crt"), cert_file=str(ccrt), key_file=str(ckey))
    return server_ctx, client_ctx


def test_mtls_handshake_succeeds_with_ca_signed_client(tmp_path):
    ca = ensure_ca(tmp_path / "pki")
    server_ctx, client_ctx = _ctxs(ca, tmp_path)
    res = _handshake(server_ctx, client_ctx, "127.0.0.1")
    assert res.get("client_ok") is True
    assert res.get("peer_cert")            # server saw + accepted the client cert


def test_mtls_rejects_client_from_a_different_ca(tmp_path):
    ca = ensure_ca(tmp_path / "pki")
    rogue = _generate_ca("rogue-ca")            # client cert signed by a CA the worker doesn't trust
    server_ctx, client_ctx = _ctxs(ca, tmp_path, client_ca=rogue)
    res = _handshake(server_ctx, client_ctx, "127.0.0.1")
    # the server (the gate) must reject the untrusted client cert -- it never accepts the peer.
    # (In TLS 1.3 the client can report local "ok" before the server's alert arrives, so assert
    # on the server side, which is what actually enforces the allowlist.)
    assert "peer_cert" not in res
    assert res.get("server_error") == "SSLCertVerificationError"


def test_client_rejects_wrong_server_san(tmp_path):
    ca = ensure_ca(tmp_path / "pki")
    srv = ca.issue_server(["10.9.9.9"])          # cert is NOT for 127.0.0.1
    scrt, skey = srv.write(tmp_path, "server")
    (tmp_path / "ca.crt").write_bytes(ca.cert_pem)
    server_ctx = server_ssl_context(str(scrt), str(skey))
    cli = ca.issue_client()
    ccrt, ckey = cli.write(tmp_path, "client")
    client_ctx = client_ssl_context(str(tmp_path / "ca.crt"), cert_file=str(ccrt), key_file=str(ckey))
    res = _handshake(server_ctx, client_ctx, "127.0.0.1")
    assert res.get("client_ok") is not True      # SAN mismatch -> client refuses the server
