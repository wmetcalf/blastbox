"""`serve` must be able to satisfy the assumption the node protocol makes (#178).

The claim protocol authenticates the NODE cryptographically but assumes the CHANNEL is
server-authenticated TLS. `serve` previously had no way to enable TLS at all, so an
operator following the deployment guide necessarily ran it plaintext — a design assumption
with no means of being satisfied.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from blastbox.host import pki
from blastbox.host.cli import _serve_tls


def args(**kw):
    base = {"host": "127.0.0.1", "tls_cert": None, "tls_key": None, "no_tls": False}
    base.update(kw)
    return argparse.Namespace(**base)


def test_a_pki_gets_tls_with_no_operator_step(tmp_path, monkeypatch):
    """The secure path must not need an extra action, or it will not be taken."""
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    out = _serve_tls(args())
    assert out["ssl_certfile"] and out["ssl_keyfile"]
    assert (d / "ingress-server.crt").exists()


def test_the_issued_certificate_verifies_against_the_fleet_ca(tmp_path, monkeypatch):
    """A node verifies the control plane with the SAME ca.crt it was enrolled with, so a
    self-signed certificate here would make every node refuse to connect.

    THE EARLIER VERSION OF THIS TEST PROVED NOTHING. Its only assertion-bearing call was
    `ctx.load_cert_chain(cert, key)`, which checks the leaf parses and pairs with its key;
    `create_default_context(cafile=...)` merely loads an anchor and builds no chain. Its comment
    even said "the chain check below is what a node actually does" -- there was no check below.
    Measured: emitting a self-signed certificate left the whole suite green. So the signature is
    now verified against the CA directly."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    d = tmp_path / "pki"
    pki.ensure_ca(d)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    out = _serve_tls(args())

    leaf = x509.load_pem_x509_certificate(Path(out["ssl_certfile"]).read_bytes())
    ca_cert = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())
    assert leaf.issuer == ca_cert.subject, "the leaf does not even claim the fleet CA"
    pub = ca_cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    # RAISES InvalidSignature if this CA did not sign it. That is the whole test.
    pub.verify(leaf.signature, leaf.tbs_certificate_bytes,
               ec.ECDSA(leaf.signature_hash_algorithm))


def test_a_self_signed_certificate_would_be_caught(tmp_path):
    """Proves the check above bites, rather than trusting that it does."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    d = tmp_path / "pki"
    pki.ensure_ca(d)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue")])
    rogue = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(minutes=5))
             .not_valid_after(now + datetime.timedelta(days=1))
             .sign(key, hashes.SHA256()))
    ca_cert = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())
    assert rogue.issuer != ca_cert.subject
    pub = ca_cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    with pytest.raises(Exception):
        pub.verify(rogue.signature, rogue.tbs_certificate_bytes,
                   ec.ECDSA(rogue.signature_hash_algorithm))


def test_an_explicit_certificate_wins(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    out = _serve_tls(args(tls_cert="/tmp/mine.crt", tls_key="/tmp/mine.key"))
    assert out == {"ssl_certfile": "/tmp/mine.crt", "ssl_keyfile": "/tmp/mine.key"}


def test_half_a_certificate_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(tmp_path / "none"))
    with pytest.raises(SystemExit, match="together"):
        _serve_tls(args(tls_cert="/tmp/mine.crt"))


def test_no_pki_serves_plaintext_exactly_as_before(tmp_path, monkeypatch):
    """No PKI means the node routes are not mounted either, so there is no new secret on
    this listener. Refusing to start a deployment that never opted in would be worse."""
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(tmp_path / "absent"))
    assert _serve_tls(args()) == {}


def test_no_tls_is_possible_but_says_what_it_costs(tmp_path, monkeypatch, caplog):
    d = tmp_path / "pki"
    pki.ensure_ca(d)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    with caplog.at_level("WARNING"):
        assert _serve_tls(args(no_tls=True)) == {}
    assert any("clear" in r.message for r in caplog.records), caplog.text


def test_a_hardened_ingress_gets_TLS_from_a_certificate_issued_elsewhere(tmp_path,
                                                                         monkeypatch):
    """THE HARDENED ARRANGEMENT MUST BE THE EASY ONE, or it will not be used.

    An internet-facing ingress should hold ca.crt and NOT ca.key -- which is what DEPLOYMENT.md
    tells operators to copy. Demanding the signing key made `serve` refuse to start on exactly
    that host, and the error message offered --no-tls as the escape: the most careful deployment
    pushed into the plaintext one, where a session header is a sniffable ten-minute bearer
    credential for a node's full authority.

    So a pair issued on the CA host and copied in is picked up with no CA key and no flags."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    issued = ca.issue_server(["127.0.0.1", "localhost"], cn="blastbox-ingress")
    issued.write(d, "ingress-server")
    (d / "ca.key").unlink()             # the signing key never reaches this host
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    out = _serve_tls(args())
    assert out["ssl_certfile"] == str(d / "ingress-server.crt")
    assert out["ssl_keyfile"] == str(d / "ingress-server.key")


def test_a_verify_only_host_with_no_certificate_is_told_all_three_options(tmp_path,
                                                                         monkeypatch):
    """When it genuinely cannot serve TLS, the message must name the HARDENED route first --
    not lead with --no-tls, which is how a careful operator ends up on plaintext."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    (d / "ca.key").unlink()
    assert (d / "ca.crt").exists() and ca is not None
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    with pytest.raises(SystemExit) as e:
        _serve_tls(args())
    message = str(e.value)
    assert "copy it to" in message, "the hardened route is not offered"
    assert message.index("copy it to") < message.index("--no-tls"), (
        "plaintext is offered before the secure route")


def test_a_certificate_from_a_ROTATED_ca_is_not_reused(tmp_path, monkeypatch, caplog):
    """The reuse branch checked only the clock. Rotate the fleet CA while `ingress-server.crt`
    is still unexpired and ingress starts happily with a leaf that every newly-enrolled node --
    which trusts the replacement CA -- rejects during the handshake. Worse, the re-issuance path
    is never reached, so a host that HOLDS the new CA key cannot heal itself either."""
    import argparse
    import logging

    from blastbox.host import cli, pki

    d = tmp_path / "pki"
    old_ca = pki.ensure_ca(d)
    issued = old_ca.issue_server(["127.0.0.1"], cn="blastbox-ingress")
    old_crt, _old_key = issued.write(d, "ingress-server")
    old_bytes = old_crt.read_bytes()

    # The operator rotates the CA in place (blastbox pki init after removing ca.*).
    (d / "ca.crt").unlink()
    (d / "ca.key").unlink()
    pki.ensure_ca(d)

    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    args = argparse.Namespace(host="127.0.0.1", port=8443, tls_cert=None, tls_key=None,
                              no_tls=False)
    with caplog.at_level(logging.WARNING):
        out = cli._serve_tls(args)
    assert out, "TLS was turned off entirely"
    assert (d / "ingress-server.crt").read_bytes() != old_bytes, (
        "ingress reused a leaf signed by the RETIRED CA; every node trusting the new anchor "
        "will fail the handshake and this host never reaches re-issuance")


def test_a_rotated_ca_without_its_key_refuses_to_start(tmp_path, monkeypatch):
    """The hardened layout: ca.crt present, ca.key deliberately absent. Rotate the anchor and the
    old leaf is not merely expiring, it is unusable -- every node trusting the new CA rejects it.
    The expiry fallback served it anyway, starting a control plane no federated node can reach
    and logging an expiry warning, which is the one thing that was not wrong."""
    import argparse

    import pytest

    from blastbox.host import cli, pki

    d = tmp_path / "pki"
    old_ca = pki.ensure_ca(d)
    old_ca.issue_server(["127.0.0.1"], cn="blastbox-ingress").write(d, "ingress-server")
    (d / "ca.crt").unlink()
    (d / "ca.key").unlink()
    pki.ensure_ca(d)                         # the rotation...
    (d / "ca.key").unlink()                  # ...on a host that never holds the signing key
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    args = argparse.Namespace(host="127.0.0.1", port=8443, tls_cert=None, tls_key=None,
                              no_tls=False)
    with pytest.raises(SystemExit, match="rotated"):
        cli._serve_tls(args)


def test_an_expiring_leaf_without_a_ca_key_is_still_served(tmp_path, monkeypatch, caplog):
    """The fallback the fix must NOT disturb: a leaf that merely nears its deadline still works,
    so a hardened host keeps serving it and says loudly how long is left."""
    import argparse
    import datetime

    from blastbox.host import cli, pki

    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    ca.issue_server(["127.0.0.1"], cn="blastbox-ingress").write(d, "ingress-server")
    (d / "ca.key").unlink()
    real_now = datetime.datetime.now

    class Later(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return real_now(tz) + datetime.timedelta(days=29)

    monkeypatch.setattr(datetime, "datetime", Later)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    args = argparse.Namespace(host="127.0.0.1", port=8443, tls_cert=None, tls_key=None,
                              no_tls=False)
    out = cli._serve_tls(args)
    assert out and out["ssl_certfile"].endswith("ingress-server.crt")


def test_a_rotated_out_leaf_inside_the_renewal_window_still_refuses(tmp_path, monkeypatch):
    """The first CA check ran only for leaves with MORE than the renewal window left, so a
    rotated-out leaf with 5 days remaining -- a quarter of a 30-day leaf's life -- skipped it,
    took the expiry fallback on a keyless host, and was served to nodes that all reject it."""
    import argparse
    import datetime

    import pytest

    from blastbox.host import cli, pki

    d = tmp_path / "pki"
    pki.ensure_ca(d).issue_server(["127.0.0.1"], cn="blastbox-ingress").write(d, "ingress-server")
    (d / "ca.crt").unlink()
    (d / "ca.key").unlink()
    pki.ensure_ca(d)
    (d / "ca.key").unlink()
    real_now = datetime.datetime.now

    class NearExpiry(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return real_now(tz) + datetime.timedelta(days=25)   # inside the 7-day window

    monkeypatch.setattr(datetime, "datetime", NearExpiry)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    args = argparse.Namespace(host="127.0.0.1", port=8443, tls_cert=None, tls_key=None,
                              no_tls=False)
    with pytest.raises(SystemExit, match="rotated"):
        cli._serve_tls(args)


def test_an_unreadable_leaf_is_not_blamed_on_a_ca_rotation(tmp_path, monkeypatch):
    """Refusing to serve an unreadable leaf is right, but the message said 'the anchor was rotated'
    -- and for a truncated file or a permissions problem, re-issuing on the CA host (the remedy it
    gave) is the wrong fix."""
    import argparse

    import pytest

    from blastbox.host import cli, pki

    d = tmp_path / "pki"
    pki.ensure_ca(d).issue_server(["127.0.0.1"], cn="blastbox-ingress").write(d, "ingress-server")
    (d / "ca.key").unlink()
    (d / "ingress-server.crt").write_text("not a certificate")
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    args = argparse.Namespace(host="127.0.0.1", port=8443, tls_cert=None, tls_key=None,
                              no_tls=False)
    with pytest.raises(SystemExit) as exc:
        cli._serve_tls(args)
    msg = str(exc.value)
    assert "rotated" not in msg, f"an unreadable leaf was blamed on a CA rotation: {msg}"
    assert "cannot be read" in msg
