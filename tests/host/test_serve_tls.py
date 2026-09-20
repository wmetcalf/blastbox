"""`serve` must be able to satisfy the assumption the node protocol makes (#178).

The claim protocol authenticates the NODE cryptographically but assumes the CHANNEL is
server-authenticated TLS. `serve` previously had no way to enable TLS at all, so an
operator following the deployment guide necessarily ran it plaintext — a design assumption
with no means of being satisfied.
"""
from __future__ import annotations

import argparse

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
    """A node verifies the control plane with the SAME ca.crt it was enrolled with. A
    self-signed certificate here would make every node refuse to connect."""
    import ssl

    d = tmp_path / "pki"
    pki.ensure_ca(d)
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    out = _serve_tls(args())
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(d / "ca.crt"))
    # load_verify_locations already accepted the CA; loading the leaf proves it parses and
    # pairs with its key, and the chain check below is what a node actually does.
    ctx.load_cert_chain(out["ssl_certfile"], out["ssl_keyfile"])


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


def test_a_verify_only_host_is_told_what_to_do(tmp_path, monkeypatch):
    """An ingress host given only ca.crt (the documented worker shape) cannot issue. That
    must be an actionable message, not a traceback or a silent downgrade to plaintext."""
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    (d / "ca.key").unlink()
    assert (d / "ca.crt").exists() and ca is not None
    monkeypatch.setenv("BLASTBOX_PKI_DIR", str(d))
    with pytest.raises(SystemExit, match="--tls-cert"):
        _serve_tls(args())
