"""node-info v2: the WireGuard key becomes optional.

A node enrolled by CSR (the credential-less pull worker) has no WireGuard key, so its
cert must be able to omit it. v1 certs, which always carry one, must keep verifying and
keep their exact byte encoding.
"""
from __future__ import annotations

import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import cli, pki
from blastbox.host.pki import NodeGrants

WG = "A" * 43 + "="


@pytest.fixture()
def ca(tmp_path):
    return pki.ensure_ca(tmp_path / "pki")


def _forged(ca, info: dict) -> bytes:
    """A CA-signed node cert whose node-info is exactly ``info`` (bypasses issue_node)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(
            x509.oid.NameOID.COMMON_NAME, info["node_id"])]))
        .issuer_name(ca._cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([pki.OID_NODE_AUTH]), critical=True)
        .add_extension(x509.UnrecognizedExtension(
            pki.OID_NODE_INFO, json.dumps(info).encode()), critical=False)
        .sign(ca._key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _info(**kw):
    base = {"node_id": "n1", "engines": [], "tiers": [], "credentials": False}
    base.update(kw)
    return base


def _ext(cert_pem: bytes) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.extensions.get_extension_for_oid(pki.OID_NODE_INFO).value.public_bytes()


def test_v2_cert_without_wg_verifies(ca):
    grants = NodeGrants(engines=("boxjs",), tiers=("wireguard",), credentials=False)
    issued = ca.issue_node("agent1", grants=grants)
    ident = pki.node_identity(ca, issued.cert_pem)
    assert ident.wg_pubkey is None
    assert ident.info_version == 2
    assert ident.grants == grants
    assert "wg" not in json.loads(_ext(issued.cert_pem))
    assert json.loads(_ext(issued.cert_pem))["v"] == 2


def test_v1_cert_still_verifies_and_requires_wg(ca):
    issued = ca.issue_node("n1", wg_pubkey=WG)
    ident = pki.node_identity(ca, issued.cert_pem)
    assert ident.wg_pubkey == WG and ident.info_version == 1
    for bad in ({}, {"wg": "not-a-key"}):
        with pytest.raises(ValueError,
                           match="carries no valid WireGuard public key"):
            pki.node_identity(ca, _forged(ca, _info(v=1, **bad)))


def test_v2_with_garbled_wg_rejected(ca):
    with pytest.raises(ValueError, match="carries no valid WireGuard public key"):
        pki.node_identity(ca, _forged(ca, _info(v=2, wg="garbage")))


def test_v2_with_valid_wg_accepted(ca):
    ident = pki.node_identity(ca, _forged(ca, _info(v=2, wg=WG)))
    assert ident.wg_pubkey == WG and ident.info_version == 2


def test_unknown_version_rejected(ca):
    with pytest.raises(ValueError, match="unsupported node-info version"):
        pki.node_identity(ca, _forged(ca, _info(v=3)))


def test_v1_bytes_unchanged(ca):
    issued = ca.issue_node("n1", wg_pubkey=WG,
                           grants=NodeGrants(engines=("e",), tiers=("t",), credentials=True))
    expected = ('{"credentials":true,"engines":["e"],"node_id":"n1","tiers":["t"],'
                f'"v":1,"wg":"{WG}"}}').encode()
    assert _ext(issued.cert_pem) == expected


def test_issue_node_rejects_garbled_wg(ca):
    with pytest.raises(ValueError, match="32-byte base64"):
        ca.issue_node("n1", wg_pubkey="nope")


def test_worker_link_skips_wg_less_node(ca, tmp_path):
    pki_dir = tmp_path / "pki"
    ca.issue_node("withkey", wg_pubkey=WG).write(pki_dir, "withkey")
    ca.issue_node("nokey").write(pki_dir, "nokey")
    ta = pki.load_trust_anchor(pki_dir)
    assert cli._wg_key_to_node(ta, pki_dir) == {WG: "withkey"}
