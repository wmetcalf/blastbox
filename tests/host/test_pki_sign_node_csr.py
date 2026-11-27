"""CertAuthority.sign_node_csr: the node's key stays on the node; only the CSR moves."""
from __future__ import annotations

import json
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from blastbox.host import cli, pki
from blastbox.host.pki import NodeGrants


@pytest.fixture()
def ca(tmp_path):
    return pki.ensure_ca(tmp_path / "pki")


def _csr(key=None, cn="n1", extra=None) -> bytes:
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    for ext, crit in extra or []:
        b = b.add_extension(ext, critical=crit)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def test_csr_grants_come_from_flags_not_csr(ca):
    forged = json.dumps({"node_id": "n1", "engines": ["evil"], "tiers": ["all"],
                         "credentials": True}).encode()
    pem = _csr(extra=[
        (x509.UnrecognizedExtension(pki.OID_NODE_INFO, forged), False),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.SubjectAlternativeName([x509.DNSName("evil.example")]), False),
    ])
    out = ca.sign_node_csr(pem, node_id="n1", grants=NodeGrants(engines=("boxjs",)))
    cert = x509.load_pem_x509_certificate(out)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert eku.critical and list(eku.value) == [pki.OID_NODE_AUTH]
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    ident = pki.node_identity(ca, out)
    assert ident.grants.engines == ("boxjs",)
    assert ident.grants.tiers == () and ident.grants.credentials is False


def test_cn_mismatch_refused(ca):
    with pytest.raises(ValueError, match="common name"):
        ca.sign_node_csr(_csr(cn="other"), node_id="n1", grants=NodeGrants())


def test_rsa_and_p384_refused(ca):
    rsa_key = rsa.generate_private_key(65537, 2048)
    with pytest.raises(ValueError, match="P-256"):
        ca.sign_node_csr(_csr(rsa_key), node_id="n1", grants=NodeGrants())
    with pytest.raises(ValueError, match="P-256"):
        ca.sign_node_csr(_csr(ec.generate_private_key(ec.SECP384R1())),
                         node_id="n1", grants=NodeGrants())


def test_bad_signature_refused(ca):
    pem = _csr()
    csr = x509.load_pem_x509_csr(pem)
    raw = bytearray(csr.public_bytes(serialization.Encoding.DER))
    raw[-1] ^= 0xFF
    bad = x509.load_der_x509_csr(bytes(raw))
    assert not bad.is_signature_valid
    with pytest.raises(ValueError, match="signature"):
        ca.sign_node_csr(bad.public_bytes(serialization.Encoding.PEM),
                         node_id="n1", grants=NodeGrants())


def test_issued_cert_passes_node_identity(ca):
    out = ca.sign_node_csr(_csr(), node_id="n1", grants=NodeGrants(tiers=("t",)))
    ident = pki.node_identity(ca, out)
    assert ident.node_id == "n1"
    assert ident.wg_pubkey is None
    assert ident.info_version == 2


def test_cli_sign_node_csr_writes_atomically(tmp_path, ca, capsys):
    csr = tmp_path / "n1.csr"
    csr.write_bytes(_csr())
    out = tmp_path / "outdir" / "n1.crt"
    rc = cli.main(["pki", "--dir", str(tmp_path / "pki"), "sign-node-csr",
                   "--csr", str(csr), "--node-id", "n1", "--engine", "boxjs",
                   "--out", str(out)])
    assert rc == 0
    assert out.exists()
    assert [p.name for p in out.parent.iterdir()] == ["n1.crt"]
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o644
    text = capsys.readouterr().out
    assert str(out) in text and "not_after" in text and "PRIVATE" not in text
    assert pki.node_identity(ca, out.read_bytes()).grants.engines == ("boxjs",)
