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


def _node_cert_with_eku(ca, ekus, critical=True) -> bytes:
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    info = pki._node_info_bytes("n1", None, NodeGrants())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "n1")]))
        .issuer_name(ca._cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=critical)
        .add_extension(x509.UnrecognizedExtension(pki.OID_NODE_INFO, info), critical=False)
        .sign(ca._key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("extra", [
    ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH,
    ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
def test_node_identity_refuses_transport_eku(ca, extra):
    pem = _node_cert_with_eku(ca, [pki.OID_NODE_AUTH, extra])
    with pytest.raises(ValueError, match="transport"):
        pki.node_identity(ca, pem)


def test_node_identity_refuses_non_critical_node_eku(ca):
    pem = _node_cert_with_eku(ca, [pki.OID_NODE_AUTH], critical=False)
    with pytest.raises(ValueError, match="critical"):
        pki.node_identity(ca, pem)
    assert pki.node_identity(ca, _node_cert_with_eku(ca, [pki.OID_NODE_AUTH])).node_id == "n1"


@pytest.mark.parametrize("days", [0, -1, 31, 365])
def test_node_cert_days_bounded(ca, days):
    with pytest.raises(ValueError, match="lifetime"):
        ca.issue_node("n1", days=days)
    with pytest.raises(ValueError, match="lifetime"):
        ca.sign_node_csr(_csr(), node_id="n1", grants=NodeGrants(), days=days)
    ca.issue_node("n1", days=30)


def test_cli_cn_mismatch_is_a_clean_error(tmp_path, ca, capsys):
    csr = tmp_path / "x.csr"
    csr.write_bytes(_csr(cn="other"))
    rc = cli.main(["pki", "--dir", str(tmp_path / "pki"), "sign-node-csr",
                   "--csr", str(csr), "--node-id", "n1"])
    assert rc == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "pki" / "node-n1.crt").exists()


def test_cli_malformed_csr_and_missing_file_are_clean_errors(tmp_path, ca, capsys):
    bad = tmp_path / "bad.csr"
    bad.write_bytes(b"not a csr")
    for path in (bad, tmp_path / "missing.csr"):
        rc = cli.main(["pki", "--dir", str(tmp_path / "pki"), "sign-node-csr",
                       "--csr", str(path), "--node-id", "n1"])
        assert rc == 1
        assert "error:" in capsys.readouterr().err


def test_cli_replaces_existing_out_and_survives_stale_tmp(tmp_path, ca, capsys):
    csr = tmp_path / "n1.csr"
    csr.write_bytes(_csr())
    out = tmp_path / "n1.crt"
    out.write_bytes(b"old")
    (tmp_path / f"n1.crt.{os.getpid()}.tmp").write_bytes(b"stale")
    rc = cli.main(["pki", "--dir", str(tmp_path / "pki"), "sign-node-csr",
                   "--csr", str(csr), "--node-id", "n1", "--out", str(out)])
    assert rc == 0
    assert f"replaced existing {out}" in capsys.readouterr().err
    assert out.read_bytes().startswith(b"-----BEGIN CERTIFICATE")
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []
