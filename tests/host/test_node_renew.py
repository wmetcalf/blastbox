from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from blastbox.host import node_renew, pki
from blastbox.host.node_renew import RenewRefused, queue_csr, sign_pending
from blastbox.host.placement import fleet_grants

GRANTS = pki.NodeGrants(engines=("williamtells",), tiers=(), credentials=False)


def make_csr(cn: str, key=None) -> tuple[bytes, object]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM), key


def rig(tmp_path: Path, node: str = "n1"):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    csr, _ = make_csr(node)
    (d / f"node-{node}.crt").write_bytes(ca.sign_node_csr(csr, node_id=node, grants=GRANTS))
    return d, ca


def pub(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_queue_rejects_cn_not_session_node(tmp_path):
    d, _ = rig(tmp_path)
    csr, _ = make_csr("other")
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", csr)
    assert not list((d / "renew").glob("*.csr"))


def test_queue_rejects_oversize_and_non_p256(tmp_path):
    d, _ = rig(tmp_path)
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", b"x" * (node_renew.MAX_CSR_BYTES + 1))
    rsa_key = rsa.generate_private_key(65537, 2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "n1")]))
           .sign(rsa_key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", csr)
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", b"not a csr")


def test_queue_overwrites_one_file_per_node_mode_0600(tmp_path):
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    second, _ = make_csr("n1")
    queue_csr(d, "n1", second)
    files = list((d / "renew").glob("*.csr"))
    assert [f.name for f in files] == ["n1.csr"]
    assert files[0].read_bytes() == second
    assert files[0].stat().st_mode & 0o777 == 0o600
    assert (d / "renew").stat().st_mode & 0o777 == 0o700


def test_queue_refuses_when_queue_full(tmp_path, monkeypatch):
    d, _ = rig(tmp_path)
    monkeypatch.setattr(node_renew, "MAX_QUEUED", 2)
    for i in range(3):
        (d / "renew").mkdir(exist_ok=True)
        (d / "renew" / f"x{i}.csr").write_bytes(b"x")
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", make_csr("n1")[0])


def test_sign_pending_uses_current_cert_grants(tmp_path):
    d, ca = rig(tmp_path)
    old = node_renew.current_cert(d, "n1")
    csr, _ = make_csr("n1")
    queue_csr(d, "n1", csr)
    assert sign_pending(ca, d) == [("n1", "renewed")]
    new = node_renew.current_cert(d, "n1")
    assert new != old and pub(new) != pub(old)
    ident = pki.node_identity(pki.load_trust_anchor(d), new)
    assert ident.grants == GRANTS
    assert not list((d / "renew").glob("*.csr"))


def test_sign_pending_refuses_revoked_node(tmp_path):
    d, ca = rig(tmp_path)
    (d / "node-n1.crt").unlink()
    queue_csr(d, "n1", make_csr("n1")[0])
    assert sign_pending(ca, d) == [("n1", "refused: no current certificate")]
    assert not list(d.glob("*.crt")) or all(p.name == "ca.crt" for p in d.glob("*.crt"))
    assert not list((d / "renew").glob("*.csr"))


def test_sign_pending_replaces_in_place(tmp_path):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    sign_pending(ca, d)
    assert sorted(p.name for p in d.glob("*.crt")) == ["ca.crt", "node-n1.crt"]
    assert not list(d.glob(".*.tmp"))
    assert set(fleet_grants(d)) == {"n1"}


def test_sign_pending_empty_and_no_dir(tmp_path):
    d, ca = rig(tmp_path)
    assert sign_pending(ca, d) == []
    (d / "renew").mkdir()
    assert sign_pending(ca, d) == []


def test_cli_renew_pending_prints_one_line_per_node(tmp_path, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(d), "renew-pending"]) == 0
    assert capsys.readouterr().out.strip() == "n1: renewed"
    os.unlink(d / "ca.key")
    assert main(["pki", "--dir", str(d), "renew-pending"]) == 1
