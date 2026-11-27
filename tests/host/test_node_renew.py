from __future__ import annotations

import datetime
import fcntl
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


def _issue_expired(d, ca, node, monkeypatch):
    real = pki._now
    monkeypatch.setattr(pki, "_now", lambda: real() - datetime.timedelta(days=30))
    csr, _ = make_csr(node)
    (d / f"node-{node}.crt").write_bytes(ca.sign_node_csr(csr, node_id=node, grants=GRANTS))
    monkeypatch.setattr(pki, "_now", real)


def test_expired_current_cert_is_not_renewed(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    _issue_expired(d, ca, "n1", monkeypatch)
    before = (d / "node-n1.crt").read_bytes()
    queue_csr(d, "n1", make_csr("n1")[0])
    assert sign_pending(ca, d) == [("n1", "refused: no current certificate")]
    assert (d / "node-n1.crt").read_bytes() == before
    assert not list((d / "renew").glob("*.csr*"))


def test_cn_mismatch_at_signing_time_is_refused(tmp_path):
    d, ca = rig(tmp_path)
    (d / "renew").mkdir()
    (d / "renew" / "n1.csr").write_bytes(make_csr("other")[0])
    before = (d / "node-n1.crt").read_bytes()
    [(nid, outcome)] = sign_pending(ca, d)
    assert nid == "n1" and outcome.startswith("refused")
    assert (d / "node-n1.crt").read_bytes() == before
    assert not list((d / "renew").glob("*.csr*"))


def test_oserror_while_replacing_keeps_the_csr(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    monkeypatch.setattr(node_renew, "_replace_file",
                        lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred:")
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]
    monkeypatch.undo()
    assert sign_pending(ca, d) == [("n1", "renewed")]


def test_queue_full_count_ignores_lock_and_tmp(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    monkeypatch.setattr(node_renew, "MAX_QUEUED", 1)
    (d / "renew").mkdir()
    for n in (".lock", ".a.tmp", ".b.tmp"):
        (d / "renew" / n).write_bytes(b"")
    queue_csr(d, "n1", make_csr("n1")[0])


def test_existing_renew_dir_is_chmodded_0700(tmp_path):
    d, _ = rig(tmp_path)
    (d / "renew").mkdir(mode=0o755)
    os.chmod(d / "renew", 0o755)
    queue_csr(d, "n1", make_csr("n1")[0])
    assert (d / "renew").stat().st_mode & 0o777 == 0o700


WG = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="


def test_renewal_keeps_the_wireguard_key_of_a_v1_cert(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    (d / "node-n1.crt").write_bytes(
        ca.issue_node("n1", wg_pubkey=WG, grants=GRANTS).cert_pem)
    queue_csr(d, "n1", make_csr("n1")[0])
    assert sign_pending(ca, d) == [("n1", "renewed")]
    ident = pki.node_identity(pki.load_trust_anchor(d), (d / "node-n1.crt").read_bytes())
    assert ident.wg_pubkey == WG and ident.info_version == 1


def test_renewal_never_widens_past_the_ingress_grant_intersection(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    broad = pki.NodeGrants(engines=("a", "b"), tiers=("warm",), credentials=True)
    narrow = pki.NodeGrants(engines=("a",), tiers=(), credentials=False)
    (d / "n1-old.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                    grants=broad, days=10))
    (d / "node-n1.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                     grants=narrow, days=3))
    assert fleet_grants(d)["n1"] == narrow
    queue_csr(d, "n1", make_csr("n1")[0])
    assert sign_pending(ca, d) == [("n1", "renewed")]
    assert fleet_grants(d)["n1"] == narrow
    assert pki.node_identity(pki.load_trust_anchor(d),
                             node_renew.current_cert(d, "n1")).grants == narrow


def test_renewal_supersedes_a_longer_lived_broader_cert_beside_it(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    broad = pki.NodeGrants(engines=("a", "b"), tiers=(), credentials=True)
    narrow = pki.NodeGrants(engines=("a",), tiers=(), credentials=False)
    (d / "n1-old.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                    grants=broad, days=10))
    (d / "node-n1.crt").write_bytes(ca.sign_node_csr(make_csr("n1")[0], node_id="n1",
                                                     grants=narrow, days=12))
    csr, key = make_csr("n1")
    queue_csr(d, "n1", csr)
    assert sign_pending(ca, d, days=7) == [("n1", "renewed")]
    anchor = pki.load_trust_anchor(d)
    left = [p for p in d.glob("*.crt") if p.name != "ca.crt"]
    assert len(left) == 1
    ident = pki.node_identity(anchor, left[0].read_bytes())
    assert ident.grants == narrow
    assert pub(node_renew.current_cert(d, "n1")) == key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize("days", [0, pki.MAX_NODE_CERT_DAYS + 1])
def test_out_of_range_days_is_refused_before_touching_the_queue(tmp_path, days):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    with pytest.raises(ValueError):
        sign_pending(ca, d, days=days)
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]


def test_cli_renew_pending_bad_days_exits_1_and_keeps_queue(tmp_path, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(d), "renew-pending", "--days", "0"]) == 1
    assert "error:" in capsys.readouterr().err
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]


def test_unreadable_trust_anchor_defers_instead_of_dropping(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])

    def boom(_d):
        raise OSError("EIO")
    monkeypatch.setattr(node_renew, "load_trust_anchor", boom)
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred:")
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]


def test_unreadable_cert_file_defers_instead_of_dropping(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    real = Path.read_bytes

    def flaky(self):
        if self.name == "node-n1.crt":
            raise OSError("EIO")
        return real(self)
    monkeypatch.setattr(Path, "read_bytes", flaky)
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred:")
    monkeypatch.undo()
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]


def test_cert_revoked_while_signing_is_not_resurrected(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    real = ca.sign_node_csr

    def revoke_then_sign(*a, **kw):
        (d / "node-n1.crt").unlink()          # operator revokes mid-sign
        return real(*a, **kw)
    monkeypatch.setattr(ca, "sign_node_csr", revoke_then_sign)
    [(nid, outcome)] = sign_pending(ca, d)
    assert not outcome.startswith("renewed")
    assert not (d / "node-n1.crt").exists()
    monkeypatch.undo()
    assert sign_pending(ca, d) == [("n1", "refused: no current certificate")]
    assert not list((d / "renew").glob("*.csr*"))


def test_deferred_restore_never_clobbers_a_newer_csr(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    old, _ = make_csr("n1")
    newer, _ = make_csr("n1")
    queue_csr(d, "n1", old)

    def fail_and_race(*a):
        queue_csr(d, "n1", newer)                   # lands between the checks
        raise OSError("disk full")
    monkeypatch.setattr(node_renew, "_replace_file", fail_and_race)
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists",
                        lambda self, **kw: False if self.name == "n1.csr" else real_exists(self))
    sign_pending(ca, d)
    monkeypatch.undo()
    assert (d / "renew" / "n1.csr").read_bytes() == newer
    assert not list((d / "renew").glob("*.signing"))


def test_queue_cap_is_exact(tmp_path, monkeypatch):
    d, _ = rig(tmp_path)
    monkeypatch.setattr(node_renew, "MAX_QUEUED", 2)
    (d / "renew").mkdir()
    for i in range(2):
        (d / "renew" / f"x{i}.csr").write_bytes(b"x")
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", make_csr("n1")[0])


def _split(tmp_path):
    """A CA host and two ingress hosts, each with its own PKI dir (no shared queue)."""
    ca_dir = tmp_path / "ca"
    ca = pki.ensure_ca(ca_dir)
    i1, i2 = tmp_path / "ingress-1", tmp_path / "ingress-2"
    cert = ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=GRANTS)
    for d in (ca_dir, i1, i2):
        d.mkdir(exist_ok=True)
        if d != ca_dir:
            (d / "ca.crt").write_bytes((ca_dir / "ca.crt").read_bytes())
        (d / "node-n1.crt").write_bytes(cert)
    return ca, ca_dir, i1, i2


def test_split_hosts_sign_the_ingress_queue_and_publish_everywhere(tmp_path):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    csr, key = make_csr("n1")
    queue_csr(i1, "n1", csr)                       # the node renewed through ingress-1
    assert sign_pending(ca, ca_dir, days=7, node_dirs=[i1, i2]) == [("n1", "renewed")]
    want = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for d in (i1, i2, ca_dir):
        assert pub(node_renew.current_cert(d, "n1")) == want, d
    assert not list((i1 / "renew").glob("*.csr*"))


def test_split_hosts_do_not_republish_where_the_node_was_revoked(tmp_path):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    (i2 / "node-n1.crt").unlink()                  # revoked on ingress-2 only
    queue_csr(i1, "n1", make_csr("n1")[0])
    assert sign_pending(ca, ca_dir, days=7, node_dirs=[i1, i2]) == [("n1", "renewed")]
    assert not (i2 / "node-n1.crt").exists()


def test_cli_renew_pending_accepts_node_dirs(tmp_path, capsys):
    from blastbox.host.cli import main
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i2, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(ca_dir), "renew-pending",
                 "--node-dir", str(i1), "--node-dir", str(i2)]) == 0
    assert capsys.readouterr().out.strip() == "n1: renewed"


def _put(d, ca_dir, cert):
    d.mkdir(exist_ok=True)
    (d / "ca.crt").write_bytes((ca_dir / "ca.crt").read_bytes())
    (d / "node-n1.crt").write_bytes(cert)


def test_split_renewal_never_widens_a_narrower_ingress(tmp_path):
    ca_dir = tmp_path / "ca"
    ca = pki.ensure_ca(ca_dir)
    broad = pki.NodeGrants(engines=("x", "y"), tiers=("warm",), credentials=True)
    narrow = pki.NodeGrants(engines=("x",), tiers=(), credentials=False)
    i1, i2 = tmp_path / "i1", tmp_path / "i2"
    _put(i1, ca_dir, ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=broad))
    _put(i2, ca_dir, ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=narrow))
    queue_csr(i1, "n1", make_csr("n1")[0])
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == [("n1", "renewed")]
    assert fleet_grants(i2)["n1"] == narrow
    assert fleet_grants(i1)["n1"] == narrow       # one cert, the narrowest view


def test_split_renewal_refuses_when_dirs_disagree_on_the_wg_key(tmp_path):
    ca_dir = tmp_path / "ca"
    ca = pki.ensure_ca(ca_dir)
    i1, i2 = tmp_path / "i1", tmp_path / "i2"
    _put(i1, ca_dir, ca.issue_node("n1", wg_pubkey=WG, grants=GRANTS).cert_pem)
    _put(i2, ca_dir, ca.sign_node_csr(make_csr("n1")[0], node_id="n1", grants=GRANTS))
    before = (i2 / "node-n1.crt").read_bytes()
    queue_csr(i1, "n1", make_csr("n1")[0])
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome.startswith("refused")
    assert (i2 / "node-n1.crt").read_bytes() == before
    assert pki.node_identity(pki.load_trust_anchor(i2), before).wg_pubkey is None


def test_failed_mirror_publish_keeps_the_csr_and_converges_next_run(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    real = node_renew._replace_file

    def flaky(path, data):
        if path.parent == i2:
            raise OSError("EIO")
        return real(path, data)
    monkeypatch.setattr(node_renew, "_replace_file", flaky)
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome.startswith("deferred")
    assert [p.name for p in (i1 / "renew").glob("*.csr*")] == ["n1.csr"]
    monkeypatch.undo()
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == [("n1", "renewed")]
    assert (i1 / "node-n1.crt").read_bytes() == (i2 / "node-n1.crt").read_bytes()


def test_restore_without_hard_links_does_not_crash(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])

    def nolink(*_a):
        raise PermissionError("EPERM: no hard links on this mount")
    monkeypatch.setattr(os, "link", nolink)
    monkeypatch.setattr(node_renew, "_replace_file",
                        lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred")
    assert [p.name for p in (d / "renew").glob("*.csr*")] == ["n1.csr"]


def test_unreachable_node_dir_renews_nothing_and_consumes_nothing(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    real = fcntl.flock

    def stale(fh, op):
        if str(i2) in fh.name:
            raise OSError(116, "Stale file handle")
        return real(fh, op)
    monkeypatch.setattr(fcntl, "flock", stale)
    with pytest.raises(OSError):
        sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    monkeypatch.undo()
    assert [p.name for p in (i1 / "renew").glob("*.csr*")] == ["n1.csr"]


def test_cli_renew_pending_unreachable_dir_exits_1(tmp_path, capsys):
    from blastbox.host.cli import main
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(ca_dir), "renew-pending", "--node-dir", str(i1),
                 "--node-dir", str(tmp_path / "missing" / "mount")]) == 1
    assert "error:" in capsys.readouterr().err
    assert [p.name for p in (i1 / "renew").glob("*.csr*")] == ["n1.csr"]


def test_every_node_dir_is_locked_for_the_whole_run(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    locked = []
    real = fcntl.flock

    def spy(fh, op):
        if op & fcntl.LOCK_EX:
            locked.append(Path(fh.name).parent)
        return real(fh, op)
    monkeypatch.setattr(fcntl, "flock", spy)
    sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert {i1, i2, ca_dir} <= set(locked)


def test_node_dirs_still_drain_the_ca_hosts_own_queue(tmp_path):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(ca_dir, "n1", make_csr("n1")[0])     # a node renewing via the CA host's ingress
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == [("n1", "renewed")]
    assert (i1 / "node-n1.crt").read_bytes() == (ca_dir / "node-n1.crt").read_bytes()


def test_revoke_removes_certs_and_queue_everywhere(tmp_path):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    removed = node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    assert len(removed) == 3
    for d in (ca_dir, i1, i2):
        assert node_renew.current_cert(d, "n1") is None
    assert not list((i1 / "renew").glob("n1.csr*"))
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == []


def test_revoke_waits_for_a_renewal_in_flight(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    order = []
    real = fcntl.flock

    def spy(fh, op):
        order.append(op)
        return real(fh, op)
    monkeypatch.setattr(fcntl, "flock", spy)
    node_renew.revoke(d, "n1")
    assert order and order[0] & fcntl.LOCK_EX


def test_cli_revoke_node(tmp_path, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    assert main(["pki", "--dir", str(d), "revoke-node", "--node-id", "n1"]) == 0
    assert node_renew.current_cert(d, "n1") is None
    assert "node-n1.crt" in capsys.readouterr().out
