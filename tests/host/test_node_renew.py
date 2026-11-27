from __future__ import annotations

import contextlib
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


def _fd_path(fh) -> str:
    fd = fh if isinstance(fh, int) else fh.fileno()
    return os.readlink(f"/proc/self/fd/{fd}")


def pending(d: Path) -> list[str]:
    """Node ids with a CSR still queued, waiting or kept for a retry."""
    r = d / "renew"
    return sorted({p.name.split(".csr")[0] for p in r.glob("*.csr*")}) if r.is_dir() else []


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
    assert pending(d) == ["n1"]
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
    assert pending(d) == ["n1"]


def test_cli_renew_pending_bad_days_exits_1_and_keeps_queue(tmp_path, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(d), "renew-pending", "--days", "0"]) == 1
    assert "error:" in capsys.readouterr().err
    assert pending(d) == ["n1"]


def test_a_garbled_node_dir_ca_crt_does_not_decide_anything(tmp_path):
    """Node dirs are judged by the CA itself; their own ca.crt only marks them as PKI dirs."""
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "ca.crt").write_bytes(b"garbage")
    queue_csr(i1, "n1", make_csr("n1")[0])
    assert sign_pending(ca, ca_dir, node_dirs=[i1]) == [("n1", "renewed")]


def test_unreadable_cert_file_defers_instead_of_dropping(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    real = node_renew._read_capped

    def flaky(path, limit, **kw):
        if path.name == "node-n1.crt":
            raise OSError("EIO")
        return real(path, limit, **kw)
    monkeypatch.setattr(node_renew, "_read_capped", flaky)
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred:")
    monkeypatch.undo()
    assert pending(d) == ["n1"]


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


def test_a_csr_queued_while_one_is_kept_wins_next_run(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    old, _ = make_csr("n1")
    newer, newer_key = make_csr("n1")
    queue_csr(d, "n1", old)

    def fail_and_race(*a):
        queue_csr(d, "n1", newer)                   # lands while the old one is kept
        raise OSError("disk full")
    monkeypatch.setattr(node_renew, "_replace_file", fail_and_race)
    sign_pending(ca, d)
    monkeypatch.undo()
    assert (d / "renew" / "n1.csr").read_bytes() == newer
    assert sign_pending(ca, d) == [("n1", "renewed")]
    assert pub(node_renew.current_cert(d, "n1")) == newer_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pending(d) == []


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


def _issued_at(monkeypatch, when):
    monkeypatch.setattr(pki, "_now", lambda: when)


def test_wg_key_comes_from_the_most_recently_issued_cert(tmp_path, monkeypatch):
    """Mid-rotation a dir holds the old-key and the new-key cert; the newest is the intent."""
    ca_dir = tmp_path / "ca"
    ca = pki.ensure_ca(ca_dir)
    real = pki._now
    now = real()
    wg2 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
    _issued_at(monkeypatch, now - datetime.timedelta(days=1))
    (ca_dir / "old.crt").write_bytes(
        ca.issue_node("n1", wg_pubkey=WG, grants=GRANTS, days=7).cert_pem)
    _issued_at(monkeypatch, now)
    (ca_dir / "node-n1.crt").write_bytes(
        ca.issue_node("n1", wg_pubkey=wg2, grants=GRANTS, days=3).cert_pem)
    monkeypatch.setattr(pki, "_now", real)
    queue_csr(ca_dir, "n1", make_csr("n1")[0])
    assert sign_pending(ca, ca_dir) == [("n1", "renewed")]
    ident = pki.node_identity(pki.load_trust_anchor(ca_dir), node_renew.current_cert(ca_dir, "n1"))
    assert ident.wg_pubkey == wg2


def test_a_dir_trusting_a_foreign_ca_cannot_get_its_certs_signed(tmp_path):
    ca_dir = tmp_path / "ca"
    ca = pki.ensure_ca(ca_dir)
    hostile = tmp_path / "hostile"
    evil = pki.ensure_ca(hostile)                  # the ingress planted its own CA
    broad = pki.NodeGrants(engines=("everything",), tiers=("vpn",), credentials=True)
    (hostile / "ghost.crt").write_bytes(
        evil.sign_node_csr(make_csr("ghost")[0], node_id="ghost", grants=broad))
    queue_csr(hostile, "ghost", make_csr("ghost")[0])
    assert sign_pending(ca, ca_dir, node_dirs=[hostile]) == [
        ("ghost", "refused: no current certificate")]
    real_anchor = pki.load_trust_anchor(ca_dir)
    for crt in hostile.glob("*.crt"):
        with pytest.raises(ValueError):
            pki.node_identity(real_anchor, crt.read_bytes())


def test_a_node_dir_without_ca_crt_fails_the_run_loudly(tmp_path):
    """An unmounted mountpoint is an empty dir: renewing or revoking 'around' it would
    leave that ingress with a stale or unrevoked cert, so refuse the whole run."""
    ca, ca_dir, i1, i2 = _split(tmp_path)
    (i2 / "ca.crt").unlink()
    queue_csr(i1, "n1", make_csr("n1")[0])
    with pytest.raises(OSError):
        sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert pending(i1) == ["n1"]
    assert (i1 / "node-n1.crt").exists()
    with pytest.raises(node_renew.PartialRevoke) as exc:   # revoke does what it can
        node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    assert exc.value.failed and exc.value.failed[0][0] == i2
    assert not (i1 / "node-n1.crt").exists()


def test_two_spellings_of_one_dir_do_not_self_deadlock(tmp_path):
    import signal
    d, ca = rig(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(d)
    queue_csr(d, "n1", make_csr("n1")[0])
    signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(10)
    try:
        assert sign_pending(ca, d, node_dirs=[alias]) == [("n1", "renewed")]
        node_renew.revoke(d, "n1", node_dirs=[alias])
    finally:
        signal.alarm(0)


def test_a_held_lock_fails_the_run_instead_of_hanging(tmp_path, monkeypatch):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 0.3)
    holder = open(i1 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)              # another holder, never released
    try:
        with pytest.raises(OSError):
            sign_pending(ca, ca_dir, node_dirs=[i1])
    finally:
        holder.close()
    assert pending(i1) == ["n1"]


def test_a_symlinked_lock_file_is_not_followed(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    target = tmp_path / "elsewhere" / "planted"
    target.parent.mkdir()
    (i1 / ".renew.lock").symlink_to(target)
    with pytest.raises(OSError):
        sign_pending(ca, ca_dir, node_dirs=[i1])
    assert not target.exists()


def test_a_symlinked_renew_dir_is_not_drained(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.csr").write_bytes(b"x")
    (i1 / "renew").symlink_to(victim)
    assert sign_pending(ca, ca_dir, node_dirs=[i1]) == []
    assert (victim / "keep.csr").exists()


def test_a_symlinked_csr_is_not_read(tmp_path):
    d, ca = rig(tmp_path)
    (d / "renew").mkdir()
    secret = tmp_path / "secret"
    secret.write_bytes(b"not for you")
    (d / "renew" / "n1.csr").symlink_to(secret)
    [(nid, outcome)] = sign_pending(ca, d)          # said, not silently skipped
    assert nid == "n1" and outcome.startswith("refused")
    assert secret.read_bytes() == b"not for you"
    assert pending(d) == []                         # only the link is gone


@pytest.mark.parametrize("bad", ["*", "n?", "../x", ""])
def test_revoke_refuses_an_invalid_node_id(tmp_path, bad):
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    with pytest.raises(ValueError):
        node_renew.revoke(d, bad)
    assert pending(d) == ["n1"]


def test_revoke_matches_csr_names_exactly(tmp_path):
    d, _ = rig(tmp_path)
    (d / "renew").mkdir()
    (d / "renew" / "x.csr.csr").write_bytes(b"belongs to node x.csr")
    node_renew.revoke(d, "x")
    assert (d / "renew" / "x.csr.csr").exists()


def test_cli_revoke_node_exits_1_when_nothing_was_revoked(tmp_path, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    assert main(["pki", "--dir", str(d), "revoke-node", "--node-id", "nobody"]) == 1


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
    assert pending(i1) == ["n1"]
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
    assert pending(d) == ["n1"]


def test_unreachable_node_dir_renews_nothing_and_consumes_nothing(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    real = fcntl.flock

    def stale(fh, op):
        if str(i2) in _fd_path(fh):
            raise OSError(116, "Stale file handle")
        return real(fh, op)
    monkeypatch.setattr(fcntl, "flock", stale)
    with pytest.raises(OSError):
        sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    monkeypatch.undo()
    assert pending(i1) == ["n1"]


def test_cli_renew_pending_unreachable_dir_exits_1(tmp_path, capsys):
    from blastbox.host.cli import main
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    assert main(["pki", "--dir", str(ca_dir), "renew-pending", "--node-dir", str(i1),
                 "--node-dir", str(tmp_path / "missing" / "mount")]) == 1
    assert "error:" in capsys.readouterr().err
    assert pending(i1) == ["n1"]


def test_every_node_dir_is_locked_for_the_whole_run(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_csr(i1, "n1", make_csr("n1")[0])
    locked = []
    real = fcntl.flock

    def spy(fh, op):
        if op & fcntl.LOCK_EX:
            locked.append(Path(_fd_path(fh)).parent)
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


def test_a_kept_csr_stays_set_aside_and_is_never_renamed_back(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    monkeypatch.setattr(node_renew, "_replace_file",
                        lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    sign_pending(ca, d)
    sign_pending(ca, d)                             # retried, still kept
    names = sorted(p.name for p in (d / "renew").glob("*.csr*"))
    assert names == ["n1.csr.signing"]              # the ingress's name is never written
    monkeypatch.undo()
    node_renew.revoke(d, "n1")
    assert not list((d / "renew").glob("*.csr*"))


def test_cli_renew_pending_exits_2_when_a_renewal_is_deferred(tmp_path, monkeypatch, capsys):
    from blastbox.host.cli import main
    d, _ = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    monkeypatch.setattr(node_renew, "_replace_file",
                        lambda *a: (_ for _ in ()).throw(OSError(30, "Read-only file system")))
    assert main(["pki", "--dir", str(d), "renew-pending"]) == 2
    assert "deferred" in capsys.readouterr().out


def test_oversized_and_fifo_files_in_a_node_dir_are_skipped(tmp_path):
    import signal
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    with open(i1 / "zz.crt", "wb") as fh:           # sparse, huge
        fh.truncate(3 << 30)
    os.mkfifo(i1 / "fifo.crt")
    (i1 / "renew").mkdir(exist_ok=True)
    os.mkfifo(i1 / "renew" / "n2.csr.signing")
    queue_csr(i1, "n1", make_csr("n1")[0])
    signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError()))
    signal.alarm(20)
    try:
        out = dict(sign_pending(ca, ca_dir, node_dirs=[i1]))
        assert out["n1"] == "renewed" and out["n2"].startswith("refused")
        with pytest.raises(node_renew.PartialRevoke) as exc:   # the huge one is reported
            node_renew.revoke(ca_dir, "n1", node_dirs=[i1])
        assert any("zz.crt" in why for _d, why in exc.value.failed)
        assert not (i1 / "node-n1.crt").exists()
    finally:
        signal.alarm(0)


def test_oversized_queued_csr_is_refused_without_reading_it(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    (d / "renew").mkdir()
    with open(d / "renew" / "n1.csr", "wb") as fh:
        fh.truncate(3 << 30)
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("refused")
    assert pending(d) == []


def test_revoke_proceeds_past_a_dir_whose_lock_is_held(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 0.3)
    holder = open(i2 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)              # a hostile ingress never lets go
    try:
        with pytest.raises(node_renew.PartialRevoke) as exc:
            node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    finally:
        holder.close()
    for d in (ca_dir, i1, i2):                      # revoked everywhere regardless
        assert node_renew.current_cert(d, "n1") is None
    assert exc.value.unlocked == [i2]


def test_same_second_certs_with_different_wg_keys_defer_not_guess(tmp_path, monkeypatch):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    now = pki._now()
    monkeypatch.setattr(pki, "_now", lambda: now)
    wg2 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
    (d / "a-old.crt").write_bytes(ca.issue_node("n1", wg_pubkey=WG, grants=GRANTS).cert_pem)
    (d / "z-new.crt").write_bytes(ca.issue_node("n1", wg_pubkey=wg2, grants=GRANTS).cert_pem)
    monkeypatch.undo()
    before = {p.name: p.read_bytes() for p in d.glob("*.crt")}
    queue_csr(d, "n1", make_csr("n1")[0])
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred") and "WireGuard" in outcome
    assert {p.name: p.read_bytes() for p in d.glob("*.crt")} == before
    assert pending(d) == ["n1"]


def test_revoke_removes_a_symlink_to_the_nodes_cert_but_not_its_target(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    outside = tmp_path / "outside.crt"
    os.replace(i1 / "node-n1.crt", outside)
    (i1 / "node-n1.crt").symlink_to(outside)        # the ingress follows it
    assert set(fleet_grants(i1)) == {"n1"}
    node_renew.revoke(ca_dir, "n1", node_dirs=[i1])
    assert not (i1 / "node-n1.crt").is_symlink()
    assert outside.exists()
    assert "n1" not in fleet_grants(i1)


def test_a_cert_linked_from_outside_its_dir_defers_loudly_and_keeps_the_csr(tmp_path):
    """The ingress follows the link; renewal will not (see the out-of-dir test), so it
    must say why and keep the CSR rather than refuse and drop it."""
    d, ca = rig(tmp_path)
    outside = tmp_path / "store" / "n1.crt"
    outside.parent.mkdir()
    os.replace(d / "node-n1.crt", outside)
    (d / "node-n1.crt").symlink_to(outside)
    assert set(fleet_grants(d)) == {"n1"}
    queue_csr(d, "n1", make_csr("n1")[0])
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred") and "link" in outcome
    assert pending(d) == ["n1"]
    os.replace(outside, d / "node-n1.crt")              # operator replaces the link
    assert sign_pending(ca, d) == [("n1", "renewed")]


def test_one_unreadable_file_does_not_stop_a_dirs_revocation(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "aaa.crt").write_bytes(b"x")
    os.chmod(i1 / "aaa.crt", 0)
    queue_csr(i1, "n1", make_csr("n1")[0])
    try:
        if os.access(i1 / "aaa.crt", os.R_OK):
            pytest.skip("running as root: mode 000 is still readable")
        with pytest.raises(node_renew.PartialRevoke) as exc:
            node_renew.revoke(ca_dir, "n1", node_dirs=[i1])
    finally:
        os.chmod(i1 / "aaa.crt", 0o644)
    assert not (i1 / "node-n1.crt").exists()
    assert pending(i1) == []
    assert i1 / "node-n1.crt" in exc.value.removed
    assert any("aaa.crt" in why for _d, why in exc.value.failed)


def test_revoke_removes_at_once_and_reports_a_lock_that_never_comes(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "REVOKE_LOCK_WAIT_S", 0.1)
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 0.5)
    holder = open(i2 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)
    seen = []
    real = node_renew._locked

    @contextlib.contextmanager
    def spy(dirs, timeout=None):
        seen.append(node_renew.current_cert(i2, "n1") is None)  # state at each wait
        with real(dirs, timeout=timeout):
            yield
    monkeypatch.setattr(node_renew, "_locked", spy)
    try:
        with pytest.raises(node_renew.PartialRevoke) as exc:
            node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    finally:
        holder.close()
    assert exc.value.unlocked == [i2]
    assert seen[-1] is True             # already revoked before the long second wait
    assert node_renew.current_cert(i2, "n1") is None


def test_an_unreadable_queued_csr_is_reported_deferred(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    real = node_renew._read_capped

    def eacces(path, limit, **kw):
        if path.name.startswith("n1.csr"):
            raise PermissionError(13, "Permission denied")
        return real(path, limit, **kw)
    monkeypatch.setattr(node_renew, "_read_capped", eacces)
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("deferred")
    assert pending(d) == ["n1"]


def test_revoke_redoes_a_dir_once_an_in_flight_renewal_lets_go(tmp_path, monkeypatch):
    """A held lock may be a renewal mid-write: revoke must not let it write the cert back."""
    import threading
    import time as _t
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "REVOKE_LOCK_WAIT_S", 0.2)
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 10.0)
    cert = (i1 / "node-n1.crt").read_bytes()
    holder = open(i1 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)

    def renewal_finishing():
        _t.sleep(0.8)                               # revoke has gone ahead unlocked by now
        (i1 / "node-n1.crt").write_bytes(cert)      # ... and the renewal writes it back
        holder.close()                              # then releases its lock
    t = threading.Thread(target=renewal_finishing)
    t.start()
    try:
        node_renew.revoke(ca_dir, "n1", node_dirs=[i1])
    finally:
        t.join()
    assert node_renew.current_cert(i1, "n1") is None


def test_revoke_reports_a_cert_too_large_to_check(tmp_path, monkeypatch):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "MAX_CERT_BYTES", 100)   # every real cert is "huge"
    with pytest.raises(node_renew.PartialRevoke) as exc:
        node_renew.revoke(ca_dir, "n1", node_dirs=[i1])
    assert any("node-n1.crt" in why for _d, why in exc.value.failed)


def test_a_directory_in_the_queue_is_refused_not_fatal(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "renew").mkdir(exist_ok=True)
    (i1 / "renew" / "evil.csr").mkdir()
    (i1 / "renew" / "evil2.csr.signing").mkdir()
    queue_csr(i1, "n1", make_csr("n1")[0])
    out = dict(sign_pending(ca, ca_dir, node_dirs=[i1]))
    assert out["n1"] == "renewed"
    assert out["evil"].startswith("refused") and out["evil2"].startswith("refused")


def test_revoke_never_holds_one_lock_while_waiting_for_another(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "REVOKE_LOCK_WAIT_S", 0.1)
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 0.3)
    held: list[int] = []
    real = node_renew._locked

    @contextlib.contextmanager
    def spy(dirs, timeout=None):
        held.append(len(held_now))
        with real(dirs, timeout=timeout):
            held_now.append(1)
            try:
                yield
            finally:
                held_now.pop()
    held_now: list[int] = []
    monkeypatch.setattr(node_renew, "_locked", spy)
    holder = open(i1 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        with pytest.raises(node_renew.PartialRevoke):
            node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    finally:
        holder.close()
    assert held and max(held) == 0       # no lock held at the start of any wait


def test_a_transient_pass_one_error_fixed_by_pass_two_is_not_reported(tmp_path, monkeypatch):
    import threading
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    monkeypatch.setattr(node_renew, "REVOKE_LOCK_WAIT_S", 0.1)
    monkeypatch.setattr(node_renew, "LOCK_TIMEOUT_S", 5.0)
    real = node_renew._read_capped
    calls = {"n": 0}

    def flaky_once(path, limit, **kw):
        if path.name == "node-n1.crt" and path.parent == i1 and calls["n"] == 0:
            calls["n"] += 1
            raise OSError(5, "Input/output error")
        return real(path, limit, **kw)
    monkeypatch.setattr(node_renew, "_read_capped", flaky_once)
    holder = open(i1 / ".renew.lock", "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)
    t = threading.Timer(0.5, holder.close)
    t.start()
    try:
        node_renew.revoke(ca_dir, "n1", node_dirs=[i1])   # no PartialRevoke
    finally:
        t.join()
    assert not (i1 / "node-n1.crt").exists()


def test_a_dangling_cert_link_does_not_defer_renewals(tmp_path):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    (i1 / "stale.crt").symlink_to(tmp_path / "gone.crt")
    queue_csr(i2, "n1", make_csr("n1")[0])
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == [("n1", "renewed")]


def test_a_cert_link_out_of_its_node_dir_never_authorises_a_renewal(tmp_path):
    """Resolved on the CA host, a link out of the dir may point at a cert the ingress
    itself cannot see (another ingress's mount): it must not count for that dir."""
    ca, ca_dir, i1, i2 = _split(tmp_path)
    (i1 / "node-n1.crt").unlink()                       # n1 revoked on ingress-1 ...
    (i1 / "takeover.crt").symlink_to(i2 / "node-n1.crt")  # ... but a link points out
    queue_csr(i1, "n1", make_csr("n1")[0])
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert not outcome.startswith("renewed")
    assert (i1 / "takeover.crt").is_symlink()           # nothing written into ingress-1


def test_a_cert_link_inside_its_node_dir_is_followed(tmp_path):
    d, ca = rig(tmp_path)
    os.replace(d / "node-n1.crt", d / "store-n1.pem")
    (d / "node-n1.crt").symlink_to("store-n1.pem")
    queue_csr(d, "n1", make_csr("n1")[0])
    assert sign_pending(ca, d) == [("n1", "renewed")]


def test_a_symlinked_csr_does_not_destroy_a_kept_retry(tmp_path, monkeypatch):
    d, ca = rig(tmp_path)
    queue_csr(d, "n1", make_csr("n1")[0])
    monkeypatch.setattr(node_renew, "_replace_file",
                        lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    sign_pending(ca, d)                                 # kept as n1.csr.signing
    monkeypatch.undo()
    (d / "renew" / "n1.csr").symlink_to(tmp_path / "whatever")
    assert sign_pending(ca, d) == [("n1", "renewed")]
