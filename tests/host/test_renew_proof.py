"""Renewal requires proof of possession of the CURRENT cert's key.

The session is a bearer token; it must not be what lets a node put a new key in its cert.
The ingress checks the proof, and the CA host checks it again against the real CA.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import node_renew, pki
from blastbox.host.node_renew import (
    RENEW_PROOF_DOMAIN,
    RenewRefused,
    queue_csr,
    renew_payload,
    sign_pending,
    sign_renew_proof,
)
from tests.host.test_node_renew import GRANTS, _split, entry, make_csr, pending, pub
from tests.host.test_node_renew import queue_csr as queue_proven


def _node(ca, d, node_id="n1"):
    """A node's real cert in ``d`` and the key it holds."""
    issued = ca.issue_node(node_id, grants=GRANTS)
    (d / f"node-{node_id}.crt").write_bytes(issued.cert_pem)
    return issued.cert_pem, serialization.load_pem_private_key(issued.key_pem, password=None)


def _rig(tmp_path):
    d = tmp_path / "pki"
    ca = pki.ensure_ca(d)
    cert, key = _node(ca, d)
    return d, ca, cert, key


def test_payload_is_the_documented_concatenation():
    csr = "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
    want = (b"blastbox/node-renew/v1\x00n1\x00"
            + hashlib.sha256(csr.encode()).hexdigest().encode() + b"\x00" + b"1700000000")
    assert RENEW_PROOF_DOMAIN == b"blastbox/node-renew/v1"
    assert renew_payload("n1", csr, 1700000000) == want


def test_a_valid_proof_queues(tmp_path):
    d, ca, cert, key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    at = int(time.time())
    queue_csr(d, "n1", csr, cert_pem=cert, issued_at=at,
              signature=sign_renew_proof(key, "n1", csr.decode(), at))
    doc = json.loads((d / "renew" / "n1.csr").read_bytes())
    assert set(doc) == {"csr_pem", "cert_pem", "issued_at", "signature"}
    assert sign_pending(ca, d) == [("n1", "renewed")]


def _refusal(d, csr, **kw):
    with pytest.raises(RenewRefused) as exc:
        queue_csr(d, "n1", csr, **kw)
    assert not pending(d)
    return exc.value


def test_ingress_refuses_a_proof_by_another_key(tmp_path):
    d, ca, cert, _key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    at = int(time.time())
    other = ec.generate_private_key(ec.SECP256R1())
    exc = _refusal(d, csr, cert_pem=cert, issued_at=at,
                   signature=sign_renew_proof(other, "n1", csr.decode(), at))
    assert exc.identity


def test_ingress_refuses_a_proof_over_a_different_csr(tmp_path):
    d, ca, cert, key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    swapped, _ = make_csr("n1")
    at = int(time.time())
    exc = _refusal(d, swapped, cert_pem=cert, issued_at=at,
                   signature=sign_renew_proof(key, "n1", csr.decode(), at))
    assert exc.identity


def test_ingress_refuses_another_nodes_cert(tmp_path):
    d, ca, _cert, _key = _rig(tmp_path)
    cert2, key2 = _node(ca, d, "n2")
    csr, _ = make_csr("n1")
    at = int(time.time())
    exc = _refusal(d, csr, cert_pem=cert2, issued_at=at,
                   signature=sign_renew_proof(key2, "n1", csr.decode(), at))
    assert exc.identity


def test_ingress_refuses_a_foreign_ca_cert(tmp_path):
    d, ca, _cert, _key = _rig(tmp_path)
    evil = pki.ensure_ca(tmp_path / "evil")
    issued = evil.issue_node("n1", grants=GRANTS)
    k = serialization.load_pem_private_key(issued.key_pem, password=None)
    csr, _ = make_csr("n1")
    at = int(time.time())
    exc = _refusal(d, csr, cert_pem=issued.cert_pem, issued_at=at,
                   signature=sign_renew_proof(k, "n1", csr.decode(), at))
    assert exc.identity


@pytest.mark.parametrize("skew", [-301, 301])
def test_ingress_refuses_a_stale_or_future_proof(tmp_path, skew):
    d, ca, cert, key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    now = 1_800_000_000
    at = now + skew
    exc = _refusal(d, csr, cert_pem=cert, issued_at=at, now=now,
                   signature=sign_renew_proof(key, "n1", csr.decode(), at))
    assert not exc.identity


@pytest.mark.parametrize("bad", ["1700000000", 1.0, True, None])
def test_ingress_refuses_a_non_integer_issued_at(tmp_path, bad):
    d, ca, cert, key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    _refusal(d, csr, cert_pem=cert, issued_at=bad,
             signature=sign_renew_proof(key, "n1", csr.decode(), 1700000000))


def test_ingress_refuses_a_signature_that_is_not_base64(tmp_path):
    d, ca, cert, _key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    exc = _refusal(d, csr, cert_pem=cert, issued_at=int(time.time()), signature="!!not b64")
    assert not exc.identity


def test_hostile_ingress_with_a_copied_genuine_cert_cannot_rekey_the_victim(tmp_path):
    """The ingress holds a copy of the victim's REAL cert, not its key. It queues a CSR for
    its own key, with no proof or a proof by its own key: the CA host refuses both."""
    ca, ca_dir, i1, i2 = _split(tmp_path)
    victim = (i2 / "node-n1.crt").read_bytes()
    (i1 / "copied.crt").write_bytes(victim)
    attacker_csr, attacker_key = make_csr("n1")
    at = int(time.time())
    for over in ({"signature": base64.b64encode(b"\x30\x00").decode()},
                 {"signature": sign_renew_proof(attacker_key, "n1",
                                                attacker_csr.decode(), at)}):
        (i1 / "renew").mkdir(exist_ok=True)
        (i1 / "renew" / "n1.csr").write_bytes(
            entry(ca, "n1", attacker_csr, cert_pem=victim.decode(), issued_at=at, **over))
        [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
        assert outcome.startswith("refused"), outcome
        assert (i2 / "node-n1.crt").read_bytes() == victim
    for d in (ca_dir, i1, i2):
        cur = node_renew.current_cert(d, "n1")
        assert cur is None or pub(cur) == pub(victim)


def test_ca_host_reverifies_against_the_real_ca_not_the_ingress(tmp_path):
    """A hostile ingress's own anchor accepted the proof; the CA host must not."""
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    evil = pki.ensure_ca(tmp_path / "evil")
    issued = evil.issue_node("n1", grants=GRANTS)
    k = serialization.load_pem_private_key(issued.key_pem, password=None)
    csr, _ = make_csr("n1")
    at = int(time.time())
    (i1 / "renew").mkdir(exist_ok=True)       # the hostile ingress writes what it likes
    (i1 / "renew" / "n1.csr").write_text(json.dumps(
        {"csr_pem": csr.decode(), "cert_pem": issued.cert_pem.decode(), "issued_at": at,
         "signature": sign_renew_proof(k, "n1", csr.decode(), at)}))
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1])
    assert outcome.startswith("refused") and "proof" in outcome


def test_ca_host_refuses_a_proof_older_than_a_day(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    csr, _ = make_csr("n1")
    old = int(time.time()) - node_renew.RENEW_PROOF_MAX_AGE_S - 60
    (i1 / "renew").mkdir()
    (i1 / "renew" / "n1.csr").write_bytes(entry(ca, "n1", csr, at=old, d=i1))
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1])
    assert outcome.startswith("refused") and "issued_at" in outcome
    assert not pending(i1)


def test_ca_host_accepts_a_proof_a_few_hours_old(tmp_path):
    """The timer may run long after the ingress queued it: 24 h, not the ingress's 300 s."""
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    csr, _ = make_csr("n1")
    (i1 / "renew").mkdir()
    (i1 / "renew" / "n1.csr").write_bytes(entry(ca, "n1", csr, at=int(time.time()) - 3 * 3600, d=i1))
    assert sign_pending(ca, ca_dir, node_dirs=[i1]) == [("n1", "renewed")]


def test_ca_host_refuses_a_legacy_bare_pem_entry(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "renew").mkdir()
    (i1 / "renew" / "n1.csr").write_bytes(make_csr("n1")[0])
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1])
    assert outcome.startswith("refused") and "legacy" in outcome
    assert not pending(i1)


def test_ca_host_refuses_a_malformed_entry(tmp_path):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "renew").mkdir()
    (i1 / "renew" / "n1.csr").write_text(json.dumps({"csr_pem": 1}))
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1])
    assert outcome.startswith("refused") and "malformed" in outcome


def test_ca_host_refuses_a_proof_cert_expired_by_processing_time(tmp_path, monkeypatch):
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    csr, _ = make_csr("n1")
    (i1 / "renew").mkdir()
    real = pki._now
    import datetime
    monkeypatch.setattr(pki, "_now", lambda: real() - datetime.timedelta(days=6, hours=23))
    (i1 / "renew" / "n1.csr").write_bytes(entry(ca, "n1", csr))   # proof cert issued long ago
    monkeypatch.setattr(pki, "_now", lambda: real() + datetime.timedelta(hours=2))
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1])
    assert outcome.startswith("refused")


def test_a_revoked_and_reissued_nodes_old_key_cannot_renew(tmp_path):
    """Revoke, then re-enrol under the same id with a NEW key: a proof by the OLD cert's
    key (still unexpired, since revocation is deletion) must not authorise a renewal."""
    d, ca, old_cert, old_key = _rig(tmp_path)
    node_renew.revoke(d, "n1")
    new_cert, _new_key = _node(ca, d)                     # re-enrolled
    attacker_csr, _ = make_csr("n1")
    at = int(time.time())
    sig = sign_renew_proof(old_key, "n1", attacker_csr.decode(), at)
    with pytest.raises(RenewRefused) as exc:              # the ingress refuses it ...
        queue_csr(d, "n1", attacker_csr, cert_pem=old_cert, issued_at=at, signature=sig)
    assert exc.value.identity
    (d / "renew").mkdir(exist_ok=True)                    # ... and so does the CA host
    (d / "renew" / "n1.csr").write_text(json.dumps(
        {"csr_pem": attacker_csr.decode(), "cert_pem": old_cert.decode(),
         "issued_at": at, "signature": sig}))
    [(nid, outcome)] = sign_pending(ca, d)
    assert outcome.startswith("refused") and "current" in outcome
    assert (d / "node-n1.crt").read_bytes() == new_cert


@pytest.mark.parametrize("at", [10 ** 400, -1, 2 ** 63])
def test_an_absurd_issued_at_is_refused_not_a_crash(tmp_path, at):
    d, ca, cert, key = _rig(tmp_path)
    csr, _ = make_csr("n1")
    with pytest.raises(RenewRefused):
        queue_csr(d, "n1", csr, cert_pem=cert, issued_at=at, signature="AA==")
    (d / "renew").mkdir(exist_ok=True)
    (d / "renew" / "aaa.csr").write_text(json.dumps(
        {"csr_pem": "x", "cert_pem": "y", "issued_at": at, "signature": "AA=="}))
    queue_csr(d, "n1", csr, cert_pem=cert, issued_at=int(time.time()),
              signature=sign_renew_proof(key, "n1", csr.decode(), int(time.time())))
    out = dict(sign_pending(ca, d))
    assert out["aaa"].startswith("refused") and out["n1"] == "renewed"


def test_a_deeply_nested_entry_is_refused_and_the_run_goes_on(tmp_path):
    """json.loads raises RecursionError (not ValueError) on deep nesting: one hostile entry
    must be discarded as malformed, not abort every other node's renewal, every run."""
    ca, ca_dir, i1, _i2 = _split(tmp_path)
    (i1 / "renew").mkdir()
    deep = b"[" * 10_000 + b"]" * 10_000
    assert len(deep) < node_renew.MAX_QUEUE_ENTRY_BYTES
    (i1 / "renew" / "aaa.csr").write_bytes(deep)
    (i1 / "renew" / "n1.csr").write_bytes(entry(ca, "n1", make_csr("n1")[0], d=i1))
    out = dict(sign_pending(ca, ca_dir, node_dirs=[i1]))
    assert out["aaa"].startswith("refused") and "malformed" in out["aaa"]
    assert out["n1"] == "renewed"
    assert pending(i1) == []


def test_a_restored_revoked_cert_on_one_ingress_cannot_overwrite_the_others(tmp_path):
    """Revoke, re-enrol with a new key everywhere; a hostile ingress then restores the OLD
    (still unexpired) cert in its own dir and queues a renewal proven with the old key.
    Its copy must not count as 'the key is current': the honest dirs keep the new cert."""
    ca, ca_dir, i1, i2 = _split(tmp_path)
    old = (i2 / "node-n1.crt").read_bytes()
    node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    issued = ca.issue_node("n1", grants=GRANTS)            # re-enrolled with a NEW key
    for d in (ca_dir, i1, i2):
        (d / "node-n1.crt").write_bytes(issued.cert_pem)
    (i2 / "node-n1.crt").write_bytes(old)                  # the hostile ingress restores it
    attacker_csr, _ = make_csr("n1")
    (i2 / "renew").mkdir(exist_ok=True)
    (i2 / "renew" / "n1.csr").write_bytes(entry(ca, "n1", attacker_csr, d=i2))
    [(nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome != "renewed" and "current" in outcome
    for d in (ca_dir, i1):
        assert (d / "node-n1.crt").read_bytes() == issued.cert_pem, d


def test_a_partly_published_renewal_lets_the_node_renew_with_its_new_key(tmp_path,
                                                                           monkeypatch):
    """A renewal published to some dirs only: the CA host records that the new key and the
    old one are the same node's, so the node -- which already adopted the new cert -- can
    renew with it, and the publication converges."""
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_proven(i1, "n1", make_csr("n1")[0])
    real = node_renew._replace_file

    def flaky(path, data):
        if path.parent == i2:
            raise OSError("EIO")
        return real(path, data)
    monkeypatch.setattr(node_renew, "_replace_file", flaky)
    [(_nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome.startswith("deferred")
    monkeypatch.undo()
    # The node fetched the new cert from ingress-1 and renews with ITS key, which ingress-2
    # (still the old cert) has never seen.
    assert pending(i1) == ["n1"]                           # kept; the node's newer CSR wins
    new_csr, new_key = make_csr("n1")
    queue_proven(i1, "n1", new_csr)
    assert sign_pending(ca, ca_dir, node_dirs=[i1, i2]) == [("n1", "renewed")]
    want = new_key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    for d in (ca_dir, i1, i2):
        assert pub(node_renew.current_cert(d, "n1")) == want, d
    assert not list((ca_dir / node_renew.PUBLISHING_DIR).glob("*"))


def _partly_published(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _split(tmp_path)
    queue_proven(i1, "n1", make_csr("n1")[0])
    real = node_renew._replace_file

    def flaky(path, data):
        if path.parent == i2:
            raise OSError("EIO")
        return real(path, data)
    monkeypatch.setattr(node_renew, "_replace_file", flaky)
    [(_nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome.startswith("deferred")
    monkeypatch.setattr(node_renew, "_replace_file", real)
    return ca, ca_dir, i1, i2


def test_an_expired_publication_record_links_nothing(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _partly_published(tmp_path, monkeypatch)
    monkeypatch.setattr(node_renew, "PUBLISHING_TTL_S", -1)
    [(_nid, outcome)] = sign_pending(ca, ca_dir, node_dirs=[i1, i2])
    assert outcome.startswith("refused") and "current" in outcome   # i1 holds only the new key


def test_revoke_drops_the_publication_record(tmp_path, monkeypatch):
    ca, ca_dir, i1, i2 = _partly_published(tmp_path, monkeypatch)
    assert node_renew._publishing_path(ca_dir, "n1").exists()
    node_renew.revoke(ca_dir, "n1", node_dirs=[i1, i2])
    assert not node_renew._publishing_path(ca_dir, "n1").exists()
