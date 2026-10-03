"""Execution receipts: the signing key, the canonical form, and sealing a receipt into a tree.

A receipt is signed by the DISPATCHER that ran the job, at the moment it seals a DONE result,
from its own in-memory observation of that run. Nothing on the job row feeds it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.host import attest


def _verify(public_pem: str, doc: dict, sig: str) -> None:
    pub = serialization.load_pem_public_key(public_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.urlsafe_b64decode(sig), attest.canonical(doc), ec.ECDSA(hashes.SHA256()))


def _obs(**kw) -> attest.RunObservation:
    base = dict(job_id="11111111-1111-1111-1111-111111111111", engine="clippyshot",
                input_sha256="b" * 64, worker_runtime="runsc", worker_tier=None,
                net_policy_effective="none", net_exit="none", started_at_ms=1_000_250,
                finished_at_ms=1_010_500)
    base.update(kw)
    return attest.RunObservation(**base)


def _tombstone(out) -> dict:
    body = json.loads((out / attest.RECEIPT_NAME).read_bytes())
    assert body["attestation"] is None and isinstance(body["reason"], str)
    assert set(body) == {"attestation", "reason"}
    return body


def _tree(tmp_path, meta: bytes = b'{"engine":"clippyshot"}'):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_bytes(meta)
    return out


# ---------------------------------------------------------------------------
# Key location, generation, identity, hardening
# ---------------------------------------------------------------------------


def test_only_an_explicit_attest_key_enables_receipts(tmp_path):
    """STRICTLY OPT-IN. BLASTBOX_PKI_DIR is the mTLS/CA dir; it must not silently mint a signing
    key on every node (or log errors on a read-only CA dir)."""
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": str(tmp_path / "k"),
                                   "BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) == tmp_path / "k"
    assert attest.attest_key_path({"BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) is None
    assert attest.attest_key_path({}) is None
    assert attest.attest_key_path({"BLASTBOX_ATTEST_KEY": "", "BLASTBOX_PKI_DIR": " "}) is None


def test_generates_p256_key_0600_and_reloads_the_same_one(tmp_path):
    path = tmp_path / "pki" / "attest.key"
    k1 = attest.load_or_create_key(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey) and priv.curve.name == "secp256r1"
    k2 = attest.load_or_create_key(path)
    assert k1.key_id == k2.key_id and k1.public_key_pem == k2.public_key_pem
    assert [p.name for p in path.parent.iterdir()] == ["attest.key"]   # no temp litter


def test_load_existing_does_not_create(tmp_path):
    with pytest.raises(FileNotFoundError):
        attest.load_existing_key(tmp_path / "attest.key")
    assert not (tmp_path / "attest.key").exists()


def test_key_id_is_sha256_of_spki_der_first_16_hex(tmp_path):
    k = attest.load_or_create_key(tmp_path / "attest.key")
    pub = serialization.load_pem_public_key(k.public_key_pem.encode())
    spki = pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)
    assert k.key_id == hashlib.sha256(spki).hexdigest()[:16]


def test_concurrent_first_use_converges_on_one_key(tmp_path):
    path = tmp_path / "attest.key"
    ids: list[str] = []
    lock = threading.Lock()

    def go():
        kid = attest.load_or_create_key(path).key_id
        with lock:
            ids.append(kid)

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(set(ids)) == 1


def test_refuses_a_key_that_is_not_p256(tmp_path):
    path = tmp_path / "attest.key"
    other = ec.generate_private_key(ec.SECP384R1())
    path.write_bytes(other.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    path.chmod(0o600)
    with pytest.raises(attest.AttestKeyRefused, match="P-256"):
        attest.load_or_create_key(path)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o610])
def test_refuses_a_key_with_group_or_other_bits(tmp_path, mode):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    path.chmod(mode)
    with pytest.raises(attest.AttestKeyRefused, match="permission"):
        attest.load_or_create_key(path)


def test_refuses_a_symlinked_key(tmp_path):
    real = tmp_path / "real.key"
    attest.load_or_create_key(real)
    link = tmp_path / "attest.key"
    link.symlink_to(real)
    with pytest.raises(attest.AttestKeyRefused, match="symlink"):
        attest.load_or_create_key(link)
    with pytest.raises(attest.AttestKeyRefused, match="symlink"):
        attest.load_existing_key(link)


def test_refuses_a_key_owned_by_someone_else(tmp_path, monkeypatch):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    monkeypatch.setattr(attest.os, "geteuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(attest.AttestKeyRefused, match="owned"):
        attest.load_or_create_key(path)


def test_refuses_a_key_that_is_not_a_regular_file(tmp_path):
    (tmp_path / "attest.key").mkdir()
    with pytest.raises(attest.AttestKeyRefused):
        attest.load_or_create_key(tmp_path / "attest.key")


def test_load_attest_key_returns_none_and_logs_when_refused(tmp_path, caplog):
    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    path.chmod(0o644)
    assert attest.load_attest_key({"BLASTBOX_ATTEST_KEY": str(path)}) is None
    assert "refus" in caplog.text.lower()


def test_unconfigured_is_silent_above_debug(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    assert attest.load_attest_key({"BLASTBOX_PKI_DIR": str(tmp_path / "pki")}) is None
    assert caplog.records == []
    assert not (tmp_path / "pki").exists()


def test_missing_key_can_be_quiet_for_non_signers(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO)
    env = {"BLASTBOX_ATTEST_KEY": str(tmp_path / "absent.key")}
    assert attest.load_attest_key(env, create=False, quiet=True) is None
    assert caplog.records == []


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def test_canonical_is_the_contract_form():
    x = {"b": 1, "a": [2, None, True], "é": "ü"}
    assert attest.canonical(x) == json.dumps(
        x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert attest.canonical(x) == b'{"a":[2,null,true],"b":1,"\\u00e9":"\\u00fc"}'


@pytest.mark.parametrize("bad", [1.5, {"a": 1.0}, [0, {"t": 2.5}], {"n": float("nan")}])
def test_canonical_refuses_floats(bad):
    """Float rendering is implementation-specific, so a float would make the signed bytes
    depend on the verifier's JSON library. Refuse, so it can never regress."""
    with pytest.raises(TypeError, match="float"):
        attest.canonical(bad)


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


def test_receipt_doc_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTBOX_HOST_ID", "toolz3")
    key = attest.load_or_create_key(tmp_path / "k")
    doc = attest.build_receipt(_obs(), key_id=key.key_id, metadata_sha256="c" * 64,
                               issued_at_ms=2_000_000)
    assert doc == {
        "v": 1, "alg": "ES256", "key_id": key.key_id, "host": "toolz3",
        "job_id": "11111111-1111-1111-1111-111111111111", "engine": "clippyshot",
        "status": "done", "executor": "local",
        "input_sha256": "b" * 64, "metadata_sha256": "c" * 64,
        "worker_runtime": "runsc", "worker_tier": None, "net_policy_effective": "none",
        "net_exit": "none", "started_at_ms": 1_000_250, "finished_at_ms": 1_010_500, "issued_at_ms": 2_000_000,
    }


def test_unknown_policy_is_omitted_not_guessed():
    doc = attest.build_receipt(_obs(net_policy_effective=None, net_exit=None), key_id="k" * 16,
                               metadata_sha256="c" * 64)
    assert "net_policy_effective" not in doc and "net_exit" not in doc
    assert isinstance(doc["issued_at_ms"], int)


def test_host_id_env_else_hostname():
    import socket

    assert attest.host_id({"BLASTBOX_HOST_ID": "toolz3"}) == "toolz3"
    assert attest.host_id({"BLASTBOX_HOST_ID": "  "}) == socket.gethostname()
    assert attest.host_id({}) == socket.gethostname()


def test_seal_writes_a_verifiable_receipt_over_the_exact_metadata_bytes(tmp_path):
    meta = b'{"engine": "clippyshot",  "x": 1}\n'
    out = _tree(tmp_path, meta)
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    assert body is not None
    on_disk = json.loads((out / attest.RECEIPT_NAME).read_bytes())
    assert on_disk == body
    doc = on_disk["attestation"]
    assert doc["metadata_sha256"] == hashlib.sha256(meta).hexdigest()
    sig = on_disk["signature"]
    assert "+" not in sig and "/" not in sig and len(sig) % 4 == 0   # urlsafe, padded
    _verify(key.public_key_pem, doc, sig)


@pytest.mark.parametrize("field,value", [
    ("job_id", "00000000-0000-0000-0000-000000000000"), ("engine", "other"),
    ("status", "failed"), ("input_sha256", "0" * 64), ("metadata_sha256", "0" * 64),
    ("executor", "node:x"), ("worker_runtime", "runc"), ("worker_tier", "firecracker"),
    ("net_policy_effective", "direct"), ("net_exit", "direct"), ("net_downgraded", False),
    ("net_inspect", False), ("finished_at_ms", 1), ("host", "evil"),
    ("key_id", "0" * 16), ("issued_at_ms", 7),
])
def test_tampering_any_field_breaks_verification(tmp_path, field, value):
    out = _tree(tmp_path)
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs(net_downgraded=True,
                                                              net_inspect=True))
    doc = dict(body["attestation"])
    assert field in doc
    doc[field] = value
    with pytest.raises(InvalidSignature):
        _verify(key.public_key_pem, doc, body["signature"])


@pytest.mark.parametrize("planted", ["file", "dir", "symlink"])
def test_a_worker_planted_receipt_becomes_a_tombstone_without_a_key(tmp_path, planted):
    out = _tree(tmp_path)
    target = out / attest.RECEIPT_NAME
    if planted == "file":
        target.write_text('{"attestation": {"attested": true}, "signature": "x"}')
    elif planted == "dir":
        target.mkdir()
        (target / "inner").write_text("x")
    else:
        (tmp_path / "elsewhere").write_text("keep me")
        target.symlink_to(tmp_path / "elsewhere")
    assert attest.seal_receipt(out, key=None, observation=_obs()) is None
    assert not target.is_symlink() and target.is_file()
    assert _tombstone(out)["reason"] == "no attestation key"
    if planted == "symlink":
        assert (tmp_path / "elsewhere").read_text() == "keep me"   # never followed


def test_a_worker_planted_receipt_is_replaced_by_ours(tmp_path):
    out = _tree(tmp_path)
    (out / attest.RECEIPT_NAME).write_text('{"attestation": {"forged": 1}, "signature": "x"}')
    key = attest.load_or_create_key(tmp_path / "k")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    assert json.loads((out / attest.RECEIPT_NAME).read_bytes()) == body


def test_no_receipt_when_metadata_is_not_a_regular_file(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (tmp_path / "real.json").write_text("{}")
    (out / "metadata.json").symlink_to(tmp_path / "real.json")
    key = attest.load_or_create_key(tmp_path / "k")
    assert attest.seal_receipt(out, key=key, observation=_obs()) is None
    assert "metadata" in _tombstone(out)["reason"]


def test_sha256_file_is_the_sha256_of_the_bytes(tmp_path):
    p = tmp_path / "in.bin"
    p.write_bytes(b"malware" * 100_000)
    assert attest.sha256_file(p) == hashlib.sha256(b"malware" * 100_000).hexdigest()


def test_no_receipt_when_the_envelope_declares_the_reserved_name(tmp_path):
    """Defence in depth behind the trust gate: never write a receipt over a declared artifact."""
    out = _tree(tmp_path, json.dumps({"artifacts": [
        {"id": "r", "path": "./attestation.json"}]}).encode())
    key = attest.load_or_create_key(tmp_path / "k")
    assert attest.seal_receipt(out, key=key, observation=_obs()) is None
    assert "reserved" in _tombstone(out)["reason"]


def _nested_artifact_tree(tmp_path, meta: bytes | None = None):
    """A tree (e.g. one retained by pre-fix code) whose envelope declares an artifact INSIDE a
    directory named attestation.json/."""
    out = _tree(tmp_path, meta if meta is not None else json.dumps({"artifacts": [
        {"id": "p", "path": "attestation.json/page.png"}]}).encode())
    (out / attest.RECEIPT_NAME).mkdir()
    (out / attest.RECEIPT_NAME / "page.png").write_bytes(b"accepted artifact")
    return out


def _attempt(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return exc
    return None


@pytest.mark.parametrize("op", ["seal_keyed", "seal_keyless", "tombstone", "strip"])
def test_receipt_writes_never_delete_a_declared_artifact_under_the_receipt_name(tmp_path, op):
    """Receipt AND tombstone writes replace whatever sits at attestation.json -- which, for a
    directory, was an rmtree, taking declared artifacts with it. Fail closed instead: refuse
    (no receipt, no tombstone) and leave the artifact alone."""
    out = _nested_artifact_tree(tmp_path)
    key = attest.load_or_create_key(tmp_path / "k")
    fn = {
        "seal_keyed": lambda: attest.seal_receipt(out, key=key, observation=_obs()),
        "seal_keyless": lambda: attest.seal_receipt(out, key=None, observation=_obs()),
        "tombstone": lambda: attest.write_tombstone(out, "retained result re-uploaded"),
        "strip": lambda: attest.strip_receipt(out),
    }[op]
    exc = _attempt(fn)
    assert (out / attest.RECEIPT_NAME / "page.png").read_bytes() == b"accepted artifact"
    assert isinstance(exc, attest.ReceiptPathOccupied)
    assert isinstance(exc, OSError)        # the sweeps' "leave it retained" path handles it


@pytest.mark.parametrize("op", ["seal_keyed", "seal_keyless", "tombstone", "strip"])
def test_receipt_writes_never_delete_a_declared_top_level_artifact_file(tmp_path, op):
    """A tree accepted before the name was reserved can declare a top-level ARTIFACT at exactly
    attestation.json -- a regular file. strip_receipt only checked the envelope for a directory
    and unlinked a file unconditionally, destroying the accepted artifact (and the upload then
    shipped bytes that no longer match the sealed envelope)."""
    out = _tree(tmp_path, json.dumps({"artifacts": [
        {"id": "a", "path": "attestation.json"}]}).encode())
    (out / attest.RECEIPT_NAME).write_bytes(b"ACCEPTED ARTIFACT BYTES")
    key = attest.load_or_create_key(tmp_path / "k")
    fn = {
        "seal_keyed": lambda: attest.seal_receipt(out, key=key, observation=_obs()),
        "seal_keyless": lambda: attest.seal_receipt(out, key=None, observation=_obs()),
        "tombstone": lambda: attest.write_tombstone(out, "retained result re-uploaded"),
        "strip": lambda: attest.strip_receipt(out),
    }[op]
    exc = _attempt(fn)
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"ACCEPTED ARTIFACT BYTES"
    assert isinstance(exc, attest.ReceiptPathOccupied)


def test_an_undeclared_file_at_the_receipt_name_is_still_replaced(tmp_path):
    """Worker-planted junk (or a stale receipt) the envelope does not declare is not protected."""
    out = _tree(tmp_path, json.dumps({"artifacts": [{"id": "a", "path": "page.png"}]}).encode())
    (out / attest.RECEIPT_NAME).write_bytes(b"planted")
    attest.strip_receipt(out)
    assert not (out / attest.RECEIPT_NAME).exists()
    attest.write_tombstone(out, "x")
    assert _tombstone(out)["reason"] == "x"
    key = attest.load_or_create_key(tmp_path / "k")
    (out / attest.RECEIPT_NAME).write_bytes(b"planted again")
    assert attest.seal_receipt(out, key=key, observation=_obs()) is not None


def test_an_unreadable_envelope_never_licenses_deleting_a_receipt_directory(tmp_path):
    """If the envelope cannot be parsed we cannot rule out a declared artifact in there."""
    out = _nested_artifact_tree(tmp_path, b"not json")
    exc = _attempt(lambda: attest.write_tombstone(out, "x"))
    assert (out / attest.RECEIPT_NAME / "page.png").read_bytes() == b"accepted artifact"
    assert isinstance(exc, attest.ReceiptPathOccupied)


def test_no_observation_writes_a_tombstone(tmp_path):
    out = _tree(tmp_path)
    key = attest.load_or_create_key(tmp_path / "k")
    assert attest.seal_receipt(out, key=key, observation=None, reason="input not hashed") is None
    assert _tombstone(out)["reason"] == "input not hashed"


def test_write_tombstone_replaces_whatever_is_there(tmp_path):
    out = _tree(tmp_path)
    (out / attest.RECEIPT_NAME).mkdir()
    attest.write_tombstone(out, "signing failed")
    assert _tombstone(out)["reason"] == "signing failed"
    assert attest.is_tombstone((out / attest.RECEIPT_NAME).read_bytes())


# ---------------------------------------------------------------------------
# Verifying a tree's receipt against this host's own key (retained-tree re-upload)
# ---------------------------------------------------------------------------


def test_tree_receipt_verification(tmp_path):
    meta = b'{"engine":"clippyshot"}'
    out = _tree(tmp_path, meta)
    key = attest.load_or_create_key(tmp_path / "k")
    other = attest.load_or_create_key(tmp_path / "other")
    jid = "11111111-1111-1111-1111-111111111111"
    attest.seal_receipt(out, key=key, observation=_obs())
    assert attest.tree_receipt_is_ours(out, key=key, job_id=jid)
    assert not attest.tree_receipt_is_ours(out, key=other, job_id=jid)
    assert not attest.tree_receipt_is_ours(out, key=None, job_id=jid)
    assert not attest.tree_receipt_is_ours(out, key=key, job_id="22222222-2222-2222-2222-222222222222")
    (out / "metadata.json").write_bytes(meta + b" ")      # metadata changed since signing
    assert not attest.tree_receipt_is_ours(out, key=key, job_id=jid)


def _valid_tree(tmp_path):
    out = _tree(tmp_path, b'{"engine":"clippyshot"}')
    key = attest.load_or_create_key(tmp_path / "k")
    attest.seal_receipt(out, key=key, observation=_obs())
    return out, key, "11111111-1111-1111-1111-111111111111"


@pytest.mark.parametrize("where", ["open", "read", "metadata"])
def test_a_transient_read_error_is_not_a_verdict(tmp_path, monkeypatch, where):
    """EIO/EAGAIN on a VALID receipt must not read as "not ours": the sweep would tombstone a
    genuine receipt permanently. It raises ReceiptUnreadable (an OSError) instead."""
    import errno as _errno

    out, key, jid = _valid_tree(tmp_path)
    real_open, real_read = attest.os.open, attest.os.read
    receipt = str(out / attest.RECEIPT_NAME)
    meta = str(out / "metadata.json")
    fds: set[int] = set()

    def fake_open(p, *a, **kw):
        if where == "open" and str(p) == receipt:
            raise OSError(_errno.EIO, "Input/output error", str(p))
        if where == "metadata" and str(p) == meta:
            raise OSError(_errno.EAGAIN, "Resource temporarily unavailable", str(p))
        fd = real_open(p, *a, **kw)
        if str(p) == receipt:
            fds.add(fd)
        return fd

    def fake_read(fd, n):
        if where == "read" and fd in fds:
            raise OSError(_errno.EIO, "Input/output error")
        return real_read(fd, n)

    monkeypatch.setattr(attest.os, "open", fake_open)
    monkeypatch.setattr(attest.os, "read", fake_read)
    with pytest.raises(attest.ReceiptUnreadable):
        attest.tree_receipt_is_ours(out, key=key, job_id=jid)


def test_a_short_read_does_not_truncate_a_valid_receipt(tmp_path, monkeypatch):
    """NFS/FUSE/signals can return fewer bytes than asked; one os.read truncated the receipt."""
    out, key, jid = _valid_tree(tmp_path)
    real_read = attest.os.read
    monkeypatch.setattr(attest.os, "read", lambda fd, n: real_read(fd, min(n, 7)))
    assert attest.tree_receipt_is_ours(out, key=key, job_id=jid)


def test_an_oversized_receipt_is_definitely_not_ours(tmp_path):
    out, key, jid = _valid_tree(tmp_path)
    (out / attest.RECEIPT_NAME).write_bytes(b" " * ((1 << 20) + 1))
    assert attest.tree_receipt_is_ours(out, key=key, job_id=jid) is False


@pytest.mark.parametrize("kind", ["missing", "symlink", "dir", "garbage"])
def test_definite_non_receipts_are_false_not_errors(tmp_path, kind):
    out, key, jid = _valid_tree(tmp_path)
    target = out / attest.RECEIPT_NAME
    target.unlink()
    if kind == "symlink":
        (tmp_path / "x").write_text("{}")
        target.symlink_to(tmp_path / "x")
    elif kind == "dir":
        target.mkdir()
    elif kind == "garbage":
        target.write_text("not json")
    assert attest.tree_receipt_is_ours(out, key=key, job_id=jid) is False


def _without_blocking(fn, fifo, timeout=3.0):
    """Run fn in a thread; if it is still stuck after ``timeout`` (blocked opening a FIFO), free
    it by opening the write end so the test cannot hang the suite, and report it stuck."""
    result: dict = {}

    def run():
        try:
            result["value"] = fn()
        except BaseException as exc:  # noqa: BLE001
            result["exc"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    stuck = t.is_alive()
    if stuck:
        wfd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)   # a reader is waiting, so this opens
        os.close(wfd)
        t.join(timeout)
    return stuck, result


def test_a_fifo_receipt_does_not_block_verification(tmp_path):
    """The retry/sweep path verifies a retained tree's receipt. A worker-planted FIFO at
    attestation.json blocked os.open forever (no O_NONBLOCK), wedging the sweep. It is not a
    regular file, so it is definitely not ours: False, promptly."""
    out, key, jid = _valid_tree(tmp_path)
    target = out / attest.RECEIPT_NAME
    target.unlink()
    os.mkfifo(target)
    stuck, result = _without_blocking(
        lambda: attest.tree_receipt_is_ours(out, key=key, job_id=jid), target)
    assert not stuck, "tree_receipt_is_ours blocked opening a FIFO receipt"
    assert result == {"value": False}


def test_a_fifo_metadata_does_not_block_verification(tmp_path):
    """Same for the metadata.json the receipt vouches for: a FIFO there is a verdict, not a hang."""
    out, key, jid = _valid_tree(tmp_path)
    meta = out / "metadata.json"
    meta.unlink()
    os.mkfifo(meta)
    stuck, result = _without_blocking(
        lambda: attest.tree_receipt_is_ours(out, key=key, job_id=jid), meta)
    assert not stuck, "tree_receipt_is_ours blocked opening a FIFO metadata.json"
    assert result == {"value": False}


def test_downgrade_and_inspect_flags_are_present_only_when_true():
    plain = attest.build_receipt(_obs(), key_id="k" * 16, metadata_sha256="c" * 64)
    assert "net_downgraded" not in plain and "net_inspect" not in plain
    flagged = attest.build_receipt(
        _obs(net_policy_effective="mitm", net_exit="none", net_downgraded=True),
        key_id="k" * 16, metadata_sha256="c" * 64)
    assert flagged["net_downgraded"] is True and flagged["net_exit"] == "none"
    assert flagged["net_policy_effective"] == "mitm"
    inspected = attest.build_receipt(_obs(net_exit="direct", net_inspect=True),
                                     key_id="k" * 16, metadata_sha256="c" * 64)
    assert inspected["net_inspect"] is True


def test_flags_never_appear_without_a_signed_policy():
    doc = attest.build_receipt(_obs(net_policy_effective=None, net_exit=None,
                                    net_downgraded=True, net_inspect=True),
                               key_id="k" * 16, metadata_sha256="c" * 64)
    assert not {"net_policy_effective", "net_exit", "net_downgraded", "net_inspect"} & set(doc)


@pytest.mark.parametrize("path", [
    "attestation.json", "./attestation.json", "attestation.json/", "attestation.json/x",
    "attestation.json//x", ".//attestation.json/./x", "/attestation.json", "//attestation.json",
    "x/../attestation.json",
])
def test_is_reserved_path_refuses_what_lands_at_or_under_the_receipt(path):
    assert attest.is_reserved_path(path)


@pytest.mark.parametrize("path", [
    " attestation.json/page.png", "attestation.json /x", " attestation.json",
    "attestation.json\t", "attestation.jsonx", "x/attestation.json", "attestation.json.bak",
])
def test_is_reserved_path_allows_names_that_are_different_files(path):
    """The filesystem does not strip whitespace: ' attestation.json' is a different file, and the
    gate must not refuse it any more than it refuses 'attestation.json.bak'."""
    assert not attest.is_reserved_path(path)


# ---------------------------------------------------------------------------
# Receipt-path protection follows what put_output SHIPS (round-2 review F2)
# ---------------------------------------------------------------------------


def _seal_of_kind(tmp_path, kind: str):
    """An output tree with a planted attestation.json and metadata.json of ``kind``."""
    out = tmp_path / "output"
    out.mkdir()
    seal = out / "metadata.json"
    if kind == "symlink":
        (tmp_path / "real.json").write_text(json.dumps({"artifacts": []}))
        seal.symlink_to(tmp_path / "real.json")
    elif kind == "dangling_symlink":
        seal.symlink_to(tmp_path / "nowhere.json")
    elif kind == "fifo":
        os.mkfifo(seal)
    elif kind == "dir":
        seal.mkdir()
        (seal / "x.json").write_text("{}")
    elif kind == "clean":
        seal.write_text(json.dumps({"artifacts": [{"id": "a", "path": "page.png"}]}))
    elif kind == "declares":
        seal.write_text(json.dumps({"artifacts": [{"id": "a", "path": "attestation.json"}]}))
    elif kind == "garbage":
        seal.write_text('{"artifacts": [{"id": "a", "pa')
    else:
        assert kind == "absent"
    (out / attest.RECEIPT_NAME).write_bytes(b"planted")
    return out


@pytest.mark.parametrize("kind", ["symlink", "dangling_symlink", "fifo", "dir"])
def test_a_seal_put_output_would_not_ship_protects_nothing(tmp_path, kind):
    """put_output skips a symlinked or non-regular metadata.json, so the result never carries
    it: no envelope accepted anything at attestation.json, and the planted file there is junk
    to tombstone/strip -- not "cannot rule out", which uploaded it as-is."""
    out = _seal_of_kind(tmp_path, kind)
    seal = out / "metadata.json"
    stuck, result = (_without_blocking(lambda: attest.tree_receipt_path_protection(out), seal)
                     if kind == "fifo" else
                     (False, {"value": attest.tree_receipt_path_protection(out)}))
    assert not stuck
    assert result == {"value": None}
    attest.strip_receipt(out)
    assert not (out / attest.RECEIPT_NAME).exists()


@pytest.mark.parametrize("kind", ["absent", "symlink", "dangling_symlink", "fifo", "dir",
                                  "clean", "declares", "garbage"])
def test_strip_receipt_refuses_exactly_when_the_tree_protects_the_receipt_path(tmp_path, kind):
    """The sweeps decide "as-is" with tree_receipt_path_protection and then strip/tombstone with
    strip_receipt; the two must never disagree, or a tree is neither recovered as-is nor
    strippable (ReceiptPathOccupied every tick) -- or worse, stripped while 'protected'."""
    out = _seal_of_kind(tmp_path, kind)
    protected = attest.tree_receipt_path_protection(out) is not None
    exc = _attempt(lambda: attest.strip_receipt(out))
    assert isinstance(exc, attest.ReceiptPathOccupied) is protected, exc
    assert (out / attest.RECEIPT_NAME).exists() is protected
    assert protected is (kind in ("declares", "garbage"))
