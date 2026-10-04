"""Execution receipts: the signing key, the canonical form, and sealing a receipt into a tree.

A receipt is signed by the DISPATCHER that ran the job, at the moment it seals a DONE result,
from its own in-memory observation of that run. Nothing on the job row feeds it.
"""
from __future__ import annotations

import base64
import errno
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


@pytest.mark.parametrize("keyed", [True, False], ids=["keyed", "keyless"])
def test_the_seal_strips_the_reserved_names_without_re_reading_the_envelope(tmp_path, keyed):
    """seal_receipt runs only on a tree the trust gate just validated (lens r7 F5: the envelope-
    re-reading branch was dead in production and is gone). Its strip is unconditional: even an
    envelope that could not be parsed to rule out a declared artifact -- which the gate would
    have refused -- never leaves a worker-planted receipt or marker in a tree that ships."""
    out = _tree(tmp_path, b"not json")
    (out / attest.RECEIPT_NAME).write_bytes(b"planted receipt")
    (out / attest.WITHHELD_NAME).write_bytes(b"planted marker")
    key = attest.load_or_create_key(tmp_path / "k") if keyed else None
    body = attest.seal_receipt(out, key=key, observation=_obs())
    stored = (out / attest.RECEIPT_NAME).read_bytes()
    assert stored != b"planted receipt"
    if keyed:
        assert body is not None and attest.verify_body(key, json.loads(stored))
    else:
        assert body is None and _tombstone(out)["reason"] == "no attestation key"
    meta_sha = hashlib.sha256(b"not json").hexdigest()
    assert attest.is_cleared_marker((out / attest.WITHHELD_NAME).read_bytes(), meta_sha)


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


@pytest.mark.parametrize("op", ["tombstone", "strip"])
def test_receipt_writes_never_delete_a_declared_artifact_under_the_receipt_name(tmp_path, op):
    """Receipt AND tombstone writes replace whatever sits at attestation.json -- which, for a
    directory, was an rmtree, taking declared artifacts with it. Fail closed instead: refuse
    (no receipt, no tombstone) and leave the artifact alone."""
    out = _nested_artifact_tree(tmp_path)
    fn = {
        "tombstone": lambda: attest.write_tombstone(out, "retained result re-uploaded"),
        "strip": lambda: attest.strip_receipt(out),
    }[op]
    exc = _attempt(fn)
    assert (out / attest.RECEIPT_NAME / "page.png").read_bytes() == b"accepted artifact"
    assert isinstance(exc, attest.ReceiptPathOccupied)
    assert isinstance(exc, OSError)        # the sweeps' "leave it retained" path handles it


@pytest.mark.parametrize("op", ["tombstone", "strip"])
def test_receipt_writes_never_delete_a_declared_top_level_artifact_file(tmp_path, op):
    """A tree accepted before the name was reserved can declare a top-level ARTIFACT at exactly
    attestation.json -- a regular file. strip_receipt only checked the envelope for a directory
    and unlinked a file unconditionally, destroying the accepted artifact (and the upload then
    shipped bytes that no longer match the sealed envelope)."""
    out = _tree(tmp_path, json.dumps({"artifacts": [
        {"id": "a", "path": "attestation.json"}]}).encode())
    (out / attest.RECEIPT_NAME).write_bytes(b"ACCEPTED ARTIFACT BYTES")
    fn = {
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


def test_a_symlinked_seal_beside_our_receipt_is_a_verdict_not_unreadable(tmp_path):
    """put_output never ships a symlinked seal, so a receipt over it vouches for nothing that
    will be stored: answer "not ours" (the sweep tombstones it) rather than ReceiptUnreadable,
    which would leave the tree retained on every tick until the reaper took the whole result."""
    meta = b'{"engine":"clippyshot"}'
    out = _tree(tmp_path, meta)
    key = attest.load_or_create_key(tmp_path / "k")
    jid = "11111111-1111-1111-1111-111111111111"
    attest.seal_receipt(out, key=key, observation=_obs())
    (tmp_path / "real.json").write_bytes(meta)
    (out / "metadata.json").unlink()
    (out / "metadata.json").symlink_to(tmp_path / "real.json")
    assert attest.tree_receipt_is_ours(out, key=key, job_id=jid) is False
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


# ---------------------------------------------------------------------------
# Fail-closed branches of the receipt-path test, pinned (round-2 review F3)
# ---------------------------------------------------------------------------


def test_a_transient_envelope_error_never_licenses_stripping(tmp_path, monkeypatch):
    """EIO opening metadata.json is no verdict. tree_receipt_path_protection propagates it (the
    sweeps retry), and strip_receipt refuses with the retry-later ReceiptUnreadable (not the
    permanent-looking ReceiptPathOccupied): the file at attestation.json -- possibly a declared
    artifact -- survives."""
    import errno as _errno

    out = _tree(tmp_path, json.dumps({"artifacts": [{"id": "a", "path": "page.png"}]}).encode())
    (out / attest.RECEIPT_NAME).write_bytes(b"maybe an artifact")
    seal = str(out / "metadata.json")
    real_open = attest.os.open

    def flaky_open(p, *a, **kw):
        if str(p) == seal:
            raise OSError(_errno.EIO, "Input/output error", str(p))
        return real_open(p, *a, **kw)

    monkeypatch.setattr(attest.os, "open", flaky_open)
    exc = _attempt(lambda: attest.tree_receipt_path_protection(out))
    assert isinstance(exc, OSError) and exc.errno == _errno.EIO
    exc = _attempt(lambda: attest.strip_receipt(out))
    assert isinstance(exc, attest.ReceiptUnreadable) and exc.errno == _errno.EIO
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"


def test_an_oversized_envelope_cannot_rule_out_the_receipt_path(tmp_path, monkeypatch):
    """A shipped envelope past ENVELOPE_MAX_BYTES is not parsed, so it cannot rule out a declared
    artifact at attestation.json -- even when the bytes, read whole, would declare nothing."""
    env = json.dumps({"artifacts": [{"id": "a", "path": "page.png"}]}).encode()
    out = _tree(tmp_path, env)
    (out / attest.RECEIPT_NAME).write_bytes(b"maybe an artifact")
    assert attest.tree_receipt_path_protection(out) is None         # within the cap: clean
    # Past BOTH the floor and the configured metadata limit (envelope_cap is their max).
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", len(env) - 1)
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", str(len(env) - 1))
    assert (attest.tree_receipt_path_protection(out)
            == attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert isinstance(_attempt(lambda: attest.strip_receipt(out)), attest.ReceiptPathOccupied)
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"


# ---------------------------------------------------------------------------
# The envelope cap follows the configured metadata limit
# ---------------------------------------------------------------------------


def _padded_envelope(size: int) -> bytes:
    """A valid envelope declaring nothing at the receipt name, padded to ``size`` bytes."""
    base = b'{"artifacts": [{"id": "a", "path": "page-001.png"}], "pad": ""}'
    return base[:-2] + b"x" * (size - len(base)) + base[-2:]


def test_an_envelope_within_the_configured_metadata_limit_is_parsed(tmp_path, monkeypatch):
    """BLASTBOX_MAX_METADATA may be configured above the fixed cap, and the dispatcher then seals
    (and signs over) an envelope that large. Judging it "cannot rule out" hid its genuine receipt
    and recovered its tree as-is. The cap is scaled down here to keep the test cheap."""
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", str(1 << 20))
    out = _tree(tmp_path, _padded_envelope(4096))
    json.loads((out / "metadata.json").read_bytes())          # valid, and over the fixed cap
    (out / attest.RECEIPT_NAME).write_bytes(b"planted")
    assert attest.tree_receipt_path_protection(out) is None
    attest.strip_receipt(out)
    assert not (out / attest.RECEIPT_NAME).exists()


def test_an_envelope_over_both_caps_still_cannot_rule_it_out(tmp_path, monkeypatch):
    monkeypatch.setattr(attest, "ENVELOPE_MAX_BYTES", 1024)
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "2048")
    out = _tree(tmp_path, _padded_envelope(4096))
    assert attest.tree_receipt_path_protection(out) == attest.RECEIPT_PATH_UNDECIDABLE_REASON


# ---------------------------------------------------------------------------
# A transient envelope read inside strip_receipt is not a verdict
# ---------------------------------------------------------------------------


def test_a_transient_envelope_error_in_strip_is_unreadable_not_occupied(tmp_path, monkeypatch):
    """EIO re-reading the envelope inside strip_receipt says nothing about what sits at
    attestation.json. ReceiptPathOccupied is the permanent-looking "a declared artifact is
    there"; this must be the retry-later ReceiptUnreadable, deleting nothing."""
    out = _tree(tmp_path, b'{"artifacts": []}')
    (out / attest.RECEIPT_NAME).write_bytes(b"planted")

    def eio(*a, **kw):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(attest, "tree_receipt_path_protection", eio)
    exc = _attempt(lambda: attest.strip_receipt(out))
    assert isinstance(exc, attest.ReceiptUnreadable), exc
    assert not isinstance(exc, attest.ReceiptPathOccupied)
    assert exc.errno == errno.EIO
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"planted"


# ---------------------------------------------------------------------------
# The withheld marker (round-4 review H1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [
    "attestation.withheld.json", "./attestation.withheld.json", "attestation.withheld.json/x",
    "/attestation.withheld.json",
])
def test_the_withheld_marker_name_is_reserved(path):
    assert attest.is_reserved_path(path)
    assert not attest.is_reserved_path(path, (attest.RECEIPT_NAME,))


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_a_fresh_seal_overwrites_a_planted_withheld_marker_with_the_cleared_body(tmp_path, kind):
    """A worker can write anything into its output tree. A planted marker would withhold the
    genuine receipt this seal writes: the gate-verified seal replaces it with the CLEARED body,
    the host's own word that this result is not withheld."""
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    marker = out / attest.WITHHELD_NAME
    if kind == "file":
        marker.write_bytes(attest.canonical(attest.tombstone_body("planted")))
    else:
        (marker / "deep").mkdir(parents=True)
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    assert attest.seal_fresh_receipt(out, key=key, observation=_obs(), job_id=_obs().job_id)
    assert not marker.is_symlink() and attest.is_cleared_marker(
        marker.read_bytes(), attest.sha256_file(out / "metadata.json"))
    assert not attest.is_tombstone((out / attest.RECEIPT_NAME).read_bytes())


@pytest.mark.parametrize("seal", ["receipt", "no_key", "tombstone"])
def test_every_receipt_or_tombstone_write_carries_the_cleared_marker(tmp_path, seal):
    """Every upload that ships a receipt or a tombstone vouches for itself with the cleared
    marker, so the route never re-judges a new result's envelope under its own ceiling."""
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    if seal == "receipt":
        attest.seal_receipt(out, key=key, observation=_obs())
    elif seal == "no_key":
        assert attest.seal_fresh_receipt(out, key=None, observation=_obs(), job_id="j")
    else:
        attest.write_tombstone(out, "why")
    assert attest.is_cleared_marker((out / attest.WITHHELD_NAME).read_bytes(),
                                    attest.sha256_file(out / "metadata.json"))
    assert sorted(p.name for p in out.iterdir()) == sorted(
        ["metadata.json", attest.RECEIPT_NAME, attest.WITHHELD_NAME])      # no tmp left


def test_strip_receipt_never_destroys_a_declared_artifact_at_the_marker_name(tmp_path):
    """P2: the envelope gate covers EVERY reserved name: a pre-upgrade tree declaring an
    artifact at attestation.withheld.json keeps it, and the refusal names that path."""
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.WITHHELD_NAME}]}))
    (out / attest.WITHHELD_NAME).write_bytes(b"accepted")
    for call in (lambda: attest.strip_receipt(out), lambda: attest.write_cleared_marker(out),
                 lambda: attest.write_tombstone(out, "why")):
        with pytest.raises(attest.ReceiptPathOccupied) as ei:
            call()
        assert attest.WITHHELD_NAME in str(ei.value)
        assert (out / attest.WITHHELD_NAME).read_bytes() == b"accepted"


def test_strip_receipt_names_the_occupied_receipt_path(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": [
        {"id": "a", "path": attest.RECEIPT_NAME}]}))
    (out / attest.RECEIPT_NAME).write_bytes(b"accepted")
    with pytest.raises(attest.ReceiptPathOccupied) as ei:
        attest.strip_receipt(out)
    assert attest.RECEIPT_NAME in str(ei.value)
    assert attest.WITHHELD_NAME not in str(ei.value)


def test_strip_receipt_removes_an_undeclared_withheld_marker(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    (out / attest.WITHHELD_NAME).write_bytes(b"planted")
    attest.strip_receipt(out)
    assert not (out / attest.WITHHELD_NAME).exists()


def _withheld_tree(tmp_path, envelope: str):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(envelope)
    (out / attest.RECEIPT_NAME).write_bytes(b"maybe an artifact")
    return out


_GARBAGE = '{"artifacts": [{"id": "a", "pa'


def test_write_withheld_marker_writes_the_tombstone_shape_and_touches_no_receipt(tmp_path):
    out = _withheld_tree(tmp_path, _GARBAGE)
    attest.write_withheld_marker(out, "why")
    assert json.loads((out / attest.WITHHELD_NAME).read_bytes()) == attest.tombstone_body("why")
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"
    assert sorted(p.name for p in out.iterdir()) == sorted(
        ["metadata.json", attest.RECEIPT_NAME, attest.WITHHELD_NAME])      # no tmp left


@pytest.mark.parametrize("kind", ["file", "dir", "symlink"])
def test_write_withheld_marker_replaces_undeclared_junk(tmp_path, kind):
    """The envelope parses and declares nothing at the marker name: whatever is there is the
    worker's, so the marker replaces it."""
    out = _withheld_tree(tmp_path, json.dumps({"artifacts": [{"id": "a", "path": attest.RECEIPT_NAME}]}))
    marker = out / attest.WITHHELD_NAME
    if kind == "file":
        marker.write_bytes(b"junk")
    elif kind == "dir":
        (marker / "x").mkdir(parents=True)
    else:
        marker.symlink_to(tmp_path / "elsewhere")
    attest.write_withheld_marker(out, "declared")
    assert not marker.is_symlink()
    assert json.loads(marker.read_bytes()) == attest.tombstone_body("declared")


@pytest.mark.parametrize("envelope", [
    _GARBAGE, json.dumps({"artifacts": [{"id": "a", "path": "attestation.withheld.json"}]})])
@pytest.mark.parametrize("data", [b"an accepted artifact",
                                  b'{"attestation":"not-withheld","withheld":false}'])
def test_write_withheld_marker_refuses_a_possibly_declared_regular_file(tmp_path, envelope, data):
    """An old tree may DECLARE an artifact at the marker's name (or its envelope cannot rule it
    out). Never destroyed -- and never shipped in the marker's place either: its bytes are the
    worker's and could be exactly the CLEARED body, which would unmask the worker-written
    attestation.json beside it. Refuse, so the tree is not shipped as-is (an accepted strand)."""
    out = _withheld_tree(tmp_path, envelope)
    (out / attest.WITHHELD_NAME).write_bytes(data)
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_withheld_marker(out, "why")
    assert (out / attest.WITHHELD_NAME).read_bytes() == data


def test_the_cleared_marker_is_exactly_one_canonical_body_per_envelope():
    sha = "ab" * 32
    cleared = attest.canonical(attest.cleared_marker_body(sha))
    assert attest.is_cleared_marker(cleared, sha)
    assert attest.bound_cleared_marker_sha256(cleared) == sha
    assert not attest.is_cleared_marker(cleared, "cd" * 32)
    assert not attest.is_tombstone(cleared)
    for other in (cleared + b" ", cleared[:-1], b" " + cleared,
                  json.dumps(attest.cleared_marker_body(sha), indent=1).encode(),
                  b'{"attestation":"not-withheld","withheld":false}',     # pre-binding body
                  attest.canonical({**attest.cleared_marker_body(sha), "withheld": 0}),
                  attest.canonical({**attest.cleared_marker_body(sha), "x": 1}),
                  attest.canonical(attest.cleared_marker_body(sha.upper())),
                  attest.canonical(attest.cleared_marker_body(sha[:-1])),
                  attest.canonical(attest.tombstone_body("x")), b"", b"garbage"):
        assert not attest.is_cleared_marker(other, sha), other
        assert attest.bound_cleared_marker_sha256(other) is None, other


@pytest.mark.parametrize("kind", ["none", "file", "dir", "symlink"])
def test_write_cleared_marker_overwrites_whatever_is_undeclared_there(tmp_path, kind):
    out = _withheld_tree(tmp_path, json.dumps({"artifacts": []}))
    marker = out / attest.WITHHELD_NAME
    if kind == "file":
        marker.write_bytes(attest.canonical(attest.tombstone_body("planted")))
    elif kind == "dir":
        (marker / "x").mkdir(parents=True)
    elif kind == "symlink":
        marker.symlink_to(tmp_path / "elsewhere")
    attest.write_cleared_marker(out)
    assert not marker.is_symlink()
    assert attest.is_cleared_marker(marker.read_bytes(), attest.sha256_file(out / "metadata.json"))
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"
    assert sorted(p.name for p in out.iterdir()) == sorted(
        ["metadata.json", attest.RECEIPT_NAME, attest.WITHHELD_NAME])      # no tmp left


@pytest.mark.parametrize("envelope", [
    _GARBAGE, json.dumps({"artifacts": [{"id": "a", "path": "attestation.withheld.json"}]})])
def test_write_cleared_marker_never_destroys_a_possibly_declared_artifact(tmp_path, envelope):
    out = _withheld_tree(tmp_path, envelope)
    (out / attest.WITHHELD_NAME).write_bytes(b"an accepted artifact")
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_cleared_marker(out)
    assert (out / attest.WITHHELD_NAME).read_bytes() == b"an accepted artifact"


def test_write_withheld_marker_refuses_a_possibly_declared_directory(tmp_path):
    """A directory at the marker's name would not be stored AT that key, so it cannot stand in
    for the marker -- and it may be accepted output, so it is not destroyed either: refuse, so
    the caller never ships the tree as-is without a marker."""
    out = _withheld_tree(tmp_path, _GARBAGE)
    (out / attest.WITHHELD_NAME / "page.png").parent.mkdir()
    (out / attest.WITHHELD_NAME / "page.png").write_bytes(b"x")
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_withheld_marker(out, "why")
    assert (out / attest.WITHHELD_NAME / "page.png").read_bytes() == b"x"


@pytest.mark.parametrize("existing", attest.WITHHELD_REASONS)
@pytest.mark.parametrize("envelope", [
    _GARBAGE, json.dumps({"artifacts": [{"id": "a", "path": "attestation.withheld.json"}]})])
def test_write_withheld_marker_keeps_a_marker_an_earlier_attempt_wrote(tmp_path, envelope,
                                                                      existing):
    """Round-6 K3: an as-is attempt writes the marker, then its upload fails and the tree stays
    retained WITH it. The retry must not read it as a possibly-declared artifact (stranded
    forever); exactly a withheld body this code writes is kept, and the tree ships with it."""
    out = _withheld_tree(tmp_path, envelope)
    body = attest.canonical(attest.tombstone_body(existing))
    (out / attest.WITHHELD_NAME).write_bytes(body)
    attest.write_withheld_marker(out, attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert (out / attest.WITHHELD_NAME).read_bytes() == body
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"


@pytest.mark.parametrize("data", [
    attest.canonical(attest.tombstone_body("some other reason")),
    attest.canonical(attest.tombstone_body(attest.RECEIPT_PATH_UNDECIDABLE_REASON)) + b" ",
    json.dumps(attest.tombstone_body(attest.RECEIPT_PATH_UNDECIDABLE_REASON)).encode(),
])
def test_write_withheld_marker_keeps_only_its_exact_canonical_bodies(tmp_path, data):
    out = _withheld_tree(tmp_path, _GARBAGE)
    (out / attest.WITHHELD_NAME).write_bytes(data)
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_withheld_marker(out, attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert (out / attest.WITHHELD_NAME).read_bytes() == data


def test_write_withheld_marker_never_keeps_a_symlink_to_a_marker_body(tmp_path):
    out = _withheld_tree(tmp_path, _GARBAGE)
    target = tmp_path / "elsewhere"
    target.write_bytes(attest.canonical(attest.tombstone_body(
        attest.RECEIPT_PATH_UNDECIDABLE_REASON)))
    (out / attest.WITHHELD_NAME).symlink_to(target)
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_withheld_marker(out, attest.RECEIPT_PATH_UNDECIDABLE_REASON)


@pytest.mark.parametrize("seal", ["absent", "symlink", "dir"])
def test_a_tombstone_with_no_shippable_envelope_ships_the_withheld_marker(tmp_path, seal):
    """K2: the cleared marker binds the metadata.json shipped beside it. With none put_output
    would ship there is nothing to bind: the marker is the withheld body (the route would find no
    envelope and 404 anyway), never a cleared body bound to nothing."""
    out = tmp_path / "output"
    out.mkdir()
    if seal == "symlink":
        (tmp_path / "real.json").write_text(json.dumps({"artifacts": []}))
        (out / "metadata.json").symlink_to(tmp_path / "real.json")
    elif seal == "dir":
        (out / "metadata.json").mkdir()
    attest.write_tombstone(out, "why")
    assert (out / attest.WITHHELD_NAME).read_bytes() == attest.canonical(
        attest.tombstone_body(attest.RECEIPT_ENVELOPE_ABSENT_REASON))
    assert attest.is_tombstone((out / attest.RECEIPT_NAME).read_bytes())


def test_a_receipt_and_its_cleared_marker_bind_the_same_envelope(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    key = attest.load_or_create_key(tmp_path / "k" / "attest.key")
    body = attest.seal_receipt(out, key=key, observation=_obs())
    assert attest.bound_cleared_marker_sha256(
        (out / attest.WITHHELD_NAME).read_bytes()) == body["attestation"]["metadata_sha256"]


def test_a_cleared_marker_that_cannot_hash_the_envelope_is_not_written(tmp_path, monkeypatch):
    """write_cleared_marker binds the envelope; when it cannot be hashed right now the sweep
    must retry (ReceiptUnreadable), not ship an unbound or stale marker."""
    out = _withheld_tree(tmp_path, json.dumps({"artifacts": []}))
    real = attest.sha256_file

    def eio(path):
        if os.path.basename(path) == "metadata.json":
            raise OSError(errno.EIO, "Input/output error")
        return real(path)

    monkeypatch.setattr(attest, "sha256_file", eio)
    with pytest.raises(attest.ReceiptUnreadable):
        attest.write_cleared_marker(out)
    assert not (out / attest.WITHHELD_NAME).exists()


@pytest.mark.parametrize("bound_to", ["other-envelope", "pre-binding"])
def test_write_withheld_marker_refuses_a_cleared_body_not_bound_to_this_envelope(tmp_path,
                                                                                bound_to):
    """L3's limit: only a cleared body bound to the tree's CURRENT metadata.json is this host's
    own (a declared artifact cannot be: the sealed envelope commits to its sha256). Any other
    cleared-looking body may be accepted output: refused, nothing destroyed."""
    out = _withheld_tree(tmp_path, _GARBAGE)
    data = (attest.canonical(attest.cleared_marker_body("ab" * 32)) if bound_to == "other-envelope"
            else b'{"attestation":"not-withheld","withheld":false}')
    (out / attest.WITHHELD_NAME).write_bytes(data)
    with pytest.raises(attest.ReceiptPathOccupied, match="this host did not write"):
        attest.write_withheld_marker(out, attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert (out / attest.WITHHELD_NAME).read_bytes() == data


def test_write_withheld_marker_replaces_its_own_cleared_marker(tmp_path):
    """L3: an earlier attempt vouched (tombstone or receipt + the cleared marker bound to this
    envelope) and its upload failed; a retry under a lower limit ships as-is and must replace
    that marker with the withheld body rather than refuse forever."""
    out = _withheld_tree(tmp_path, _GARBAGE)
    (out / attest.WITHHELD_NAME).write_bytes(attest.canonical(attest.cleared_marker_body(
        attest.sha256_file(out / "metadata.json"))))
    attest.write_withheld_marker(out, attest.RECEIPT_PATH_UNDECIDABLE_REASON)
    assert (out / attest.WITHHELD_NAME).read_bytes() == attest.canonical(
        attest.tombstone_body(attest.RECEIPT_PATH_UNDECIDABLE_REASON))
    assert (out / attest.RECEIPT_NAME).read_bytes() == b"maybe an artifact"


def test_write_withheld_marker_never_replaces_a_bound_body_the_envelope_declares(tmp_path):
    """A parseable envelope that DECLARES the marker's name never sat beside a cleared marker
    this host wrote (every writer refuses there), so even a body bound to it is kept."""
    out = _withheld_tree(tmp_path, json.dumps(
        {"artifacts": [{"id": "a", "path": "attestation.withheld.json"}]}))
    data = attest.canonical(attest.cleared_marker_body(attest.sha256_file(out / "metadata.json")))
    (out / attest.WITHHELD_NAME).write_bytes(data)
    with pytest.raises(attest.ReceiptPathOccupied):
        attest.write_withheld_marker(out, attest.RECEIPT_PATH_DECLARED_REASON)
    assert (out / attest.WITHHELD_NAME).read_bytes() == data


def _sealable(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    (out / "metadata.json").write_text(json.dumps({"artifacts": []}))
    return out, attest.load_or_create_key(tmp_path / "k" / "attest.key")


def test_a_marker_only_failure_keeps_the_receipt_and_refuses_the_upload(tmp_path, monkeypatch):
    """Our receipt landed; only its marker failed. Not safe to upload (no marker), and the
    genuine receipt must NOT be replaced by a "signing failed" tombstone."""
    out, key = _sealable(tmp_path)
    real = attest._write_marker
    calls = {"n": 0}

    def flaky(out_dir, data):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(28, "No space left on device")
        return real(out_dir, data)

    monkeypatch.setattr(attest, "_write_marker", flaky)
    assert attest.seal_fresh_receipt(out, key=key, observation=_obs(),
                                     job_id=_obs().job_id) is False
    body = json.loads((out / attest.RECEIPT_NAME).read_bytes())
    assert not attest.is_tombstone(attest.canonical(body))
    assert attest.verify_body(key, body)
    assert not (out / attest.WITHHELD_NAME).exists()
    assert attest.tree_receipt_is_ours(out, key=key, job_id=_obs().job_id)


def test_a_tombstone_fallback_whose_marker_fails_is_not_safe_to_upload(tmp_path, monkeypatch):
    """The receipt write failed outright, so the fallback writes a tombstone -- whose marker then
    fails too. Nothing at attestation.json may ship without its marker: False."""
    out, key = _sealable(tmp_path)

    def receipt_fails(*a, **kw):
        raise OSError(5, "Input/output error")

    def marker_fails(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(attest, "seal_receipt", receipt_fails)
    monkeypatch.setattr(attest, "_write_marker", marker_fails)
    assert attest.seal_fresh_receipt(out, key=key, observation=_obs(),
                                     job_id=_obs().job_id) is False
    assert not (out / attest.WITHHELD_NAME).exists()


def _tombstone_reason_exprs():
    """(file:line, reason expression) for every reason this host can write into a tombstone at
    attestation.json: write_tombstone's reason argument, and seal_receipt/seal_fresh_receipt's
    reason= (written when the run was not observed)."""
    import ast
    from pathlib import Path

    src = Path(attest.__file__).resolve().parents[1]
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(
                node.func, "id", None)
            exprs = []
            if fn == "write_tombstone" and len(node.args) >= 2:
                exprs.append(node.args[1])
            if fn in ("write_tombstone", "seal_receipt", "seal_fresh_receipt"):
                exprs += [k.value for k in node.keywords if k.arg == "reason"]
            for e in exprs:
                yield f"{path.name}:{node.lineno}", e


def test_every_tombstone_reason_written_in_src_is_a_named_constant():
    """S1 (prosecutor r134). The route names a stored tombstone's reason only when it is in
    TOMBSTONE_REASONS, so every reason src writes must be one of them -- a literal or an
    f-string here would be reported with the generic reason."""
    import ast

    seen = []
    for where, e in _tombstone_reason_exprs():
        if isinstance(e, ast.BoolOp):
            # seal_receipt's ``reason or RUN_NOT_OBSERVED_REASON``: the fallback is checked
            # here, the forwarded parameter at its callers.
            assert isinstance(e.values[0], ast.Name) and e.values[0].id == "reason", where
            e = e.values[-1]
        if isinstance(e, ast.Name) and e.id == "reason":
            continue        # a forwarded parameter: checked at its callers
        assert isinstance(e, (ast.Name, ast.Attribute)), \
            f"{where}: tombstone reason is not a named constant"
        name = e.id if isinstance(e, ast.Name) else e.attr
        assert getattr(attest, name) in attest.TOMBSTONE_REASONS, f"{where}: {name}"
        seen.append(name)
    assert len(seen) >= 7, seen


def test_the_largest_receipt_build_receipt_can_produce_is_under_the_read_cap():
    """S2: the route answers 404 past _RECEIPT_MAX_BYTES, so no genuine receipt may reach it.
    Every variable field is bounded: job_id is a UUID, engine an allowlisted name, runtime/tier/
    posture host-chosen, and host the hostname (<= 64 bytes) or BLASTBOX_HOST_ID -- an
    environment string, at most MAX_ARG_STRLEN (128 KiB) through execve. ensure_ascii escapes a
    control byte to six bytes, the worst expansion."""
    key = attest.AttestKey(ec.generate_private_key(ec.SECP256R1()))
    obs = attest.RunObservation(
        job_id="0" * 36, engine="e" * 255, input_sha256="d" * 64, worker_runtime="r" * 64,
        worker_tier="t" * 64, started_at_ms=2 ** 63, finished_at_ms=2 ** 63,
        net_policy_effective="n" * 64, net_exit="x" * 64, net_downgraded=True, net_inspect=True)
    doc = attest.build_receipt(obs, key_id=key.key_id, metadata_sha256="f" * 64,
                               issued_at_ms=2 ** 63, host="\x01" * (128 << 10))
    body = attest.canonical({"attestation": doc, "signature": key.sign(doc)})
    assert len(body) <= attest._RECEIPT_MAX_BYTES, len(body)
