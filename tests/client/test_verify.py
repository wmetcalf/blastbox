"""blastbox.client.verify: verify a receipt a REAL dispatcher key signed, and fail closed on
every way it can be wrong."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from blastbox.attest_wire import VerifyKey, canonical, signature_valid
from blastbox.client import verify as v
from blastbox.host import attest

JOB = "0b9d6a0e-6c1d-4f43-9d55-0f6a3c1c7e21"
INPUT = b"%PDF-1.7 the submitted sample"
INPUT_SHA = hashlib.sha256(INPUT).hexdigest()
METADATA = b'{"engine":"williamtells","records":[]}'
METADATA_SHA = hashlib.sha256(METADATA).hexdigest()
NOW_MS = 1_790_000_000_000


@pytest.fixture
def key(tmp_path):
    return attest.load_or_create_key(tmp_path / "a" / "attest.key")


@pytest.fixture
def other_key(tmp_path):
    return attest.load_or_create_key(tmp_path / "b" / "attest.key")


@pytest.fixture
def pinned(key):
    return v.load_pinned_keys(key.public_key_pem)


def _doc(key, *, net: dict | None = None, **over) -> dict:
    obs = attest.RunObservation(
        job_id=JOB, engine="williamtells", input_sha256=INPUT_SHA, worker_runtime="warm",
        worker_tier="static", started_at_ms=NOW_MS - 5000, finished_at_ms=NOW_MS - 1000,
        **(net or {}))
    doc = attest.build_receipt(obs, key_id=key.key_id, metadata_sha256=METADATA_SHA,
                               issued_at_ms=NOW_MS - 900, host="c0ffee")
    doc.update(over)
    return doc


def _body(key, doc: dict, signer=None) -> bytes:
    """The bytes the ingress serves: canonical({"attestation", "signature"}), as seal_receipt
    writes them."""
    return canonical({"attestation": doc, "signature": (signer or key).sign(doc)})


def _verify(raw, pinned, **kw):
    kw.setdefault("expect_job_id", JOB)
    kw.setdefault("expect_input_sha256", INPUT_SHA)
    kw.setdefault("metadata_bytes", METADATA)
    return v.verify_receipt(raw, keys=pinned, **kw)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_a_genuine_receipt_verifies_and_reports_the_signed_fields(key, pinned):
    r = _verify(_body(key, _doc(key)), pinned, expect_engine="williamtells")
    assert r.job_id == JOB and r.engine == "williamtells" and r.status == "done"
    assert r.key_id == key.key_id and r.host == "c0ffee" and r.executor == "local"
    assert r.input_sha256 == INPUT_SHA and r.metadata_sha256 == METADATA_SHA
    assert (r.worker_runtime, r.worker_tier) == ("warm", "static")
    assert (r.started_at_ms, r.finished_at_ms, r.issued_at_ms) == (
        NOW_MS - 5000, NOW_MS - 1000, NOW_MS - 900)
    assert r.input_bound and r.metadata_bound
    assert dict(r.signed) == _doc(key)


def test_absent_network_fields_are_reported_as_NOT_attested_never_as_none(key, pinned):
    r = _verify(_body(key, _doc(key)), pinned)
    assert r.network is None and r.network_attested is False
    d = r.as_dict()
    assert d["network"] is None and d["network_attested"] is False
    json.dumps(d)  # JSON-friendly


def test_attested_network_posture_is_reported(key, pinned):
    r = _verify(_body(key, _doc(key, net={"net_policy_effective": "inetsim",
                                          "net_exit": "inetsim"})), pinned)
    assert r.network == v.AttestedNetwork("inetsim", "inetsim", downgraded=False, inspect=False)
    r = _verify(_body(key, _doc(key, net={"net_policy_effective": "proxy", "net_exit": "none",
                                          "net_downgraded": True, "net_inspect": True})), pinned)
    assert r.network == v.AttestedNetwork("proxy", "none", downgraded=True, inspect=True)
    assert r.as_dict()["network"] == {"policy_effective": "proxy", "exit": "none",
                                      "downgraded": True, "inspect": True}


def test_unbound_input_and_metadata_are_reported_as_unbound(key, pinned):
    r = v.verify_receipt(_body(key, _doc(key)), keys=pinned, expect_job_id=JOB)
    assert not r.input_bound and not r.metadata_bound


def test_str_and_parsed_mapping_bodies_verify(key, pinned):
    raw = _body(key, _doc(key))
    assert _verify(raw.decode(), pinned).job_id == JOB
    assert _verify(json.loads(raw), pinned).job_id == JOB


def test_null_worker_runtime_and_tier_verify(key, pinned):
    r = _verify(_body(key, _doc(key, worker_runtime=None, worker_tier=None)), pinned)
    assert r.worker_runtime is None and r.worker_tier is None


def test_uppercase_expected_input_hash_is_accepted(key, pinned):
    assert _verify(_body(key, _doc(key)), pinned, expect_input_sha256=INPUT_SHA.upper())


@pytest.mark.parametrize("net", [
    {},
    {"net_policy_effective": "none", "net_exit": "none"},
    {"net_policy_effective": "direct", "net_exit": "direct"},
    {"net_policy_effective": "p", "net_exit": "none", "net_downgraded": True},
    {"net_policy_effective": "p", "net_exit": "inetsim", "net_inspect": True},
    {"net_policy_effective": "p", "net_exit": None},
])
def test_every_shape_the_signer_emits_verifies(key, pinned, net):
    """Drift guard: whatever build_receipt emits, this verifier accepts. A field added there
    without a receipt version bump fails HERE, not silently in a consumer."""
    assert _verify(_body(key, _doc(key, net=net)), pinned)


# ---------------------------------------------------------------------------
# Signature / key selection
# ---------------------------------------------------------------------------


def _tampered(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if value is None:
        return "x"
    if len(value) == 64:
        return ("0" if value[0] != "0" else "1") + value[1:]
    return value + "x"


_SIGNED_FIELDS = sorted([
    "host", "job_id", "engine", "status", "executor", "input_sha256", "metadata_sha256",
    "worker_runtime", "worker_tier", "started_at_ms", "finished_at_ms", "issued_at_ms",
    "net_policy_effective", "net_exit", "net_downgraded", "net_inspect"])


@pytest.mark.parametrize("field", _SIGNED_FIELDS)
def test_tampering_any_signed_field_breaks_the_signature(key, pinned, field):
    doc = _doc(key, net={"net_policy_effective": "inetsim", "net_exit": "inetsim",
                         "net_downgraded": True, "net_inspect": True})
    sig = key.sign(doc)
    if field in ("net_downgraded", "net_inspect"):
        del doc[field]                         # the only other legal value is "absent"
    else:
        doc[field] = _tampered(doc[field])
    with pytest.raises(v.BadSignature):
        v.verify_receipt(canonical({"attestation": doc, "signature": sig}), keys=pinned,
                         expect_job_id=doc["job_id"])


def test_stripping_the_signed_network_posture_breaks_the_signature(key, pinned):
    doc = _doc(key, net={"net_policy_effective": "none", "net_exit": "none"})
    sig = key.sign(doc)
    del doc["net_policy_effective"], doc["net_exit"]
    with pytest.raises(v.BadSignature):
        _verify(canonical({"attestation": doc, "signature": sig}), pinned)


def test_adding_a_network_posture_breaks_the_signature(key, pinned):
    doc = _doc(key)
    sig = key.sign(doc)
    doc.update(net_policy_effective="none", net_exit="none")
    with pytest.raises(v.BadSignature):
        _verify(canonical({"attestation": doc, "signature": sig}), pinned)


def test_a_flipped_signature_byte_fails(key, pinned):
    import base64
    body = json.loads(_body(key, _doc(key)))
    der = bytearray(base64.urlsafe_b64decode(body["signature"]))
    der[-1] ^= 1
    body["signature"] = base64.urlsafe_b64encode(bytes(der)).decode()
    with pytest.raises(v.BadSignature):
        _verify(json.dumps(body), pinned)


@pytest.mark.parametrize("mangle", [
    # unpadded (a 72-byte DER signature needs no padding: drop a character instead)
    lambda s: s.rstrip("=") if s.endswith("=") else s[:-1],
    lambda s: s[:10] + "!" + s[10:],         # outside the alphabet (a lenient decoder drops it)
    lambda s: "+" + s[1:],                   # standard (not url-safe) alphabet
    lambda s: "",
])
def test_a_signature_that_is_not_strict_padded_base64url_is_malformed(key, pinned, mangle):
    body = json.loads(_body(key, _doc(key)))
    body["signature"] = mangle(body["signature"])
    with pytest.raises(v.ReceiptMalformed):
        _verify(json.dumps(body), pinned)


def test_a_signature_has_exactly_one_accepted_spelling():
    """Non-zero trailing bits decode to the same DER; only the canonical spelling is taken."""
    assert v._decode_signature("QQ==") == b"A"
    with pytest.raises(v.ReceiptMalformed, match="canonical"):
        v._decode_signature("QR==")


def test_signed_by_another_key_under_the_pinned_key_id_fails(key, other_key, pinned):
    doc = _doc(key)                                   # names the pinned key_id...
    raw = _body(key, doc, signer=other_key)           # ...signed by a different key
    with pytest.raises(v.BadSignature):
        _verify(raw, pinned)


def test_an_unpinned_key_id_fails_and_names_it(key, other_key, pinned):
    doc = _doc(other_key)
    with pytest.raises(v.UnknownSigningKey) as ei:
        _verify(_body(other_key, doc), pinned)
    assert ei.value.key_id == other_key.key_id and ei.value.code == "unknown_key"


def test_any_pinned_key_verifies_its_own_receipts(key, other_key):
    keys = v.load_pinned_keys(key.public_key_pem, other_key.public_key_pem)
    assert _verify(_body(key, _doc(key)), keys).key_id == key.key_id
    assert _verify(_body(other_key, _doc(other_key)), keys).key_id == other_key.key_id


@pytest.mark.parametrize("key_id", ["ABCDEF0123456789", "abc", 7, None, "g" * 16])
def test_a_malformed_key_id_is_malformed(key, pinned, key_id):
    with pytest.raises(v.ReceiptMalformed):
        _verify(_body(key, _doc(key, key_id=key_id)), pinned)


# ---------------------------------------------------------------------------
# Version / algorithm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("over", [{"v": 2}, {"v": True}, {"v": "1"}, {"alg": "ES384"},
                                  {"alg": "none"}])
def test_an_unsupported_version_or_alg_is_refused(key, pinned, over):
    with pytest.raises(v.UnsupportedReceipt):
        _verify(_body(key, _doc(key, **over)), pinned)


def test_a_missing_version_is_refused(key, pinned):
    doc = _doc(key)
    del doc["v"]
    with pytest.raises(v.UnsupportedReceipt):
        _verify(_body(key, doc), pinned)


# ---------------------------------------------------------------------------
# Strict parsing / schema
# ---------------------------------------------------------------------------


def _splice(raw: bytes, needle: str, replacement: str) -> bytes:
    text = raw.decode()
    assert needle in text
    return text.replace(needle, replacement, 1).encode()


def test_a_duplicate_key_in_the_document_is_refused(key, pinned):
    """A parser that keeps the FIRST occurrence would see a different job than the one signed."""
    raw = _body(key, _doc(key))
    with pytest.raises(v.ReceiptMalformed, match="duplicate"):
        _verify(_splice(raw, '"job_id":', '"job_id":"other","job_id":'), pinned)


def test_a_duplicate_top_level_key_is_refused(key, pinned):
    raw = _body(key, _doc(key))
    with pytest.raises(v.ReceiptMalformed, match="duplicate"):
        _verify(_splice(raw, '"signature":', '"signature":"AAAA","signature":'), pinned)


@pytest.mark.parametrize("number", ["1.0", "1e3", "NaN", "Infinity", "-Infinity"])
def test_floats_and_non_finite_numbers_are_refused(key, pinned, number):
    raw = _body(key, _doc(key))
    with pytest.raises(v.ReceiptMalformed):
        _verify(_splice(raw, f'"started_at_ms":{NOW_MS - 5000}', f'"started_at_ms":{number}'),
                pinned)


def test_a_float_in_a_parsed_mapping_is_refused(key, pinned):
    body = json.loads(_body(key, _doc(key)))
    body["attestation"]["started_at_ms"] = float(body["attestation"]["started_at_ms"])
    with pytest.raises(v.ReceiptMalformed):
        _verify(body, pinned)


@pytest.mark.parametrize("raw", [
    b"\xff\xfe{}", "﻿{}".encode(), b'{"attestation": {}, "signature": "x"}'.decode()
    .encode("utf-16"), b"not json", b"[]", b"null", b"{}", b"",
])
def test_non_json_or_non_utf8_bodies_are_malformed(pinned, raw):
    with pytest.raises(v.ReceiptMalformed):
        _verify(raw, pinned)


def test_an_oversized_body_is_refused_before_parsing(pinned):
    with pytest.raises(v.ReceiptMalformed, match="larger"):
        _verify(b" " * (v.RECEIPT_MAX_BYTES + 1), pinned)


def test_deeply_nested_json_is_malformed_not_a_crash(pinned):
    with pytest.raises(v.ReceiptMalformed):
        _verify(b"[" * 100_000 + b"]" * 100_000, pinned)


def test_an_unsigned_extra_top_level_key_is_refused(key, pinned):
    body = json.loads(_body(key, _doc(key)))
    body["note"] = "unsigned"
    with pytest.raises(v.ReceiptMalformed):
        _verify(json.dumps(body), pinned)


def test_an_unknown_signed_field_is_refused(key, pinned):
    with pytest.raises(v.ReceiptMalformed, match="unknown field"):
        _verify(_body(key, _doc(key, partial=True)), pinned)


@pytest.mark.parametrize("field", ["host", "job_id", "engine", "status", "executor",
                                   "input_sha256", "metadata_sha256", "worker_runtime",
                                   "worker_tier", "started_at_ms", "finished_at_ms",
                                   "issued_at_ms"])
def test_a_missing_field_is_refused(key, pinned, field):
    doc = _doc(key)
    del doc[field]
    with pytest.raises(v.ReceiptMalformed, match="missing"):
        _verify(_body(key, doc), pinned)


@pytest.mark.parametrize("over", [
    {"started_at_ms": True}, {"issued_at_ms": -1}, {"finished_at_ms": "1"},
    {"issued_at_ms": 1 << 64}, {"job_id": 5}, {"engine": None}, {"host": ["x"]},
    {"worker_tier": 3}, {"input_sha256": INPUT_SHA.upper()}, {"metadata_sha256": "ab"},
])
def test_mistyped_fields_are_refused(key, pinned, over):
    with pytest.raises(v.ReceiptMalformed):
        _verify(_body(key, _doc(key, **over)), pinned)


@pytest.mark.parametrize("net", [
    {"net_exit": "none"},                                         # exit without a policy
    {"net_downgraded": True},                                     # flag without a policy
    {"net_policy_effective": "none"},                             # policy without an exit
    {"net_policy_effective": "none", "net_exit": "none", "net_downgraded": False},
    {"net_policy_effective": "none", "net_exit": "none", "net_inspect": 1},
    {"net_policy_effective": None, "net_exit": "none"},
    {"net_policy_effective": "none", "net_exit": 0},
])
def test_inconsistent_network_fields_are_refused(key, pinned, net):
    with pytest.raises(v.ReceiptMalformed):
        _verify(_body(key, _doc(key, **net)), pinned)


# ---------------------------------------------------------------------------
# Tombstones
# ---------------------------------------------------------------------------


def test_a_tombstone_is_a_typed_no_receipt_with_its_reason(pinned):
    raw = canonical(attest.tombstone_body(attest.NO_ATTEST_KEY_REASON))
    with pytest.raises(v.NoReceipt) as ei:
        _verify(raw, pinned)
    assert ei.value.code == "tombstone" and ei.value.reason == attest.NO_ATTEST_KEY_REASON
    assert not isinstance(ei.value, v.ReceiptMalformed)


def test_a_tombstone_reason_is_sanitised_for_display(pinned):
    raw = json.dumps({"attestation": None, "reason": "\x1b]0;pwn\x07" + "x" * 500})
    with pytest.raises(v.NoReceipt) as ei:
        _verify(raw, pinned)
    assert "\x1b" not in str(ei.value) and "\x07" not in ei.value.reason
    assert len(ei.value.reason) < 200


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


def test_job_id_mismatch(key, pinned):
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(_body(key, _doc(key)), pinned,
                expect_job_id="11111111-1111-4111-8111-111111111111")
    assert ei.value.code == "job_id_mismatch"


def test_input_mismatch(key, pinned):
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(_body(key, _doc(key)), pinned,
                expect_input_sha256=hashlib.sha256(INPUT + b"!").hexdigest())
    assert ei.value.code == "input_mismatch"


def test_metadata_mismatch(key, pinned):
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(_body(key, _doc(key)), pinned, metadata_bytes=METADATA + b" ")
    assert ei.value.code == "metadata_mismatch"


def test_engine_mismatch(key, pinned):
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(_body(key, _doc(key)), pinned, expect_engine="clamav")
    assert ei.value.code == "engine_mismatch"


@pytest.mark.parametrize("status", ["failed", "running", "DONE", ""])
def test_a_signed_status_other_than_done_fails(key, pinned, status):
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(_body(key, _doc(key, status=status)), pinned)
    assert ei.value.code == "status_not_done"


def test_max_age(key, pinned):
    raw = _body(key, _doc(key))                       # issued NOW_MS - 900
    assert _verify(raw, pinned, max_age=1, now_ms=NOW_MS)
    assert _verify(raw, pinned, max_age=timedelta(seconds=1), now_ms=NOW_MS)
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(raw, pinned, max_age=0.5, now_ms=NOW_MS)
    assert ei.value.code == "stale"


def test_a_receipt_from_the_future_fails_when_age_is_checked(key, pinned):
    raw = _body(key, _doc(key, issued_at_ms=NOW_MS + 301_000))
    with pytest.raises(v.ReceiptMismatch) as ei:
        _verify(raw, pinned, max_age=3600, now_ms=NOW_MS)
    assert ei.value.code == "issued_in_future"
    assert _verify(raw, pinned, max_age=3600, max_clock_skew=400, now_ms=NOW_MS)


@pytest.mark.parametrize("kw", [
    {"expect_job_id": ""}, {"expect_job_id": None}, {"expect_input_sha256": "abc"},
    {"expect_input_sha256": b"x" * 64}, {"metadata_bytes": "text"}, {"max_age": -1},
    {"max_age": float("nan")}, {"max_age": True}, {"expect_engine": ""},
    {"now_ms": 1.5},
])
def test_bad_arguments_raise_not_verify(key, pinned, kw):
    with pytest.raises((TypeError, ValueError)):
        _verify(_body(key, _doc(key)), pinned, **kw)


def test_mismatch_checks_run_only_after_the_signature(key, other_key, pinned):
    """A forged receipt with every binding wrong reports the forgery, not a binding."""
    raw = _body(key, _doc(key, job_id="x"), signer=other_key)
    with pytest.raises(v.BadSignature):
        _verify(raw, pinned)


# ---------------------------------------------------------------------------
# Pinned keys
# ---------------------------------------------------------------------------


def test_keys_load_from_every_supported_source(tmp_path, key):
    pem = key.public_key_pem
    body = attest.public_key_body(key)
    printout = f"key_id: {key.key_id}\nalg: ES256\npath: /k\n{pem}"
    (tmp_path / "k.pem").write_text(pem)
    (tmp_path / "k.json").write_text(json.dumps(body))
    (tmp_path / "k.txt").write_text(printout)
    for src in (pem, pem.encode(), body, json.dumps(body), printout,
                tmp_path / "k.pem", tmp_path / "k.json", tmp_path / "k.txt",
                VerifyKey.from_attest_key(key)):
        keys = v.load_pinned_keys(src)
        assert list(keys) == [key.key_id], src


def test_the_same_key_twice_is_pinned_once(key):
    keys = v.load_pinned_keys(key.public_key_pem, attest.public_key_body(key))
    assert len(keys) == 1


def test_two_different_keys_under_one_key_id_are_refused(monkeypatch, key, other_key):
    monkeypatch.setattr(VerifyKey, "key_id", property(lambda self: "same"))
    with pytest.raises(v.KeyIdCollision):
        v.load_pinned_keys(key.public_key_pem, other_key.public_key_pem)
    with pytest.raises(v.KeyIdCollision):
        v.PinnedKeys([VerifyKey.from_attest_key(key), VerifyKey.from_attest_key(other_key)])
    assert issubclass(v.KeyIdCollision, v.VerifyKeyRefused)


def test_a_stated_key_id_is_never_trusted(key, other_key):
    body = attest.public_key_body(key) | {"key_id": other_key.key_id}
    with pytest.raises(v.VerifyKeyRefused, match="key_id"):
        v.load_pinned_keys(body)
    printout = f"key_id: {other_key.key_id}\nalg: ES256\n{key.public_key_pem}"
    with pytest.raises(v.VerifyKeyRefused, match="key_id"):
        v.load_pinned_keys(printout)
    with pytest.raises(v.VerifyKeyRefused, match="alg"):
        v.load_pinned_keys(f"alg: ES384\n{key.public_key_pem}")
    with pytest.raises(v.VerifyKeyRefused, match="alg"):
        v.load_pinned_keys(attest.public_key_body(key) | {"alg": "RS256"})


def test_receipts_select_keys_by_the_RECOMPUTED_key_id(key, other_key):
    """A key body claiming another key's id cannot be pinned under it, so a receipt naming that
    id never reaches the wrong key."""
    keys = v.load_pinned_keys(key.public_key_pem)
    assert set(keys) == {key.key_id}
    with pytest.raises(v.UnknownSigningKey):
        _verify(_body(other_key, _doc(other_key)), keys)


def test_a_str_is_key_text_never_a_path(tmp_path, key):
    (tmp_path / "k.pem").write_text(key.public_key_pem)
    with pytest.raises(v.VerifyKeyRefused, match="pathlib.Path"):
        v.load_pinned_keys(str(tmp_path / "k.pem"))


def _pem(pub) -> str:
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.mark.parametrize("make", [
    lambda: _pem(ec.generate_private_key(ec.SECP384R1()).public_key()),
    lambda: _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()),
    lambda: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
    # Well-formed SPKI with an algorithm OID (1.2.3.4) no backend implements:
    # load_pem_public_key raises UnsupportedAlgorithm, which must still be a refusal.
    lambda: ("-----BEGIN PUBLIC KEY-----\n"
             + base64.b64encode(bytes.fromhex("300c300506032a03040303000102")).decode()
             + "\n-----END PUBLIC KEY-----\n"),
])
def test_a_key_that_is_not_P256_is_refused(make):
    with pytest.raises(v.VerifyKeyRefused):
        v.load_pinned_keys(make())


class _P384Signer:
    """An attest-key look-alike on P-384: signs ECDSA/SHA-256 over the canonical doc."""

    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())

    def sign(self, doc):
        der = self.private_key.sign(canonical(doc), ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(der).decode()


def test_a_programmatic_non_P256_verify_key_is_refused():
    """The PEM path refuses P-384; the programmatic constructors must too, or a P-384
    ECDSA/SHA-256 signature would verify under a receipt claiming ES256."""
    signer = _P384Signer()
    with pytest.raises(v.VerifyKeyRefused, match="P-256"):
        VerifyKey(signer.private_key.public_key())
    with pytest.raises(v.VerifyKeyRefused, match="P-256"):
        VerifyKey.from_attest_key(signer)
    with pytest.raises(v.VerifyKeyRefused, match="P-256"):
        VerifyKey("not a key")  # type: ignore[arg-type]


def test_pinning_a_mutated_non_P256_verify_key_is_refused(key):
    """Even a VerifyKey forced onto P-384 after construction cannot be pinned, and the wire
    check itself says no for a non-P-256 key."""
    signer = _P384Signer()
    vk = VerifyKey(key.private_key.public_key())
    object.__setattr__(vk, "public_key", signer.private_key.public_key())
    with pytest.raises(v.VerifyKeyRefused, match="P-256"):
        v.PinnedKeys([vk])
    with pytest.raises(v.VerifyKeyRefused, match="P-256"):
        v.verify_receipt(b"{}", keys=vk, expect_job_id=JOB)
    doc = _doc(key)
    der = base64.urlsafe_b64decode(signer.sign(doc))
    assert not signature_valid(signer.private_key.public_key(), doc, der)


def test_two_pem_blocks_in_one_source_are_refused(key, other_key):
    with pytest.raises(v.VerifyKeyRefused, match="exactly one"):
        v.load_pinned_keys(key.public_key_pem + other_key.public_key_pem)


def test_unreadable_oversized_and_special_key_files_are_refused(tmp_path):
    with pytest.raises(v.VerifyKeyRefused, match="cannot read"):
        v.load_pinned_keys(tmp_path / "missing.pem")
    with pytest.raises(v.VerifyKeyRefused, match="regular file"):
        v.load_pinned_keys(tmp_path)
    big = tmp_path / "big.pem"
    big.write_bytes(b"x" * (v.KEY_FILE_MAX_BYTES + 1))
    with pytest.raises(v.VerifyKeyRefused, match="larger"):
        v.load_pinned_keys(big)


def test_no_keys_is_refused(key):
    with pytest.raises(v.VerifyKeyRefused):
        v.load_pinned_keys()
    with pytest.raises(v.VerifyKeyRefused):
        v.verify_receipt(_body(key, _doc(key)), keys=[], expect_job_id=JOB)
    with pytest.raises(v.VerifyKeyRefused):
        v.verify_receipt(_body(key, _doc(key)), keys=v.PinnedKeys(), expect_job_id=JOB)


@pytest.mark.parametrize("keys", ["pem text", b"pem", {"public_key_pem": "x"}, 3, ["pem"]])
def test_keys_must_be_verify_keys_not_raw_material(key, keys):
    with pytest.raises(TypeError):
        v.verify_receipt(_body(key, _doc(key)), keys=keys, expect_job_id=JOB)


def test_unsupported_key_source_type(key):
    with pytest.raises(TypeError):
        v.load_pinned_keys(42)  # type: ignore[arg-type]


def test_a_single_verify_key_is_accepted(key):
    assert _verify(_body(key, _doc(key)), VerifyKey.from_attest_key(key))


def test_pinned_keys_is_read_only(key):
    keys = v.load_pinned_keys(key.public_key_pem)
    with pytest.raises(TypeError):
        keys["x"] = keys[key.key_id]  # type: ignore[index]
    assert key.key_id in repr(keys)


def test_the_host_and_client_share_one_wire_contract(key):
    """attest.py's canonical/VerifyKey ARE the shared ones (not copies that could drift)."""
    from blastbox import attest_wire
    assert attest.canonical is attest_wire.canonical is v.canonical
    assert attest.VerifyKey is attest_wire.VerifyKey is v.VerifyKey
    assert attest.ALG == v.ALG and attest.VERSION == v.VERSION
    assert Path(attest.__file__).parent.name == "host"
