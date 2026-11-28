"""Gate for the v1 node-protocol conformance vectors (scripts/gen_conformance.py).

The Go pull-worker agent consumes the same JSON files, so these tests pin both that the
committed files are exactly what the Python reference generates and that every committed
verdict still holds when replayed through the reference functions.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance" / "v1"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_conformance", ROOT / "scripts" / "gen_conformance.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_conformance"] = mod
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def test_vectors_match_generator():
    expected = gen.generate()
    assert expected, "generator produced nothing"
    for rel, data in expected.items():
        committed = (VECTORS / rel).read_bytes()
        assert committed == data, f"{rel} drifted from the Python reference"


def test_committed_once_artifacts_verify():
    assert gen.verify_committed_once() == []


def test_sha256sums_cover_every_file():
    sums = {}
    for line in (VECTORS / "SHA256SUMS").read_text().splitlines():
        digest, _, rel = line.partition("  ")
        sums[rel] = digest
    files = {str(p.relative_to(VECTORS)) for p in VECTORS.rglob("*")
             if p.is_file() and p.name != "SHA256SUMS"}
    assert set(sums) == files
    for rel, digest in sums.items():
        assert hashlib.sha256((VECTORS / rel).read_bytes()).hexdigest() == digest, rel


def _verify(pem: str, payload_hex: str, sig_b64: str) -> None:
    pub = serialization.load_pem_public_key(pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(base64.b64decode(sig_b64), bytes.fromhex(payload_hex),
               ec.ECDSA(hashes.SHA256()))


def test_ecdsa_cross_both_directions_verify():
    doc = _load("ecdsa_cross.json")
    assert doc["python_signed"], "python_signed must not be empty"
    negatives = [e for e in doc["python_signed"] if e.get("valid") is False]
    assert negatives, "python_signed needs a tampered-signature negative"
    assert not any(e.get("valid") is False for e in doc["go_signed"])
    for entry in doc["python_signed"] + doc["go_signed"]:
        if entry.get("valid", True):
            _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])
    from cryptography.exceptions import InvalidSignature
    for entry in negatives:
        with pytest.raises(InvalidSignature):
            _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])


def test_ecdsa_cross_rejects_tampered_payload():
    from cryptography.exceptions import InvalidSignature

    entry = next(e for e in _load("ecdsa_cross.json")["python_signed"] if e.get("valid", True))
    with pytest.raises(InvalidSignature):
        _verify(entry["public_key_pem"], entry["payload_hex"] + "00", entry["signature_b64"])


def test_challenge_verdicts_replay():
    from blastbox.host import node_auth

    doc = _load("challenge.json")
    secret = bytes.fromhex(doc["secret_hex"])
    for case in doc["cases"]:
        try:
            node_auth._check_challenge(case["challenge"], case["scope"], secret=secret,
                                       now=case["verify_at"])
            got = "ok"
        except node_auth.ClaimRefused as exc:
            got = gen.classify_refusal(str(exc))
        if got == "foreign_or_wrong_scope":      # the reference cannot tell these apart
            assert case["verdict"] in ("foreign", "wrong_scope"), case
        else:
            assert got == case["verdict"], case


def test_signing_payload_replay():
    from blastbox.host import node_auth

    for case in _load("signing_payload.json")["cases"]:
        got = node_auth.signing_payload(case["challenge"], case["scope"], case["node_id"])
        assert got.hex() == case["payload_hex"]


def test_node_cert_verdicts_replay():
    doc = _load("node_certs/cases.json")
    verdicts = {c["name"]: c["verdict"] for c in doc["cases"]}
    for name in ("v1_with_wg", "v2_without_wg"):
        assert verdicts[name] == "ok"
    for name in ("wrong_eku", "client_auth_eku", "node_plus_client_auth_eku", "cn_mismatch", "expired",
                 "missing_node_info", "garbled_node_info"):
        assert verdicts[name] == "refused", name
    assert any(c["name"] == "rsa_key" and c["admit"]["verdict"] == "refused"
               for c in doc["cases"])


def test_session_token_verdicts_replay_under_the_file_secret():
    """Every verify entry must hold under the ONE secret the file publishes."""
    from blastbox.host import node_auth

    doc = _load("session_token.json")
    secret = bytes.fromhex(doc["secret_hex"])
    for case in doc["verify"]:
        try:
            got_id = node_auth.verify_session(case["token"], secret=secret,
                                              now=case["verify_at"])
            got = "ok"
        except node_auth.ClaimRefused as exc:
            got_id = None
            got = ("malformed" if "malformed" in str(exc)
                   else "expired" if "expired" in str(exc) else "forged")
        assert (got, got_id) == (case["verdict"], case["node_id"]), case


def test_vector_pairs_never_contradict():
    """The same (token, verify_at) must not carry two different verdicts."""
    seen: dict = {}
    for case in _load("session_token.json")["verify"]:
        k = (case["token"], case["verify_at"])
        assert seen.setdefault(k, case["verdict"]) == case["verdict"], case


def test_fresh_node_cert_generation_does_not_trip_the_lifetime_cap():
    files = gen.build_node_certs()       # in memory only; writes nothing
    assert "cases.json" in files and "v1_with_wg.crt" in files


ADDED_NEGATIVES = ("node_eku_not_critical", "node_plus_server_auth_eku", "node_plus_any_eku",
                   "v2_bad_wg", "v1_without_wg")


def test_node_cert_vectors_pin_every_eku_and_wg_refusal():
    verdicts = {c["name"]: c["verdict"] for c in _load("node_certs/cases.json")["cases"]}
    for name in ADDED_NEGATIVES:
        assert verdicts.get(name) == "refused", name
    assert verdicts.get("v2_with_wg") == "ok"


def test_renew_proof_payloads_replay():
    from blastbox.host import node_renew

    doc = _load("renew_proof.json")
    assert doc["domain"] == node_renew.RENEW_PROOF_DOMAIN.decode()
    assert doc["payload_cases"], "renew_proof.json needs payload cases"
    for case in doc["payload_cases"] + doc["python_signed"] + doc["go_signed"]:
        got = node_renew.renew_payload(case["node_id"], case["csr_pem"], case["issued_at"])
        assert got.hex() == case["payload_hex"], case


def test_renew_proof_signatures_both_directions():
    from cryptography.exceptions import InvalidSignature

    doc = _load("renew_proof.json")
    assert doc["python_signed"], "python_signed must not be empty"
    assert any(e.get("valid") is False for e in doc["python_signed"])
    assert not any(e.get("valid") is False for e in doc["go_signed"])
    for entry in doc["python_signed"] + doc["go_signed"]:
        if entry.get("valid", True):
            _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])
        else:
            with pytest.raises(InvalidSignature):
                _verify(entry["public_key_pem"], entry["payload_hex"], entry["signature_b64"])


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(max_age_ca_s=1),
    lambda d: d.update(max_skew_ingress_s=9999),
    lambda d: d.update(payload="something else"),
    lambda d: d.update(python_signed=[e for e in d["python_signed"] if e.get("valid") is False]),
    lambda d: d.update(go_signed=[{"node_id": "n", "csr_pem": "", "issued_at": 1}]),
])
def test_check_catches_a_doctored_renew_proof(tmp_path, mutate):
    import shutil
    out = tmp_path / "v1"
    shutil.copytree(VECTORS, out)
    doc = json.loads((out / "renew_proof.json").read_text())
    mutate(doc)
    (out / "renew_proof.json").write_text(json.dumps(doc))
    (out / "SHA256SUMS").write_bytes(gen.sha256sums(out))
    assert any("renew_proof" in p for p in gen.check(out))


# ---------------------------------------------------------------- data plane (PR B)

import io  # noqa: E402
import tarfile  # noqa: E402


def _each(sub: str):
    return sorted((VECTORS / sub).glob("*.json"))


def test_result_tars_verdicts_replay_through_the_reference():
    assert gen.verify_result_tars() == []
    docs = [json.loads(p.read_text()) for p in _each("result_tars")]
    assert {d["server_verdict"] for d in docs} == {"accepted", "rejected"}
    assert len(docs) >= 20


def _owned_headers(rig, who="alpha"):
    tok = rig.token(who)
    got = rig.client.post("/v1/nodes/claim", json={"engine": "clamav"},
                          headers={gen.SESSION_HDR: tok}).json()
    return {gen.SESSION_HDR: tok, "x-blastbox-claim-id": got["job"]["claim_id"],
            "x-blastbox-receipt": got["receipt"]}


@pytest.mark.parametrize("case", [p.stem for p in _each("result_tars")
                                  if json.loads(p.read_text())["server_verdict"] == "accepted"])
def test_accepted_result_tar_gets_202_from_the_real_route(case):
    vec = json.loads((VECTORS / "result_tars" / f"{case}.json").read_text())
    with gen._dp_rig() as rig:
        rig.submit()
        h = _owned_headers(rig)
        r = rig.client.put("/v1/nodes/jobs/job-1/result", headers=h,
                           content=(VECTORS / "result_tars" / f"{case}.tar").read_bytes())
        assert r.status_code == vec["http_status"] == 202, r.text
        assert r.json() == {"status": "accepted"}


def test_every_rejected_result_tar_gets_422_from_the_real_route():
    rejected = [p.stem for p in _each("result_tars")
                if json.loads(p.read_text())["server_verdict"] == "rejected"]
    assert len(rejected) >= 15
    with gen._dp_rig() as rig:
        rig.submit()
        h = _owned_headers(rig)
        for case in rejected:
            r = rig.client.put("/v1/nodes/jobs/job-1/result", headers=h,
                               content=(VECTORS / "result_tars" / f"{case}.tar").read_bytes())
            assert r.status_code == 422, (case, r.status_code, r.text)
        # a rejection leaves nothing behind that a replay could mistake for an upload
        assert list((rig.root / "results" / "job-1").glob("*")) == []


@pytest.mark.parametrize("path", _each("result_tars/writer"), ids=lambda p: p.stem)
def test_writer_goldens(path):
    doc = json.loads(path.read_text())
    tree = gen.tree_from_json(doc["tree"])
    tar = gen.go_writer_tar(tree)
    assert hashlib.sha256(tar).hexdigest() == doc["tar_sha256"]
    assert len(tar) == doc["tar_bytes"] and len(tar) % 512 == 0
    assert tar.endswith(b"\0" * 1024) and tar[257:265] == b"ustar\x0000"   # USTAR magic+version
    # no record padding: the end marker is the last two blocks, and the last member's data
    # (padded to 512) sits directly before it
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as tf:
        members = tf.getmembers()
        assert [m.name for m in members] == sorted(tree, key=lambda s: s.encode())
        for m in members:
            assert m.isreg() and m.mode == 0o644 and m.uid == m.gid == 0 and m.mtime == 0
            assert m.uname == "" and m.gname == ""
            f = tf.extractfile(m)
            assert f is not None and f.read() == tree[m.name]
    # and the server accepts what the writer writes
    assert gen.server_verdict_for_tar(tar) == "accepted"


def test_writer_has_a_golden_for_every_tree():
    assert {p.stem for p in _each("result_tars/writer")} == set(gen.WRITER_TREES)


def test_claim_response_decisions_follow_the_run_block():
    seen = set()
    for p in _each("claim_responses"):
        v = json.loads(p.read_text())
        seen.add(v["decision"])
        if v["decision"] in ("run", "release_unstarted"):
            assert v["status"] == 200 and "run" in v["body"]
            assert (v["decision"] == "run") == (v["body"]["run"]["network"] == "none"), p.name
            assert v["body"]["receipt"] == "<RECEIPT>"
            assert v["body"]["job"]["claim_id"] == "<CLAIM_ID>"
        elif v["decision"] == "idle":
            assert v["status"] == 204 and v["body"] is None
        elif v["decision"] == "rehandshake":
            assert v["status"] == 401
        elif v["decision"] == "refused":
            assert v["status"] == 403
    assert seen == {"run", "idle", "rehandshake", "refused", "release_unstarted"}
    sink = json.loads((VECTORS / "claim_responses" / "release_network_sinkhole.json").read_text())
    assert sink["body"]["run"]["network"] == "sinkhole" and sink["synthetic"] is True


def test_input_stream_verdicts_and_accept_matches_the_real_route():
    seen = set()
    for p in _each("input_stream"):
        v = json.loads(p.read_text())
        seen.add(v["verdict"])
        assert gen.judge_input(v) == v["verdict"], p.name
    assert seen == {"accept", "abort_short", "abort_long", "abort_hash", "abort_redirect"}
    acc = json.loads((VECTORS / "input_stream" / "accept.json").read_text())
    with gen._dp_rig() as rig:
        rig.submit()
        r = rig.client.get("/v1/nodes/jobs/job-1/input", headers=_owned_headers(rig))
        assert r.status_code == 200 and r.content.hex() == acc["body_hex"]
        assert r.headers["x-blastbox-input-sha256"] == acc["headers"]["x-blastbox-input-sha256"]
        assert r.headers["content-length"] == acc["headers"]["content-length"]


def test_envelope_seal_matches_files_on_disk():
    seen = set()
    for p in _each("envelope_seal"):
        v = json.loads(p.read_text())
        seen.add(v["verdict"])
        if v["verdict"] != "sealed":
            assert v["artifacts"] is None
            continue
        tree = gen.tree_from_json(v["tree"])
        for a in v["artifacts"]:
            data = tree[a["path"]]
            assert a["sha256"] == hashlib.sha256(data).hexdigest() and a["bytes"] == len(data)
    assert seen == {"sealed", "refused"}


def test_transcripts_shape():
    for p in _each("transcripts"):
        steps = json.loads(p.read_text())
        assert steps and all(set(s) == {"req", "resp"} for s in steps)
        assert all(set(s["req"]) == {"method", "path", "headers_present"} for s in steps)
    exp = [(s["req"]["method"], s["resp"]["status"]) for s in json.loads(
        (VECTORS / "transcripts" / "session_expiry_mid_upload.json").read_text())]
    assert exp[-4:] == [("PUT", 401), ("GET", 200), ("POST", 200), ("PUT", 202)]
