#!/usr/bin/env python3
"""Generate (or --check) the v1 cross-language conformance vectors for the node protocol.

Python is the reference. The Go pull-worker agent consumes the SAME files under
``conformance/v1/``, so their JSON shapes are a contract: a change to a shape or a value is a
new directory (``v2/``), never an edit of ``v1``.

Two kinds of file:

* GENERATED -- a pure function of fixed inputs and the reference code (``generate()``). Default
  mode rewrites them; ``--check`` compares them byte-for-byte and exits 1 on drift.
* COMMITTED ONCE -- ``node_certs/**`` (random serials/keys) and the ``python_signed`` half of
  ``ecdsa_cross.json`` (ECDSA is randomised). They are created only when absent (or by
  ``--regen-certs`` / ``--regen-signed``) and ``--check`` VERIFIES them with the reference
  functions instead of regenerating them.

Nothing under ``src/`` is touched; where a reference function reads the clock it is given an
explicit ``now`` or ``pki._now`` is patched here.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from blastbox import attest_wire  # noqa: E402
from blastbox.host import node_auth, node_renew, pki  # noqa: E402
from blastbox.worker.sandbox import nsjail, seatbelt  # noqa: E402
from blastbox.worker.sandbox.base import Mount, SandboxRequest  # noqa: E402

OUT = ROOT / "conformance" / "v1"

# ---------------------------------------------------------------------------
# Fixed inputs. Changing any of these changes the vectors: that is a v2.
# ---------------------------------------------------------------------------
SECRET = bytes(range(32))
OTHER_SECRET = bytes(range(32, 64))
T0 = 1_700_000_000.0                       # a fixed "now" for challenge / session / receipt vectors
WG_KEY = base64.b64encode(bytes(range(1, 33))).decode()

#: the frozen "now" certificate verdicts are evaluated at; recorded in node_certs/cases.json
CERT_NOW = datetime.datetime(2027, 6, 1, tzinfo=datetime.timezone.utc)
CERT_ISSUED = datetime.datetime(2026, 1, 1, 0, 5, tzinfo=datetime.timezone.utc)
CERT_DAYS = 3650                           # ~10 years: verdicts are stable for a decade


def _dumps(doc: Any) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# challenge.json  -- node_auth.challenge_for / _check_challenge
# ---------------------------------------------------------------------------
def classify_refusal(message: str) -> str:
    """Map a ClaimRefused message onto the vector verdict vocabulary."""
    if "malformed" in message:
        return "malformed"
    if "expired" in message:
        return "expired"
    if "not issued by this server" in message:
        return "foreign_or_wrong_scope"
    raise AssertionError(f"unclassified refusal: {message}")


def gen_challenge() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def add(scope: str, challenge: str, verify_at: float, verdict: str, *,
            minted_scope: str | None = None, expiry_repr: str | None = None) -> None:
        # The verdict is stated here INDEPENDENTLY and then proven against the reference.
        try:
            node_auth._check_challenge(challenge, scope, secret=SECRET, now=verify_at)
            got = "ok"
        except node_auth.ClaimRefused as exc:
            got = classify_refusal(str(exc))
        if got == "foreign_or_wrong_scope":
            got = verdict                  # the reference cannot tell these apart; see README
            assert verdict in ("foreign", "wrong_scope")
        assert got == verdict, (scope, challenge, got, verdict)
        cases.append({"scope": scope, "minted_scope": minted_scope, "expiry_repr": expiry_repr,
                      "challenge": challenge, "verify_at": verify_at, "verdict": verdict})

    for label, now, scope in (
        ("integral", T0, node_auth.SCOPE_CLAIM_NEXT),
        ("fractional", 1_700_000_000.123456, "job-7f3a"),
        ("unicode_scope", T0, "jöb-\U0001f600"),
        ("large_exponent", 1e22, node_auth.SCOPE_CLAIM_NEXT),   # repr is "1e+22"
    ):
        challenge = node_auth.challenge_for(scope, secret=SECRET, now=now)
        expiry_repr = challenge.partition(":")[0]
        if label == "large_exponent":
            assert expiry_repr == "1e+22"
        add(scope, challenge, now + 1.0, "ok", minted_scope=scope, expiry_repr=expiry_repr)
        # boundary: exactly the expiry is still valid, a hair after is not
        expiry = float(expiry_repr)
        if label != "large_exponent":      # there now+1 == expiry, so it would be a duplicate
            add(scope, challenge, expiry, "ok", minted_scope=scope, expiry_repr=expiry_repr)
        if label != "large_exponent":      # nextafter(1e22) is no longer a "+1 second" story
            add(scope, challenge, expiry + 0.001, "expired",
                minted_scope=scope, expiry_repr=expiry_repr)

    claim = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=SECRET, now=T0)
    er = claim.partition(":")[0]
    add("job-1", claim, T0 + 1, "wrong_scope",
        minted_scope=node_auth.SCOPE_CLAIM_NEXT, expiry_repr=er)
    add("", claim, T0 + 1, "wrong_scope", minted_scope=node_auth.SCOPE_CLAIM_NEXT, expiry_repr=er)

    foreign = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=OTHER_SECRET, now=T0)
    add(node_auth.SCOPE_CLAIM_NEXT, foreign, T0 + 1, "foreign",
        minted_scope=node_auth.SCOPE_CLAIM_NEXT, expiry_repr=foreign.partition(":")[0])
    # right MAC, tampered expiry (extends life): the MAC covers the expiry
    mac = claim.partition(":")[2]
    add(node_auth.SCOPE_CLAIM_NEXT, f"1700009999.0:{mac}", T0 + 1, "foreign",
        minted_scope=node_auth.SCOPE_CLAIM_NEXT, expiry_repr="1700009999.0")
    add(node_auth.SCOPE_CLAIM_NEXT, f"{er}:{mac.upper()}", T0 + 1, "foreign",
        minted_scope=node_auth.SCOPE_CLAIM_NEXT, expiry_repr=er)

    for bad in ("", "garbage", f"{er}:", f":{mac}", "notafloat:" + mac, f"{er}"):
        add(node_auth.SCOPE_CLAIM_NEXT, bad, T0 + 1, "malformed")
    # non-ASCII where a hex digest is expected must be a refusal, never a crash
    add(node_auth.SCOPE_CLAIM_NEXT, "1000.0:é", T0 + 1, "foreign")

    return {"secret_hex": SECRET.hex(), "ttl_s": node_auth.CHALLENGE_TTL_S, "cases": cases}


# ---------------------------------------------------------------------------
# signing_payload.json  -- node_auth.signing_payload
# ---------------------------------------------------------------------------
def gen_signing_payload() -> dict[str, Any]:
    cases = []
    chal = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=SECRET, now=T0)
    for challenge, scope, node_id in (
        (chal, node_auth.SCOPE_CLAIM_NEXT, "mac-mini-1"),
        (chal, "job-7f3a", "worker.a_b-2"),
        (node_auth.challenge_for("jöb-\U0001f600", secret=SECRET, now=T0),
         "jöb-\U0001f600", "n"),
        ("1.5:abc", "", "x"),
    ):
        cases.append({"challenge": challenge, "scope": scope, "node_id": node_id,
                      "payload_hex": node_auth.signing_payload(challenge, scope, node_id).hex()})
    return {"domain": "blastbox/node-claim/v1", "cases": cases}


# ---------------------------------------------------------------------------
# session_token.json  -- node_auth.issue_session / verify_session
# ---------------------------------------------------------------------------
def gen_session_token() -> dict[str, Any]:
    issue = []
    tokens: dict[str, str] = {}
    for node_id, now, ttl in (("mac-mini-1", T0, 600.0), ("worker.a_b-2", 1_700_000_000.5, 600.0),
                              ("n", T0, 1.0)):
        tok = node_auth.issue_session(node_id, secret=SECRET, now=now, ttl_s=ttl)
        tokens[node_id] = tok
        issue.append({"node_id": node_id, "now": now, "ttl_s": ttl, "token": tok})

    verify = []

    def add(token: str, at: float, verdict: str, node_id: str | None = None,
            secret: bytes = SECRET) -> None:
        try:
            got_id: str | None = node_auth.verify_session(token, secret=secret, now=at)
            got = "ok"
        except node_auth.ClaimRefused as exc:
            got_id = None
            got = ("malformed" if "malformed" in str(exc)
                   else "expired" if "expired" in str(exc) else "forged")
        assert (got, got_id) == (verdict, node_id), (token, got, got_id)
        verify.append({"token": token, "verify_at": at, "verdict": verdict, "node_id": node_id})

    t = tokens["mac-mini-1"]
    add(t, T0 + 1, "ok", "mac-mini-1")
    add(t, T0 + 600.0, "ok", "mac-mini-1")              # exactly the expiry is still valid
    add(t, T0 + 600.001, "expired")
    head, _, mac = t.rpartition(":")
    node, _, exp = head.rpartition(":")
    add(f"other-node:{exp}:{mac}", T0 + 1, "forged")     # MAC is bound to the node id
    add(f"{node}:{float(exp) + 1000!r}:{mac}", T0 + 1, "forged")   # ...and to the expiry
    add(f"{node}:{exp}:{mac[:-1]}0" if mac[-1] != "0" else f"{node}:{exp}:{mac[:-1]}1",
        T0 + 1, "forged")
    add(f"{node}:{exp}:{mac.upper()}", T0 + 1, "forged")
    # minted under ANOTHER secret, verified under the file's: a consumer only has secret_hex
    add(node_auth.issue_session("mac-mini-1", secret=OTHER_SECRET, now=T0), T0 + 1, "forged")
    for bad in ("", "x", "a:b", f"::{mac}", f"{node}::{mac}", f"{node}:{exp}:", f"{node}:nan1:{mac}"):
        add(bad, T0 + 1, "malformed")
    return {"secret_hex": SECRET.hex(), "ttl_s": node_auth.SESSION_TTL_S,
            "issue": issue, "verify": verify}


# ---------------------------------------------------------------------------
# receipt.json  -- node_auth.claim_receipt / check_claim_receipt
# ---------------------------------------------------------------------------
def gen_receipt() -> dict[str, Any]:
    issue = []
    for job_id, claim_id, node_id in (("job-1", "claim-a", "mac-mini-1"),
                                      ("jöb-\U0001f600", "cé", "worker.a_b-2"),
                                      ("", "", "n")):
        issue.append({"job_id": job_id, "claim_id": claim_id, "node_id": node_id,
                      "receipt": node_auth.claim_receipt(job_id, claim_id, node_id, secret=SECRET)})

    check = []

    def add(receipt: str, job_id: str, claim_id: str, node_id: str, verdict: str) -> None:
        try:
            node_auth.check_claim_receipt(receipt, job_id, claim_id, node_id, secret=SECRET)
            got = "ok"
        except node_auth.ClaimRefused:
            got = "refused"
        assert got == verdict
        check.append({"receipt": receipt, "job_id": job_id, "claim_id": claim_id,
                      "node_id": node_id, "verdict": verdict})

    first = issue[0]
    r = first["receipt"]
    add(r, "job-1", "claim-a", "mac-mini-1", "ok")
    add(r, "job-2", "claim-a", "mac-mini-1", "refused")        # another job
    add(r, "job-1", "claim-b", "mac-mini-1", "refused")        # another claim
    add(r, "job-1", "claim-a", "other-node", "refused")        # another node (receipt replay)
    add(r.upper(), "job-1", "claim-a", "mac-mini-1", "refused")
    add("", "job-1", "claim-a", "mac-mini-1", "refused")
    add("é", "job-1", "claim-a", "mac-mini-1", "refused")  # non-ASCII is a refusal, not a crash
    # field boundaries are NUL-separated: moving a byte between fields must change the MAC
    add(node_auth.claim_receipt("job-1c", "laim-a", "mac-mini-1", secret=SECRET),
        "job-1", "claim-a", "mac-mini-1", "refused")
    return {"secret_hex": SECRET.hex(), "issue": issue, "check": check}


# ---------------------------------------------------------------------------
# canonical_json.json  -- attest_wire.canonical
# ---------------------------------------------------------------------------
def gen_canonical_json() -> dict[str, Any]:
    ok_inputs: list[Any] = [
        {},
        [],
        {"a": {}, "b": []},
        None, True, False, 0, -1, "",
        {"b": 1, "a": 2, "c": {"z": 1, "y": [3, 2, 1], "x": None}},
        {"k": "emoji \U0001f600 \U0001f9d1‍\U0001f4bb"},                 # non-BMP + ZWJ
        {"ctl": "".join(chr(c) for c in range(0x20)) + "\x7f"},               # control chars
        {"html": "<script>alert('x') & \"y\"</script>"},                      # '<>&' and quotes
        {"quote": 'a"b\\c/d'},
        {"é": 1, "e": 2, "中文": 3, "Z": 4, "a": 5},             # unicode keys
        # UTF-16 order differs from code-point order here: U+FFFF vs U+1F600 (surrogate D83D)
        {"\U0001f600": 1, "￿": 2},
        {"big": 2**64, "neg": -(2**63), "huge": 10**30, "min": -(10**30)},
        [1, [2, [3, [4, {"k": [5, {}]}]]]],
        {"": "empty key", "a b": "space key", "a\nb": "newline key"},
        {"nested": {"b": {"d": 1, "c": 2}, "a": [{"y": 1, "x": 2}]}},
        "  ",                                                       # JS line separators
        {"utf8_edges": "\u007f\u0080\u07ff\u0800\uffff"},                    # UTF-8 length edges
    ]
    cases: list[dict[str, Any]] = [
        {"input": value, "canonical_hex": attest_wire.canonical(value).hex()}
        for value in ok_inputs
    ]
    for bad in ({"a": 1.5}, {"a": [1, {"b": 2.0}]}, [0.0], {"x": {"y": {"z": -0.5}}},
                1e100, [1e22], {"a": float("1e-7")}):
        try:
            attest_wire.canonical(bad)
        except TypeError:
            pass
        else:  # pragma: no cover - would mean the reference stopped rejecting floats
            raise AssertionError(f"canonical() accepted a float: {bad!r}")
        cases.append({"input_repr": repr(bad), "error": "float"})
    return {"cases": cases}


# ---------------------------------------------------------------------------
# sandbox/seatbelt/*.json  -- seatbelt.build_profile
# ---------------------------------------------------------------------------
_SEATBELT_CASES: dict[str, dict[str, Any]] = {
    "minimal": dict(exec_paths=["/opt/engine/bin/scan"], ro_paths=[], rw_paths=[],
                    accelerators=[], scratch=None, canary=None),
    "ro_and_scratch": dict(exec_paths=["/opt/engine/bin/scan"],
                           ro_paths=["/opt/engine/models", "/opt/engine/config"],
                           rw_paths=["/var/run/bb/scratch-1"], accelerators=[],
                           scratch="/var/run/bb/scratch-1", canary=None),
    "ane_gpu_canary": dict(exec_paths=["/opt/engine/bin/scan", "/opt/engine/bin/helper"],
                           ro_paths=["/opt/engine/models"],
                           rw_paths=["/var/run/bb/scratch-2", "/var/run/bb/out"],
                           accelerators=["gpu", "ane"], scratch="/var/run/bb/scratch-2",
                           canary="bb.canary.0123456789abcdef"),
    "nested_rw_roots": dict(exec_paths=["/opt/engine/bin/scan"], ro_paths=[],
                            rw_paths=["/var/run/bb/work", "/var/run/bb/work/sub/out"],
                            accelerators=[], scratch="/var/run/bb/work", canary=None),
    "ane_without_scratch": dict(exec_paths=["/opt/engine/bin/scan"], ro_paths=[], rw_paths=[],
                                accelerators=["ane"], scratch=None, canary="bb.canary.x"),
}


def gen_seatbelt() -> dict[str, dict[str, Any]]:
    out = {}
    for name, req in _SEATBELT_CASES.items():
        profile, params = seatbelt.build_profile(
            exec_paths=list(req["exec_paths"]), ro_paths=list(req["ro_paths"]),
            rw_paths=list(req["rw_paths"]), accelerators=frozenset(req["accelerators"]),
            scratch=req["scratch"], canary=req["canary"])
        out[name] = {"request": req, "profile": profile, "params": params}
    return out


# ---------------------------------------------------------------------------
# sandbox/nsjail/*.json  -- NsjailSandbox._build_argv
# ---------------------------------------------------------------------------
#: _build_argv probes the host (Path.exists / is_symlink) for system mounts. Those answers are
#: PINNED here to a merged-usr layout and recorded in every vector as ``host_pins`` so a
#: consumer can reproduce them. The object is built without __init__ (which probes binaries,
#: AppArmor and the policy file) and given fixed attributes instead.
_PIN_EXISTS = ["/bin", "/dev/null", "/dev/random", "/dev/urandom", "/dev/zero", "/etc",
               "/lib", "/lib64", "/sbin", "/usr"]
_PIN_SYMLINKS = ["/bin", "/lib", "/lib64", "/sbin"]
_NSJAIL_BIN = "/usr/local/bin/nsjail"
_NSJAIL_SECCOMP = "/etc/blastbox/seccomp.policy"
_NSJAIL_AA = ("/usr/bin/aa-exec", "blastbox-child")

_NSJAIL_CASES: dict[str, dict[str, Any]] = {
    "default": dict(argv=["/opt/engine/bin/scan", "--in", "/in/sample"], ro_mounts=[],
                    rw_mounts=[], limits={}, env={}, attach_apparmor=False, aa_exec=False),
    "mounts_env_limits": dict(
        argv=["/opt/engine/bin/scan"],
        ro_mounts=[{"source": "/srv/in", "target": "/in"},
                   {"source": "/opt/engine", "target": "/opt/engine"}],
        rw_mounts=[{"source": "/var/run/bb/out", "target": "/out"}],
        limits={"timeout_s": 30, "memory_bytes": 512 * 1024 * 1024,
                "tmpfs_bytes": 64 * 1024 * 1024},
        env={"LANG": "C", "HOME": "/out"}, attach_apparmor=False, aa_exec=False),
    "net_egress": dict(argv=["/opt/engine/bin/fetch"], ro_mounts=[], rw_mounts=[],
                       limits={"timeout_s": 10, "net_egress": True}, env={},
                       attach_apparmor=False, aa_exec=False),
    "apparmor_attached": dict(argv=["/opt/engine/bin/scan"], ro_mounts=[], rw_mounts=[],
                              limits={}, env={}, attach_apparmor=True, aa_exec=True),
    "apparmor_available_not_attached": dict(argv=["/opt/engine/bin/scan"], ro_mounts=[],
                                            rw_mounts=[], limits={}, env={},
                                            attach_apparmor=False, aa_exec=True),
}


@contextmanager
def _pinned_host() -> Iterator[None]:
    from pathlib import Path as _P

    def exists(self: _P, **_: Any) -> bool:
        return str(self) in _PIN_EXISTS

    def is_symlink(self: _P) -> bool:
        return str(self) in _PIN_SYMLINKS

    with mock.patch.object(_P, "exists", exists), mock.patch.object(_P, "is_symlink", is_symlink):
        yield


def _nsjail_argv(case: dict[str, Any]) -> list[str]:
    from blastbox.limits import Limits

    sb = object.__new__(nsjail.NsjailSandbox)
    sb._nsjail = _NSJAIL_BIN
    sb._seccomp_policy = Path(_NSJAIL_SECCOMP)
    sb._aa_exec = _NSJAIL_AA[0] if case["aa_exec"] else None
    sb._apparmor_profile = _NSJAIL_AA[1]
    req = SandboxRequest(
        argv=list(case["argv"]),
        ro_mounts=[Mount(Path(m["source"]), Path(m["target"])) for m in case["ro_mounts"]],
        rw_mounts=[Mount(Path(m["source"]), Path(m["target"])) for m in case["rw_mounts"]],
        limits=Limits(**case["limits"]), env=dict(case["env"]))
    with _pinned_host():
        return sb._build_argv(req, attach_apparmor=case["attach_apparmor"])


def gen_nsjail() -> dict[str, dict[str, Any]]:
    from blastbox.limits import Limits

    defaults = {k: getattr(Limits(), k) for k in ("timeout_s", "memory_bytes", "tmpfs_bytes",
                                                  "net_egress")}
    pins = {"nsjail": _NSJAIL_BIN, "seccomp_policy": _NSJAIL_SECCOMP,
            "aa_exec": _NSJAIL_AA[0], "apparmor_profile": _NSJAIL_AA[1],
            "paths_that_exist": _PIN_EXISTS, "paths_that_are_symlinks": _PIN_SYMLINKS,
            "minimal_env": nsjail._MINIMAL_ENV, "limit_defaults": defaults}
    out = {}
    for name, case in _NSJAIL_CASES.items():
        out[name] = {"request": case, "host_pins": pins, "argv": _nsjail_argv(case)}
    return out


# ---------------------------------------------------------------------------
# generate(): every deterministic file, relative path -> bytes
# ---------------------------------------------------------------------------
def generate() -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "challenge.json": _dumps(gen_challenge()),
        "signing_payload.json": _dumps(gen_signing_payload()),
        "session_token.json": _dumps(gen_session_token()),
        "receipt.json": _dumps(gen_receipt()),
        "canonical_json.json": _dumps(gen_canonical_json()),
        "README.md": README.encode(),
    }
    for name, doc in gen_seatbelt().items():
        files[f"sandbox/seatbelt/{name}.json"] = _dumps(doc)
    for name, doc in gen_nsjail().items():
        files[f"sandbox/nsjail/{name}.json"] = _dumps(doc)
    for name, doc in gen_claim_responses().items():
        files[f"claim_responses/{name}.json"] = _dumps(doc)
    for name, doc in gen_input_stream().items():
        files[f"input_stream/{name}.json"] = _dumps(doc)
    for name, doc in gen_writer().items():
        files[f"result_tars/writer/{name}.json"] = _dumps(doc)
    for name, doc in gen_envelope_seal().items():
        files[f"envelope_seal/{name}.json"] = _dumps(doc)
    for name, steps in gen_transcripts().items():
        files[f"transcripts/{name}.json"] = _dumps(steps)
    return files


# ---------------------------------------------------------------------------
# Committed-once: node certificates (spec 8)
# ---------------------------------------------------------------------------
def _pem_key(key: Any) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


_TEST_ONLY = (b"# TEST ONLY -- a conformance fixture. Never deploy, never trust this CA.\n")


def _node_like(ca: pki.CertAuthority, cn: str, public_key: Any, *, ekus: list[Any],
               info: bytes | None, not_before: datetime.datetime,
               not_after: datetime.datetime, eku_critical: bool = True) -> bytes:
    """A node-shaped cert with exactly the deviations a negative vector needs."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca._cert.subject).public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=eku_critical)
    )
    if info is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(pki.OID_NODE_INFO, info), critical=False)
    cert = builder.sign(ca._key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def _info(node_id: str, **over: Any) -> bytes:
    doc: dict[str, Any] = {"v": 2, "node_id": node_id, "engines": ["clippyshot"],
                           "tiers": ["warm"], "credentials": False}
    doc.update(over)
    return json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()


def _admit_claim(key: Any, node_id: str, scope: str = node_auth.SCOPE_CLAIM_NEXT) -> dict[str, Any]:
    at = CERT_NOW.timestamp()
    challenge = node_auth.challenge_for(scope, secret=SECRET, now=at)
    payload = node_auth.signing_payload(challenge, scope, node_id)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    else:
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return {"challenge": challenge, "scope": scope, "verify_at": at + 5,
            "signature_b64": _b64(sig)}


def build_node_certs() -> dict[str, bytes]:
    """Create the test CA + every cert. Random keys/serials: run ONCE and commit."""
    files: dict[str, bytes] = {}
    # The fixtures must outlive the 30-day production cap so their verdicts stay stable;
    # lift the cap for this in-memory build only.
    with mock.patch.object(pki, "_now", lambda: CERT_ISSUED), \
            mock.patch.object(pki, "MAX_NODE_CERT_DAYS", CERT_DAYS):
        ca = pki._generate_ca("Blastbox CONFORMANCE TEST CA (TEST ONLY)", days=CERT_DAYS)
        foreign = pki._generate_ca("Blastbox CONFORMANCE FOREIGN CA (TEST ONLY)", days=CERT_DAYS)
        files["ca.crt"] = ca.cert_pem
        files["ca.key"] = _TEST_ONLY + ca.key_pem
        nb = CERT_ISSUED - datetime.timedelta(minutes=5)
        na = CERT_ISSUED + datetime.timedelta(days=CERT_DAYS)
        grants = pki.NodeGrants(engines=("clippyshot", "redtusk"), tiers=("warm",),
                                credentials=False)

        def keyed(name: str, key: Any, cert: bytes, claim: bool = True) -> dict[str, Any]:
            files[f"{name}.crt"] = cert
            files[f"{name}.key"] = _TEST_ONLY + _pem_key(key)
            return {"cert": f"{name}.crt", "key": f"{name}.key"}

        cases: list[dict[str, Any]] = []

        def case(name: str, key: Any, cert: bytes, verdict: str, node_id: str, why: str,
                 *, admit: str | None = None, claim_node: str | None = None) -> None:
            entry = {"name": name, "node_id": node_id, "verdict": verdict, "why": why,
                     **keyed(name, key, cert)}
            entry["admit"] = ({"verdict": admit, **_admit_claim(key, claim_node or node_id)}
                              if admit else None)
            cases.append(entry)

        # positives: the reference issuer itself
        k1 = ec.generate_private_key(ec.SECP256R1())
        case("v1_with_wg", k1, ca._build_node_cert("node-v1", k1.public_key(), WG_KEY, grants,
                                                    CERT_DAYS).public_bytes(serialization.Encoding.PEM),
             "ok", "node-v1", "node-info v1: WireGuard key present", admit="ok")
        k2 = ec.generate_private_key(ec.SECP256R1())
        case("v2_without_wg", k2, ca._build_node_cert("node-v2", k2.public_key(), None, grants,
                                                       CERT_DAYS).public_bytes(serialization.Encoding.PEM),
             "ok", "node-v2", "node-info v2: no WireGuard key", admit="ok")

        # negatives
        def neg(name: str, node_id: str, why: str, *, cn: str | None = None,
                ekus: list[Any] | None = None, info: bytes | None | str = "default",
                nbf: datetime.datetime = nb, naf: datetime.datetime = na,
                key: Any = None, signer: pki.CertAuthority = ca,
                admit: str | None = None) -> None:
            key = key or ec.generate_private_key(ec.SECP256R1())
            body = _info(node_id) if info == "default" else info
            assert body is None or isinstance(body, bytes)
            cert = _node_like(signer, cn or node_id, key.public_key(),
                              ekus=ekus if ekus is not None else [pki.OID_NODE_AUTH],
                              info=body, not_before=nbf, not_after=naf)
            case(name, key, cert, "refused", node_id, why, admit=admit)

        neg("wrong_eku", "node-weku", "EKU is serverAuth only, not the node EKU",
            ekus=[ExtendedKeyUsageOID.SERVER_AUTH])
        neg("client_auth_eku", "node-client", "EKU is clientAuth only (a dispatcher-style cert)",
            ekus=[ExtendedKeyUsageOID.CLIENT_AUTH])
        neg("cn_mismatch", "node-real", "subject CN differs from node_id in node-info",
            cn="node-spoofed")
        neg("expired", "node-old", "not_after is before the frozen now",
            nbf=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
            naf=datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc))
        neg("missing_node_info", "node-noinfo", "no node-info extension", info=None)
        neg("garbled_node_info", "node-garbled", "node-info is not JSON", info=b"\xff\x00not json")
        neg("unsupported_version", "node-v3", "node-info version 3 is unknown",
            info=_info("node-v3", v=3))
        neg("foreign_ca", "node-foreign", "signed by a CA that is not the trust anchor",
            signer=foreign)

        # RSA key: node_identity accepts the certificate; the claim is refused (EC only)
        rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _node_like(ca, "node-rsa", rk.public_key(), ekus=[pki.OID_NODE_AUTH],
                          info=_info("node-rsa"), not_before=nb, not_after=na)
        entry = {"name": "rsa_key", "node_id": "node-rsa", "verdict": "ok",
                 "why": "RSA public key: identity verifies but admit_identity refuses it",
                 **keyed("rsa_key", rk, cert)}
        entry["admit"] = {"verdict": "refused", **_admit_claim(rk, "node-rsa")}
        cases.append(entry)

        # right certificate, signature by a different key
        wk = ec.generate_private_key(ec.SECP256R1())
        for entry in cases:
            if entry["name"] == "v1_with_wg":
                at = CERT_NOW.timestamp()
                chal = node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT, secret=SECRET, now=at)
                bad_sig = wk.sign(node_auth.signing_payload(chal, node_auth.SCOPE_CLAIM_NEXT,
                                                            "node-v1"), ec.ECDSA(hashes.SHA256()))
                cases.append({**entry, "name": "v1_wrong_key_signature", "verdict": "ok",
                              "why": "valid cert, claim signed by someone else's key",
                              "admit": {"verdict": "refused", "challenge": chal,
                                        "scope": node_auth.SCOPE_CLAIM_NEXT,
                                        "verify_at": at + 5, "signature_b64": _b64(bad_sig)}})
                break

    doc = {"now": CERT_NOW.isoformat(), "now_epoch": CERT_NOW.timestamp(),
           "secret_hex": SECRET.hex(), "ca": "ca.crt", "cases": cases,
           "warning": "TEST ONLY fixtures; verdict = node_identity, admit = admit_identity"}
    files["cases.json"] = _dumps(doc)
    files["README.md"] = (b"TEST ONLY. These keys and this CA exist so two implementations can "
                          b"agree on certificate verdicts. Never deploy them.\n")
    return files


#: (name, node_id, verdict, why, _node_like overrides) -- appended after the first commit
ADDED_CERT_CASES: list[tuple[str, str, str, str, dict[str, Any]]] = [
    ("node_plus_client_auth_eku", "node-dual", "refused",
     "node EKU plus clientAuth: a node cert must never double as a transport cert",
     {"ekus": [pki.OID_NODE_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]}),
    ("node_eku_not_critical", "node-noncrit", "refused",
     "node EKU present but the extension is not marked critical",
     {"eku_critical": False}),
    ("node_plus_server_auth_eku", "node-srv", "refused",
     "node EKU plus serverAuth: a node cert must never double as a transport cert",
     {"ekus": [pki.OID_NODE_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]}),
    ("node_plus_any_eku", "node-any", "refused",
     "node EKU plus anyExtendedKeyUsage",
     {"ekus": [pki.OID_NODE_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]}),
    ("v2_with_wg", "node-v2wg", "ok",
     "node-info v2 MAY carry a WireGuard key; when present it is validated",
     {"info_over": {"wg": WG_KEY}}),
    ("v2_bad_wg", "node-v2badwg", "refused",
     "node-info v2 with a wg that is not a 32-byte base64 key",
     {"info_over": {"wg": "not-a-key"}}),
    ("v1_without_wg", "node-v1nowg", "refused",
     "node-info v1 requires a WireGuard key",
     {"info_over": {"v": 1}}),
]


def add_node_cert_negatives(certs: Path) -> bool:
    """Append cases added AFTER the first commit, signed by the EXISTING test CA.

    Additive only: nothing already committed is regenerated, so a Go agent's recorded
    verdicts and ``go_signed`` stay valid. Each case is added once, when missing.
    Returns True if ``cases.json`` changed.
    """
    doc = json.loads((certs / "cases.json").read_text())
    names = {c["name"] for c in doc["cases"]}
    missing = [c for c in ADDED_CERT_CASES if c[0] not in names]
    if not missing:
        return False
    ca_cert = x509.load_pem_x509_certificate((certs / "ca.crt").read_bytes())
    raw = (certs / "ca.key").read_bytes()
    ca_key = serialization.load_pem_private_key(
        b"-----BEGIN" + raw.partition(b"-----BEGIN")[2], password=None)   # skip TEST ONLY line
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)
    ca = pki.CertAuthority(ca_cert, ca_key)
    nb = CERT_ISSUED - datetime.timedelta(minutes=5)
    na = CERT_ISSUED + datetime.timedelta(days=CERT_DAYS)
    for name, node_id, verdict, why, over in missing:
        key = ec.generate_private_key(ec.SECP256R1())
        over = dict(over)
        info = _info(node_id, **over.pop("info_over", {}))
        cert = _node_like(ca, node_id, key.public_key(),
                          ekus=over.pop("ekus", [pki.OID_NODE_AUTH]), info=info,
                          not_before=nb, not_after=na, **over)
        (certs / f"{name}.crt").write_bytes(cert)
        (certs / f"{name}.key").write_bytes(_TEST_ONLY + _pem_key(key))
        doc["cases"].append({
            "name": name, "node_id": node_id, "verdict": verdict, "why": why,
            "cert": f"{name}.crt", "key": f"{name}.key",
            "admit": {"verdict": verdict, **_admit_claim(key, node_id)}})
    (certs / "cases.json").write_bytes(_dumps(doc))
    return True


# ---------------------------------------------------------------------------
# Committed-once: ecdsa_cross.json python_signed
# ---------------------------------------------------------------------------
def build_ecdsa_python_signed() -> list[dict[str, str]]:
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    out = []
    for scope, node_id in ((node_auth.SCOPE_CLAIM_NEXT, "mac-mini-1"), ("job-7f3a", "node-v1"),
                           ("jöb-\U0001f600", "n")):
        chal = node_auth.challenge_for(scope, secret=SECRET, now=T0)
        sig = node_auth.sign_claim(_pem_key(key), chal, scope, node_id)
        out.append({"public_key_pem": pub_pem,
                    "payload_hex": node_auth.signing_payload(chal, scope, node_id).hex(),
                    "signature_b64": _b64(sig)})
    return out


# ---------------------------------------------------------------------------
# Committed-once: renew_proof.json  -- node_renew.renew_payload / sign_renew_proof
# ---------------------------------------------------------------------------
RENEW_PAYLOAD_CASES: list[tuple[str, str, int]] = [
    ("n1", "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
     1_700_000_000),
    ("mac-mini-1",                                      # CRLF: hashed exactly as sent
     "-----BEGIN CERTIFICATE REQUEST-----\r\nAAAA\r\n-----END CERTIFICATE REQUEST-----\r\n", 0),
    ("worker.a_b-2", "csr with a trailing space ", 4_102_444_800),
    ("n", "", 1),                                       # empty CSR still hashes
    ("node-v2", "x\u00e9\U0001f600", 1_700_000_300),  # UTF-8 before hashing
]


def _bump_r(sig: bytes) -> bytes:
    """Well-formed DER whose ``r`` is off by one: must fail verification, not parsing."""
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    r, s_ = decode_dss_signature(sig)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return encode_dss_signature((r % (order - 1)) + 1 if (r % (order - 1)) + 1 != r else 1, s_)


def build_renew_proof(go_signed: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Payload cases (deterministic) plus python_signed proofs (random key: committed once)."""
    payload_cases = [{"node_id": n, "csr_pem": c, "issued_at": t,
                      "payload_hex": node_renew.renew_payload(n, c, t).hex()}
                     for n, c, t in RENEW_PAYLOAD_CASES]
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    csr_key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node-v2")]))
           .sign(csr_key, hashes.SHA256())).public_bytes(serialization.Encoding.PEM).decode()
    signed = []
    for node_id, csr_pem, at in (("node-v2", csr, 1_700_000_000),
                                 ("mac-mini-1", RENEW_PAYLOAD_CASES[1][1], 0)):
        sig = node_renew.sign_renew_proof(key, node_id, csr_pem, at)
        signed.append({"node_id": node_id, "csr_pem": csr_pem, "issued_at": at,
                       "public_key_pem": pub_pem,
                       "payload_hex": node_renew.renew_payload(node_id, csr_pem, at).hex(),
                       "signature_b64": sig})
    tampered = dict(signed[0])
    tampered["signature_b64"] = _b64(_bump_r(base64.b64decode(signed[0]["signature_b64"])))
    tampered["valid"] = False
    signed.append(tampered)
    return {**_renew_proof_constants(),
            "payload_cases": payload_cases, "python_signed": signed,
            "go_signed": go_signed or []}


def _renew_proof_constants() -> dict[str, Any]:
    return {"domain": node_renew.RENEW_PROOF_DOMAIN.decode(),
            "payload": RENEW_PAYLOAD_DESCRIPTION,
            "issued_at_unit": "unix seconds (integer)",
            "max_skew_ingress_s": node_renew.RENEW_PROOF_MAX_SKEW_S,
            "max_age_ca_s": node_renew.RENEW_PROOF_MAX_AGE_S}


RENEW_PAYLOAD_DESCRIPTION = ("domain || 0x00 || node_id || 0x00 || sha256hex(utf8(csr_pem)) || "
                             "0x00 || decimal(issued_at)")


def verify_renew_proof_doc(out: Path) -> list[str]:
    problems: list[str] = []
    try:
        doc = json.loads((out / "renew_proof.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"renew_proof.json unreadable: {exc}"]
    for k, v in _renew_proof_constants().items():
        if doc.get(k) != v:
            problems.append(f"renew_proof.json: {k} differs from the Python reference")
    if not any(e.get("valid", True) for e in doc.get("python_signed", [])):
        problems.append("renew_proof.json: no valid python_signed proof")
    want = [(n, c, t) for n, c, t in RENEW_PAYLOAD_CASES]
    if [(c["node_id"], c["csr_pem"], c["issued_at"]) for c in doc.get("payload_cases", [])] != want:
        problems.append("renew_proof.json: payload_cases differ from the generator's inputs")
    if not any(e.get("valid") is False for e in doc.get("python_signed", [])):
        problems.append("renew_proof.json: no negative (valid: false) entry")
    for listname in ("payload_cases", "python_signed", "go_signed"):
        for e in doc.get(listname, []):
            try:
                real = node_renew.renew_payload(e["node_id"], e["csr_pem"],
                                                e["issued_at"]).hex()
                if listname != "payload_cases":
                    e["public_key_pem"], e["signature_b64"]  # noqa: B018 - must exist
                e["payload_hex"]  # noqa: B018 - must exist
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                problems.append(f"renew_proof.json: a malformed {listname} entry ({exc!r})")
                continue
            if real != e["payload_hex"]:
                problems.append(f"renew_proof.json: a {listname} payload_hex is not "
                                "renew_payload of its inputs")
            if listname == "payload_cases":
                continue
            expect_valid = e.get("valid", True)
            if listname == "go_signed" and not expect_valid:
                problems.append("renew_proof.json: go_signed entries must verify")
            pub = serialization.load_pem_public_key(e["public_key_pem"].encode())
            try:
                assert isinstance(pub, ec.EllipticCurvePublicKey)
                pub.verify(base64.b64decode(e["signature_b64"]),
                           bytes.fromhex(e["payload_hex"]), ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:  # noqa: BLE001 - any verify failure is "does not verify"
                ok = False
            if ok != expect_valid:
                problems.append(f"renew_proof.json: a {listname} signature verdict is wrong")
    return problems


def add_ecdsa_negative(cross: Path) -> bool:
    """Append a tampered-signature entry (``"valid": false``) if none is committed yet.

    Additive: existing entries are untouched. The signature is over the REAL payload with
    ``r`` bumped, so it is well-formed DER that must fail verification (not a parse error).
    """
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    doc = json.loads(cross.read_text())
    if any(e.get("valid") is False for e in doc["python_signed"]):
        return False
    key = ec.generate_private_key(ec.SECP256R1())
    scope, node_id = node_auth.SCOPE_CLAIM_NEXT, "node-tampered"
    chal = node_auth.challenge_for(scope, secret=SECRET, now=T0)
    payload = node_auth.signing_payload(chal, scope, node_id)
    r, s_ = decode_dss_signature(key.sign(payload, ec.ECDSA(hashes.SHA256())))
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    bad = encode_dss_signature((r % (order - 1)) + 1 if (r % (order - 1)) + 1 != r else 1, s_)
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    doc["python_signed"].append({
        "valid": False, "challenge": chal, "scope": scope, "node_id": node_id,
        "public_key_pem": pub_pem, "payload_hex": payload.hex(), "signature_b64": _b64(bad)})
    cross.write_bytes(_dumps(doc))
    return True


# ---------------------------------------------------------------------------
# Data plane (PR B): claim responses, input stream, result tars, envelope seal, transcripts
# ---------------------------------------------------------------------------
DP_SAMPLE = b"sample-bytes"
DP_SAMPLE_SHA = hashlib.sha256(DP_SAMPLE).hexdigest()
DP_WG = "A" * 42 + "B="
SESSION_HDR = "x-blastbox-node-session"


def tree_to_json(tree: dict[str, bytes]) -> dict[str, str]:
    """``metadata.json`` as UTF-8 text, every other file as hex."""
    return {k: (v.decode() if k == "metadata.json" else v.hex()) for k, v in tree.items()}


def tree_from_json(doc: dict[str, str]) -> dict[str, bytes]:
    return {k: (v.encode() if k == "metadata.json" else bytes.fromhex(v)) for k, v in doc.items()}


def go_writer_tar(tree: dict[str, bytes]) -> bytes:
    """Byte-for-byte the output of agent/internal/runner/tarw.go (Go ``archive/tar``).

    USTAR, regular files only, paths sorted bytewise, mode 0644, uid/gid 0, empty uname/gname,
    mtime 0, no directory entries, 512-byte blocks and the two-block end marker with NO padding
    to a 10240-byte record (Go's writer does not pad; Python's ``tarfile`` does by default).
    Go writes devmajor/devminor as ``0000000\\0``; Python leaves them NUL, so they are pinned
    and the checksum is recomputed (same trick as that branch's testdata/tarcheck.py).
    """
    out = bytearray()
    for name in sorted(tree, key=lambda s: s.encode()):
        data = tree[name]
        ti = tarfile.TarInfo(name)
        ti.size, ti.mode, ti.uid, ti.gid = len(data), 0o644, 0, 0
        ti.uname, ti.gname, ti.mtime = "", "", 0
        ti.type = tarfile.REGTYPE
        h = bytearray(ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape"))
        h[329:337] = b"0000000\0"
        h[337:345] = b"0000000\0"
        h[148:156] = b"        "
        h[148:156] = b"%06o\0 " % sum(h)
        out += h
        out += data + b"\0" * (-len(data) % 512)
    out += b"\0" * 1024
    return bytes(out)


def _meta(**over: Any) -> bytes:
    doc = {"engine": "clamav", "status": "ok", "input_sha256": DP_SAMPLE_SHA,
           "detected": {"label": "bin", "mime": "application/octet-stream",
                        "confidence": 0.9, "source": "magika"},
           "artifacts": [], "warnings": [],
           "payload": {"_type": "extracted_text", "text": "hi", "char_count": 2}}
    doc.update(over)
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


WRITER_TREES: dict[str, dict[str, bytes]] = {
    "minimal": {"metadata.json": b'{"a":1}'},
    "empty_file": {"metadata.json": b"{}", "artifacts/empty": b""},
    "sorted_bytewise": {"metadata.json": b"{}", "B.txt": b"", "art/z.bin": b"zz",
                        "art/a.txt": b"hello\n", "a.txt": b"lower"},
    "block_boundaries": {"metadata.json": b"{}", "artifacts/b511": b"x" * 511,
                         "artifacts/b512": b"y" * 512, "artifacts/b513": b"z" * 513},
    "binary_bytes": {"metadata.json": b"{}", "artifacts/all.bin": bytes(range(256))},
    "ustar_prefix_split": {"metadata.json": b'{"a":1}',
                           "a-" + "n" * 90 + "/" + "m" * 90: b"split into ustar prefix"},
    "deep_path": {"metadata.json": b"{}", "deep/er/path/f": b"x" * 1000},
    "unicode_name": {"metadata.json": b"{}", "artifacts/café.txt": b"utf8 name"},
}


def gen_writer() -> dict[str, dict[str, Any]]:
    out = {}
    for name, tree in WRITER_TREES.items():
        tar = go_writer_tar(tree)
        out[name] = {"tree": tree_to_json(tree), "tar_bytes": len(tar),
                     "tar_sha256": hashlib.sha256(tar).hexdigest()}
    return out


# ---- result_tars: adversarial, committed once ------------------------------------------
def _tar(members: list[Any], *, metadata: bool = True, fmt: int = tarfile.PAX_FORMAT) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        if metadata:
            members = [("metadata.json", b"{}")] + list(members)
        for member in members:
            if isinstance(member, tarfile.TarInfo):
                tf.addfile(member)
                continue
            name, content = member
            if isinstance(content, tarfile.TarInfo):
                tf.addfile(content)
                continue
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


def _special(name: str, typ: bytes, link: str = "") -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = link
    return ti


def _dir(name: str) -> tarfile.TarInfo:
    return _special(name, tarfile.DIRTYPE)


def _gzip(b: bytes) -> bytes:
    return gzip.compress(b, mtime=0)


#: (case, server_verdict, reason, builder). Verdicts are re-derived from the REAL
#: ``node_results.vet_tar`` + ``_safe_extract_tar`` by ``--check`` -- this table only seeds
#: the first commit, it is not trusted afterwards.
RESULT_TAR_CASES: list[tuple[str, str, str, Any]] = [
    ("ok_minimal", "accepted", "metadata.json only",
     lambda: go_writer_tar({"metadata.json": b"{}"})),
    ("ok_artifacts", "accepted", "metadata plus nested artifacts, as the Go writer emits",
     lambda: go_writer_tar(WRITER_TREES["sorted_bytewise"])),
    ("ok_directory_entries", "accepted", "directory members are tolerated",
     lambda: _tar([_dir("artifacts"), ("artifacts/a.bin", b"\x00\x01")])),
    ("ok_dot_slash_names", "accepted", "a leading ./ is normalised away",
     lambda: _tar([("./artifacts/a.bin", b"x")])),
    ("bad_dotdot", "rejected", "parent reference in a member path",
     lambda: _tar([("../evil", b"x")])),
    ("bad_nested_dotdot", "rejected", "parent reference inside a path",
     lambda: _tar([("a/../../evil", b"x")])),
    ("bad_absolute", "rejected", "absolute member path",
     lambda: _tar([("/etc/evil", b"x")])),
    ("bad_symlink", "rejected", "symlink member",
     lambda: _tar([("l", _special("l", tarfile.SYMTYPE, "/etc/passwd"))])),
    ("bad_hardlink", "rejected", "hardlink member",
     lambda: _tar([("h", _special("h", tarfile.LNKTYPE, "metadata.json"))])),
    ("bad_chardev", "rejected", "character device member",
     lambda: _tar([("d", _special("d", tarfile.CHRTYPE))])),
    ("bad_fifo", "rejected", "FIFO member",
     lambda: _tar([("f", _special("f", tarfile.FIFOTYPE))])),
    ("bad_duplicate", "rejected", "the same path twice",
     lambda: _tar([("x", b"1"), ("x", b"2")])),
    ("bad_duplicate_via_dot", "rejected", "the same path twice, one spelled with ./",
     lambda: _tar([("x", b"1"), ("./x", b"2")])),
    ("bad_missing_metadata", "rejected", "no root metadata.json",
     lambda: _tar([("a", b"x")], metadata=False)),
    ("bad_metadata_in_subdir", "rejected", "metadata.json not at the root",
     lambda: _tar([("sub/metadata.json", b"{}")], metadata=False)),
    ("bad_metadata_is_dir", "rejected", "metadata.json is a directory",
     lambda: _tar([("m", _dir("metadata.json"))], metadata=False)),
    ("bad_backslash", "rejected", "backslash in a member path",
     lambda: _tar([("a\\b", b"x")])),
    ("bad_garbage", "rejected", "not a tar at all", lambda: b"not a tar at all" * 100),
    ("bad_empty_body", "rejected", "empty body", lambda: b""),
    ("bad_gzip", "rejected", "compressed tar (the stream must be a plain tar)",
     lambda: _gzip(_tar([]))),
    ("bad_truncated", "rejected", "tar cut mid-member",
     lambda: _tar([("big", b"x" * 4096)])[:1024 + 700]),
]


def _result_limits() -> Any:
    from blastbox.limits import Limits

    return Limits()


def server_verdict_for_tar(data: bytes) -> str:
    """accepted / rejected, by the SAME two steps the PUT route runs (quarantine extraction)."""
    from blastbox.host import node_results as nr
    from blastbox.host.runtime.remote_http import _safe_extract_tar

    lim = _result_limits()
    max_members = lim.max_artifacts + 64
    try:
        fh = io.BytesIO(data)
        nr.vet_tar(fh, max_members=max_members, max_total_bytes=lim.max_total_artifact_bytes)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            out.mkdir()
            _safe_extract_tar(fh, out, max_total_bytes=lim.max_total_artifact_bytes,
                              max_members=max_members,
                              max_metadata_bytes=lim.max_metadata_bytes)
    except Exception:  # noqa: BLE001 - any fault is "refused", exactly as the route treats it
        return "rejected"
    return "accepted"


def write_result_tars(out: Path) -> None:
    """Committed once: written only when absent, with the verdict the reference returns now."""
    d = out / "result_tars"
    for case, _seed, reason, build in RESULT_TAR_CASES:
        tar_path = d / f"{case}.tar"
        if tar_path.exists():
            continue
        data = build()
        verdict = server_verdict_for_tar(data)
        _write(out, f"result_tars/{case}.tar", data)
        _write(out, f"result_tars/{case}.json", _dumps({
            "server_verdict": verdict, "reason": reason,
            "http_status": 202 if verdict == "accepted" else 422,
            "tar_sha256": hashlib.sha256(data).hexdigest()}))


def verify_result_tars(out: Path = OUT) -> list[str]:
    problems: list[str] = []
    d = out / "result_tars"
    for case, seed, _reason, _build in RESULT_TAR_CASES:
        try:
            data = (d / f"{case}.tar").read_bytes()
            doc = json.loads((d / f"{case}.json").read_text())
        except (OSError, ValueError) as exc:
            problems.append(f"result_tars/{case}: unreadable ({exc})")
            continue
        if doc.get("tar_sha256") != hashlib.sha256(data).hexdigest():
            problems.append(f"result_tars/{case}: tar_sha256 does not match the .tar")
        got = server_verdict_for_tar(data)
        if got != doc.get("server_verdict"):
            problems.append(f"result_tars/{case}: vet+extract says {got}, vector says "
                            f"{doc.get('server_verdict')}")
        if doc.get("server_verdict") != seed:
            problems.append(f"result_tars/{case}: verdict {doc.get('server_verdict')} differs "
                            f"from the case's designed verdict {seed}")
    return problems


# ---- the real app, driven with the TestClient ------------------------------------------
class _Rig:
    """A real ``register_node_claim_routes`` app with a throwaway PKI, store and job root."""

    def __init__(self, root: Path) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from blastbox.host.ingress.node_claim import register_node_claim_routes
        from blastbox.host.jobs.memory import InMemoryJobStore

        self.root = root
        self.pki = root / "pki"
        ca = pki.ensure_ca(self.pki)
        ca.issue_node("alpha", wg_pubkey=DP_WG, grants=pki.NodeGrants(
            engines=("clamav",), tiers=("socks", "inetsim"), credentials=True)
        ).write(self.pki, "node-alpha")
        ca.issue_node("beta", wg_pubkey=DP_WG, grants=pki.NodeGrants(
            engines=("boxjs",))).write(self.pki, "node-beta")
        self.store = InMemoryJobStore()
        self.jobs = root / "jobs"
        app = FastAPI()
        assert register_node_claim_routes(app, job_store=self.store, pki_dir=self.pki,
                                          job_root=self.jobs) is True
        self.client = TestClient(app)

    def submit(self, *, job_id: str = "job-1", spool: bytes | None = DP_SAMPLE,
               params: dict[str, Any] | None = None) -> None:
        from blastbox.host.jobs.base import Job, JobStatus

        self.store.create(Job(job_id=job_id, engine="clamav", filename="sample.bin",
                              status=JobStatus.QUEUED, created_at=1.0,
                              input_sha256=DP_SAMPLE_SHA, params=params or {}))
        if spool is not None:
            (self.jobs / job_id / "input").mkdir(parents=True)
            (self.jobs / job_id / "input" / "sample.bin").write_bytes(spool)

    def challenge(self) -> Any:
        return self.client.get("/v1/nodes/challenge")

    def session(self, who: str, challenge: str) -> Any:
        key = (self.pki / f"node-{who}.key").read_bytes()
        sig = _b64(node_auth.sign_claim(key, challenge, node_auth.SCOPE_CLAIM_NEXT, who))
        return self.client.post("/v1/nodes/session", json={
            "cert_pem": (self.pki / f"node-{who}.crt").read_text(),
            "challenge": challenge, "signature": sig})

    def token(self, who: str) -> str:
        return self.session(who, self.challenge().json()["challenge"]).json()["token"]


@contextmanager
def _dp_rig(env: dict[str, str] | None = None) -> Iterator[_Rig]:
    import os

    with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ):
        for k in [k for k in os.environ if k.startswith("BLASTBOX_")]:
            del os.environ[k]
        os.environ["BLASTBOX_NODE_RESULTS_DIR"] = str(Path(td) / "results")
        os.environ.update(env or {})
        yield _Rig(Path(td))


def _normalise_claim(body: Any) -> Any:
    if not isinstance(body, dict) or "job" not in body:
        return body
    body = json.loads(json.dumps(body))
    body["job"]["claim_id"] = "<CLAIM_ID>"
    body["job"]["started_at"] = "<STARTED_AT>"
    body["receipt"] = "<RECEIPT>"
    return body


def _claim_vec(r: Any, decision: str, description: str, **extra: Any) -> dict[str, Any]:
    body = _normalise_claim(r.json() if r.content else None)
    return {"description": description, "status": r.status_code, "body": body,
            "decision": decision, **extra}


def gen_claim_responses() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def claim(rig: _Rig, who: str = "alpha", token: str | None = None) -> Any:
        return rig.client.post("/v1/nodes/claim", json={"engine": "clamav"},
                               headers={SESSION_HDR: token or rig.token(who)})

    with _dp_rig() as rig:
        rig.submit()
        out["run_basic"] = _claim_vec(claim(rig), "run",
                                      "network none, input spooled on the ingress host")
    with _dp_rig() as rig:
        rig.submit(params={"scan": "fast", "depth": 3, "BLASTBOX_SECRET": "x"})
        out["run_params_filtered"] = _claim_vec(
            claim(rig), "run", "BLASTBOX_* params are stripped from run.params; job.params keeps them")
    with _dp_rig() as rig:
        rig.submit(spool=None)
        out["run_input_bytes_unknown"] = _claim_vec(
            claim(rig), "run", "input not spooled here: run.input.bytes is null, size is "
                               "taken from the stream's headers")
    for label, driver in (("socks", "socks"), ("inetsim", "inetsim")):
        exit_spec = "exit=socks,host=127.0.0.1,port=1080" if driver == "socks" else "exit=inetsim"
        with _dp_rig({"BLASTBOX_NETPOLICY_EGRESS": exit_spec,
                      "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "egress"}) as rig:
            rig.submit()
            out[f"release_network_{label}"] = _claim_vec(
                claim(rig), "release_unstarted",
                f"run.network is {driver!r}: this agent cannot enforce it, so it must release "
                "the job unstarted (never run it with open egress)")
    # The reference has no driver literally named "sinkhole"; the Go agent treats ANY
    # run.network other than "none" as unenforceable, so pin the spelling the brief names.
    with _dp_rig({"BLASTBOX_NETPOLICY_EGRESS": "exit=inetsim",
                  "BLASTBOX_ENGINE_CLAMAV_NETPOLICY": "egress"}) as rig:
        rig.submit()
        vec = _claim_vec(claim(rig), "release_unstarted",
                         "SYNTHETIC: the real run body from release_network_inetsim with "
                         "network rewritten to 'sinkhole'", synthetic=True)
        vec["body"]["run"]["network"] = "sinkhole"
        out["release_network_sinkhole"] = vec
    with _dp_rig() as rig:
        out["idle_no_work"] = _claim_vec(claim(rig), "idle", "204: entitled, nothing to run")
    with _dp_rig() as rig:
        rig.submit()
        tok = node_auth.issue_session(
            "alpha", secret=node_auth.resolve_claim_secret(rig.store, rig.pki, pepper=None),
            now=time.time() - node_auth.SESSION_TTL_S - 5)
        out["rehandshake_expired_session"] = _claim_vec(
            claim(rig, token=tok), "rehandshake", "expired session: 401, open a new session")
    with _dp_rig() as rig:
        out["rehandshake_no_session"] = _claim_vec(
            rig.client.post("/v1/nodes/claim", json={"engine": "clamav"}), "rehandshake",
            "no session header: 401")
    with _dp_rig() as rig:
        rig.submit()
        out["refused_engine_not_granted"] = _claim_vec(
            claim(rig, "beta"), "refused",
            "403: node beta is not granted clamav; do NOT re-handshake, back off")
    return out


# ---- input_stream ----------------------------------------------------------------------
def judge_input(vec: dict[str, Any]) -> str:
    """The reference verdict for an input stream: what the Go agent MUST decide."""
    if 300 <= vec["status"] < 400:
        return "abort_redirect"
    if vec["status"] != 200:
        return "abort_status"
    body = bytes.fromhex(vec["body_hex"])
    exp = vec["expected"]
    headers = {k.lower(): v for k, v in vec["headers"].items()}
    declared = int(headers["content-length"]) if "content-length" in headers else None
    want = exp["bytes"] if exp["bytes"] is not None else declared
    if want is not None and want > vec["max_input"]:
        return "abort_long"
    if len(body) > (want if want is not None else vec["max_input"]):
        return "abort_long"
    if want is not None and len(body) < want:
        return "abort_short"
    if headers.get("x-blastbox-input-sha256") != exp["sha256"]:
        return "abort_hash"
    if hashlib.sha256(body).hexdigest() != exp["sha256"]:
        return "abort_hash"
    return "accept"


def gen_input_stream() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with _dp_rig() as rig:
        rig.submit()
        tok = rig.token("alpha")
        got = rig.client.post("/v1/nodes/claim", json={"engine": "clamav"},
                              headers={SESSION_HDR: tok}).json()
        hdr = {SESSION_HDR: tok, "x-blastbox-claim-id": got["job"]["claim_id"],
               "x-blastbox-receipt": got["receipt"]}
        r = rig.client.get("/v1/nodes/jobs/job-1/input", headers=hdr)
        assert r.status_code == 200
        real = {k: r.headers[k] for k in ("content-length", "content-type",
                                          "x-blastbox-input-sha256")}
        body = r.content
        run_limit = got["run"]["limits"]["max_input"]
    exp = {"sha256": DP_SAMPLE_SHA, "bytes": len(DP_SAMPLE)}

    def vec(desc: str, verdict: str, *, status: int = 200, headers: dict[str, str] | None = None,
            body_bytes: bytes = body, expected: dict[str, Any] | None = None,
            max_input: int = run_limit) -> dict[str, Any]:
        return {"description": desc, "status": status, "headers": headers or dict(real),
                "body_hex": body_bytes.hex(), "expected": expected or dict(exp),
                "max_input": max_input, "verdict": verdict}

    out["accept"] = vec("headers and body exactly as the real route sent them", "accept")
    out["accept_bytes_unknown"] = vec(
        "run.input.bytes is null: length comes from the stream", "accept",
        expected={"sha256": DP_SAMPLE_SHA, "bytes": None})
    out["abort_short"] = vec("connection ended before expected.bytes", "abort_short",
                             body_bytes=body[:-1])
    out["abort_long"] = vec("more bytes than expected.bytes", "abort_long",
                            body_bytes=body + b"X",
                            headers={**real, "content-length": str(len(body) + 1)})
    out["abort_long_over_max_input"] = vec(
        "expected.bytes already exceeds run.limits.max_input: abort before reading", "abort_long",
        max_input=len(body) - 1)
    out["abort_hash_body"] = vec("same length, flipped byte: hash mismatch", "abort_hash",
                                 body_bytes=bytes([body[0] ^ 1]) + body[1:])
    out["abort_hash_header"] = vec(
        "x-blastbox-input-sha256 disagrees with run.input.sha256", "abort_hash",
        headers={**real, "x-blastbox-input-sha256": "0" * 64})
    out["abort_redirect"] = vec(
        "3xx: never follow a redirect with the session headers", "abort_redirect", status=307,
        headers={"location": "http://169.254.169.254/latest/meta-data", "content-length": "0"},
        body_bytes=b"")
    for name, v in out.items():
        assert judge_input(v) == v["verdict"], name
    return out


# ---- envelope_seal ---------------------------------------------------------------------
def gen_envelope_seal() -> dict[str, dict[str, Any]]:
    from blastbox.host.trust import OutputTrustError, validate_worker_output

    def _a(id_: str, path: str, kind: str = "binary", **over: Any) -> dict[str, Any]:
        # the schema REQUIRES sha256/bytes from the worker; the host discards them
        return {"id": id_, "path": path, "kind": kind, "sha256": "00" * 32, "bytes": 0, **over}

    art = _a("a1", "artifacts/a.bin")
    cases: list[tuple[str, str, dict[str, bytes], dict[str, Any]]] = [
        ("no_artifacts", "metadata only", {"metadata.json": _meta()}, {}),
        ("reseal_overwrites_worker_claims",
         "worker-reported sha256/bytes are discarded; the host recomputes them from the files",
         {"metadata.json": _meta(artifacts=[{**art, "sha256": "ff" * 32, "bytes": 999}]),
          "artifacts/a.bin": b"\x00\x01hello"}, {}),
        ("two_artifacts_nested", "ordering follows the declaration, not the tar",
         {"metadata.json": _meta(artifacts=[
             _a("z", "artifacts/z.bin"), _a("a", "deep/er/a.txt", "text")]),
          "artifacts/z.bin": b"zz", "deep/er/a.txt": b"hello\n"}, {}),
        ("empty_artifact", "zero-byte artifact seals to the empty-string sha256",
         {"metadata.json": _meta(artifacts=[art]), "artifacts/a.bin": b""}, {}),
        ("missing_artifact", "declared but not in the tree",
         {"metadata.json": _meta(artifacts=[art])}, {}),
        ("input_sha_mismatch", "worker processed a different document",
         {"metadata.json": _meta(input_sha256="ab" * 32)}, {}),
        ("engine_mismatch", "worker reports another engine",
         {"metadata.json": _meta(engine="boxjs")}, {}),
        ("path_escape", "declared artifact path leaves the output dir",
         {"metadata.json": _meta(artifacts=[{**art, "path": "../escape"}])}, {}),
        ("reserved_attestation_path", "attestation.json is the host's, never an artifact",
         {"metadata.json": _meta(artifacts=[{**art, "path": "attestation.json"}]),
          "attestation.json": b"{}"}, {}),
        ("metadata_not_json", "metadata.json is not an envelope",
         {"metadata.json": b"not json"}, {}),
    ]
    out: dict[str, dict[str, Any]] = {}
    for name, desc, tree, _ in cases:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, data in tree.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            try:
                env = validate_worker_output(output_dir=root, input_sha256=DP_SAMPLE_SHA,
                                             engine="clamav", limits=_result_limits())
                verdict: str = "sealed"
                arts: Any = [{"id": a.id, "path": a.path, "kind": a.kind,
                              "sha256": a.sha256, "bytes": a.bytes} for a in env.artifacts]
            except OutputTrustError:
                verdict, arts = "refused", None
        out[name] = {"description": desc, "engine": "clamav", "input_sha256": DP_SAMPLE_SHA,
                     "tree": tree_to_json(tree), "verdict": verdict, "artifacts": arts}
    return out


# ---- transcripts -----------------------------------------------------------------------
class _Tape:
    def __init__(self, rig: _Rig) -> None:
        self.rig = rig
        self.steps: list[dict[str, Any]] = []

    def call(self, method: str, template: str, path: str | None = None, *,
             headers: dict[str, str] | None = None, **kw: Any) -> Any:
        r = self.rig.client.request(method, path or template, headers=headers, **kw)
        self.steps.append({"req": {"method": method, "path": template,
                                   "headers_present": sorted(h.lower() for h in (headers or {}))},
                           "resp": {"status": r.status_code}})
        return r


def gen_transcripts() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    tar_ok = go_writer_tar({"metadata.json": _meta()})
    res_path = "/v1/nodes/jobs/{job_id}/result"
    inp_path = "/v1/nodes/jobs/{job_id}/input"
    job_path = "/v1/nodes/jobs/{job_id}"

    def handshake(t: _Tape, who: str) -> str:
        ch = t.call("GET", "/v1/nodes/challenge").json()["challenge"]
        key = (t.rig.pki / f"node-{who}.key").read_bytes()
        sig = _b64(node_auth.sign_claim(key, ch, node_auth.SCOPE_CLAIM_NEXT, who))
        r = t.call("POST", "/v1/nodes/session", json={
            "cert_pem": (t.rig.pki / f"node-{who}.crt").read_text(),
            "challenge": ch, "signature": sig})
        return r.json()["token"] if r.status_code == 200 else ""

    def claim(t: _Tape, tok: str, headers_extra: bool = False) -> Any:
        return t.call("POST", "/v1/nodes/claim", json={"engine": "clamav"},
                      headers={SESSION_HDR: tok})

    def owned(tok: str, got: dict[str, Any]) -> dict[str, str]:
        return {SESSION_HDR: tok, "x-blastbox-claim-id": got["job"]["claim_id"],
                "x-blastbox-receipt": got["receipt"]}

    with _dp_rig() as rig:
        rig.submit()
        t = _Tape(rig)
        tok = handshake(t, "alpha")
        got = claim(t, tok).json()
        h = owned(tok, got)
        t.call("GET", inp_path, "/v1/nodes/jobs/job-1/input", headers=h)
        t.call("PUT", res_path, "/v1/nodes/jobs/job-1/result", content=tar_ok, headers={
            **h, "x-blastbox-worker-runtime": "nsjail", "x-blastbox-started-at-ms": "1",
            "x-blastbox-finished-at-ms": "2"})
        out["happy"] = t.steps
    with _dp_rig() as rig:
        rig.submit()
        t = _Tape(rig)
        tok = handshake(t, "beta")
        claim(t, tok)
        out["refused"] = t.steps
    with _dp_rig() as rig:
        rig.submit()
        t = _Tape(rig)
        tok = handshake(t, "alpha")
        got = claim(t, tok).json()
        h = owned(tok, got)
        # the claim moves to someone else; the CAS on (status, claim_id) is lost -> 409
        t.call("POST", job_path, "/v1/nodes/jobs/job-1", headers={SESSION_HDR: tok}, json={
            "claim_id": got["job"]["claim_id"], "receipt": got["receipt"],
            "expect_status": "queued", "fields": {"worker_runtime": "nsjail"}})
        out["lost_claim_409"] = t.steps
    with _dp_rig() as rig:
        rig.submit()
        t = _Tape(rig)
        tok = handshake(t, "alpha")
        got = claim(t, tok).json()
        h = owned(tok, got)
        t.call("GET", inp_path, "/v1/nodes/jobs/job-1/input", headers=h)
        stale = node_auth.issue_session(
            "alpha", secret=node_auth.resolve_claim_secret(rig.store, rig.pki, pepper=None),
            now=time.time() - node_auth.SESSION_TTL_S - 5)
        meta = {"x-blastbox-worker-runtime": "nsjail", "x-blastbox-started-at-ms": "1",
                "x-blastbox-finished-at-ms": "2"}
        t.call("PUT", res_path, "/v1/nodes/jobs/job-1/result", content=tar_ok,
               headers={**h, SESSION_HDR: stale, **meta})              # 401
        tok2 = handshake(t, "alpha")                                    # challenge + session
        t.call("PUT", res_path, "/v1/nodes/jobs/job-1/result", content=tar_ok,
               headers={**h, SESSION_HDR: tok2, **meta})                # 202, same claim
        out["session_expiry_mid_upload"] = t.steps
    return out


# ---------------------------------------------------------------------------
# Verification of committed-once artifacts + sha256sums
# ---------------------------------------------------------------------------
def verify_committed_once(out: Path = OUT) -> list[str]:
    """Replay every committed cert / signature through the reference. Returns problems."""
    problems: list[str] = []
    certs = out / "node_certs"
    try:
        doc = json.loads((certs / "cases.json").read_text())
        anchor = pki.TrustAnchor(x509.load_pem_x509_certificate((certs / doc["ca"]).read_bytes()))
    except (OSError, ValueError, KeyError) as exc:
        return [f"node_certs unreadable: {exc}"]
    now = CERT_NOW
    if doc["now"] != now.isoformat():
        problems.append("cases.json now differs from the generator's frozen now")
    secret = bytes.fromhex(doc["secret_hex"])
    with mock.patch.object(pki, "_now", lambda: now):
        for c in doc["cases"]:
            pem = (certs / c["cert"]).read_bytes()
            try:
                ident = pki.node_identity(anchor, pem)
                got = "ok"
                if ident.node_id != c["node_id"]:
                    problems.append(f"{c['name']}: node_id {ident.node_id!r} != {c['node_id']!r}")
            except Exception:  # noqa: BLE001 - every verify failure is the same verdict
                got = "refused"
            if got != c["verdict"]:
                problems.append(f"{c['name']}: node_identity says {got}, vector says {c['verdict']}")
            if c["admit"] is not None:
                a = c["admit"]
                try:
                    node_auth.admit_identity(
                        anchor, pem, challenge=a["challenge"], scope=a["scope"],
                        signature=base64.b64decode(a["signature_b64"]), secret=secret,
                        now=a["verify_at"])
                    got = "ok"
                except node_auth.ClaimRefused:
                    got = "refused"
                if got != a["verdict"]:
                    problems.append(f"{c['name']}: admit says {got}, vector says {a['verdict']}")
    # info version / wg expectations for the two positives
    for name, version, has_wg in (("v1_with_wg", 1, True), ("v2_without_wg", 2, False)):
        pem = (certs / f"{name}.crt").read_bytes()
        with mock.patch.object(pki, "_now", lambda: now):
            ident = pki.node_identity(anchor, pem)
        if ident.info_version != version or (ident.wg_pubkey is not None) != has_wg:
            problems.append(f"{name}: unexpected info_version/wg ({ident.info_version})")

    try:
        cross = json.loads((out / "ecdsa_cross.json").read_text())
    except (OSError, ValueError) as exc:
        return problems + [f"ecdsa_cross.json unreadable: {exc}"]
    if not cross.get("python_signed"):
        problems.append("ecdsa_cross.json: python_signed is empty")
    if not any(e.get("valid") is False for e in cross.get("python_signed", [])):
        problems.append("ecdsa_cross.json: no negative (valid: false) entry")
    for listname in ("python_signed", "go_signed"):
        for entry in cross.get(listname, []):
            expect_valid = entry.get("valid", True)
            if listname == "go_signed" and not expect_valid:
                problems.append("ecdsa_cross.json: go_signed entries must verify")
            if "challenge" in entry:           # inputs recorded: payload must be the real one
                real = node_auth.signing_payload(
                    entry["challenge"], entry["scope"], entry["node_id"]).hex()
                if real != entry["payload_hex"]:
                    problems.append(
                        "ecdsa_cross.json: payload_hex is not the signing payload of its inputs")
            pub = serialization.load_pem_public_key(entry["public_key_pem"].encode())
            try:
                assert isinstance(pub, ec.EllipticCurvePublicKey)
                pub.verify(base64.b64decode(entry["signature_b64"]),
                           bytes.fromhex(entry["payload_hex"]), ec.ECDSA(hashes.SHA256()))
                verified = True
            except Exception:  # noqa: BLE001
                verified = False
            if verified != expect_valid:
                problems.append(
                    f"ecdsa_cross.json: a {listname} signature verdict is "
                    f"{'valid' if verified else 'invalid'}, entry says {expect_valid}")
    problems += verify_renew_proof_doc(out)
    return problems + verify_result_tars(out)


def sha256sums(out: Path = OUT) -> bytes:
    lines = []
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out)}")
    return ("\n".join(lines) + "\n").encode()


def _write(out: Path, rel: str, data: bytes) -> None:
    path = out / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_all(out: Path = OUT, *, regen_certs: bool = False, regen_signed: bool = False) -> None:
    certs = out / "node_certs"
    if regen_certs or not (certs / "cases.json").exists():
        for rel, data in build_node_certs().items():
            _write(certs, rel, data)
    for rel, data in generate().items():
        _write(out, rel, data)
    cross = out / "ecdsa_cross.json"
    if regen_signed or not cross.exists():
        go_signed = json.loads(cross.read_text()).get("go_signed", []) if cross.exists() else []
        if regen_signed:
            go_signed = []                 # their signatures were over a different key set
        _write(out, "ecdsa_cross.json",
               _dumps({"python_signed": build_ecdsa_python_signed(), "go_signed": go_signed}))
    proof = out / "renew_proof.json"
    if regen_signed or not proof.exists():
        go = [] if regen_signed or not proof.exists() else json.loads(proof.read_text())["go_signed"]
        _write(out, "renew_proof.json", _dumps(build_renew_proof(go)))
    else:                                   # constants are not random: keep them current
        doc = json.loads(proof.read_text())
        if any(doc.get(k) != v for k, v in _renew_proof_constants().items()):
            doc.update(_renew_proof_constants())
            _write(out, "renew_proof.json", _dumps(doc))
    add_node_cert_negatives(certs)
    add_ecdsa_negative(cross)
    write_result_tars(out)
    problems = verify_committed_once(out)
    if problems:
        raise SystemExit("committed-once artifacts do not verify:\n  " + "\n  ".join(problems))
    _write(out, "SHA256SUMS", sha256sums(out))


def check(out: Path = OUT) -> list[str]:
    problems: list[str] = []
    for rel, data in generate().items():
        path = out / rel
        if not path.is_file():
            problems.append(f"missing: {rel}")
        elif path.read_bytes() != data:
            problems.append(f"drift: {rel} differs from the Python reference")
    problems += verify_committed_once(out)
    sums = out / "SHA256SUMS"
    if not sums.is_file():
        problems.append("missing: SHA256SUMS")
    elif sums.read_bytes() != sha256sums(out):
        problems.append("SHA256SUMS does not cover exactly the files present, or a hash is stale")
    return problems


README = """\
# Blastbox node protocol -- conformance vectors v1

Python (`src/blastbox/...`) is the reference; these files are generated from it by
`scripts/gen_conformance.py`. The Go pull-worker agent consumes the same files, so the JSON
shapes are a contract. **A change to a shape or value means a new directory `v2/`, never an
edit of `v1/`.**

| file | what it pins | reference function |
|---|---|---|
| `challenge.json` | challenge string + verdicts (`ok`, `expired`, `wrong_scope`, `foreign`, `malformed`); the expiry is Python `repr(float)` and is opaque | `node_auth.challenge_for`, `_check_challenge` |
| `signing_payload.json` | exact bytes a node signs | `node_auth.signing_payload` |
| `session_token.json` | `issue` (inputs -> token) and `verify` (token, time -> `ok`/`expired`/`forged`/`malformed`) | `issue_session`, `verify_session` |
| `receipt.json` | `issue` (inputs -> receipt) and `check` (-> `ok`/`refused`) | `claim_receipt`, `check_claim_receipt` |
| `canonical_json.json` | `{input, canonical_hex}` or `{input_repr, error: "float"}` | `attest_wire.canonical` |
| `renew_proof.json` | renewal proof of possession: `payload_cases` pin `renew_payload` bytes (`domain || 0x00 || node_id || 0x00 || sha256hex(utf8(csr_pem)) || 0x00 || decimal(issued_at)`); `python_signed` are P-256/SHA-256 DER base64 proofs (one tampered `"valid": false`); the Go agent appends `go_signed` | `node_renew.renew_payload`, `sign_renew_proof` |
| `ecdsa_cross.json` | P-256/SHA-256 DER signatures, base64. `python_signed` is written by Python; the Go agent appends `go_signed`. Every entry must verify unless it has `"valid": false` (absent means true; python_signed only), which is a tampered signature that must be rejected | `node_auth.sign_claim` |
| `node_certs/` | TEST CA, v1 (WireGuard key) and v2 (no key) node certs, and negatives; `cases.json` gives each verdict at the frozen `now` | `pki.node_identity`, `node_auth.admit_identity` |
| `sandbox/seatbelt/*.json` | `request` -> exact SBPL `profile` + `-D` `params` | `seatbelt.build_profile` |
| `sandbox/nsjail/*.json` | `request` -> exact `argv`, with `host_pins` for the host probes that were fixed | `NsjailSandbox._build_argv` |
| `claim_responses/*.json` | status + normalised body of the REAL `POST /v1/nodes/claim`, and the agent's `decision` (`run`, `idle`, `rehandshake`, `refused`, `release_unstarted`) | `register_node_claim_routes` (`claim`, `_run_block`) |
| `input_stream/*.json` | `GET .../input` as `{status, headers, body_hex, expected, max_input, verdict}`; verdicts `accept`, `abort_short`, `abort_long`, `abort_hash`, `abort_redirect` | the route, plus `judge_input` in the generator |
| `result_tars/<case>.tar` + `.json` | adversarial result tars (committed once, bytes pinned by SHA256SUMS) and the server's verdict `accepted`/`rejected` (202 / 422) | `node_results.vet_tar` + `_safe_extract_tar` (the `PUT .../result` route) |
| `result_tars/writer/*.json` | `{tree, tar_sha256}`: the exact tar the Go writer must produce for a file tree | `agent/internal/runner/tarw.go` semantics, built by `go_writer_tar` |
| `envelope_seal/*.json` | tree -> sealed artifacts (`sha256`/`bytes` recomputed from disk) or `refused` | `trust.validate_worker_output` |
| `transcripts/*.json` | ordered `[{req: {method, path, headers_present}, resp: {status}}]` for `happy`, `refused`, `lost_claim_409`, `session_expiry_mid_upload` | the real routes |
| `SHA256SUMS` | hash of every other file | |

Notes for consumers:

* `challenge.json`: the Python reference cannot tell a foreign MAC from a wrong scope (both are
  "not issued by this server for this scope"); the vector labels them by construction and an
  implementation may report either as a refusal. `minted_scope` is what the challenge was minted for.
* Times are explicit (`verify_at`, `now`) -- nothing here reads a clock.
* Certificate verdicts are evaluated at `node_certs/cases.json` `now`. Ten-year validity
  except the deliberately `expired` case.
* `canonical_json.json` inputs must be decoded with exact integers (Go: `json.Decoder.UseNumber`), or integers beyond 2^53 lose precision.
* `node_plus_client_auth_eku` (node EKU plus clientAuth) is refused: a node cert must never double as a transport cert.
* `node_plus_server_auth_eku`, `node_plus_any_eku` and `node_eku_not_critical` are refused too: the node EKU must be critical and alone among transport EKUs.
* `v2_with_wg` is accepted (v2 MAY carry a key, and it is validated); `v2_bad_wg` and `v1_without_wg` are refused.
* `session_token.json` entries all verify under the single `secret_hex`; a `forged` entry was minted under another secret.
* `rsa_key` verifies as an identity but its `admit` verdict is `refused` (EC keys only).

* Data-plane vectors (all produced by driving the real app, throwaway PKI, DEFAULT `Limits`, no `BLASTBOX_*` env):
  * `claim_responses`: random values are replaced by placeholders `<CLAIM_ID>` (`job.claim_id`), `<STARTED_AT>` (`job.started_at`) and `<RECEIPT>`; match on shape, never on those. `run.network` is the exit driver name (`none` unless the engine has a governed egress personality). The reference has no driver called `sinkhole`, so `release_network_sinkhole` is `"synthetic": true` (real body, `network` rewritten); the real non-`none` cases are `release_network_socks` and `release_network_inetsim`. The agent releases the job UNSTARTED whenever `run.network != "none"`. `idle` is 204 with `body: null`.
  * `input_stream`: `expected` is `run.input` (`bytes` may be null, then the stream's `content-length` is the length). Header names are lowercase. `abort_redirect` has a 307 and must never be followed.
  * `result_tars/*.tar` are committed once (a rebuild would change nothing today, but the bytes are the contract); `--check` replays every one through `vet_tar` + extraction and compares to its `.json`. Caps (member count, byte totals, 413 stream ceiling) depend on `Limits` and are not vectors.
  * `result_tars/writer`: USTAR, regular files only, paths sorted bytewise, mode 0644, uid/gid 0, empty uname/gname, mtime 0, no directory entries, 512-byte blocks plus the two-block end marker, and NO padding to a 10240-byte record (the Go writer does not pad; Python's tarfile does unless told otherwise). Go writes devmajor/devminor as `0000000\0`. In `tree`, `metadata.json` is UTF-8 text and every other value is hex.
  * `transcripts`: `lost_claim_409` is the status write (`POST /jobs/{id}` with `expect_status`) losing its compare-and-swap; a node that has lost its claim sees 403 on input/result. `session_expiry_mid_upload`: PUT 401, then challenge + session, then the same PUT 202.

Regenerate / check:

```text
python scripts/gen_conformance.py            # rewrite generated files + SHA256SUMS
python scripts/gen_conformance.py --check    # exit 1 on drift (CI)
python scripts/gen_conformance.py --regen-certs   # new test CA + certs (a Go agent's recorded cert verdicts go stale; go_signed is kept)
python scripts/gen_conformance.py --regen-signed  # new python_signed (drops go_signed)
```

`node_certs/**` and `python_signed` are committed once (random keys/serials, randomised ECDSA);
`--check` re-verifies them with the reference rather than regenerating them.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if committed files drift")
    ap.add_argument("--regen-certs", action="store_true")
    ap.add_argument("--regen-signed", action="store_true")
    args = ap.parse_args(argv)
    if args.check:
        problems = check()
        if problems:
            print("conformance vectors drifted:\n  " + "\n  ".join(problems), file=sys.stderr)
            return 1
        print("conformance vectors: ok")
        return 0
    write_all(regen_certs=args.regen_certs, regen_signed=args.regen_signed)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
