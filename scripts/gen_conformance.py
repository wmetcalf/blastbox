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
import hashlib
import json
import sys
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
    return {"domain": node_renew.RENEW_PROOF_DOMAIN.decode(),
            "payload": "domain || 0x00 || node_id || 0x00 || sha256hex(utf8(csr_pem)) || "
                       "0x00 || decimal(issued_at)",
            "max_skew_ingress_s": node_renew.RENEW_PROOF_MAX_SKEW_S,
            "max_age_ca_s": node_renew.RENEW_PROOF_MAX_AGE_S,
            "payload_cases": payload_cases, "python_signed": signed,
            "go_signed": go_signed or []}


def verify_renew_proof_doc(out: Path) -> list[str]:
    problems: list[str] = []
    try:
        doc = json.loads((out / "renew_proof.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"renew_proof.json unreadable: {exc}"]
    if doc.get("domain") != node_renew.RENEW_PROOF_DOMAIN.decode():
        problems.append("renew_proof.json: domain differs from node_renew.RENEW_PROOF_DOMAIN")
    want = [(n, c, t) for n, c, t in RENEW_PAYLOAD_CASES]
    if [(c["node_id"], c["csr_pem"], c["issued_at"]) for c in doc.get("payload_cases", [])] != want:
        problems.append("renew_proof.json: payload_cases differ from the generator's inputs")
    if not any(e.get("valid") is False for e in doc.get("python_signed", [])):
        problems.append("renew_proof.json: no negative (valid: false) entry")
    for listname in ("payload_cases", "python_signed", "go_signed"):
        for e in doc.get(listname, []):
            real = node_renew.renew_payload(e["node_id"], e["csr_pem"], e["issued_at"]).hex()
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
    return problems


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
    add_node_cert_negatives(certs)
    add_ecdsa_negative(cross)
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
