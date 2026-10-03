"""Execution receipts: signed at the point of observation.

The DISPATCHER that executed a job signs a receipt at the moment it seals a successful (DONE)
result, built ONLY from what that dispatcher itself observed of THAT run -- held in memory for
the run, never read back from the job row, which other parties (nodes, peer dispatchers, anyone
with the DSN) can write:

    input_sha256     sha256 of the input bytes it materialised and handed to the sandbox
    metadata_sha256  sha256 of the exact metadata.json bytes it uploads
    worker_runtime   } as it launched them
    worker_tier      }
    net_policy_effective  the personality this dispatcher ITSELF enforced for this run (local
                          cold via netd/netns, local warm slots); OMITTED wherever it did not
                          enforce the posture itself -- every remote/VM tier
    net_exit         the exit driver actually APPLIED ("none", "direct", "inetsim", ...),
                     present only with net_policy_effective: the NAME is operator-defined, so
                     two hosts could sign one name for opposite postures. A containment claim
                     (anything but "direct") is signed only when the dispatcher VERIFIED that
                     containment for this run; otherwise all network fields are omitted.
    net_downgraded   true when the applied args failed the run closed to --network=none
                     (net_exit is then "none"); absent otherwise
    net_inspect      true when the run was routed through the TLS-MITM inspect gateway
    started_at_ms / finished_at_ms / issued_at_ms   integer epoch ms, its own clock

The receipt is written as ``attestation.json`` beside ``metadata.json`` in the sealed output
tree, so it reaches the blob store through the same ``put_output`` as the result it vouches for.
The ingress only SERVES those bytes; nothing in the ingress signs anything. When a finalize does
NOT sign (no key, signing failed, ...), it writes a TOMBSTONE there instead --
``{"attestation": null, "reason": "..."}`` -- because the store never deletes a single object,
so a superseded attempt's receipt would otherwise survive. The ingress answers 404 for one.

Opt-in: only an explicit ``BLASTBOX_ATTEST_KEY`` enables receipts.

What it does NOT prove: that detections are true (the envelope is still the worker's account),
or that the signer ran the job at all when the signer can also write the shared results prefix
-- any pinned key whose holder can write there can attach a receipt to a job it never ran. Pin
only keys of hosts you trust as much as the control plane.

Wire contract (shared with verifiers, e.g. Loadout):

    body         {"attestation": doc, "signature": sig}
    canonical(x) json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                 -- and NO FLOATS anywhere in x (canonical() raises): float rendering is
                 implementation-specific, so a float would tie the signed bytes to Python.
    key_id       sha256(SubjectPublicKeyInfo DER).hexdigest()[:16]
    signature    base64url, padded, of DER ECDSA-P256-SHA256 over canonical(doc)

A verifier pins the key out of band (``blastbox attest-key``); a key served by a host proves
nothing on its own.
"""
from __future__ import annotations

import base64
import contextlib
import errno
import hashlib
import json
import logging
import os
import posixpath
import socket
import stat
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from blastbox.limits import Limits

_log = logging.getLogger("blastbox.host.attest")

ATTEST_KEY_ENV = "BLASTBOX_ATTEST_KEY"
HOST_ID_ENV = "BLASTBOX_HOST_ID"

#: The receipt's name in the sealed output tree and in the blob store's results prefix.
RECEIPT_NAME = "attestation.json"
#: The uploader's durable "no receipt" verdict for a tree it shipped AS-IS (its envelope declares,
#: or cannot rule out, an artifact at the receipt name -- see :func:`write_withheld_marker`). Its
#: mere presence in a stored result makes the attestation route answer the no-receipt 404 before
#: it reads anything at RECEIPT_NAME, so a ceiling mismatch between uploader and route can never
#: turn the uploader's "cannot rule out" into the route's "nothing declared, serve it".
WITHHELD_NAME = "attestation.withheld.json"
#: Every name the dispatchers own in a sealed tree; the trust gate refuses an artifact at or
#: under any of them.
RESERVED_NAMES = (RECEIPT_NAME, WITHHELD_NAME)
_SEAL_NAME = "metadata.json"

VERSION = 1
ALG = "ES256"

#: Sentinel for dispatcher constructors: resolve the key from the environment.
FROM_ENV = object()

_READ_CHUNK = 1024 * 1024


class AttestKeyRefused(ValueError):
    """An existing key file this process will not sign with (unsafe or not P-256)."""


# ---------------------------------------------------------------------------
# Canonical form
# ---------------------------------------------------------------------------


def _reject_floats(x: object, path: str = "$") -> None:
    if isinstance(x, float):
        raise TypeError(f"canonical(): float at {path} -- the signed form carries integers only")
    if isinstance(x, dict):
        for k, v in x.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(x, (list, tuple)):
        for i, v in enumerate(x):
            _reject_floats(v, f"{path}[{i}]")


def canonical(x: object) -> bytes:
    """The exact bytes that are signed. Part of the contract -- do not change."""
    _reject_floats(x)
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# ---------------------------------------------------------------------------
# Key
# ---------------------------------------------------------------------------


def _env_value(env: Mapping[str, str], name: str) -> str | None:
    # SET-BUT-EMPTY IS NOT A PATH: deployment tooling emits `VAR=` for unset values.
    value = (env.get(name) or "").strip()
    return value or None


def attest_key_path(env: Mapping[str, str] | None = None) -> Path | None:
    """``BLASTBOX_ATTEST_KEY``, else ``None`` (disabled). STRICTLY OPT-IN.

    Deliberately NOT derived from ``BLASTBOX_PKI_DIR``: that is the mTLS/CA directory, set on
    every node, and deriving from it silently minted a signing key on each of them (or logged
    errors on a read-only CA dir). A host that never chose to attest must not start minting."""
    env = os.environ if env is None else env
    explicit = _env_value(env, ATTEST_KEY_ENV)
    return Path(explicit) if explicit else None


def host_id(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get(HOST_ID_ENV) or "").strip() or socket.gethostname()


@dataclass(frozen=True)
class AttestKey:
    """An EC P-256 signing key."""

    private_key: ec.EllipticCurvePrivateKey

    @property
    def public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @property
    def key_id(self) -> str:
        spki = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(spki).hexdigest()[:16]

    def sign(self, doc: Mapping[str, object]) -> str:
        der = self.private_key.sign(canonical(doc), ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(der).decode()


def _read_hardened(path: Path) -> bytes:
    """Read an existing key file, refusing anything another principal could have planted or
    read: a symlink, a non-regular file, a file not owned by this euid, or any group/other bit.
    Opened with O_NOFOLLOW and judged on the OPEN descriptor, so a swap between check and read
    changes nothing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:                       # ELOOP: the final component is a symlink
            raise AttestKeyRefused(f"attestation key {path} is a symlink; refusing it") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise AttestKeyRefused(f"attestation key {path} is not a regular file")
        if st.st_uid != os.geteuid():
            raise AttestKeyRefused(
                f"attestation key {path} is owned by uid {st.st_uid}, not this process "
                f"(euid {os.geteuid()}); refusing it")
        if st.st_mode & 0o077:
            raise AttestKeyRefused(
                f"attestation key {path} has group/other permission bits "
                f"({stat.S_IMODE(st.st_mode):o}); it must be 0600 or stricter")
        chunks = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_key(data: bytes, path: Path) -> AttestKey:
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise AttestKeyRefused(f"attestation key {path} is not a readable PEM private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise AttestKeyRefused(f"attestation key {path} is not an EC P-256 private key "
                               f"(alg is fixed at {ALG})")
    return AttestKey(key)


def load_existing_key(path: Path) -> AttestKey:
    """Load the key at ``path`` WITHOUT creating one. FileNotFoundError if absent."""
    path = Path(path)
    return _parse_key(_read_hardened(path), path)


def load_or_create_key(path: Path) -> AttestKey:
    """Load the key at ``path``, generating it (0600) on first use.

    Generation is ATOMIC and race-safe: the key is written in full to a private temp file beside
    the target, then hard-linked into place. ``link`` fails if the target exists, so processes
    starting together converge on whichever key landed first instead of overwriting a key a
    verifier may already have pinned. Either way the result is re-read through the hardened
    loader, so the file actually used is always the one that passed the checks."""
    path = Path(path)
    try:
        return load_existing_key(path)
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    tmp = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(pem)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass            # a concurrent starter won; use ITS key
    finally:
        tmp.unlink(missing_ok=True)
    return load_existing_key(path)


def load_attest_key(env: Mapping[str, str] | None = None, *, create: bool = True,
                    quiet: bool = False) -> AttestKey | None:
    """The configured key, or ``None`` -- attestation disabled, or the key refused/unloadable.

    Never raises: a dispatcher whose key is bad must keep running jobs (without receipts), so a
    failure is logged LOUDLY here. ``quiet`` is for a process that is NOT the signer (the ingress
    key route): there a missing, foreign-owned or unreadable key is the normal case, so every
    failure is logged at debug only."""
    path = attest_key_path(env)
    if path is None:
        _log.debug("attestation: %s not set; receipts are off", ATTEST_KEY_ENV)
        return None
    log = _log.debug if quiet else _log.error
    try:
        return load_or_create_key(path) if create else load_existing_key(path)
    except FileNotFoundError:
        log("attestation: no key at %s; receipts are DISABLED", path)
    except AttestKeyRefused as exc:
        log("attestation: key refused (%s); receipts are DISABLED", exc)
    except Exception as exc:  # noqa: BLE001 - never take the dispatcher down over a receipt
        log("attestation: key at %s unusable (%s); receipts are DISABLED", path, exc)
    return None


def resolve_key(value: object) -> AttestKey | None:
    """A dispatcher constructor argument: an AttestKey, None (disabled), or FROM_ENV."""
    if value is FROM_ENV:
        return load_attest_key()
    if value is None or isinstance(value, AttestKey):
        return value
    raise TypeError(f"attest_key must be an AttestKey, None or FROM_ENV, not {type(value)!r}")


# ---------------------------------------------------------------------------
# The receipt
# ---------------------------------------------------------------------------


def now_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass(frozen=True)
class RunObservation:
    """What ONE dispatcher saw of ONE run, collected in memory as it happened."""

    job_id: str
    engine: str
    input_sha256: str
    worker_runtime: str | None
    worker_tier: str | None
    started_at_ms: int
    finished_at_ms: int
    # Only where THIS dispatcher enforced -- and, for a containment claim, VERIFIED -- the
    # posture for this run; None everywhere else.
    net_policy_effective: str | None = None
    net_exit: str | None = None
    # The APPLIED posture differs from the personality's declaration:
    net_downgraded: bool = False    # the network args failed the run closed to --network=none
    net_inspect: bool = False       # the run was routed through the TLS-MITM inspect gateway


def sha256_file(path: Path) -> str:
    """sha256 of a regular file's bytes, opened without following a final symlink.
    O_NONBLOCK so a FIFO planted in its place is opened (then refused by fstat) rather than
    blocking the caller forever; it changes nothing for a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        h = hashlib.sha256()
        while chunk := os.read(fd, _READ_CHUNK):
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def build_receipt(obs: RunObservation, *, key_id: str, metadata_sha256: str,
                  issued_at_ms: int | None = None, host: str | None = None) -> dict:
    doc: dict[str, object] = {
        "v": VERSION,
        "alg": ALG,
        "key_id": key_id,
        "host": host_id() if host is None else host,
        "job_id": obs.job_id,
        "engine": obs.engine,
        "status": "done",
        # Kept for wire compatibility. The signer claims it executed the run; that claim is only
        # as good as the signer -- any pinned key whose holder can write the shared results prefix
        # can attach a receipt to a job it never ran.
        "executor": "local",
        "input_sha256": obs.input_sha256,
        "metadata_sha256": metadata_sha256,
        "worker_runtime": obs.worker_runtime,
        "worker_tier": obs.worker_tier,
        "started_at_ms": int(obs.started_at_ms),
        "finished_at_ms": int(obs.finished_at_ms),
        "issued_at_ms": now_ms() if issued_at_ms is None else int(issued_at_ms),
    }
    if obs.net_policy_effective is not None:
        doc["net_policy_effective"] = obs.net_policy_effective
        doc["net_exit"] = obs.net_exit
        # Booleans, present only when true, so an ordinary receipt carries neither.
        if obs.net_downgraded:
            doc["net_downgraded"] = True
        if obs.net_inspect:
            doc["net_inspect"] = True
    return doc


def is_reserved_path(path: str, names: tuple[str, ...] = RESERVED_NAMES) -> bool:
    """Whether an envelope artifact path is, or lies under, a reserved name (by default any of
    RESERVED_NAMES: the receipt and the withheld marker). The whole name is the dispatcher's: an
    artifact at ``attestation.json/x`` lives in a directory that the receipt (or tombstone) write
    has to replace.

    Compared the way the trust gate RESOLVES an artifact path (``Path(relpath).parts``, walked
    segment by segment under the output dir) -- never whitespace-stripped: ``' attestation.json'``
    is a different file on disk and is not refused. ``.``/``//``/trailing-slash spellings collapse
    exactly as the walk collapses them. Two spellings the gate rejects outright as unsafe (a root
    anchor, ``..``) are judged on their anchor-stripped / normalised form, so the answer only ever
    errs towards refusing a path that lands nowhere."""
    parts = PurePosixPath(path).parts
    if parts and parts[0] in ("/", "//"):
        parts = parts[1:]
    if parts and parts[0] in names:
        return True
    p = posixpath.normpath(path)
    return any(p == n or p.startswith(n + "/") for n in names)


#: metadata.json is capped at 4 MiB by default (Limits.max_metadata_bytes); this is only the
#: FLOOR of the ceiling past which the envelope is "cannot rule it out", never a trust verdict.
#: The ceiling actually applied is :func:`envelope_cap`.
ENVELOPE_MAX_BYTES = 64 << 20


def envelope_cap(limits: Limits | None = None) -> int:
    """The largest envelope parsed for a receipt-path decision: the configured metadata limit
    (``limits``, else BLASTBOX_MAX_METADATA via Limits.from_env -- the one the dispatchers and
    the trust gate enforce), never below ENVELOPE_MAX_BYTES. A host configured to accept larger
    envelopes seals and signs over them, so a fixed cap would judge a genuine one "cannot rule
    out" -- hiding its receipt. The floor keeps an envelope sealed by a peer with a larger limit
    than this process parseable up to the old fixed size. An unparseable env setting (which
    fails the dispatchers loudly at startup) falls back to the floor here."""
    if limits is None:
        try:
            limits = Limits.from_env()
        except ValueError:
            return ENVELOPE_MAX_BYTES
    return max(ENVELOPE_MAX_BYTES, int(limits.max_metadata_bytes))


class ReceiptPathOccupied(OSError):
    """``attestation.json`` holds an artifact the envelope declares (or the envelope
    cannot be parsed to rule that out -- a transient READ error is ReceiptUnreadable instead). Replacing it would delete accepted artifacts, so nothing is
    written there: no receipt and no tombstone. An OSError so the sweeps' existing "leave it
    retained" OSError path handles it."""


def _artifact_paths_of(data: bytes) -> list[str] | None:
    """The artifact paths an envelope's bytes declare, or None when they cannot be parsed."""
    try:
        env = json.loads(data)
        return [str(a.get("path", "")) for a in env.get("artifacts") or []]
    except Exception:  # noqa: BLE001 - unparseable: cannot rule anything out
        return None


#: Why a result whose envelope declares an artifact at the receipt name has no receipt.
RECEIPT_PATH_DECLARED_REASON = ("receipt path is occupied by a declared artifact of a result "
                                "accepted before the name was reserved")
#: Why a result whose envelope cannot be parsed has no receipt: nothing rules out that whatever
#: sits at attestation.json is accepted output, and no dispatcher signs over such an envelope.
RECEIPT_PATH_UNDECIDABLE_REASON = ("the result's envelope cannot be read to rule out a declared "
                                   "artifact at the receipt path")
#: Why a result whose stored prefix has no envelope has no receipt: a genuine receipt always
#: signs the envelope's sha256, and put_output stores the envelope LAST, so its absence means a
#: partial upload (or a seal that was never shipped) -- nothing at attestation.json is a receipt.
RECEIPT_ENVELOPE_ABSENT_REASON = "the stored result has no envelope for a receipt to vouch for"


def envelope_receipt_path_protection(data: bytes | None) -> str | None:
    """Why whatever sits at attestation.json in a result with these envelope bytes must be left
    alone and never presented as a receipt or tombstone -- or None when the envelope rules that
    out. ``data`` None = the envelope is larger than ENVELOPE_MAX_BYTES (cannot be parsed whole).

    Two verdicts: the envelope DECLARES an artifact at or under the name (only possible in a tree
    accepted before the trust gate reserved it), or it cannot be parsed, so nothing rules that
    out. seal_receipt never signs over either, so no genuine receipt is lost by refusing."""
    paths = None if data is None else _artifact_paths_of(data)
    if paths is None:
        return RECEIPT_PATH_UNDECIDABLE_REASON
    if any(is_reserved_path(p) for p in paths):
        return RECEIPT_PATH_DECLARED_REASON
    return None


def tree_receipt_path_protection(out_dir: Path, *, limits: Limits | None = None) -> str | None:
    """:func:`envelope_receipt_path_protection` for ``<out_dir>/metadata.json`` -- THE single
    envelope test behind every receipt-path decision (the sweeps' as-is choice, strip_receipt,
    seal_receipt), so they cannot diverge.

    Judged on the envelope put_output would SHIP. It ships ``metadata.json`` only as a regular,
    non-symlink file; anything else (absent, a symlink -- ELOOP under O_NOFOLLOW, dangling or not
    -- a FIFO, a directory) never reaches the store, so no envelope accepted anything at
    attestation.json and there is nothing to protect: None, and whatever sits there is worker
    junk to strip or tombstone. A shipped envelope that is over the cap or unparseable is
    "cannot rule out" (protect). Opened O_NOFOLLOW|O_NONBLOCK and judged on the descriptor, so a
    FIFO never blocks. Any other OSError -- EIO, EACCES, a flap -- is no verdict and propagates,
    so the caller retries rather than acting on it. ``limits`` as for :func:`envelope_cap`: a
    caller outside the service (the migration CLI) passes the service's, so it strips what the
    service would. The attestation route never repeats this test: an as-is verdict travels with
    the tree as the withheld marker (:func:`write_withheld_marker`)."""
    shipped, data = _shipped_envelope(out_dir, limits)
    return envelope_receipt_path_protection(data) if shipped else None


def _shipped_envelope(out_dir: Path, limits: Limits | None) -> tuple[bool, bytes | None]:
    """(whether put_output would ship ``<out_dir>/metadata.json``, its bytes -- None when over
    :func:`envelope_cap`). See :func:`tree_receipt_path_protection`; any OSError other than the
    not-shipped verdicts propagates."""
    seal = Path(out_dir) / _SEAL_NAME
    try:
        fd = os.open(seal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False, None              # absent: never shipped
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False, None          # a symlink: put_output never ships it
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False, None          # a FIFO/directory/...: put_output never ships it
        return True, _read_capped(fd, envelope_cap(limits))
    finally:
        os.close(fd)


def _may_hold_declared_artifacts(out_dir: Path) -> bool:
    """Whether the envelope declares (or might declare) an artifact at or under attestation.json:
    :func:`tree_receipt_path_protection`, with a transient read error (EIO, EACCES...) read as
    "cannot rule it out" -- the deletion paths fail closed where the sweeps' as-is choice would
    instead retry. An envelope put_output would not ship (absent, symlinked, non-regular) is a
    VERDICT there, not an error, so it protects nothing here either."""
    try:
        return tree_receipt_path_protection(out_dir) is not None
    except OSError:
        return True


def strip_receipt(out_dir: Path, *, gate_verified: bool = False,
                  limits: Limits | None = None,
                  names: tuple[str, ...] = RESERVED_NAMES) -> None:
    """Remove whatever sits at ``<out_dir>/attestation.json`` -- and at the withheld marker's
    name, ``names`` by default being every reserved one -- (file, directory or symlink) without
    following a symlink. A worker can write into its output tree, and a planted withheld marker
    would hide the receipt this tree is about to carry.

    Raises ReceiptPathOccupied, deleting nothing, when the envelope declares an artifact AT or
    UNDER that name -- a top-level file named attestation.json or a directory of artifacts
    (possible only in a tree accepted before the trust gate reserved the whole name), or when the
    envelope cannot be PARSED to rule that out: never destroy accepted output to make room for a
    receipt. Raises ReceiptUnreadable, deleting nothing, when the envelope cannot be READ right
    now (EIO, EACCES...) -- no verdict, retry later. Anything undeclared there (worker-planted
    junk, a stale receipt) is replaced.

    ``gate_verified``: the caller is the dispatcher sealing a tree the trust gate JUST validated,
    and the gate refuses any artifact at or under the reserved name -- so nothing there can be
    accepted output and the envelope is not re-read. That makes the strip unconditional: a
    transient envelope read error can never leave a worker-planted receipt in a tree that ships.
    ``limits`` as for :func:`tree_receipt_path_protection`."""
    out_dir = Path(out_dir)
    present = []
    for name in names:
        try:
            present.append((out_dir / name, os.lstat(out_dir / name)))
        except FileNotFoundError:
            continue
    if not present:
        return
    if not gate_verified:
        try:
            why = tree_receipt_path_protection(out_dir, limits=limits)
        except OSError as exc:
            # No verdict either way: a retry-later error, never the permanent-looking
            # ReceiptPathOccupied. Both sweeps leave the tree in place and retry it.
            raise ReceiptUnreadable(
                exc.errno, f"cannot read the envelope to rule out a declared artifact at "
                           f"{RECEIPT_NAME} ({exc}); leaving it in place") from exc
        if why is not None:
            raise ReceiptPathOccupied(
                errno.EEXIST, f"{RECEIPT_NAME} holds a declared artifact (or the envelope "
                              f"cannot be parsed to rule that out); refusing to replace it")
    for target, st in present:
        _remove_entry(target, st)


def _remove_entry(target: Path, st: os.stat_result) -> None:
    """Remove ``target`` (lstat ``st``) without following a symlink; already gone is fine."""
    if stat.S_ISDIR(st.st_mode):
        # NOT shutil.rmtree: its fd walk RECURSES, so a worker-built chain ~1000 dirs deep (0
        # bytes, far under the gate's entry cap) raised RecursionError -- not an OSError -- and
        # no receipt or tombstone could ever be written over it. The bounded iterative walk
        # purge_job_dir already uses for the same attack: openat/unlinkat under O_NOFOLLOW (a
        # symlink is never followed, at the top or below), a fixed fd budget, no PATH_MAX.
        from blastbox.host.jobs.retention import _rmtree_iterative

        _rmtree_iterative(target)
    else:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(target)


def _write_atomic(out_dir: Path, data: bytes, *, gate_verified: bool = False) -> None:
    tmp = out_dir / f".{RECEIPT_NAME}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        strip_receipt(out_dir, gate_verified=gate_verified)   # os.replace cannot replace a dir
        os.replace(tmp, out_dir / RECEIPT_NAME)
    finally:
        tmp.unlink(missing_ok=True)


def strip_withheld_marker(out_dir: Path, *, limits: Limits | None = None) -> None:
    """Remove a planted withheld marker (only that name) from a tree that is about to ship WITH
    its receipt, e.g. a retained tree whose receipt this host signed. Refuses exactly as
    :func:`strip_receipt` does when the envelope protects the reserved names."""
    strip_receipt(out_dir, limits=limits, names=(WITHHELD_NAME,))


#: The reason a withheld marker that is not tombstone-shaped (a declared artifact of an old tree
#: sitting at the marker's name) is reported with.
RECEIPT_WITHHELD_REASON = "the uploader withheld the receipt for this result"


def write_withheld_marker(out_dir: Path, reason: str, *, limits: Limits | None = None) -> None:
    """Record, IN the tree, that it is shipped as-is with no receipt: a tombstone-shaped
    ``{"attestation": null, "reason": reason}`` at WITHHELD_NAME. Call it immediately before
    uploading a tree the receipt-path test protects (``reason`` = its verdict); the attestation
    route answers the no-receipt 404 whenever the stored result holds that name, BEFORE it reads
    the receipt name, so the uploader's verdict is never re-derived under another ceiling.

    Nothing at RECEIPT_NAME is touched. Raises OSError -- never ships without it -- when the
    marker cannot be written; the caller must then NOT upload as-is (leave the tree retained /
    count it failed).

    Something already at WITHHELD_NAME (only in a tree accepted before the name was reserved,
    or planted by its worker):

    * the envelope rules out that it is accepted output (parseable, nothing declared at or under
      the name): worker junk -- replaced by the marker;
    * otherwise it may be a declared artifact and is never destroyed. A REGULAR file there is
      left in place: put_output ships it at the marker's key, and its mere presence makes the
      route answer the 404 -- the fail-closed outcome, whatever its bytes. Anything else (a
      directory, symlink, FIFO) would not be stored at that key, so it cannot stand in for the
      marker: ReceiptPathOccupied, and the tree is not shipped as-is.

    A transient envelope read error propagates (no verdict; retry)."""
    out_dir = Path(out_dir)
    target = out_dir / WITHHELD_NAME
    try:
        st: os.stat_result | None = os.lstat(target)
    except FileNotFoundError:
        st = None
    if st is not None:
        shipped, data = _shipped_envelope(out_dir, limits)
        paths = (None if data is None else _artifact_paths_of(data)) if shipped else []
        if paths is None or any(is_reserved_path(p, (WITHHELD_NAME,)) for p in paths):
            if stat.S_ISREG(st.st_mode):
                return              # possibly accepted output; its presence withholds
            raise ReceiptPathOccupied(
                errno.EEXIST, f"{WITHHELD_NAME} may hold a declared artifact that is not a "
                              f"regular file; refusing to replace it or ship without it")
        _remove_entry(target, st)
    tmp = out_dir / f".{WITHHELD_NAME}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(canonical(tombstone_body(reason)))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)


def tombstone_body(reason: str) -> dict:
    return {"attestation": None, "reason": reason}


def write_tombstone(out_dir: Path, reason: str, *, gate_verified: bool = False) -> None:
    """Write the "no receipt for this run" marker. Uploaded like a receipt, so it OVERWRITES a
    superseded attempt's receipt in the store (which never deletes a single object).
    ``gate_verified`` as for :func:`strip_receipt`."""
    _write_atomic(Path(out_dir), canonical(tombstone_body(reason)), gate_verified=gate_verified)


def is_tombstone(data: bytes) -> bool:
    try:
        body = json.loads(data)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(body, dict) and body.get("attestation", 0) is None


def seal_receipt(out_dir: Path, *, key: AttestKey | None,
                 observation: RunObservation | None, reason: str | None = None,
                 gate_verified: bool = False) -> dict | None:
    """Replace whatever sits at ``attestation.json`` with this dispatcher's signed receipt, or,
    when it does not sign, a tombstone saying why. Returns the SIGNED body, or None when a
    tombstone was written. Call it IMMEDIATELY before uploading ``out_dir``: the metadata hash is
    of the bytes on disk at this moment, which are the bytes put_output ships.

    Raises ReceiptPathOccupied, writing nothing, when attestation.json is a directory holding
    declared artifacts: no receipt rather than a wrong one, and never at the artifacts' expense.
    ``gate_verified`` (the fresh-dispatch seal, see :func:`strip_receipt`): the gate already
    ruled that out, so the envelope is not re-read for it and the strip is unconditional."""
    out_dir = Path(out_dir)
    if key is None:
        write_tombstone(out_dir, "no attestation key", gate_verified=gate_verified)
        return None
    if observation is None:
        write_tombstone(out_dir, reason or "run not observed", gate_verified=gate_verified)
        return None
    try:
        metadata_sha256 = sha256_file(out_dir / _SEAL_NAME)
    except (OSError, ValueError) as exc:
        _log.error("attestation: job %s has no regular metadata.json to vouch for (%s); "
                   "no receipt", observation.job_id, exc)
        write_tombstone(out_dir, "metadata.json is not a regular file",
                        gate_verified=gate_verified)
        return None
    if not gate_verified and _may_hold_declared_artifacts(out_dir):
        # The trust gate refuses this; never let a declared artifact stand in for a receipt.
        _log.error("attestation: job %s declares %s as an artifact; no receipt",
                   observation.job_id, RECEIPT_NAME)
        write_tombstone(out_dir, f"envelope declares the reserved path {RECEIPT_NAME}")
        return None
    doc = build_receipt(observation, key_id=key.key_id, metadata_sha256=metadata_sha256)
    body = {"attestation": doc, "signature": key.sign(doc)}
    _write_atomic(out_dir, canonical(body), gate_verified=gate_verified)
    return body


def seal_fresh_receipt(out_dir: Path, *, key: AttestKey | None,
                       observation: RunObservation | None, job_id: str,
                       reason: str | None = None) -> bool:
    """The dispatchers' seal of a tree the trust gate has JUST validated, immediately before it
    ships. Writes our receipt or, failing that, a "signing failed" tombstone -- both with
    ``gate_verified`` so neither depends on re-reading the envelope. Never raises.

    Returns whether the tree is SAFE TO UPLOAD: True once a receipt or tombstone is at
    attestation.json. False when neither could be written (ENOSPC, EIO on the write...): a
    worker-planted receipt may still be sitting there, and without a tombstone a superseded
    attempt's receipt in the store would not be overwritten either. The caller must then NOT
    upload and takes its ordinary upload-failure path -- FAILED, tree retained for the
    pending-upload sweep, which sanitises attestation.json before it uploads. Failing closed
    this way reuses the one path an object-store outage already takes, rather than inventing a
    third outcome (e.g. shipping with nothing at the name)."""
    try:
        seal_receipt(out_dir, key=key, observation=observation, reason=reason,
                     gate_verified=True)
        return True
    except Exception as exc:  # noqa: BLE001 - a receipt problem must never fail a job by itself
        _log.error("attestation: could not write the receipt for job %s (%s); the job "
                   "completes without one", job_id, exc)
    try:
        # Never ship a planted or half-written one, and overwrite a superseded attempt's.
        write_tombstone(out_dir, "signing failed", gate_verified=True)
        return True
    except Exception:  # noqa: BLE001
        _log.exception("attestation: could not write a tombstone for job %s either; NOT "
                       "uploading a tree that may still hold a worker-planted %s",
                       job_id, RECEIPT_NAME)
    return False


def verify_body(key: AttestKey, body: object) -> bool:
    """Whether ``body`` is a receipt validly signed by ``key``."""
    try:
        assert isinstance(body, dict)
        doc, sig = body["attestation"], body["signature"]
        assert isinstance(doc, dict) and isinstance(sig, str)
        key.private_key.public_key().verify(
            base64.urlsafe_b64decode(sig), canonical(doc), ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001 - anything short of a clean verify is "no"
        return False
    return True


#: A receipt is a few hundred bytes; anything past this is not one of ours.
_RECEIPT_MAX_BYTES = 1 << 20


class ReceiptUnreadable(OSError):
    """The receipt (or the metadata it vouches for) could not be READ right now -- EIO, EAGAIN, a
    permission flap. Not a verdict: the caller must neither tombstone nor upload, and retry later.
    An OSError subclass so a sweep's existing "leave it retained" OSError path handles it."""


def _read_capped(fd: int, cap: int) -> bytes | None:
    """Read to EOF in a loop (a single os.read may legitimately return a SHORT read on NFS/FUSE
    or after a signal). None when the file is larger than ``cap``."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(65536, cap + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > cap:
            return None


def tree_receipt_is_ours(out_dir: Path, *, key: AttestKey | None, job_id: str) -> bool:
    """True only if ``<out_dir>/attestation.json`` is a receipt THIS key signed, for ``job_id``,
    over the metadata.json bytes currently in the tree.

    Three outcomes, and the difference matters to the caller: True; False = DEFINITELY not ours
    (absent, a symlink or non-regular file, oversized, unparseable, or a signature/key/job/metadata
    mismatch) -- safe to replace with a tombstone; ReceiptUnreadable = could not read it right
    now -- replacing it would destroy a genuine receipt over a transient error."""
    if key is None:
        return False
    out_dir = Path(out_dir)
    try:
        # O_NONBLOCK: a worker-planted FIFO must not block the sweep in open(); fstat below
        # refuses it (and anything else that is not a regular file) on the open descriptor, and
        # the read is capped -- as read_snapshots_readonly does for the node-share dir.
        fd = os.open(out_dir / RECEIPT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError as exc:
        if exc.errno == errno.ELOOP:                # a symlink: never ours
            return False
        raise ReceiptUnreadable(exc.errno, f"cannot open {RECEIPT_NAME}: {exc}") from exc
    try:
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            data = _read_capped(fd, _RECEIPT_MAX_BYTES)
        except OSError as exc:
            raise ReceiptUnreadable(exc.errno, f"cannot read {RECEIPT_NAME}: {exc}") from exc
    finally:
        os.close(fd)
    if data is None:
        return False
    try:
        body = json.loads(data)
        doc = body["attestation"]
        if not (verify_body(key, body) and doc.get("key_id") == key.key_id
                and doc.get("job_id") == job_id):
            return False
    except Exception:  # noqa: BLE001 - parsed bytes that are not our receipt: a verdict
        return False
    try:
        metadata_sha256 = sha256_file(out_dir / _SEAL_NAME)
    except ValueError:                              # not a regular file: a verdict
        return False
    except OSError as exc:
        if exc.errno == errno.ELOOP:                # a symlinked seal is never shipped: a verdict
            return False
        raise ReceiptUnreadable(exc.errno, f"cannot read {_SEAL_NAME}: {exc}") from exc
    return doc.get("metadata_sha256") == metadata_sha256


def public_key_body(key: AttestKey) -> dict:
    return {"key_id": key.key_id, "alg": ALG, "public_key_pem": key.public_key_pem}
