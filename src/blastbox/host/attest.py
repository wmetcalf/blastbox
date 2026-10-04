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
#: or cannot rule out, an artifact at the receipt name -- see :func:`write_withheld_marker`). Stored
#: with any content but a cleared body (:func:`cleared_marker_body`), or over
#: WITHHELD_MARKER_MAX_BYTES, it makes the attestation route answer the no-receipt 404 before it
#: reads anything at RECEIPT_NAME, so a ceiling mismatch between uploader and route can never turn
#: the uploader's "cannot rule out" into the route's "nothing declared, serve it".
WITHHELD_NAME = "attestation.withheld.json"
#: A CLEARED marker (:func:`cleared_marker_body`) means "NOT withheld", and only for the
#: envelope it names (:func:`is_cleared_marker`). The store never deletes a single object, so an
#: upload that ships a
#: receipt for a tree whose results prefix may already hold a marker -- an earlier as-is upload of
#: the same job -- OVERWRITES it with this body (:func:`write_cleared_marker`) rather than
#: stripping it locally, which would leave the stored marker hiding the receipt forever. EVERY
#: upload that ships a receipt or a tombstone carries it -- the fresh seals (written with the
#: receipt/tombstone, over whatever a worker planted there: the gate refused declaring the name),
#: the sweep's receipt and tombstone branches and the migration's tombstone branch. The route
#: does NOT take it as a verdict (round 7, O1): a well-formed cleared body only means "not
#: withheld", and the stored envelope is still judged under the route's ceiling -- over it, the
#: receipt is withheld. A cleared marker is only ever written in the same upload as an attestation.json this
#: host wrote (a receipt or a tombstone), never with nothing at that name. A result with NO marker
#: is legacy (pre-receipt, or an as-is upload by an earlier build) and the route still judges its
#: envelope.
#:
#: BOUND TO THE ENVELOPE. The body names the sha256 of the metadata.json shipped in the same
#: upload. That is how write_withheld_marker recognises this host's own marker in a retained tree
#: (and replaces it when a retry under a lower limit ships as-is). A result
#: uploaded by older code (no reserved names) could DECLARE an artifact at WITHHELD_NAME; the
#: sealed envelope commits to every declared artifact's sha256 (seal_envelope re-hashes them from
#: disk), so that artifact's bytes would have to contain the hash of an envelope that contains
#: the hash of those bytes -- a sha256 cycle. A pre-binding body, or one bound to any other
#: envelope, is never taken for the host's own.
CLEARED_MARKER_ATTESTATION = "not-withheld"
#: The most of a stored marker the route reads; anything longer is withheld, never truncated.
WITHHELD_MARKER_MAX_BYTES = 4096
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
#: The route's answer for an envelope larger than its own ceiling (:func:`envelope_cap`): it
#: cannot be parsed to rule out a declared artifact at attestation.json, and no marker vouches
#: for an envelope the ingress cannot judge, so the receipt is withheld. Names the fix.
RECEIPT_ENVELOPE_OVER_LIMIT_REASON = (
    "the result's envelope is larger than this ingress's metadata limit, so it cannot rule out a "
    "declared artifact at attestation.json; set BLASTBOX_MAX_METADATA on the ingress at least as "
    "high as on the dispatchers that seal results")
#: The tombstone the legacy migration ships in place of whatever the worker left at
#: attestation.json: a pre-blob-store result carries no receipt by construction.
RECEIPT_LEGACY_MIGRATED_REASON = "a legacy result migrated to the store carries no receipt"


def envelope_receipt_path_protection(data: bytes | None) -> str | None:
    """Why whatever sits at attestation.json in a result with these envelope bytes must be left
    alone and never presented as a receipt or tombstone -- or None when the envelope rules that
    out. ``data`` None = the envelope is larger than the caller's :func:`envelope_cap` (cannot be
    parsed whole).

    Two verdicts: the envelope DECLARES an artifact at or under the name (only possible in a tree
    accepted before the trust gate reserved it), or it cannot be parsed, so nothing rules that
    out. The trust gate refuses either before a dispatcher seals, so no genuine receipt is lost
    by refusing."""
    paths = None if data is None else _artifact_paths_of(data)
    if paths is None:
        return RECEIPT_PATH_UNDECIDABLE_REASON
    if any(is_reserved_path(p) for p in paths):
        return RECEIPT_PATH_DECLARED_REASON
    return None


def tree_receipt_path_protection(out_dir: Path, *, limits: Limits | None = None) -> str | None:
    """:func:`envelope_receipt_path_protection` for ``<out_dir>/metadata.json`` -- THE single
    envelope test behind every receipt-path decision on a tree that did not just pass the trust
    gate (the sweeps' as-is choice, strip_receipt without ``gate_verified``, the migration), so
    they cannot diverge.

    Judged on the envelope put_output would SHIP. It ships ``metadata.json`` only as a regular,
    non-symlink file; anything else (absent, a symlink -- ELOOP under O_NOFOLLOW, dangling or not
    -- a FIFO, a directory) never reaches the store, so no envelope accepted anything at
    attestation.json and there is nothing to protect: None, and whatever sits there is worker
    junk to strip or tombstone. A shipped envelope that is over the cap or unparseable is
    "cannot rule out" (protect). Opened O_NOFOLLOW|O_NONBLOCK and judged on the descriptor, so a
    FIFO never blocks. Any other OSError -- EIO, EACCES, a flap -- is no verdict and propagates,
    so the caller retries rather than acting on it. ``limits`` as for :func:`envelope_cap`: a
    caller outside the service (the migration CLI) passes the service's, so it judges as the
    service would. An as-is verdict travels with the tree as the withheld marker
    (:func:`write_withheld_marker`), and the attestation route ALSO runs
    :func:`envelope_receipt_path_protection` on the STORED envelope, under its own
    :func:`envelope_cap`, for every result without a withheld body (unmarked or cleared) -- a
    cleared marker cannot vouch, because a pre-#188 dispatcher shipped a worker's tree verbatim.
    Do not remove that route check as redundant."""
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
            occupied = ", ".join(t.name for t, _ in present)
            raise ReceiptPathOccupied(
                errno.EEXIST, f"{occupied} may hold a declared artifact ({why}); refusing to "
                              f"replace it")
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


def _write_atomic(out_dir: Path, data: bytes, *, gate_verified: bool = False,
                  limits: Limits | None = None, metadata_sha256: str | None = None) -> None:
    tmp = out_dir / f".{RECEIPT_NAME}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # os.replace cannot replace a dir
        strip_receipt(out_dir, gate_verified=gate_verified, limits=limits)
        os.replace(tmp, out_dir / RECEIPT_NAME)
    finally:
        tmp.unlink(missing_ok=True)
    # Every receipt or tombstone ships with the CLEARED marker, bound to the envelope in the tree
    # (``metadata_sha256``: the one the receipt signed): an overwrite of any withheld marker an
    # earlier upload of the job stored, and recognisable as this host's own on a retry. strip_receipt above already
    # cleared (or refused for) everything at the reserved names. Every caller writes metadata.json
    # BEFORE this and never after (the dispatchers seal it first; the sweeps never rewrite it). A
    # failure here raises ReceiptMarkerUnwritten, so the caller never ships a receipt without it
    # -- and can tell that what it wrote at RECEIPT_NAME DID land.
    try:
        _write_vouching_marker(out_dir, metadata_sha256)
    except Exception as exc:  # noqa: BLE001 - re-raised, typed
        raise ReceiptMarkerUnwritten(
            getattr(exc, "errno", None) or errno.EIO,
            f"{RECEIPT_NAME} was written but its {WITHHELD_NAME} marker was not ({exc})") from exc


class ReceiptMarkerUnwritten(OSError):
    """What :func:`_write_atomic` wrote at RECEIPT_NAME LANDED, but the marker that must ship
    beside it could not be written. The tree must not ship as it stands -- and the receipt must
    not be replaced either: it is genuine, only its marker is missing."""


def cleared_marker_body(metadata_sha256: str) -> dict:
    """The cleared marker for a result whose shipped metadata.json has this sha256."""
    return {"attestation": CLEARED_MARKER_ATTESTATION, "withheld": False,
            "metadata_sha256": metadata_sha256}


def is_cleared_marker(data: bytes, metadata_sha256: str) -> bool:
    """Whether bytes stored at WITHHELD_NAME are EXACTLY the canonical cleared body for the
    envelope whose sha256 is ``metadata_sha256`` -- this host's own cleared marker for it. Byte
    equality, not a parse."""
    return data == canonical(cleared_marker_body(metadata_sha256))


def bound_cleared_marker_sha256(data: bytes) -> str | None:
    """The envelope sha256 ``data`` is the canonical cleared body for, or None when it is not
    exactly a cleared body for any 64-hex sha256 (a tombstone, unparseable bytes, a near-miss such
    as ``"withheld": 0``, extra keys, the pre-binding body). The route answers None with the
    no-receipt 404; for any well-formed cleared body it lets the envelope decide (the binding
    does not vouch there). The binding identifies this host's own marker to
    :func:`write_withheld_marker`."""
    try:
        body = json.loads(data)
        sha = body["metadata_sha256"]
    except Exception:  # noqa: BLE001 - not a cleared body
        return None
    if not (isinstance(sha, str) and len(sha) == 64
            and all(c in "0123456789abcdef" for c in sha)):
        return None
    return sha if is_cleared_marker(data, sha) else None


def _shipped_metadata_sha256(out_dir: Path) -> str | None:
    """sha256 of the metadata.json put_output would ship from ``out_dir`` NOW, or None when it
    would ship none (absent, a symlink, not a regular file). Any other OSError propagates."""
    try:
        return sha256_file(out_dir / _SEAL_NAME)
    except FileNotFoundError:
        return None
    except ValueError:                              # not a regular file: never shipped
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:                # a symlink: never shipped
            return None
        raise


def _write_vouching_marker(out_dir: Path, metadata_sha256: str | None) -> None:
    """The marker that ships beside an attestation.json this host has just written: the cleared
    body bound to ``metadata_sha256`` (hashed from the tree now when None). With no shippable
    envelope there is nothing to bind: the withheld body, which the route answers like the
    missing envelope it will find."""
    if metadata_sha256 is None:
        metadata_sha256 = _shipped_metadata_sha256(out_dir)
    if metadata_sha256 is None:
        _write_marker(out_dir, canonical(tombstone_body(RECEIPT_ENVELOPE_ABSENT_REASON)))
    else:
        _write_marker(out_dir, canonical(cleared_marker_body(metadata_sha256)))


def write_cleared_marker(out_dir: Path, *, limits: Limits | None = None) -> None:
    """Put the canonical CLEARED body, bound to the tree's metadata.json, at WITHHELD_NAME in a
    tree that is about to ship with the receipt THIS host signed and the caller just verified
    (:func:`tree_receipt_is_ours`) -- never in a tree with nothing of this host's at the receipt
    name. Receipt and tombstone writes do this themselves. An overwrite, not a strip: the store never
    deletes a single object, so a marker an earlier as-is upload of this job stored would
    otherwise survive the upload and withhold the receipt forever.

    Refuses exactly as :func:`strip_receipt` does -- ReceiptPathOccupied when the envelope
    declares (or cannot rule out) an artifact at a reserved name, ReceiptUnreadable when it
    cannot be read right now -- writing nothing. Raises OSError when the marker cannot be
    written; the caller must then NOT upload (a stored marker would hide the receipt)."""
    out_dir = Path(out_dir)
    try:
        why = tree_receipt_path_protection(out_dir, limits=limits)
    except OSError as exc:
        raise ReceiptUnreadable(
            exc.errno, f"cannot read the envelope to rule out a declared artifact at "
                       f"{WITHHELD_NAME} ({exc}); leaving it in place") from exc
    if why is not None:
        raise ReceiptPathOccupied(
            errno.EEXIST, f"{WITHHELD_NAME} may hold a declared artifact; refusing to "
                          f"replace it ({why})")
    try:
        # Bound to the envelope the receipt kept here signed: tree_receipt_is_ours checked that
        # its metadata_sha256 is this file's.
        metadata_sha256 = sha256_file(out_dir / _SEAL_NAME)
    except (OSError, ValueError) as exc:
        raise ReceiptUnreadable(
            getattr(exc, "errno", None) or errno.EIO,
            f"cannot hash {_SEAL_NAME} to bind the cleared marker ({exc})") from exc
    # The verdict is taken above: nothing there is accepted output.
    strip_receipt(out_dir, gate_verified=True, names=(WITHHELD_NAME,))
    _write_marker(out_dir, canonical(cleared_marker_body(metadata_sha256)))


#: The reason a withheld marker that is not tombstone-shaped (unparseable, or anything else but
#: the cleared body) is reported with.
RECEIPT_WITHHELD_REASON = "the uploader withheld the receipt for this result"

# A dispatcher whose seal_fresh_receipt returned False never contacts the result store: what is
# at attestation.json (our receipt, a tombstone, or possibly a worker-planted file when nothing
# could be written) lacks its cleared marker. The job is FAILED with this in its error and the
# tree retained for the pending-upload sweep -- not an upload failure.
SEAL_INCOMPLETE_REASON = "receipt seal incomplete"


def write_withheld_marker(out_dir: Path, reason: str, *, limits: Limits | None = None) -> None:
    """Record, IN the tree, that it is shipped as-is with no receipt: a tombstone-shaped
    ``{"attestation": null, "reason": reason}`` at WITHHELD_NAME. Call it immediately before
    uploading a tree the receipt-path test protects (``reason`` = its verdict); the attestation
    route answers the no-receipt 404 whenever the stored result holds that name with anything
    but the cleared body (:func:`is_cleared_marker`), BEFORE it reads the receipt name, so the
    uploader's verdict is never re-derived under another ceiling.

    Nothing at RECEIPT_NAME is touched. Raises OSError -- never ships without it -- when the
    marker cannot be written; the caller must then NOT upload as-is (leave the tree retained /
    count it failed).

    Something already at WITHHELD_NAME (only in a tree accepted before the name was reserved,
    or planted by its worker):

    * the envelope rules out that it is accepted output (parseable, nothing declared at or under
      the name): worker junk -- replaced by the marker;
    * otherwise it may be a declared artifact: ReceiptPathOccupied, nothing destroyed, and the
      tree is NOT shipped as-is. Its bytes are the worker's: shipped at the marker's key they
      could be exactly the cleared body and unmask the worker-written attestation.json beside
      it, and a non-regular entry would not be stored there at all. ACCEPTED STRAND: such a
      tree (an envelope declaring, or unparseable beside, a file at a name reserved since
      before it was accepted) stays retained / counted failed, and the callers log it loudly.

    EXCEPT a regular file holding exactly a withheld body this function writes
    (:func:`_is_host_withheld_marker`): an earlier attempt's own marker, left in a tree whose
    upload then failed. It is kept and the tree ships with it. Refusing it stranded every such
    retry forever -- the undecidable verdict can never rule the name out. Keeping it is safe even
    for a worker-written lookalike: its presence alone withholds, and nothing is destroyed.

    And a regular file holding exactly the CLEARED body bound to the sha256 of the tree's current
    metadata.json (:func:`_is_host_cleared_marker`), while the envelope is undecidable: an earlier
    attempt vouched (a receipt or tombstone plus that marker), its upload failed, and this retry
    runs under a lower limit. It is REPLACED by the withheld body; refusing it stranded the retry
    on every tick or rerun. It cannot be a declared artifact: the sealed envelope commits to every
    declared artifact's sha256, so an artifact holding that envelope's sha256 is a hash cycle
    (the same argument the route's binding rests on). A parseable envelope that declares the name
    never sat beside a marker this host wrote (every writer refuses there), so it is refused.

    A transient envelope read error propagates (no verdict; retry)."""
    out_dir = Path(out_dir)
    target = out_dir / WITHHELD_NAME
    try:
        st: os.stat_result | None = os.lstat(target)
    except FileNotFoundError:
        st = None
    if st is not None and stat.S_ISREG(st.st_mode) and _is_host_withheld_marker(target):
        return
    if st is not None:
        shipped, data = _shipped_envelope(out_dir, limits)
        paths = (None if data is None else _artifact_paths_of(data)) if shipped else []
        if paths is None and stat.S_ISREG(st.st_mode) and _is_host_cleared_marker(out_dir, target):
            pass        # this host's own cleared marker from an earlier attempt: replaced below
        elif paths is None or any(is_reserved_path(p, (WITHHELD_NAME,)) for p in paths):
            raise ReceiptPathOccupied(
                errno.EEXIST,
                f"{WITHHELD_NAME} holds an entry this host did not write, and the envelope "
                f"{'cannot be read to rule out' if paths is None else 'declares'} an artifact "
                f"there; refusing to replace it or ship without it")
        _remove_entry(target, st)
    _write_marker(out_dir, canonical(tombstone_body(reason)))


#: Every reason :func:`write_withheld_marker` is called with: the as-is verdicts of
#: :func:`tree_receipt_path_protection`.
WITHHELD_REASONS = (RECEIPT_PATH_DECLARED_REASON, RECEIPT_PATH_UNDECIDABLE_REASON)
# Every reason this host ever writes into a withheld marker (write_withheld_marker's, plus
# _write_vouching_marker's no-envelope body). The route names only these.
MARKER_REASONS = (*WITHHELD_REASONS, RECEIPT_ENVELOPE_ABSENT_REASON)


def _read_marker_file(path: Path) -> bytes | None:
    """``path``'s bytes when it is a regular file of at most WITHHELD_MARKER_MAX_BYTES. Opened
    O_NOFOLLOW|O_NONBLOCK and judged on the descriptor; anything else (a symlink, a FIFO, a
    directory, oversized, an error) is None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return _read_capped(fd, WITHHELD_MARKER_MAX_BYTES)
    except OSError:
        return None
    finally:
        os.close(fd)


def _is_host_withheld_marker(path: Path) -> bool:
    """Whether ``path`` is a regular file whose bytes are exactly the canonical withheld body for
    one of WITHHELD_REASONS (read as :func:`_read_marker_file`)."""
    data = _read_marker_file(path)
    return data is not None and any(data == canonical(tombstone_body(r))
                                    for r in WITHHELD_REASONS)


def _is_host_cleared_marker(out_dir: Path, path: Path) -> bool:
    """Whether ``path`` is a regular file whose bytes are exactly the canonical cleared body bound
    to the sha256 of the metadata.json put_output would ship from ``out_dir`` now. An envelope
    that cannot be hashed (absent, not shippable, unreadable) is False."""
    data = _read_marker_file(path)
    if data is None:
        return False
    try:
        metadata_sha256 = _shipped_metadata_sha256(out_dir)
    except OSError:
        return False
    return metadata_sha256 is not None and is_cleared_marker(data, metadata_sha256)


def _write_marker(out_dir: Path, data: bytes) -> None:
    """Atomically put ``data`` at WITHHELD_NAME (nothing may be there but a regular file)."""
    tmp = out_dir / f".{WITHHELD_NAME}.{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out_dir / WITHHELD_NAME)
    finally:
        tmp.unlink(missing_ok=True)


#: The tombstone reasons this host writes at attestation.json when it does not sign. Every
#: write_tombstone (and seal_receipt's ``reason``) passes one of these constants, never free text.
NO_ATTEST_KEY_REASON = "no attestation key"
RUN_NOT_OBSERVED_REASON = "run not observed"
INPUT_UNHASHED_REASON = "input could not be hashed"
METADATA_NOT_REGULAR_REASON = "metadata.json is not a regular file"
SIGNING_FAILED_REASON = "signing failed"
RETAINED_REUPLOAD_REASON = "retained result re-uploaded without a receipt from this host"
#: Written by 0.1.45's seal_receipt (since removed: the trust gate refuses the declaration); its
#: tombstones are still in stores, so the route keeps naming it.
LEGACY_RESERVED_PATH_DECLARED_REASON = f"envelope declares the reserved path {RECEIPT_NAME}"
#: Every reason any release of this host writes into a tombstone at RECEIPT_NAME. The route names
#: only these: a pre-#188 node shipped worker trees verbatim, so any other text may be the
#: worker's (as for MARKER_REASONS).
TOMBSTONE_REASONS = (NO_ATTEST_KEY_REASON, RUN_NOT_OBSERVED_REASON, INPUT_UNHASHED_REASON,
                     METADATA_NOT_REGULAR_REASON, SIGNING_FAILED_REASON,
                     RETAINED_REUPLOAD_REASON, RECEIPT_LEGACY_MIGRATED_REASON,
                     LEGACY_RESERVED_PATH_DECLARED_REASON)
#: The reason a stored tombstone whose reason is not one of TOMBSTONE_REASONS is reported with.
RECEIPT_TOMBSTONE_REASON = "the uploader stored no receipt for this result"
#: The reason a stored attestation.json past _RECEIPT_MAX_BYTES is reported with: no receipt
#: build_receipt produces comes near that size, so it is not one.
RECEIPT_OVERSIZE_REASON = "the stored receipt is larger than any receipt this host writes"


def tombstone_body(reason: str) -> dict:
    return {"attestation": None, "reason": reason}


def write_tombstone(out_dir: Path, reason: str, *, gate_verified: bool = False,
                    limits: Limits | None = None) -> None:
    """Write the "no receipt for this run" marker. Uploaded like a receipt, so it OVERWRITES a
    superseded attempt's receipt in the store (which never deletes a single object).
    ``gate_verified`` and ``limits`` as for :func:`strip_receipt`."""
    _write_atomic(Path(out_dir), canonical(tombstone_body(reason)), gate_verified=gate_verified,
                  limits=limits)


def is_tombstone(data: bytes) -> bool:
    try:
        body = json.loads(data)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(body, dict) and body.get("attestation", 0) is None


def seal_receipt(out_dir: Path, *, key: AttestKey | None,
                 observation: RunObservation | None, reason: str | None = None) -> dict | None:
    """Replace whatever sits at ``attestation.json`` with this dispatcher's signed receipt, or,
    when it does not sign, a tombstone saying why. Returns the SIGNED body, or None when a
    tombstone was written. Call it IMMEDIATELY before uploading ``out_dir``: the metadata hash is
    of the bytes on disk at this moment, which are the bytes put_output ships.

    ONLY for a tree the trust gate has just validated (the dispatchers' seal, through
    :func:`seal_fresh_receipt`): the gate refuses any artifact at or under a reserved name, so
    the envelope is not re-read and the strip is unconditional (``gate_verified``, see
    :func:`strip_receipt`). A retained or legacy tree is never sealed here -- the sweeps judge
    its envelope and write a tombstone or the withheld marker instead.

    ``reason`` (the tombstone's reason when ``observation`` is None) must be one of
    TOMBSTONE_REASONS; the route reports any other with RECEIPT_TOMBSTONE_REASON."""
    out_dir = Path(out_dir)
    if key is None:
        write_tombstone(out_dir, NO_ATTEST_KEY_REASON, gate_verified=True)
        return None
    if observation is None:
        write_tombstone(out_dir, reason or RUN_NOT_OBSERVED_REASON, gate_verified=True)
        return None
    try:
        metadata_sha256 = sha256_file(out_dir / _SEAL_NAME)
    except (OSError, ValueError) as exc:
        _log.error("attestation: job %s has no regular metadata.json to vouch for (%s); "
                   "no receipt", observation.job_id, exc)
        write_tombstone(out_dir, METADATA_NOT_REGULAR_REASON, gate_verified=True)
        return None
    doc = build_receipt(observation, key_id=key.key_id, metadata_sha256=metadata_sha256)
    body = {"attestation": doc, "signature": key.sign(doc)}
    _write_atomic(out_dir, canonical(body), gate_verified=True, metadata_sha256=metadata_sha256)
    return body


def seal_fresh_receipt(out_dir: Path, *, key: AttestKey | None,
                       observation: RunObservation | None, job_id: str,
                       reason: str | None = None) -> bool:
    """The dispatchers' seal of a tree the trust gate has JUST validated, immediately before it
    ships. Writes our receipt or, failing that, a "signing failed" tombstone -- both with
    ``gate_verified`` so neither depends on re-reading the envelope. Never raises.

    Returns whether the tree is SAFE TO UPLOAD: True once a receipt or tombstone is at
    attestation.json WITH its cleared marker. False when our receipt landed but its marker did
    not (ReceiptMarkerUnwritten: the receipt is kept, never tombstoned over, and the sweep below
    ships it with its marker), or when a tombstone's marker failed, or when neither could be
    written (ENOSPC, EIO on the write...): a worker-planted receipt may then still be sitting
    there, and without a tombstone a superseded attempt's receipt in the store would not be
    overwritten either. The caller must then NOT
    upload and takes its ordinary upload-failure path -- FAILED, tree retained for the
    pending-upload sweep, which sanitises attestation.json before it uploads. Failing closed
    this way reuses the one path an object-store outage already takes, rather than inventing a
    third outcome (e.g. shipping with nothing at the name)."""
    try:
        seal_receipt(out_dir, key=key, observation=observation, reason=reason)
        return True
    except ReceiptMarkerUnwritten as exc:
        # Ours landed at RECEIPT_NAME (a genuine receipt, or seal_receipt's own tombstone); only
        # its marker is missing. A "signing failed" tombstone over it would destroy a genuine
        # receipt for a wrong reason. Refuse the upload instead: the pending-upload sweep finds
        # the receipt ours (tree_receipt_is_ours) and ships it with its cleared marker.
        _log.error("attestation: wrote the receipt for job %s but not its %s marker (%s); NOT "
                   "uploading -- the pending-upload sweep ships it with its marker",
                   job_id, WITHHELD_NAME, exc)
        return False
    except Exception as exc:  # noqa: BLE001 - fall back to a tombstone; only its failure refuses
        _log.error("attestation: could not write the receipt for job %s (%s); writing a "
                   "\"signing failed\" tombstone instead", job_id, exc)
    try:
        # Never ship a planted or half-written one, and overwrite a superseded attempt's. A
        # tombstone whose marker then fails raises ReceiptMarkerUnwritten here: not shipped.
        write_tombstone(out_dir, SIGNING_FAILED_REASON, gate_verified=True)
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
