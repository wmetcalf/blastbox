"""The security envelope: sealed by the worker SDK, re-validated by the host."""
from __future__ import annotations

import hashlib
import os
import stat as _stat
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .leaf import Detection, Warning
from .nodes import ChildNode, _REBUILD_CALLBACKS, parse_node


class DeclaredArtifact(BaseModel):
    """What an engine declares; the SDK turns it into a sealed Artifact."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    path: str = Field(max_length=4096)   # outdir-relative
    kind: str = Field(min_length=1, max_length=64)


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    path: str
    kind: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=0)


class Envelope(BaseModel):
    """A signed, sealed, and validated job result envelope.

    The ``payload`` field is typed as ``Annotated[ChildNode, ...]`` at class
    definition time.  After each ``register_node_type()`` call,
    ``_rebuild_envelope()`` is triggered via ``nodes._REBUILD_CALLBACKS`` and
    calls ``Envelope.model_rebuild(force=True, _types_namespace=...)`` so that
    pydantic re-evaluates the ``"_PayloadNode"`` forward-ref string against the
    current live union — without any top-level circular import.
    """
    model_config = ConfigDict(extra="forbid")
    engine: str = Field(min_length=1, max_length=64)
    status: Literal["ok", "rejected", "engine_error"] = "ok"
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    detected: Detection
    artifacts: list[Artifact] = Field(default_factory=list)
    warnings: list[Warning] = Field(default_factory=list)
    # Initial annotation uses ChildNode (the base union); _rebuild_envelope()
    # replaces model_fields["payload"].annotation with the live Node union after
    # each register_node_type() call so engine subtypes are also accepted.
    payload: Annotated[ChildNode, Field(discriminator="type")]


def _rebuild_envelope() -> None:
    """Rebuild Envelope against the current live Node union.

    Called by nodes.rebuild_node_union() via _REBUILD_CALLBACKS.
    Uses a lazy import to avoid a circular dependency at module-top level.
    Updates the ``payload`` field's annotation to the current live ``Node``
    union so pydantic regenerates the discriminated-union validator correctly.
    """
    import blastbox.contract.nodes as _nodes
    Envelope.model_fields["payload"].annotation = _nodes.Node  # type: ignore[assignment]
    Envelope.model_rebuild(force=True)


# Register so every rebuild_node_union() call (triggered by register_node_type)
# also refreshes the Envelope discriminated union.
_REBUILD_CALLBACKS.append(_rebuild_envelope)
# Apply immediately so the initial union is in place.
_rebuild_envelope()


def _collect_refs(node) -> set[str]:
    """Walk a node tree and collect every ArtifactRef.id it references."""
    from .leaf import ArtifactRef as _ArtifactRef

    refs: set[str] = set()
    stack: list = [node]
    while stack:
        v = stack.pop()
        if isinstance(v, _ArtifactRef):
            refs.add(v.id)
        elif isinstance(v, BaseModel):
            for f in type(v).model_fields:
                stack.append(getattr(v, f))
        elif isinstance(v, (list, tuple)):
            for it in v:
                stack.append(it)
        elif isinstance(v, dict):
            for it in v.values():
                stack.append(it)
    return refs


def open_confined_regular_fd(base: Path, relpath: str) -> int:
    """Open ``base/relpath`` as a regular file, TOCTOU-safely, confined strictly under ``base``.

    Walks the path one segment at a time relative to a directory fd, opening each component with
    ``O_NOFOLLOW`` (a symlinked component can't redirect the walk) and ``O_DIRECTORY`` on
    intermediates; the leaf is opened ``O_RDONLY|O_NOFOLLOW|O_NONBLOCK`` and ``fstat``'d to require
    a regular file. This defeats, on a still-live worker-writable dir, both the symlink-swap (read
    a host file) and the FIFO-block (a special-file target stalling the reader) attacks — a symlink
    leaf fails ``ELOOP``, a FIFO/socket/device fails the ``S_ISREG`` check, and ``O_NONBLOCK`` means
    a FIFO can never block. ``..`` and absolute paths are rejected. Returns an fd the caller closes;
    raises ``FileNotFoundError`` (missing), ``OSError`` (symlink/non-dir component), or ``ValueError``
    (unsafe shape / not a regular file)."""
    rel = Path(relpath)
    if rel.is_absolute() or not rel.parts or any(p == ".." for p in rel.parts):
        raise ValueError(f"unsafe path (absolute, empty, or contains '..'): {relpath!r}")
    dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel.parts[:-1]:
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nfd
        leaf_fd = os.open(
            rel.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd
        )
    finally:
        os.close(dir_fd)
    try:
        if not _stat.S_ISREG(os.fstat(leaf_fd).st_mode):
            raise ValueError(f"not a regular file: {relpath!r}")
        return leaf_fd
    except BaseException:
        os.close(leaf_fd)
        raise


def _hash_fd(fd: int, *, max_bytes: int | None = None) -> tuple[str, int]:
    """SHA-256 + byte count of an open fd, read in chunks (constant memory). If ``max_bytes`` is
    set, abort as soon as the RUNNING total exceeds it — so a still-live worker that grows the
    file after the initial stat can't force unbounded host I/O past the cap."""
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ValueError(f"file grew past {max_bytes} bytes during read")
        digest.update(chunk)
    return digest.hexdigest(), total


def atomic_write_confined(base: Path, name: str, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically write ``data`` to ``base/name``, symlink/TOCTOU-safe even when ``base`` is a
    worker-writable dir.

    The temp is created relative to a directory fd under a RANDOM name with
    ``O_CREAT|O_EXCL|O_NOFOLLOW`` (a worker can't pre-plant a symlink/file there to redirect the
    host write), then ``renameat`` replaces ``name`` (clobbering any worker-planted symlink at the
    destination, since rename doesn't follow it). ``name`` must be a single path segment.

    ``mode`` is applied EXACTLY via fchmod (not subject to the process umask). Use 0o644 for
    host-authored files a DIFFERENT uid must read — e.g. the host writes go.json that the
    non-root worker (uid 65532 on the gVisor tier) reads, or metadata.json the API serves from a
    different uid; the per-dir 0o700 confinement keeps other local users out regardless."""
    import secrets
    if not name or "/" in name or name in (".", ".."):
        raise ValueError(f"unsafe name: {name!r}")
    dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tmp_name = f".{name}.{secrets.token_hex(8)}.tmp"
        tfd = os.open(
            tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd
        )
        try:
            os.fchmod(tfd, mode)  # exact mode regardless of the host umask (cross-uid reads)
            mv = memoryview(data)
            while mv:
                mv = mv[os.write(tfd, mv):]
            os.close(tfd)
            tfd = -1
            os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        finally:
            if tfd >= 0:
                os.close(tfd)
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    finally:
        os.close(dir_fd)


@contextmanager
def confined_atomic_writer(base: Path, relpath: str, *, mode: int = 0o644, dir_mode: int = 0o700):
    """Yield a writable fd for ``base/relpath``, symlink/TOCTOU-safe even when ``base`` is a
    worker-writable dir, placing the result atomically only on clean exit.

    The streaming sibling of :func:`atomic_write_confined`, for copying out artifacts whose bytes
    are verified WHILE writing (running sha + size cap). Walks ``relpath`` one segment at a time
    relative to a directory fd — existing intermediates opened ``O_NOFOLLOW|O_DIRECTORY``, missing
    ones created with ``mkdir``+``O_NOFOLLOW`` reopen — so a worker-planted symlink at ANY
    component fails the walk (``O_NOFOLLOW`` → ``ELOOP``/``ENOTDIR``) instead of redirecting the
    write outside ``base``. The body streams into a RANDOM ``O_CREAT|O_EXCL|O_NOFOLLOW`` temp; on
    a clean exit the temp is ``fchmod``'d to ``mode`` and ``renameat``'d over the leaf (clobbering
    any worker-planted symlink there, since rename replaces the dir entry without following it);
    on ANY exception the temp is unlinked and the destination is left untouched. So a caller that
    raises after detecting a bad hash/size never publishes the artifact. ``..``/absolute paths are
    rejected."""
    import secrets
    rel = Path(relpath)
    if rel.is_absolute() or not rel.parts or any(p in ("..", ".") for p in rel.parts):
        raise ValueError(f"unsafe path (absolute, empty, or contains '.'/'..'): {relpath!r}")
    dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel.parts[:-1]:
            try:
                os.mkdir(part, dir_mode, dir_fd=dir_fd)
            except FileExistsError:
                pass
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nfd
            # Exact mode via fchmod on the (O_NOFOLLOW-opened) dir fd, umask-independent — the
            # API may serve NESTED artifacts as a different uid, so intermediate dirs need 0o755
            # to be traversable to the 0o644 files inside (the metadata/single-segment path has
            # no intermediates and keeps the 0o700 default).
            os.fchmod(dir_fd, dir_mode)
        leaf = rel.parts[-1]
        tmp_name = f".{leaf}.{secrets.token_hex(8)}.tmp"
        tfd = os.open(
            tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd
        )
        committed = False
        try:
            yield tfd
            os.fchmod(tfd, mode)  # exact mode regardless of umask (cross-uid serving)
            os.close(tfd)
            tfd = -1
            os.replace(tmp_name, leaf, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            committed = True
        finally:
            if tfd >= 0:
                os.close(tfd)
            if not committed:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    finally:
        os.close(dir_fd)


def read_confined_regular_bytes(base: Path, relpath: str, *, max_bytes: int) -> bytes:
    """TOCTOU-safe, size-capped read of ``base/relpath`` via :func:`open_confined_regular_fd`.

    Enforces ``max_bytes`` from a running total while reading (so growth on a live dir can't
    exceed the cap). Raises the same exceptions as :func:`open_confined_regular_fd`, plus
    ``ValueError`` if the file exceeds ``max_bytes``."""
    fd = open_confined_regular_fd(base, relpath)
    try:
        if os.fstat(fd).st_size > max_bytes:
            raise ValueError(f"{relpath!r} exceeds {max_bytes} bytes")
        out = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            out += chunk
            if len(out) > max_bytes:
                raise ValueError(f"{relpath!r} exceeds {max_bytes} bytes")
        return bytes(out)
    finally:
        os.close(fd)


def seal_envelope(*, engine: str, outdir: Path, input_sha256: str,
                  detected: Detection, declared: list[DeclaredArtifact],
                  warnings: list[Warning], payload: ChildNode,
                  status: Literal["ok", "rejected", "engine_error"] = "ok",
                  max_artifact_bytes: int | None = None) -> Envelope:
    """Seal declared artifacts + payload into a validated Envelope.

    Computes sha256/bytes from disk, confines every path under outdir, and
    verifies every ArtifactRef in the payload resolves to a declared id.
    Raises ValueError on any violation — the worker must not emit on failure.

    Size is taken from ``stat()`` and (when ``max_artifact_bytes`` is set) the cap is
    enforced **before** any bytes are read, then the hash is computed in CHUNKS — so a
    malicious worker declaring a giant artifact is rejected without the host ever reading
    the whole file into memory.
    """
    artifacts: list[Artifact] = []
    declared_ids: set[str] = set()
    for d in declared:
        if d.id in declared_ids:
            raise ValueError(f"duplicate artifact id: {d.id}")
        declared_ids.add(d.id)
        # Reserve metadata.json (+ the atomic-write temp prefix): the host OVERWRITES
        # metadata.json with the SEALED envelope after sealing, so a worker declaring it as an
        # artifact would record a sha256/bytes for the OLD raw file while the host serves the new
        # sealed one — desyncing served-bytes from the sealed hash. Reject it.
        _name = Path(d.path).name
        if _name == "metadata.json" or _name.startswith(".metadata.json."):
            raise ValueError(f"reserved output path may not be a declared artifact: {d.path}")
        # TOCTOU-safe open: confines under outdir AND rejects symlink/.. components + special
        # files in one walk (no separate resolve()/is_file()/open() the worker could race on a
        # still-live bind mount). ENOENT -> "missing"; everything else (escape, symlink, FIFO,
        # device, dir) -> a confinement failure.
        try:
            fd = open_confined_regular_fd(outdir, d.path)
        except FileNotFoundError as exc:
            raise ValueError(f"declared artifact file missing: {d.path}") from exc
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"declared artifact path not confined to outdir or not a regular file: "
                f"{d.path} ({exc})"
            ) from exc
        try:
            size = os.fstat(fd).st_size
            if max_artifact_bytes is not None and size > max_artifact_bytes:
                # Reject BEFORE reading — no unbounded read into memory from a hostile worker.
                raise ValueError(
                    f"declared artifact {d.path} size {size} exceeds {max_artifact_bytes}"
                )
            sha256, n = _hash_fd(fd, max_bytes=max_artifact_bytes)
        finally:
            os.close(fd)
        artifacts.append(Artifact(id=d.id, path=d.path, kind=d.kind, sha256=sha256, bytes=n))
    unresolved = _collect_refs(payload) - declared_ids
    if unresolved:
        raise ValueError(f"payload has unresolved ArtifactRef(s): {sorted(unresolved)}")
    return Envelope(engine=engine, status=status, input_sha256=input_sha256,
                    detected=detected, artifacts=artifacts, warnings=warnings,
                    payload=payload)


def validate_envelope(env: Envelope, *, outdir: Path, max_artifact_bytes: int,
                      max_total_bytes: int, max_artifacts: int) -> Envelope:
    """Host-side re-validation: enforce count/size bounds and verify on-disk sizes.

    Re-stats every artifact file under outdir to confirm st_size matches
    the declared bytes (so a tampered worker-reported size is caught).
    Raises ValueError on any violation.
    """
    if len(env.artifacts) > max_artifacts:
        raise ValueError(f"artifact count {len(env.artifacts)} exceeds {max_artifacts}")
    outdir_resolved = outdir.resolve(strict=False)
    total = 0
    for a in env.artifacts:
        target = (outdir / a.path).resolve(strict=False)
        if outdir_resolved != target and outdir_resolved not in target.parents:
            raise ValueError(f"artifact path not confined to outdir: {a.path}")
        if not target.is_file():
            raise ValueError(f"artifact file missing or not a regular file: {a.path}")
        actual_size = target.stat().st_size
        if actual_size != a.bytes:
            raise ValueError(
                f"artifact {a.id} declared bytes={a.bytes} but on-disk size={actual_size}"
            )
        if actual_size > max_artifact_bytes:
            raise ValueError(f"artifact {a.id} bytes {actual_size} exceeds {max_artifact_bytes}")
        total += actual_size
    if total > max_total_bytes:
        raise ValueError(f"total artifact bytes {total} exceeds {max_total_bytes}")
    return env


# Backstop nesting bound enforced at PARSE time (matches contract/walk._MAX_DEPTH=128, which
# only guards consumers that iter_nodes). Counts EVERY nested dict/list — including Record.fields
# (a second recursion vector iter_nodes never walks) — so a deep payload is rejected with a clean
# ValueError rather than relying on a catchable RecursionError whose threshold depends on
# sys.getrecursionlimit.
_MAX_PAYLOAD_DEPTH = 128


def _check_json_depth(obj: object, max_depth: int) -> None:
    """Reject if the nested dict/list structure of ``obj`` exceeds ``max_depth`` (iterative —
    no recursion, so the check itself can't blow the stack)."""
    stack: list[tuple[object, int]] = [(obj, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"payload nesting exceeds maximum depth of {max_depth}")
        if isinstance(node, dict):
            for v in node.values():
                stack.append((v, depth + 1))
        elif isinstance(node, list):
            for v in node:
                stack.append((v, depth + 1))


def _raw_json_max_depth(raw: bytes) -> int:
    """Max nesting depth of unescaped ``{``/``[`` in raw JSON bytes — string-aware (brackets
    inside string literals don't count). Used to reject deep input BEFORE ``json.loads``, which
    itself raises RecursionError on deeply nested input (the C scanner recurses)."""
    depth = 0
    maxd = 0
    in_str = False
    esc = False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:  # backslash
                esc = True
            elif b == 0x22:  # closing quote
                in_str = False
            continue
        if b == 0x22:  # opening quote
            in_str = True
        elif b == 0x7B or b == 0x5B:  # { or [
            depth += 1
            if depth > maxd:
                maxd = depth
        elif b == 0x7D or b == 0x5D:  # } or ]
            depth -= 1
    return maxd


def envelope_from_json(raw: bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Envelope:
    """Parse a worker-emitted metadata.json into an Envelope (size + depth bounded)."""
    if len(raw) > max_bytes:
        raise ValueError(f"metadata json {len(raw)} bytes exceeds {max_bytes}")
    # Bound nesting depth on the RAW bytes BEFORE json.loads — json.loads itself RecursionErrors
    # on deep input, so the post-parse structural check alone was too late.
    if _raw_json_max_depth(raw) > _MAX_PAYLOAD_DEPTH:
        raise ValueError(f"JSON nesting exceeds maximum depth of {_MAX_PAYLOAD_DEPTH}")
    import json
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("envelope JSON must be a JSON object")
    payload_data = obj.get("payload")
    if payload_data is None:
        raise ValueError("envelope JSON missing required 'payload' field")
    # Belt-and-suspenders structural depth check on the parsed payload subtree.
    _check_json_depth(payload_data, _MAX_PAYLOAD_DEPTH)
    obj["payload"] = parse_node(payload_data)
    return Envelope.model_validate(obj)
