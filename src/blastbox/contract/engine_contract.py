"""Engine output contracts: what an engine promises to emit, checked against what it emitted.

The sealed Envelope (``envelope.py``) proves a result is *well-formed*. It cannot say whether
it is the result *this engine* promised: that the screenshots it advertises are present, that
it never writes a file kind nobody maps, that its payload is built from the node types its
consumers walk. An engine contract (``blastbox-engine.toml`` at the engine repo root) states
that promise; :func:`check_envelope` / :func:`check_result` compare a real result against it.

The contract is the producer's side only. Consumers (e.g. Loadout) keep their own manifest and
output mapper and should check they reference an engine that ships a contract.
"""
from __future__ import annotations

import dataclasses
from collections import deque
import fnmatch
import importlib
import json
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .nodes import _Node

SCHEMA = "blastbox-engine-contract/1"
CONTRACT_FILENAME = "blastbox-engine.toml"

_NETWORK_POLICIES = frozenset({
    "none", "drop", "direct", "inetsim", "tor", "socks", "httpproxy", "wireguard", "openvpn",
})


Status = Literal["ok", "rejected", "engine_error"]


def _all_statuses() -> list[Status]:
    return ["ok", "rejected", "engine_error"]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class EngineSection(_Strict):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    formats: list[str] = Field(min_length=1)
    network: list[str] = Field(default_factory=lambda: ["none"], min_length=1)
    max_input_bytes: int | None = Field(default=None, gt=0)
    statuses: list[Status] = Field(default_factory=_all_statuses)

    @model_validator(mode="after")
    def _known_network(self) -> "EngineSection":
        unknown = set(self.network) - _NETWORK_POLICIES
        if unknown:
            raise ValueError(f"unknown network policies {sorted(unknown)}")
        return self


class ArtifactSpec(_Strict):
    """One family of declared artifacts. ``id`` and ``path`` are fnmatch globs."""
    id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=4096)
    kind: str = Field(min_length=1, max_length=64)
    required: bool = False
    max_count: int = Field(default=1, ge=0, description="0 = uncapped (the engine enforces no count)")
    max_bytes: int | None = Field(default=None, gt=0)
    role: str = Field(default="", max_length=64)
    description: str = ""


class PayloadSection(_Strict):
    root: str = Field(min_length=1)
    node_types: list[str] = Field(min_length=1)
    required_root_fields: list[str] = Field(default_factory=list)
    schema_version: str | None = None
    schema_field: str = Field(default="schema_version", min_length=1)

    @model_validator(mode="after")
    def _root_listed(self) -> "PayloadSection":
        if self.root not in self.node_types:
            raise ValueError("payload.root must be one of payload.node_types")
        return self


class DetectionSpec(_Strict):
    """A finding the engine's output carries that a consumer is expected to turn into a detection."""
    code: str = Field(min_length=1, max_length=128)
    severity: Literal["info", "low", "medium", "high", "critical"]
    source: str = Field(min_length=1, description="where in the output the finding lives")
    description: str = ""


class GapSpec(_Strict):
    """Something the output cannot express today. Recorded, not hidden."""
    id: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1)


class ConsumerSection(_Strict):
    name: str
    engine: str
    mapper: str = ""
    emits: list[str] = Field(default_factory=list)


class EngineContract(_Strict):
    schema_: Literal["blastbox-engine-contract/1"] = Field(alias="schema")
    engine: EngineSection
    artifacts: list[ArtifactSpec] = Field(default_factory=list)
    payload: PayloadSection
    detections: list[DetectionSpec] = Field(default_factory=list)
    gaps: list[GapSpec] = Field(default_factory=list)
    consumers: list[ConsumerSection] = Field(default_factory=list)


@dataclass(frozen=True)
class Violation:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


def load_contract(path: str | Path) -> EngineContract:
    """Parse and validate a contract file. Raises ``ValueError`` with every problem listed."""
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    try:
        return EngineContract.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"{path}: invalid engine contract\n{exc}") from None


def _matches(spec: ArtifactSpec, ident: str, path: str, kind: str) -> bool:
    return (fnmatch.fnmatchcase(ident, spec.id) and fnmatch.fnmatchcase(path, spec.path)
            and kind == spec.kind)


def _spec_for(contract: EngineContract, ident: str, path: str, kind: str) -> ArtifactSpec | None:
    for spec in contract.artifacts:
        if _matches(spec, ident, path, kind):
            return spec
    return None


def _node_type(node: object) -> str | None:
    value = getattr(node, "type", None)
    return value if isinstance(value, str) else None


_MAX_WALK_DEPTH = 256

# Artifacts the HOST appends to a sealed envelope after validating the worker's output (the netd
# capture and its TLS-decrypted/mixed derivatives, ``host/dispatch.py``). They are not the
# engine's output, so an engine contract never lists them; matched on the exact
# (id, kind, path) the host writes. Known residual: the host does not reserve that triple, so a
# worker that declares it exactly is indistinguishable in a sealed envelope; check_result (the
# engine's own tests) never applies the exemption and catches it there.
_HOST_ARTIFACTS: frozenset[tuple[str, str, str]] = frozenset({
    ("network.capture.pcap", "network_capture", "capture/dump.pcap"),
    ("network.capture.decrypted.pcap", "network_capture_decrypted", "capture/decrypted.pcap"),
    ("network.capture.mixed.pcap", "network_capture_mixed", "capture/mixed.pcap"),
})

_NO_CAPTURE_NETWORKS = frozenset({"none", "drop"})

# The node types every host can parse. register_node_type registers into the process that
# imports the engine; the dispatcher's trust gate never imports engine modules, so any other
# type fails its schema validation (magika._sealed records it live) -- seal it as a Record.
_HOST_NODE_TYPES = frozenset({"page", "embedded_resource", "extracted_text", "record"})

# Root names the host trust gate refuses as artifacts, nested paths included (host/attest.py
# RESERVED_NAMES: the signed receipt and its withheld marker). Mirrored here because host/attest
# needs the host extra (cryptography); a test pins the two equal.
_HOST_RESERVED_NAMES = ("attestation.json", "attestation.withheld.json")

# The payload root the worker harness itself seals for an engine that raised or a precheck
# refusal (``harness.py``: engine_error / rejected): a Record, whatever the engine's root is.
_HARNESS_ERROR_NODE = "record"


def _payload_nodes(root: object) -> list[object]:
    """Every node in the payload: ``children`` AND node-bearing fields (``EmbeddedResource.metadata``,
    Records nested in ``Record.fields``, any node a registered engine type carries in its own
    fields, including inside plain pydantic models). ``walk.iter_nodes`` follows ``children`` only, which would let a node type the
    contract never declared ride in under ``metadata``."""
    found: list[object] = []
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > _MAX_WALK_DEPTH:
            raise ValueError(f"payload tree exceeds maximum nesting depth of {_MAX_WALK_DEPTH}")
        if isinstance(value, BaseModel):
            if isinstance(value, _Node):
                found.append(value)
            items: list[object] = [getattr(value, name, None) for name in type(value).model_fields]
            items.extend((getattr(value, "__pydantic_extra__", None) or {}).values())
        elif dataclasses.is_dataclass(value) and not isinstance(value, type):
            items = [getattr(value, f.name, None) for f in dataclasses.fields(value)]
        elif isinstance(value, dict):
            items = list(value.values())
        elif isinstance(value, (list, tuple, set, frozenset, deque)):
            items = list(value)
        else:
            continue
        stack.extend((item, depth + 1) for item in reversed(items)
                     if isinstance(item, (BaseModel, dict, list, tuple, set, frozenset, deque))
                     or (dataclasses.is_dataclass(item) and not isinstance(item, type)))
    return found


def _check(contract: EngineContract, *, engine: str | None, status: str,
           artifacts: list[tuple[str, str, str, int | None]], payload: object,
           missing_files: frozenset[str] = frozenset()) -> list[Violation]:
    out: list[Violation] = []
    if engine is not None and engine != contract.engine.name:
        out.append(Violation("engine_name", f"result is from {engine!r}, contract is {contract.engine.name!r}"))
    if status not in contract.engine.statuses:
        out.append(Violation("status", f"status {status!r} not in contract statuses {contract.engine.statuses}"))

    counts: dict[int, int] = {}
    present: set[int] = set()
    for ident, path, kind, size in artifacts:
        spec = _spec_for(contract, ident, path, kind)
        if path in missing_files:
            # Declared but not a regular file (absent, or a symlink): sealing refuses it.
            out.append(Violation("artifact_file_missing",
                                 f"{ident} declared at {path} but no regular file is there"))
            if spec is None:
                out.append(Violation("undeclared_artifact", f"{ident} ({kind}) at {path} matches no contract artifact"))
            continue
        if spec is None:
            out.append(Violation("undeclared_artifact", f"{ident} ({kind}) at {path} matches no contract artifact"))
            continue
        key = contract.artifacts.index(spec)
        counts[key] = counts.get(key, 0) + 1
        too_large = False
        # Counts go to the first matching family; presence and byte caps apply for every family
        # it matches, so an earlier catch-all glob can neither make a later required family look
        # absent nor carry an artifact past that family's max_bytes.
        for i, other in enumerate(contract.artifacts):
            if not _matches(other, ident, path, kind):
                continue
            present.add(i)
            if (other.max_bytes is not None and size is not None and size > other.max_bytes
                    and not too_large):
                too_large = True
                out.append(Violation("artifact_too_large", f"{ident} is {size} bytes, contract max {other.max_bytes}"))
    for key, spec in enumerate(contract.artifacts):
        n = counts.get(key, 0)
        if spec.max_count and n > spec.max_count:
            out.append(Violation("artifact_count", f"{spec.id}: {n} artifacts, contract max {spec.max_count}"))
        if spec.required and status == "ok" and key not in present:
            out.append(Violation("missing_artifact", f"required artifact {spec.id} ({spec.kind}) absent"))

    allowed = set(contract.payload.node_types)
    nodes = _payload_nodes(payload)
    if status != "ok" and _node_type(payload) == _HARNESS_ERROR_NODE:
        # The harness seals a bare Record ROOT for engine_error and for a precheck refusal
        # (status rejected); anything below the root is still the engine's and is checked.
        nodes = nodes[1:]
    seen = {t for t in (_node_type(n) for n in nodes) if t is not None}
    for t in sorted(seen - allowed):
        out.append(Violation("undeclared_node_type", f"payload contains {t!r}, not in contract node_types"))
    for t in sorted(seen - _HOST_NODE_TYPES):
        out.append(Violation("host_unknown_node_type",
                             f"payload contains {t!r}: the host trust gate never imports engine "
                             "modules, so it cannot parse a register_node_type type; seal it as "
                             "a Record (see engines/magika.py _sealed)"))

    if status == "ok":
        root_type = _node_type(payload)
        if root_type != contract.payload.root:
            out.append(Violation("payload_root", f"payload root is {root_type!r}, contract says {contract.payload.root!r}"))
        fields = getattr(payload, "fields", None)
        if fields is None:
            # Non-Record roots (EmbeddedResource) carry their typed bag in `metadata`.
            fields = getattr(getattr(payload, "metadata", None), "fields", None)
        if isinstance(fields, dict):
            for name in contract.payload.required_root_fields:
                if name not in fields:
                    out.append(Violation("missing_root_field", f"payload root lacks field {name!r}"))
            want, schema_key = contract.payload.schema_version, contract.payload.schema_field
            if want is not None and fields.get(schema_key) != want:
                out.append(Violation("schema_version",
                                     f"payload {schema_key} {fields.get(schema_key)!r}, contract {want!r}"))
        elif contract.payload.required_root_fields or contract.payload.schema_version:
            out.append(Violation("missing_root_field", "contract requires root fields but the root has no Record fields or metadata"))
    return out


def _host_cap_problems(env: Any, limits: Any, extra_bytes: int = 0) -> list[str]:
    """The host's output caps (``Limits``) applied to a sealed envelope: metadata size, artifact
    count, per-artifact and total bytes. The total includes metadata.json itself, as the cold and
    warm dispatchers count it (``Dispatcher._enforce_output_size_cap``), the stricter host path."""
    if limits is None:
        return []
    out: list[str] = []
    meta_len = len(env.model_dump_json(by_alias=True).encode())
    cap = getattr(limits, "max_metadata_bytes", None)
    if cap is not None and meta_len > cap:
        out.append(f"metadata.json {meta_len} bytes exceeds the host's max_metadata_bytes {cap}")
    n = getattr(limits, "max_artifacts", None)
    if n is not None and len(env.artifacts) > n:
        out.append(f"{len(env.artifacts)} artifacts exceed the host's max_artifacts {n}")
    per = getattr(limits, "max_artifact_bytes", None)
    for a in env.artifacts:
        if per is not None and a.bytes > per:
            out.append(f"artifact {a.id} is {a.bytes} bytes, over the host's max_artifact_bytes {per}")
    total_cap = getattr(limits, "max_total_artifact_bytes", None)
    total = sum(a.bytes for a in env.artifacts) + meta_len + extra_bytes
    if total_cap is not None and total > total_cap:
        parts = f"artifacts + metadata.json{' + undeclared files in outdir' if extra_bytes else ''}"
        out.append(f"{total} output bytes ({parts}"
                   f"{f', {extra_bytes} of them undeclared' if extra_bytes else ''}) exceed the "
                   f"host's max_total_artifact_bytes {total_cap}")
    return out


def _host_reserved(path: str) -> str | None:
    parts = PurePosixPath(path).parts
    parts = parts[1:] if parts and parts[0] == "/" else parts
    return parts[0] if parts and parts[0] in _HOST_RESERVED_NAMES else None


def _undeclared_bytes(outdir: Path, env: Any) -> int:
    """Bytes of regular files under ``outdir`` that are not declared artifacts (nor the harness's
    metadata.json): the cold/warm dispatcher's output cap counts every file in the tree."""
    declared = {PurePosixPath(a.path).as_posix() for a in env.artifacts} | {"metadata.json"}
    total = 0
    for root, _dirs, files in os.walk(outdir):
        for name in files:
            p = Path(root) / name
            rel = p.relative_to(outdir).as_posix()
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and rel not in declared:
                total += st.st_size
    return total


def check_envelope(contract: EngineContract, envelope: Any, *, limits: Any = None) -> list[Violation]:
    """Check a sealed ``Envelope`` (or its parsed JSON) against the contract. Empty list = conforms.
    With ``limits`` (a host's ``Limits``), also report its output caps as ``host_limit``."""
    from .envelope import Envelope

    env = envelope if isinstance(envelope, Envelope) else Envelope.model_validate(envelope)
    # The host seals a capture only for an exit driver other than none/drop, so the exemption
    # applies only when the contract allows one. A sealed envelope cannot say who wrote a file;
    # an engine's own tests (check_result) never get the exemption.
    captures = bool(set(contract.engine.network) - _NO_CAPTURE_NETWORKS)
    arts: list[tuple[str, str, str, int | None]] = [
        (a.id, a.path, a.kind, a.bytes) for a in env.artifacts
        if not (captures and (a.id, a.kind, a.path) in _HOST_ARTIFACTS)]
    caps = [Violation("host_limit", p) for p in _host_cap_problems(env, limits)]
    caps += [Violation("reserved_path", f"{a.id} at {a.path}: the host trust gate refuses {r}")
             for a in env.artifacts for r in [_host_reserved(a.path)] if r]
    # What the trust gate's re-seal (seal_envelope) refuses: the reserved root metadata.json,
    # duplicate ids, ArtifactRefs to undeclared ids; plus its JSON depth/schema parse.
    from .envelope import _collect_refs, envelope_from_json

    for a in env.artifacts:
        parts = PurePosixPath(a.path).parts
        if parts and (parts[0] == "metadata.json" or parts[0].startswith(".metadata.json.")):
            caps.append(Violation("reserved_path", f"{a.id} at {a.path}: the seal refuses the "
                                  "reserved root metadata.json"))
    from .envelope import DeclaredArtifact

    for a in env.artifacts:
        try:   # the host re-seal rebuilds each entry as a DeclaredArtifact
            DeclaredArtifact(id=a.id, path=a.path, kind=a.kind)
        except ValidationError as exc:
            caps.append(Violation("unsealable", f"artifact {a.id!r}: the host re-seal rejects it: "
                                  f"{exc.errors()[0].get('msg', exc)}"))
        pp = PurePosixPath(a.path)
        if pp.is_absolute() or ".." in pp.parts:
            caps.append(Violation("unsealable", f"{a.id} at {a.path}: not confined to outdir (the "
                                  "host re-seal refuses absolute and '..' paths)"))
    ids = [a.id for a in env.artifacts]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    if dups:
        caps.append(Violation("unsealable", f"duplicate artifact id(s) {dups}: the host re-seal refuses them"))
    unresolved = sorted(_collect_refs(env.payload) - set(ids))
    if unresolved:
        caps.append(Violation("unsealable", f"payload has unresolved ArtifactRef(s) {unresolved}: "
                              "the host re-seal refuses them"))
    try:
        envelope_from_json(env.model_dump_json(by_alias=True).encode(), max_bytes=sys.maxsize)
    except ValueError as exc:
        caps.append(Violation("unsealable", f"the host trust gate would refuse this envelope: {exc}"))
    return caps + _check(contract, engine=env.engine, status=env.status, artifacts=arts,
                         payload=env.payload)


def check_result(contract: EngineContract, result: Any, outdir: str | Path | None = None, *,
                 limits: Any = None) -> list[Violation]:
    """Check an unsealed ``DetonationResult`` (what an engine's own tests hold). With ``outdir``,
    byte caps are checked from the files on disk."""
    if limits is not None and outdir is None:
        raise TypeError("check_result(limits=...) needs outdir: the host caps are judged on the "
                        "sealed output")
    arts: list[tuple[str, str, str, int | None]] = []
    missing: set[str] = set()
    unsealable: list[Violation] = []
    if outdir is not None:
        # Whatever the harness's seal would refuse (a path escaping outdir through a symlinked
        # parent, an absolute or `..` path, the reserved metadata.json, a duplicate id, a dangling
        # ArtifactRef) turns every real job into engine_error; say so rather than re-implement it.
        from .envelope import envelope_from_json, seal_envelope

        _payload_nodes(result.payload)  # depth cap first: the seal's ref walk has none
        # Sealed exactly as the harness does (everything verbatim), then parsed the way the host
        # trust gate parses metadata.json (its JSON depth bound is tighter than the walker's).
        try:
            env = seal_envelope(engine=contract.engine.name, outdir=Path(outdir),
                                input_sha256="0" * 64, detected=result.detected,
                                declared=list(result.artifacts), warnings=result.warnings,
                                payload=result.payload, status=result.status,
                                max_artifact_bytes=getattr(limits, "max_artifact_bytes", None))
            # The worker harness writes metadata.json uncapped; the host gate caps it at
            # limits.max_metadata_bytes, so only judge the size when the caller says which host.
            cap = getattr(limits, "max_metadata_bytes", None) or sys.maxsize
            envelope_from_json(env.model_dump_json(by_alias=True).encode(), max_bytes=cap)
            problems = _host_cap_problems(env, limits, _undeclared_bytes(Path(outdir), env)
                                          if limits is not None else 0)
            if problems:
                raise ValueError("; ".join(problems))
        except (ValueError, OSError) as exc:
            note = (" (detected is None: the harness accepts that only when engine.detect() "
                    "supplies one at pre-detection)" if result.detected is None else "")
            unsealable.append(Violation(
                "unsealable", f"the harness seal or host trust gate would refuse this result{note}: {exc}"))
    if outdir is not None:
        for a in result.artifacts:
            reserved = _host_reserved(a.path)
            if reserved:
                unsealable.append(Violation("reserved_path",
                                            f"{a.id} at {a.path}: the host trust gate refuses {reserved}"))
        meta = Path(outdir) / "metadata.json"
        # The harness's atomic rename replaces a symlink/FIFO there; only a directory breaks it.
        if meta.is_dir() and not meta.is_symlink():
            unsealable.append(Violation(
                "reserved_path", "outdir/metadata.json is a directory: the harness cannot write "
                "the sealed envelope there and every job fails"))
    for a in result.artifacts:
        size = None
        if outdir is not None:
            try:
                st = os.lstat(Path(outdir) / a.path)
            except (OSError, ValueError):   # ValueError: an embedded NUL
                st = None
            if st is not None and stat.S_ISREG(st.st_mode):
                size = st.st_size
            else:
                missing.add(a.path)
        arts.append((a.id, a.path, a.kind, size))
    return unsealable + _check(contract, engine=None, status=result.status, artifacts=arts,
                               payload=result.payload, missing_files=frozenset(missing))


def builtin_contract(name: str) -> EngineContract:
    """The contract shipped for a blastbox built-in engine (``blastbox/engines/contracts/<name>.toml``)."""
    return load_contract(Path(__file__).resolve().parents[1] / "engines" / "contracts" / f"{name}.toml")


def assert_conforms(contract: EngineContract, result: Any, outdir: str | Path | None = None, *,
                    check_name: bool = True, limits: Any = None) -> None:
    """Test helper: raise ``AssertionError`` listing every violation. Accepts a sealed Envelope,
    its parsed ``metadata.json``, or an unsealed ``DetonationResult``. ``limits`` (a host's
    ``Limits``) is passed to :func:`check_result` for an unsealed result."""
    if hasattr(result, "artifacts") and not hasattr(result, "input_sha256") and not isinstance(result, dict):
        problems = check_result(contract, result, outdir, limits=limits)
    else:
        problems = check_envelope(contract, result, limits=limits)
    if not check_name:
        problems = [p for p in problems if p.code != "engine_name"]
    if problems:
        raise AssertionError(f"{contract.engine.name} violates its engine contract:\n"
                             + "\n".join(f"  {p}" for p in problems))


_UNPARSEABLE = object()


def _contract_engine_name(path: Path) -> object:
    """``[engine].name``, None when absent, or ``_UNPARSEABLE`` when the file cannot be read
    as TOML (then the caller returns it so ``load_contract`` reports the real error)."""
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return _UNPARSEABLE
    engine = data.get("engine")
    name = engine.get("name") if isinstance(engine, dict) else None
    return name if isinstance(name, str) else None


def _textual_engine_name(path: Path) -> str | None:
    """The ``[engine]`` table's ``name = "..."`` in a contract that does not parse (best effort)."""
    try:
        text = path.read_bytes()[:65536].decode("utf-8", errors="replace")
    except OSError:
        return None
    # Only inside the [engine] table: [[consumers]] also has a name.
    table = re.search(r'^\s*\[engine\]\s*(?:#[^\n]*)?$(.*?)(?=^\s*\[)', text + "\n[",
                      re.MULTILINE | re.DOTALL)
    if table is None:
        return None
    m = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', table.group(1), re.MULTILINE)
    return m.group(1) if m else None


def find_contract(start: str | Path, engine: str | None = None) -> Path | None:
    """Walk up from ``start`` to the nearest contract.

    With ``engine``, each directory (nearest first) offers its ``blastbox-engine.<engine>.toml``,
    then its plain ``blastbox-engine.toml`` only when that file's ``[engine].name`` is
    ``engine``: it never silently returns another engine's contract. An unparseable plain
    contract is returned only if no matching contract exists further up."""
    here = Path(start).resolve()
    broken: Path | None = None
    for d in (here, *here.parents):
        if engine:
            candidate = d / f"blastbox-engine.{engine}.toml"
            if candidate.is_file():
                return candidate
        candidate = d / CONTRACT_FILENAME
        if candidate.is_file():
            if engine is None:
                return candidate
            name = _contract_engine_name(candidate)
            if name == engine:
                return candidate
            if name is _UNPARSEABLE or name is None:
                # Whose is it? A broken file that still SAYS name = "<engine>" is this engine's
                # own (e.g. a worktree being edited): return it so load_contract reports the
                # error. One that names nobody is the fallback if nothing matches further up.
                claimed = _textual_engine_name(candidate)
                if claimed == engine:
                    return candidate
                if claimed is None and broken is None:
                    broken = candidate
    # No matching contract anywhere: hand back the nearest unparseable one so load_contract
    # reports its real error instead of a None TypeError.
    return broken


_USAGE = """usage: python -m blastbox.contract.engine_contract validate CONTRACT
       python -m blastbox.contract.engine_contract check [--import MODULE]... CONTRACT ENVELOPE.json

--import MODULE imports the engine module that calls ``register_node_type`` for its custom payload
nodes, so the envelope's payload can be parsed (repeatable)."""


def main(argv: list[str] | None = None) -> int:
    """Command line entry point; see ``_USAGE``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "validate":
        try:
            c = load_contract(args[1])
        except (ValueError, OSError) as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"ok: {c.engine.name} ({len(c.artifacts)} artifact families, {len(c.gaps)} gaps)")
        return 0
    if args and args[0] == "check":
        rest, modules = args[1:], []
        while len(rest) >= 2 and rest[0] == "--import":
            modules.append(rest[1])
            rest = rest[2:]
        if len(rest) == 2 and not rest[0].startswith("--"):
            try:
                for module in modules:
                    importlib.import_module(module)
                c = load_contract(rest[0])
                env = json.loads(Path(rest[1]).read_text())
                problems = check_envelope(c, env)
            except (ImportError, ValueError, OSError, ValidationError) as exc:
                print(exc, file=sys.stderr)
                return 1
            for p in problems:
                print(p)
            print("conforms" if not problems else f"{len(problems)} violation(s)")
            return 0 if not problems else 1
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
