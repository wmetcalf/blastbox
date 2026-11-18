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

import fnmatch
import importlib
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
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
# (id, kind, path) the host writes so an engine cannot hide an undeclared file behind the id.
_HOST_ARTIFACTS: frozenset[tuple[str, str, str]] = frozenset({
    ("network.capture.pcap", "network_capture", "capture/dump.pcap"),
    ("network.capture.decrypted.pcap", "network_capture_decrypted", "capture/decrypted.pcap"),
    ("network.capture.mixed.pcap", "network_capture_mixed", "capture/mixed.pcap"),
})

# The payload the worker harness itself seals for an engine that raised (``harness.py``
# ``_engine_error_envelope``): a Record, whatever the engine's own root type is.
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
        elif isinstance(value, dict):
            items = list(value.values())
        elif isinstance(value, (list, tuple)):
            items = list(value)
        else:
            continue
        stack.extend((item, depth + 1) for item in reversed(items)
                     if isinstance(item, (BaseModel, dict, list, tuple)))
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
        if path in missing_files:
            # Declared but never written: sealing rejects this, so it is not present.
            out.append(Violation("artifact_file_missing", f"{ident} declared at {path} but no file is there"))
            continue
        spec = _spec_for(contract, ident, path, kind)
        if spec is None:
            out.append(Violation("undeclared_artifact", f"{ident} ({kind}) at {path} matches no contract artifact"))
            continue
        key = contract.artifacts.index(spec)
        counts[key] = counts.get(key, 0) + 1
        # Caps go to the first matching family; presence counts for every family it matches,
        # so an earlier catch-all glob cannot make a later required family look absent.
        present.update(i for i, other in enumerate(contract.artifacts)
                       if _matches(other, ident, path, kind))
        if spec.max_bytes is not None and size is not None and size > spec.max_bytes:
            out.append(Violation("artifact_too_large", f"{ident} is {size} bytes, contract max {spec.max_bytes}"))
    for key, spec in enumerate(contract.artifacts):
        n = counts.get(key, 0)
        if spec.max_count and n > spec.max_count:
            out.append(Violation("artifact_count", f"{spec.id}: {n} artifacts, contract max {spec.max_count}"))
        if spec.required and status == "ok" and key not in present:
            out.append(Violation("missing_artifact", f"required artifact {spec.id} ({spec.kind}) absent"))

    allowed = set(contract.payload.node_types)
    if status != "ok":
        allowed.add(_HARNESS_ERROR_NODE)
    seen = {t for t in (_node_type(n) for n in _payload_nodes(payload)) if t is not None}
    for t in sorted(seen - allowed):
        out.append(Violation("undeclared_node_type", f"payload contains {t!r}, not in contract node_types"))

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


def check_envelope(contract: EngineContract, envelope: Any) -> list[Violation]:
    """Check a sealed ``Envelope`` (or its parsed JSON) against the contract. Empty list = conforms."""
    from .envelope import Envelope

    env = envelope if isinstance(envelope, Envelope) else Envelope.model_validate(envelope)
    arts: list[tuple[str, str, str, int | None]] = [
        (a.id, a.path, a.kind, a.bytes) for a in env.artifacts
        if (a.id, a.kind, a.path) not in _HOST_ARTIFACTS]
    return _check(contract, engine=env.engine, status=env.status, artifacts=arts, payload=env.payload)


def check_result(contract: EngineContract, result: Any, outdir: str | Path | None = None) -> list[Violation]:
    """Check an unsealed ``DetonationResult`` (what an engine's own tests hold). With ``outdir``,
    byte caps are checked from the files on disk."""
    arts: list[tuple[str, str, str, int | None]] = []
    missing: set[str] = set()
    for a in result.artifacts:
        size = None
        if outdir is not None:
            p = Path(outdir) / a.path
            if p.is_file() and not p.is_symlink():
                size = p.stat().st_size
            else:
                missing.add(a.path)
        arts.append((a.id, a.path, a.kind, size))
    return _check(contract, engine=None, status=result.status, artifacts=arts, payload=result.payload,
                  missing_files=frozenset(missing))


def builtin_contract(name: str) -> EngineContract:
    """The contract shipped for a blastbox built-in engine (``blastbox/engines/contracts/<name>.toml``)."""
    return load_contract(Path(__file__).resolve().parents[1] / "engines" / "contracts" / f"{name}.toml")


def assert_conforms(contract: EngineContract, result: Any, outdir: str | Path | None = None, *,
                    check_name: bool = True) -> None:
    """Test helper: raise ``AssertionError`` listing every violation. Accepts a sealed Envelope,
    its parsed ``metadata.json``, or an unsealed ``DetonationResult``."""
    if hasattr(result, "artifacts") and not hasattr(result, "input_sha256") and not isinstance(result, dict):
        problems = check_result(contract, result, outdir)
    else:
        problems = check_envelope(contract, result)
    if not check_name:
        problems = [p for p in problems if p.code != "engine_name"]
    if problems:
        raise AssertionError(f"{contract.engine.name} violates its engine contract:\n"
                             + "\n".join(f"  {p}" for p in problems))


def _contract_engine_name(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            name = tomllib.load(fh).get("engine", {}).get("name")
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        return None
    return name if isinstance(name, str) else None


def find_contract(start: str | Path, engine: str | None = None) -> Path | None:
    """Walk up from ``start`` to the nearest contract.

    With ``engine``, a multi-engine repo's ``blastbox-engine.<engine>.toml`` is found wherever it
    sits on the way up, and a plain ``blastbox-engine.toml`` is accepted only when its
    ``[engine].name`` is ``engine``: it never silently returns another engine's contract."""
    here = Path(start).resolve()
    dirs = (here, *here.parents)
    if engine:
        for d in dirs:
            candidate = d / f"blastbox-engine.{engine}.toml"
            if candidate.is_file():
                return candidate
    for d in dirs:
        candidate = d / CONTRACT_FILENAME
        if candidate.is_file() and (engine is None or _contract_engine_name(candidate) == engine):
            return candidate
    return None


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
