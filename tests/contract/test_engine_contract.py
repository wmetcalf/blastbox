"""Engine output contracts: load, validate, and check real results against them."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from blastbox.contract import (
    DeclaredArtifact, Detection, Dimensions, ArtifactRef, Page, Record, seal_envelope,
)
from blastbox.contract.engine_contract import (
    CONTRACT_FILENAME, check_envelope, check_result, find_contract, load_contract, main,
)
from blastbox.worker.engine import DetonationResult

CONTRACT = """
schema = "blastbox-engine-contract/1"

[engine]
name = "demo"
formats = ["ics"]
network = ["none"]

[[artifacts]]
id = "manifest"
path = "manifest.json"
kind = "file"
required = true

[[artifacts]]
id = "page-*"
path = "pages/*.png"
kind = "image"
max_count = 2
max_bytes = 64

[payload]
root = "record"
node_types = ["record", "page"]
required_root_fields = ["schema_version"]
schema_version = "demo/1"

[[detections]]
code = "demo.bad"
severity = "high"
source = "manifest.json findings[]"

[[gaps]]
id = "free-text"
description = "alerts are free text"
"""

DET = Detection(label="ics", mime="text/calendar", confidence=1.0, source="test")


@pytest.fixture
def contract_path(tmp_path: Path) -> Path:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT)
    return p


def _outdir(tmp_path: Path, pages: int = 1, page_bytes: int = 8) -> Path:
    out = tmp_path / "out"
    (out / "pages").mkdir(parents=True)
    (out / "manifest.json").write_text("{}")
    for i in range(pages):
        (out / "pages" / f"{i}.png").write_bytes(b"x" * page_bytes)
    return out


def _result(pages: int = 1, *, schema: str = "demo/1", extra: list[DeclaredArtifact] | None = None,
            status: str = "ok") -> DetonationResult:
    declared = [DeclaredArtifact(id="manifest", path="manifest.json", kind="file")]
    declared += [DeclaredArtifact(id=f"page-{i}", path=f"pages/{i}.png", kind="image") for i in range(pages)]
    declared += extra or []
    payload: Record | Page = Record(fields={"schema_version": schema})
    if schema == "page-root":
        payload = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"), image=ArtifactRef(id="page-0"))
    return DetonationResult(payload=payload, artifacts=declared, detected=DET, status=status)  # type: ignore[arg-type]


def test_load_contract(contract_path: Path) -> None:
    c = load_contract(contract_path)
    assert c.engine.name == "demo"
    assert [a.id for a in c.artifacts] == ["manifest", "page-*"]
    assert c.gaps[0].id == "free-text"


def test_load_rejects_unknown_keys_and_network(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('network = ["none"]', 'network = ["internet"]'))
    with pytest.raises(ValueError, match="unknown network"):
        load_contract(p)
    p.write_text(CONTRACT + '\nsurprise = 1\n')
    with pytest.raises(ValueError, match="invalid engine contract"):
        load_contract(p)


def test_root_must_be_listed(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "extracted_text"'))
    with pytest.raises(ValueError, match="payload.root"):
        load_contract(p)


def test_conforming_result(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    assert check_result(load_contract(contract_path), _result(), out) == []


def test_conforming_sealed_envelope_and_cli(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    assert check_envelope(load_contract(contract_path), env) == []
    env_json = tmp_path / "metadata.json"
    env_json.write_text(env.model_dump_json(by_alias=True))
    assert main(["check", str(contract_path), str(env_json)]) == 0
    assert main(["validate", str(contract_path)]) == 0


def test_violations(contract_path: Path, tmp_path: Path) -> None:
    c = load_contract(contract_path)
    out = _outdir(tmp_path, pages=3, page_bytes=100)
    extra = [DeclaredArtifact(id="debug", path="debug.log", kind="file")]
    (out / "debug.log").write_text("x")
    codes = {v.code for v in check_result(c, _result(pages=3, schema="demo/0", extra=extra), out)}
    assert {"undeclared_artifact", "artifact_count", "artifact_too_large", "schema_version"} <= codes


def test_missing_required_only_when_ok(contract_path: Path) -> None:
    c = load_contract(contract_path)
    r = DetonationResult(payload=Record(fields={"schema_version": "demo/1"}), artifacts=[], detected=DET)
    assert {v.code for v in check_result(c, r)} == {"missing_artifact"}
    rejected = DetonationResult(payload=Record(), artifacts=[], detected=DET, status="rejected")
    assert check_result(c, rejected) == []


def test_payload_root_and_node_types(contract_path: Path) -> None:
    c = load_contract(contract_path)
    r = _result(schema="page-root")
    codes = {v.code for v in check_result(c, r)}
    assert "payload_root" in codes


def test_engine_name_mismatch(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="other", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    assert [v.code for v in check_envelope(load_contract(contract_path), env)] == ["engine_name"]


def test_cli_reports_violations(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="other", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    env_json = tmp_path / "metadata.json"
    env_json.write_text(json.dumps(json.loads(env.model_dump_json(by_alias=True))))
    assert main(["check", str(contract_path), str(env_json)]) == 1
    assert main(["bogus"]) == 2


def test_find_contract(contract_path: Path) -> None:
    nested = contract_path.parent / "a" / "b"
    nested.mkdir(parents=True)
    assert find_contract(nested) == contract_path


def test_max_count_zero_is_uncapped(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace("max_count = 2", "max_count = 0"))
    out = _outdir(tmp_path, pages=5)
    assert check_result(load_contract(p), _result(pages=5), out) == []


def test_find_contract_multi_engine(tmp_path: Path) -> None:
    (tmp_path / "blastbox-engine.email-render.toml").write_text(CONTRACT)
    nested = tmp_path / "src"
    nested.mkdir()
    assert find_contract(nested, "email-render") == tmp_path / "blastbox-engine.email-render.toml"
    assert find_contract(nested) is None


def test_required_fields_on_embedded_resource_root(tmp_path: Path) -> None:
    from blastbox.contract import EmbeddedResource
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "embedded_resource"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["embedded_resource", "record", "page"]'))
    c = load_contract(p)
    def res(meta: dict) -> DetonationResult:
        root = EmbeddedResource(embedded_path="", content_type="message/rfc822", depth=0,
                                metadata=Record(fields=meta))
        return DetonationResult(payload=root, artifacts=[DeclaredArtifact(id="manifest", path="manifest.json", kind="file")],
                                detected=DET)
    assert check_result(c, res({"schema_version": "demo/1"})) == []
    assert {v.code for v in check_result(c, res({}))} == {"missing_root_field", "schema_version"}


def test_builtin_engines_ship_contracts() -> None:
    """Every engine bundled in blastbox has a contract next to it and the contract validates."""
    root = Path(__file__).resolve().parents[2] / "src" / "blastbox" / "engines"
    engines = sorted(p.stem for p in root.glob("*.py") if p.stem != "__init__")
    missing = [e for e in engines if not (root / "contracts" / f"{e}.toml").is_file()]
    assert missing == []
    for e in engines:
        assert load_contract(root / "contracts" / f"{e}.toml").engine.name


def test_node_types_cover_metadata_and_nested_records(tmp_path: Path) -> None:
    """`payload.node_types` constrains types anywhere in the tree -- including the Record behind
    EmbeddedResource.metadata and Records nested in Record.fields, not only `children`."""
    from blastbox.contract import EmbeddedResource
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "embedded_resource"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["embedded_resource"]')
                 .replace('required_root_fields = ["schema_version"]\nschema_version = "demo/1"\n', ''))
    c = load_contract(p)
    manifest = [DeclaredArtifact(id="manifest", path="manifest.json", kind="file")]
    bare = EmbeddedResource(embedded_path="", content_type="message/rfc822", depth=0)
    assert check_result(c, DetonationResult(payload=bare, artifacts=manifest, detected=DET)) == []
    with_meta = EmbeddedResource(embedded_path="", content_type="message/rfc822", depth=0,
                                 metadata=Record(fields={"k": "v"}))
    assert [v.code for v in check_result(c, DetonationResult(payload=with_meta, artifacts=manifest,
                                                             detected=DET))] == ["undeclared_node_type"]
    # A Record nested in a Record's fields is a node too.
    p.write_text(CONTRACT.replace('node_types = ["record", "page"]', 'node_types = ["record"]'))
    c2 = load_contract(p)
    nested = Record(fields={"schema_version": "demo/1", "inner": Record(fields={"a": 1})})
    assert check_result(c2, DetonationResult(payload=nested, artifacts=manifest, detected=DET)) == []
    child = EmbeddedResource(embedded_path="x", content_type="text/plain", depth=1)
    deep = Record(fields={"schema_version": "demo/1", "inner": Record(fields={"a": 1})})
    holder = EmbeddedResource(embedded_path="", content_type="message/rfc822", depth=0,
                              metadata=deep, children=[child])
    p.write_text(CONTRACT.replace('root = "record"', 'root = "embedded_resource"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["embedded_resource", "page"]'))
    codes = [v.detail for v in check_result(load_contract(p), DetonationResult(
        payload=holder, artifacts=manifest, detected=DET))]
    assert any("'record'" in d for d in codes)


def test_cli_imports_registration_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A custom node registered by the engine's own module is parseable once the CLI imports it."""
    mod = tmp_path / "demo_nodes_mod.py"
    mod.write_text(
        "from typing import Literal\n"
        "from pydantic import Field\n"
        "from blastbox.contract.nodes import Record, register_node_type\n"
        "class DemoNode(Record):\n"
        "    type: Literal['demo_node'] = Field(default='demo_node', alias='_type')\n"
        "register_node_type(DemoNode)\n"
    )
    contract = tmp_path / CONTRACT_FILENAME
    contract.write_text(CONTRACT.replace('root = "record"', 'root = "demo_node"')
                        .replace('node_types = ["record", "page"]', 'node_types = ["demo_node"]')
                        .replace('required_root_fields = ["schema_version"]\nschema_version = "demo/1"\n', '')
                        .replace("max_count = 2", "max_count = 0"))
    out = _outdir(tmp_path)
    env_json = tmp_path / "metadata.json"
    # Built in a subprocess-free way: the envelope JSON a demo engine would emit.
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=_result().artifacts, warnings=[], payload=Record(fields={}))
    data = json.loads(env.model_dump_json(by_alias=True))
    data["payload"]["_type"] = "demo_node"
    env_json.write_text(json.dumps(data))
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        assert main(["check", "--import", "demo_nodes_mod", str(contract), str(env_json)]) == 0
        assert main(["check", "--import", "no_such_module_xyz", str(contract), str(env_json)]) == 1
    finally:
        from blastbox.contract import nodes
        nodes._ENGINE_NODE_TYPES[:] = [t for t in nodes._ENGINE_NODE_TYPES
                                       if getattr(t, "__module__", "") != "demo_nodes_mod"]
        nodes.rebuild_node_union()
