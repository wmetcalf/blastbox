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


def test_cli_imports_registration_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:
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
        # Parseable once imported -- but the host dispatcher never imports engine modules, so
        # the result is still reported as a node type the trust gate refuses.
        assert main(["check", "--import", "demo_nodes_mod", str(contract), str(env_json)]) == 1
        # Parsed (so the import worked) and reported as a type the host cannot parse.
        assert "host_unknown_node_type" in capsys.readouterr().out
        assert main(["check", "--import", "no_such_module_xyz", str(contract), str(env_json)]) == 1
    finally:
        from blastbox.contract import nodes
        nodes._ENGINE_NODE_TYPES[:] = [t for t in nodes._ENGINE_NODE_TYPES
                                       if getattr(t, "__module__", "") != "demo_nodes_mod"]
        nodes.rebuild_node_union()


def test_node_types_checked_on_every_status(contract_path: Path) -> None:
    """Root/field checks are ok-only, but a node type the contract never declared fails on any
    status. The harness's own error payload (a Record) is always allowed."""
    p = contract_path
    p.write_text(CONTRACT.replace('node_types = ["record", "page"]', 'node_types = ["record"]'))
    c = load_contract(p)
    page = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"), image=ArtifactRef(id="page-0"))
    bad = DetonationResult(payload=page, artifacts=[], detected=DET, status="engine_error")  # type: ignore[arg-type]
    assert [v.code for v in check_result(c, bad)] == ["undeclared_node_type"]
    p.write_text(CONTRACT.replace('root = "record"', 'root = "page"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["page"]'))
    harness_error = DetonationResult(payload=Record(fields={"error": "x"}), artifacts=[],
                                     detected=DET, status="engine_error")
    assert check_result(load_contract(p), harness_error) == []


def test_host_sealed_capture_artifacts_are_not_the_engines(contract_path: Path, tmp_path: Path) -> None:
    """The host appends netd capture pcaps to the sealed envelope; they are not engine output."""
    contract_path.write_text(CONTRACT.replace('network = ["none"]', 'network = ["inetsim"]'))
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    data = json.loads(env.model_dump_json(by_alias=True))
    for art_id, kind, path in (("network.capture.pcap", "network_capture", "capture/dump.pcap"),
                               ("network.capture.decrypted.pcap", "network_capture_decrypted",
                                "capture/decrypted.pcap")):
        data["artifacts"].append({"id": art_id, "path": path, "kind": kind,
                                  "sha256": "0" * 64, "bytes": 1})
    assert check_envelope(load_contract(contract_path), data) == []
    # Only the host's exact shape is exempt: the same id with another kind is still undeclared.
    data["artifacts"].append({"id": "network.capture.mixed.pcap", "path": "x.pcap", "kind": "file",
                              "sha256": "0" * 64, "bytes": 1})
    assert [v.code for v in check_envelope(load_contract(contract_path), data)] == ["undeclared_artifact"]


def test_declared_but_unwritten_artifact_fails_with_outdir(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    (out / "manifest.json").unlink()
    codes = [v.code for v in check_result(load_contract(contract_path), _result(), out)]
    assert codes == ["unsealable", "artifact_file_missing", "missing_artifact"]


def test_find_contract_engine_never_falls_back_to_another_engine(tmp_path: Path) -> None:
    (tmp_path / CONTRACT_FILENAME).write_text(CONTRACT)  # engine "demo"
    nested = tmp_path / "src"
    nested.mkdir()
    assert find_contract(nested, "other") is None
    assert find_contract(nested, "demo") == tmp_path / CONTRACT_FILENAME
    # An engine-specific file higher up beats a nearer plain contract for another engine.
    (tmp_path / "blastbox-engine.other.toml").write_text(CONTRACT.replace('name = "demo"', 'name = "other"'))
    (nested / CONTRACT_FILENAME).write_text(CONTRACT)
    assert find_contract(nested, "other") == tmp_path / "blastbox-engine.other.toml"


def test_builtin_contract_names_match_their_engines() -> None:
    from blastbox.contract.engine_contract import builtin_contract
    from blastbox.engines import clamav, detonate, magika, urlgrab
    engines = {"clamav": clamav.ClamAVEngine, "detonate": detonate.DetonateEngine,
               "magika": magika.MagikaEngine, "urlgrab": urlgrab.UrlGrabEngine}
    for stem, cls in engines.items():
        assert builtin_contract(stem).engine.name == cls.name, stem


def test_nodes_inside_plain_models_are_walked(tmp_path: Path) -> None:
    from typing import Literal
    from pydantic import BaseModel, Field
    from blastbox.contract.engine_contract import _payload_nodes
    from blastbox.contract.nodes import _Node

    class Section(BaseModel):
        meta: Record

    class Report(_Node):
        type: Literal["report_t"] = Field(default="report_t", alias="_type")
        sections: list[Section] = Field(default_factory=list)

    report = Report(sections=[Section(meta=Record(fields={"a": 1}))])
    assert [getattr(n, "type") for n in _payload_nodes(report)] == ["report_t", "record"]


def test_overlapping_specs_satisfy_a_required_family(tmp_path: Path) -> None:
    """An artifact matching an earlier optional family still satisfies a later required one."""
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "*"
path = "*.json"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    out = _outdir(tmp_path)
    assert check_result(load_contract(p), _result(), out) == []


def test_host_capture_exemption_needs_a_network_that_captures(contract_path: Path, tmp_path: Path) -> None:
    """The host only seals a capture for an exit driver other than none/drop; an engine whose
    contract allows only those cannot hide an undeclared file behind the capture's name."""
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    data = json.loads(env.model_dump_json(by_alias=True))
    data["artifacts"].append({"id": "network.capture.pcap", "path": "capture/dump.pcap",
                              "kind": "network_capture", "sha256": "0" * 64, "bytes": 1})
    offline = load_contract(contract_path)  # network = ["none"]
    assert [v.code for v in check_envelope(offline, data)] == ["undeclared_artifact"]
    contract_path.write_text(CONTRACT.replace('network = ["none"]', 'network = ["none", "inetsim"]'))
    assert check_envelope(load_contract(contract_path), data) == []


def test_every_matching_family_byte_cap_applies(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"
path = "manifest.json"
kind = "file"
required = true''', '''[[artifacts]]
id = "*"
path = "*.json"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"
path = "manifest.json"
kind = "file"
required = true
max_bytes = 1'''))
    out = _outdir(tmp_path)
    (out / "manifest.json").write_text("{}")  # 2 bytes > 1
    assert [v.code for v in check_result(load_contract(p), _result(), out)] == ["artifact_too_large"]


def test_find_contract_prefers_the_nearest_matching_contract(tmp_path: Path) -> None:
    (tmp_path / "blastbox-engine.demo.toml").write_text(CONTRACT)
    nested = tmp_path / "engine"
    nested.mkdir()
    (nested / CONTRACT_FILENAME).write_text(CONTRACT)  # name "demo", nearer
    assert find_contract(nested / "x", "demo") == nested / CONTRACT_FILENAME


def test_undeclared_and_unwritten_reports_both(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    extra = [DeclaredArtifact(id="debug", path="debug.log", kind="file")]
    codes = sorted(v.code for v in check_result(load_contract(contract_path), _result(extra=extra), out))
    assert codes == ["artifact_file_missing", "undeclared_artifact", "unsealable"]


# --- marla round 2 (Claude lens) ----------------------------------------------------------

@pytest.mark.parametrize("case", ["symlinked_parent", "absolute", "dotdot", "reserved", "dup_id"])
def test_check_result_with_outdir_refuses_what_sealing_refuses(contract_path: Path, tmp_path: Path, case: str) -> None:
    contract_path.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "*"
path = "*"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    out = _outdir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.bin").write_text("x")
    extra: list[DeclaredArtifact]
    if case == "symlinked_parent":
        (out / "linked").symlink_to(outside, target_is_directory=True)
        extra = [DeclaredArtifact(id="x", path="linked/x.bin", kind="file")]
    elif case == "absolute":
        extra = [DeclaredArtifact(id="x", path=str(outside / "x.bin"), kind="file")]
    elif case == "dotdot":
        extra = [DeclaredArtifact(id="x", path="../outside/x.bin", kind="file")]
    elif case == "reserved":
        (out / "metadata.json").write_text("{}")
        extra = [DeclaredArtifact(id="x", path="metadata.json", kind="file")]
    else:
        extra = [DeclaredArtifact(id="manifest", path="manifest.json", kind="file")]
    codes = {v.code for v in check_result(load_contract(contract_path), _result(extra=extra), out)}
    assert "unsealable" in codes, codes


def test_symlinked_leaf_is_not_present(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    real = tmp_path / "real.json"
    real.write_text("{}")
    (out / "manifest.json").unlink()
    (out / "manifest.json").symlink_to(real)
    codes = [v.code for v in check_result(load_contract(contract_path), _result(), out)]
    assert "artifact_file_missing" in codes and "missing_artifact" in codes


def test_host_capture_exemption_needs_the_exact_triple(contract_path: Path, tmp_path: Path) -> None:
    contract_path.write_text(CONTRACT.replace('network = ["none"]', 'network = ["inetsim"]'))
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    base = json.loads(env.model_dump_json(by_alias=True))
    for art in ({"id": "network.capture.pcap", "kind": "network_capture", "path": "loot.bin"},
                {"id": "network.capture.pcap", "kind": "file", "path": "capture/dump.pcap"}):
        data = json.loads(json.dumps(base))
        data["artifacts"].append({**art, "sha256": "0" * 64, "bytes": 1})
        assert [v.code for v in check_envelope(load_contract(contract_path), data)] == \
            ["undeclared_artifact"], art


def test_find_contract_returns_a_broken_own_contract_for_load_to_report(tmp_path: Path) -> None:
    (tmp_path / CONTRACT_FILENAME).write_text('[engine]\nname = "demo"\nformats = ["x"\n')
    assert find_contract(tmp_path / "tests", "demo") == tmp_path / CONTRACT_FILENAME
    (tmp_path / CONTRACT_FILENAME).write_bytes(b'# caf\xe9\n[engine]\nname = "demo"\n')
    assert find_contract(tmp_path / "tests", "demo") == tmp_path / CONTRACT_FILENAME
    with pytest.raises((ValueError, UnicodeDecodeError)):
        load_contract(tmp_path / CONTRACT_FILENAME)


def test_walker_descends_dataclasses_and_extra_fields() -> None:
    from dataclasses import dataclass
    from typing import Literal
    from pydantic import BaseModel, ConfigDict, Field
    from blastbox.contract.engine_contract import _payload_nodes
    from blastbox.contract.nodes import _Node

    page = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"), image=ArtifactRef(id="p"))

    @dataclass
    class Section:
        page: Page

    class Loose(BaseModel):
        model_config = ConfigDict(extra="allow")

    class ReportDc(_Node):
        type: Literal["report_dc"] = Field(default="report_dc", alias="_type")
        sections: list[Section] = Field(default_factory=list)
        loose: Loose | None = None

    rep = ReportDc(sections=[Section(page=page)], loose=Loose(p=page))
    types = [getattr(n, "type") for n in _payload_nodes(rep)]
    assert types.count("page") == 2


def test_oversized_artifact_still_satisfies_later_required_family(tmp_path: Path) -> None:
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "*"
path = "*.json"
kind = "file"
max_count = 0
max_bytes = 1

[[artifacts]]
id = "manifest"'''))
    out = _outdir(tmp_path)
    assert [v.code for v in check_result(load_contract(p), _result(), out)] == ["artifact_too_large"]


def test_non_ok_record_allowance_is_root_only(tmp_path: Path) -> None:
    from blastbox.contract import EmbeddedResource
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "embedded_resource"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["embedded_resource"]')
                 .replace('required_root_fields = ["schema_version"]\nschema_version = "demo/1"\n', ''))
    c = load_contract(p)
    inner = EmbeddedResource(embedded_path="x", content_type="t", depth=1, metadata=Record())
    root = EmbeddedResource(embedded_path="", content_type="t", depth=0, children=[inner])
    for status in ("rejected", "engine_error"):
        r = DetonationResult(payload=root, artifacts=[], detected=DET, status=status)  # type: ignore[arg-type]
        assert [v.code for v in check_result(c, r)] == ["undeclared_node_type"], status


def test_find_contract_skips_an_unparseable_contract_when_a_match_exists_above(tmp_path: Path) -> None:
    (tmp_path / CONTRACT_FILENAME).write_text(CONTRACT)  # demo
    child = tmp_path / "other"
    child.mkdir()
    (child / CONTRACT_FILENAME).write_text('[engine]\nname = "other"\nformats = [\n')
    assert find_contract(child, "demo") == tmp_path / CONTRACT_FILENAME


# --- marla round 3 (Claude lens) ----------------------------------------------------------

def test_nul_byte_artifact_path_is_a_violation_not_a_crash(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    extra = [DeclaredArtifact(id="a", path="a\x00b", kind="file")]
    codes = {v.code for v in check_result(load_contract(contract_path), _result(extra=extra), out)}
    assert {"unsealable", "artifact_file_missing"} <= codes


def test_cyclic_payload_fails_fast_with_outdir(contract_path: Path, tmp_path: Path) -> None:
    import signal
    from blastbox.contract import EmbeddedResource
    root = EmbeddedResource(embedded_path="", content_type="t", depth=0)
    root.children.append(root)
    r = DetonationResult(payload=root, artifacts=[], detected=DET)

    def _hung(*_a: object) -> None:  # a regression must FAIL, not hang CI
        raise AssertionError("check_result hung on a cyclic payload")

    old = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(10)
    try:
        with pytest.raises(ValueError, match="depth"):
            check_result(load_contract(contract_path), r, _outdir(tmp_path))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def test_warnings_none_is_unsealable_like_the_harness(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    r = _result()
    r.warnings = None  # type: ignore[assignment]
    assert "unsealable" in {v.code for v in check_result(load_contract(contract_path), r, out)}


@pytest.mark.parametrize("spelling", ["./metadata.json", "metadata.json/", ".//metadata.json"])
def test_reserved_metadata_json_any_spelling_is_refused(tmp_path: Path, spelling: str) -> None:
    out = _outdir(tmp_path)
    (out / "metadata.json").write_text("{}")
    with pytest.raises(ValueError, match="reserved"):
        seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                      declared=[DeclaredArtifact(id="raw", path=spelling, kind="file")],
                      warnings=[], payload=Record())


# --- marla round 4 (Claude lens) ----------------------------------------------------------

def test_detected_none_is_unsealable(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    r = _result()
    r.detected = None  # type: ignore[assignment]
    v = [x for x in check_result(load_contract(contract_path), r, out) if x.code == "unsealable"]
    assert v and "detect()" in v[0].detail


def test_broken_own_contract_beats_a_same_engine_ancestor(tmp_path: Path) -> None:
    (tmp_path / CONTRACT_FILENAME).write_text(CONTRACT)  # demo, valid
    wt = tmp_path / ".worktrees" / "feat"
    (wt / "tests").mkdir(parents=True)
    (wt / CONTRACT_FILENAME).write_text(CONTRACT.replace('formats = ["ics"]', 'formats = ["ics"'))
    assert find_contract(wt / "tests", "demo") == wt / CONTRACT_FILENAME


def test_nameless_own_contract_is_returned_for_load_to_report(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / CONTRACT_FILENAME).write_text(CONTRACT.replace("[engine]", "[engin]"))
    found = find_contract(tmp_path / "tests", "demo")
    assert found == tmp_path / CONTRACT_FILENAME
    with pytest.raises(ValueError, match="invalid engine contract"):
        load_contract(found)


def test_metadata_json_directory_is_reserved(tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    (out / "metadata.json").mkdir()
    (out / "metadata.json" / "x").write_text("x")
    with pytest.raises(ValueError, match="reserved"):
        seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                      declared=[DeclaredArtifact(id="x", path="metadata.json/x", kind="file")],
                      warnings=[], payload=Record())


def test_payload_deeper_than_the_host_gate_is_unsealable(tmp_path: Path) -> None:
    from blastbox.contract import EmbeddedResource
    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "embedded_resource"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["embedded_resource"]')
                 .replace('required_root_fields = ["schema_version"]\nschema_version = "demo/1"\n', '')
                 .replace('required = true', 'required = false'))
    root = cur = EmbeddedResource(embedded_path="", content_type="t", depth=0)
    for k in range(1, 64):
        nxt = EmbeddedResource(embedded_path=f"e{k}", content_type="t", depth=k)
        cur.children.append(nxt)
        cur = nxt
    r = DetonationResult(payload=root, artifacts=[], detected=DET)
    assert "unsealable" in {v.code for v in check_result(load_contract(p), r, _outdir(tmp_path))}


def test_walker_descends_other_collections() -> None:
    from collections import deque
    from typing import Literal
    from pydantic import Field
    from blastbox.contract.engine_contract import _payload_nodes
    from blastbox.contract.nodes import _Node

    class Holder(_Node):
        type: Literal["holder_t"] = Field(default="holder_t", alias="_type")
        q: deque[Record] = Field(default_factory=deque)
        s: frozenset[str] = frozenset()

    h = Holder(q=deque([Record(fields={"a": 1})]), s=frozenset({"x"}))
    assert [getattr(n, "type") for n in _payload_nodes(h)] == ["holder_t", "record"]


# --- full-PR sweep ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["attestation.json", "attestation.withheld.json", "attestation.json/x"])
def test_host_reserved_names_are_unsealable(contract_path: Path, tmp_path: Path, name: str) -> None:
    contract_path.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "att"
path = "*"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    out = _outdir(tmp_path)
    (out / name).parent.mkdir(parents=True, exist_ok=True)
    (out / name).write_text("{}")
    extra = [DeclaredArtifact(id="att", path=name, kind="file")]
    codes = {v.code for v in check_result(load_contract(contract_path), _result(extra=extra), out)}
    assert "reserved_path" in codes


def test_reserved_names_match_the_host() -> None:
    pytest.importorskip("cryptography")
    from blastbox.contract.engine_contract import _HOST_RESERVED_NAMES
    from blastbox.host.attest import RESERVED_NAMES
    assert set(_HOST_RESERVED_NAMES) == set(RESERVED_NAMES)


def test_undeclared_metadata_json_directory_is_flagged(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    (out / "metadata.json").mkdir()
    codes = {v.code for v in check_result(load_contract(contract_path), _result(), out)}
    assert "reserved_path" in codes


def test_host_metadata_cap_follows_limits(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.limits import Limits
    out = _outdir(tmp_path)
    big = _result()
    big.payload = Record(fields={"schema_version": "demo/1", "blob": "x" * 5_000_000})
    c = load_contract(contract_path)
    assert check_result(c, big, out) == []           # the harness has no cap
    small = Limits(max_metadata_bytes=1_000_000)
    assert "unsealable" in {v.code for v in check_result(c, big, out, limits=small)}


def test_temp_prefix_of_root_metadata_is_reserved(tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    (out / ".metadata.json.tmp1").write_text("x")
    with pytest.raises(ValueError, match="reserved"):
        seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                      declared=[DeclaredArtifact(id="t", path=".metadata.json.tmp1", kind="file")],
                      warnings=[], payload=Record())


def test_minimal_engine_example_ships_a_conforming_contract(tmp_path: Path) -> None:
    import importlib.util
    root = Path(__file__).resolve().parents[2] / "examples" / "minimal-engine"
    c = load_contract(root / CONTRACT_FILENAME)
    spec = importlib.util.spec_from_file_location("echo_engine", root / "echo_engine.py")
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"hello")
    out = tmp_path / "out"
    out.mkdir()
    from blastbox.limits import Limits
    r = mod.EchoEngine().detonate(sample, out, Limits())
    assert check_result(c, r, out) == []
    assert c.engine.name == mod.EchoEngine.name


def test_assert_conforms_passes_limits_through(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.contract.engine_contract import assert_conforms
    from blastbox.limits import Limits
    out = _outdir(tmp_path)
    big = _result()
    big.payload = Record(fields={"schema_version": "demo/1", "blob": "x" * 2_000_000})
    c = load_contract(contract_path)
    assert_conforms(c, big, out)
    with pytest.raises(AssertionError, match="unsealable"):
        assert_conforms(c, big, out, limits=Limits(max_metadata_bytes=1_000_000))


# --- marla round 7 (Claude lens) ----------------------------------------------------------

def test_symlinked_or_fifo_metadata_json_is_not_flagged(contract_path: Path, tmp_path: Path) -> None:
    out = _outdir(tmp_path)
    (out / "metadata.json").symlink_to(out / "manifest.json")
    assert "reserved_path" not in {v.code for v in check_result(load_contract(contract_path), _result(), out)}


def test_limits_apply_every_host_output_cap(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.limits import Limits
    c = load_contract(contract_path)
    out = _outdir(tmp_path, pages=2)
    r = _result(pages=2)
    assert check_result(c, r, out, limits=Limits()) == []
    for lim in (Limits(max_artifacts=1), Limits(max_artifact_bytes=4),
                Limits(max_total_artifact_bytes=10)):
        assert "unsealable" in {v.code for v in check_result(c, r, out, limits=lim)}, lim


def test_walker_descends_frozensets_of_nodes() -> None:
    from typing import Literal
    from pydantic import ConfigDict, Field
    from blastbox.contract.engine_contract import _payload_nodes
    from blastbox.contract.nodes import _Node

    class Tag(_Node):
        model_config = ConfigDict(frozen=True, populate_by_name=True)
        type: Literal["tag_t"] = Field(default="tag_t", alias="_type")

    class Holder(_Node):
        type: Literal["holder_fs"] = Field(default="holder_fs", alias="_type")
        tags: frozenset[Tag] = frozenset()

    assert [getattr(n, "type") for n in _payload_nodes(Holder(tags=frozenset({Tag()})))] == [
        "holder_fs", "tag_t"]


# --- marla round 8 (Claude lens) ----------------------------------------------------------

def test_sealed_envelope_checks_honour_limits(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.contract.engine_contract import assert_conforms
    from blastbox.limits import Limits
    out = _outdir(tmp_path, pages=2)
    r = _result(pages=2)
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    c = load_contract(contract_path)
    assert check_envelope(c, env, limits=Limits()) == []
    for lim in (Limits(max_artifacts=1), Limits(max_artifact_bytes=4),
                Limits(max_total_artifact_bytes=10), Limits(max_metadata_bytes=100)):
        assert "host_limit" in {v.code for v in check_envelope(c, env, limits=lim)}, lim
        with pytest.raises(AssertionError):
            assert_conforms(c, json.loads(env.model_dump_json(by_alias=True)), limits=lim)


def test_total_cap_counts_metadata_json_like_the_cold_dispatcher(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.limits import Limits
    out = _outdir(tmp_path)
    r = _result()
    declared_total = 2 + 8   # manifest.json "{}" + one 8-byte page
    lim = Limits(max_total_artifact_bytes=declared_total + 10)
    assert "unsealable" in {v.code for v in check_result(load_contract(contract_path), r, out, limits=lim)}


@pytest.mark.parametrize("kind", ["fifo", "dangling", "dir_symlink"])
def test_metadata_json_the_harness_can_replace_is_not_flagged(contract_path: Path, tmp_path: Path, kind: str) -> None:
    import os
    out = _outdir(tmp_path)
    meta = out / "metadata.json"
    if kind == "fifo":
        os.mkfifo(meta)
    elif kind == "dangling":
        meta.symlink_to(out / "gone")
    else:
        (out / "d").mkdir()
        meta.symlink_to(out / "d", target_is_directory=True)
    assert "reserved_path" not in {v.code for v in check_result(load_contract(contract_path), _result(), out)}


def test_total_cap_counts_undeclared_files_in_outdir(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.limits import Limits
    out = _outdir(tmp_path)
    (out / "scratch.bin").write_bytes(b"x" * 5000)
    lim = Limits(max_total_artifact_bytes=4000)
    assert "unsealable" in {v.code for v in check_result(load_contract(contract_path), _result(), out, limits=lim)}


# --- final sweep 2 ---------------------------------------------------------------------------

def test_registered_node_types_are_refused_like_the_host(tmp_path: Path) -> None:
    from typing import Literal
    from pydantic import Field
    from blastbox.contract.nodes import _Node

    class Verdict(_Node):
        type: Literal["demo_verdict_t"] = Field(default="demo_verdict_t", alias="_type")

    p = tmp_path / CONTRACT_FILENAME
    p.write_text(CONTRACT.replace('root = "record"', 'root = "demo_verdict_t"')
                 .replace('node_types = ["record", "page"]', 'node_types = ["demo_verdict_t"]')
                 .replace('required_root_fields = ["schema_version"]\nschema_version = "demo/1"\n', '')
                 .replace("required = true", "required = false"))
    r = DetonationResult(payload=Verdict(), artifacts=[], detected=DET)
    assert "host_unknown_node_type" in {v.code for v in check_result(load_contract(p), r)}


def test_sealed_dict_gets_host_parity_checks(contract_path: Path, tmp_path: Path) -> None:
    contract_path.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "att"
path = "*"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    out = _outdir(tmp_path)
    (out / "attestation.json").write_text("{}")
    r = _result(extra=[DeclaredArtifact(id="att", path="attestation.json", kind="file")])
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    data = json.loads(env.model_dump_json(by_alias=True))
    assert "reserved_path" in {v.code for v in check_envelope(load_contract(contract_path), data)}


def test_limits_without_outdir_is_an_error(contract_path: Path) -> None:
    from blastbox.limits import Limits
    with pytest.raises(TypeError, match="outdir"):
        check_result(load_contract(contract_path), _result(), limits=Limits())


def test_textual_name_is_read_from_the_engine_table(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    broken = (CONTRACT.replace('name = "demo"', 'nmae = "demo"') + '''
[[consumers]]
name = "loadout"
engine = "demo"
''').replace('formats = ["ics"]', 'formats = ["ics"')
    (tmp_path / CONTRACT_FILENAME).write_text(broken)
    assert find_contract(tmp_path / "tests", "demo") == tmp_path / CONTRACT_FILENAME


def test_textual_name_with_a_commented_engine_header(tmp_path: Path) -> None:
    (tmp_path / CONTRACT_FILENAME).write_text(CONTRACT)
    child = tmp_path / "e"
    (child / "tests").mkdir(parents=True)
    (child / CONTRACT_FILENAME).write_text(CONTRACT.replace("[engine]", "[engine] # local engine")
                                           .replace('formats = ["ics"]', 'formats = ["ics"'))
    assert find_contract(child / "tests", "demo") == child / CONTRACT_FILENAME


def test_check_envelope_applies_the_host_json_depth_gate(contract_path: Path, tmp_path: Path) -> None:
    root = cur = Record(fields={"schema_version": "demo/1"})
    for _ in range(70):
        nxt = Record()
        cur.fields["n"] = nxt
        cur = nxt
    out = _outdir(tmp_path)
    r = _result()
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=root)
    data = json.loads(env.model_dump_json(by_alias=True))
    assert "unsealable" in {v.code for v in check_envelope(load_contract(contract_path), data)}


def test_total_cap_message_names_undeclared_bytes(contract_path: Path, tmp_path: Path) -> None:
    from blastbox.limits import Limits
    out = _outdir(tmp_path)
    (out / "scratch.bin").write_bytes(b"x" * 5000)
    v = check_result(load_contract(contract_path), _result(), out,
                     limits=Limits(max_total_artifact_bytes=4000))
    assert any("undeclared" in x.detail for x in v)


# --- bot review on the final head ------------------------------------------------------------

def _sealed_dict(out: Path, r: DetonationResult) -> dict:
    env = seal_envelope(engine="demo", outdir=out, input_sha256="0" * 64, detected=DET,
                        declared=r.artifacts, warnings=[], payload=r.payload)
    return json.loads(env.model_dump_json(by_alias=True))


def test_check_envelope_refuses_reserved_metadata_paths(contract_path: Path, tmp_path: Path) -> None:
    contract_path.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "x"
path = "*"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    data = _sealed_dict(_outdir(tmp_path), _result())
    data["artifacts"].append({"id": "x", "path": "./metadata.json", "kind": "file",
                              "sha256": "0" * 64, "bytes": 1})
    assert "reserved_path" in {v.code for v in check_envelope(load_contract(contract_path), data)}


def test_check_envelope_refuses_unresolved_refs_and_duplicate_ids(contract_path: Path, tmp_path: Path) -> None:
    c = load_contract(contract_path)
    data = _sealed_dict(_outdir(tmp_path), _result(schema="page-root"))
    data["artifacts"] = [a for a in data["artifacts"] if a["id"] != "page-0"]
    assert "unsealable" in {v.code for v in check_envelope(c, data)}
    data2 = _sealed_dict(_outdir(tmp_path / "b"), _result())
    data2["artifacts"].append(dict(data2["artifacts"][0]))
    assert "unsealable" in {v.code for v in check_envelope(c, data2)}


@pytest.mark.parametrize("path", ["../outside.bin", "/tmp/outside.bin", "a/../../b"])
def test_check_envelope_refuses_unconfined_paths(contract_path: Path, tmp_path: Path, path: str) -> None:
    contract_path.write_text(CONTRACT.replace('''[[artifacts]]
id = "manifest"''', '''[[artifacts]]
id = "x"
path = "*"
kind = "file"
max_count = 0

[[artifacts]]
id = "manifest"'''))
    data = _sealed_dict(_outdir(tmp_path), _result())
    data["artifacts"].append({"id": "x", "path": path, "kind": "file", "sha256": "0" * 64, "bytes": 1})
    assert "unsealable" in {v.code for v in check_envelope(load_contract(contract_path), data)}
