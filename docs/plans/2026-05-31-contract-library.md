# Detonation Framework — Contract Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the typed data-contract library (`blastbox.contract`) — the shared typed node tree, the security envelope, and the validation/sealing logic that every engine and the host orchestrator depend on.

**Architecture:** A standalone pydantic-v2 package with leaf types, a recursive composite-node union whose generic floor is `Record`, an `Envelope` the worker SDK *seals* (computes hashes/sizes, confines paths, resolves `ArtifactRef`s) and the host re-validates, and generic cross-engine tree walkers. No `host/` or `worker/` dependencies — this subsystem stands alone and is the foundation everything else imports.

**Tech Stack:** Python 3.12+, pydantic v2, pytest.

**Note:** Package name `blastbox` is a working placeholder (spec Open Questions). If renamed, find/replace the package dir + imports.

---

## File Structure

- `pyproject.toml` — package definition (pydantic + dev deps)
- `src/blastbox/__init__.py` — version
- `src/blastbox/contract/__init__.py` — public exports
- `src/blastbox/contract/leaf.py` — `Hash`, `Detection`, `Warning`, `ArtifactRef`, `Dimensions`, `Lang`
- `src/blastbox/contract/nodes.py` — `Record`, `ExtractedText`, `Page`, `EmbeddedResource`, the `Node` union + engine-type registry
- `src/blastbox/contract/envelope.py` — `Artifact`, `DeclaredArtifact`, `Envelope`, `seal_envelope()`, `validate_envelope()`
- `src/blastbox/contract/walk.py` — `iter_nodes()`, `find_by_type()`
- `tests/contract/test_leaf.py`, `test_nodes.py`, `test_envelope.py`, `test_walk.py`

---

### Task 0: Project skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `src/blastbox/__init__.py`
- Create: `src/blastbox/contract/__init__.py`
- Test: `tests/contract/test_smoke.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_smoke.py
def test_package_imports():
    import blastbox.contract as c
    assert c.__doc__ is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_smoke.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blastbox'`

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "blastbox"
version = "0.0.1"
description = "Reusable detonation framework for untrusted-document workers"
requires-python = ">=3.12"
dependencies = ["pydantic>=2.6.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0.0", "mypy>=1.9.0", "ruff>=0.3.0"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
addopts = "-ra -q"
```

```python
# src/blastbox/__init__.py
__version__ = "0.0.1"
```

```python
# src/blastbox/contract/__init__.py
"""Typed data contract for the detonation framework.

Engines emit a typed payload tree + declared artifacts; the worker SDK seals
them into an Envelope (hashes, sizes, path-confinement); the host re-validates.
"""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pip install -e .[dev] && python -m pytest tests/contract/test_smoke.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/blastbox tests/contract/test_smoke.py
git commit -m "chore: blastbox package skeleton + contract subpackage"
```

---

### Task 1: Leaf types

**Files:**
- Create: `src/blastbox/contract/leaf.py`
- Test: `tests/contract/test_leaf.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_leaf.py
import pytest
from pydantic import ValidationError
from blastbox.contract.leaf import Hash, Detection, Warning, ArtifactRef, Dimensions

def test_hash_accepts_valid_sha256():
    h = Hash(algo="sha256", value="a" * 64)
    assert h.value == "a" * 64

@pytest.mark.parametrize("algo,value", [
    ("sha256", "a" * 63),       # too short
    ("sha256", "g" * 64),       # non-hex
    ("phash", "xyz"),           # non-hex
])
def test_hash_rejects_malformed(algo, value):
    with pytest.raises(ValidationError):
        Hash(algo=algo, value=value)

def test_artifactref_is_id_only():
    r = ArtifactRef(id="a5")
    assert r.id == "a5"

def test_artifactref_rejects_pathlike():
    with pytest.raises(ValidationError):
        ArtifactRef(id="../etc/passwd")

def test_detection_confidence_bounds():
    Detection(label="docx", mime="application/...", confidence=1.0, source="magika")
    with pytest.raises(ValidationError):
        Detection(label="docx", mime="x", confidence=1.5, source="magika")

def test_dimensions_positive():
    Dimensions(width=1.0, height=2.0, unit="mm")
    with pytest.raises(ValidationError):
        Dimensions(width=0, height=2.0, unit="mm")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_leaf.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blastbox.contract.leaf'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/leaf.py
"""Leaf types: the shared vocabulary every engine can reuse."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_SAFE_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
# Expected hex length per hash algorithm (None = any positive hex length).
_HASH_HEXLEN: dict[str, int | None] = {
    "sha256": 64, "phash": 16, "dhash": 16, "ahash": 16, "colorhash": None,
}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Hash(_Frozen):
    algo: Literal["sha256", "phash", "dhash", "ahash", "colorhash"]
    value: str

    @field_validator("value")
    @classmethod
    def _hex(cls, v: str, info) -> str:
        if not _HEX_RE.match(v):
            raise ValueError("hash value must be hex")
        expected = _HASH_HEXLEN.get(info.data.get("algo"))
        if expected is not None and len(v) != expected:
            raise ValueError(f"expected {expected} hex chars, got {len(v)}")
        return v.lower()


class ArtifactRef(_Frozen):
    """A reference into the Envelope's artifact set by id (never a path)."""
    id: str

    @field_validator("id")
    @classmethod
    def _safe(cls, v: str) -> str:
        if not _SAFE_ID_RE.match(v):
            raise ValueError("artifact id must match [A-Za-z0-9._-]{1,128}")
        return v


class Detection(_Frozen):
    label: str = Field(min_length=1, max_length=64)
    mime: str = Field(max_length=255)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1, max_length=32)


class Warning(_Frozen):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(max_length=2000)
    context: str | None = Field(default=None, max_length=255)


class Dimensions(_Frozen):
    width: float = Field(gt=0)
    height: float = Field(gt=0)
    unit: Literal["mm", "px", "pt"]


class Lang(_Frozen):
    code: str = Field(min_length=2, max_length=64)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_leaf.py -v`
Expected: PASS (all parametrized cases)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/leaf.py tests/contract/test_leaf.py
git commit -m "feat(contract): leaf types with validators"
```

---

### Task 2: Record — the generic floor

**Files:**
- Create: `src/blastbox/contract/nodes.py`
- Test: `tests/contract/test_nodes.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_nodes.py
import pytest
from pydantic import ValidationError
from blastbox.contract.nodes import Record

def test_record_holds_scalars_lists_and_nested_records():
    r = Record(fields={
        "title": "Quarterly",
        "rows": 1200,
        "ratio": 0.5,
        "flag": True,
        "tags": ["a", "b"],
        "nested": {"_type": "record", "fields": {"k": "v"}},
    })
    assert r.fields["rows"] == 1200
    assert isinstance(r.fields["nested"], Record)
    assert r.fields["nested"].fields["k"] == "v"

def test_record_rejects_unsupported_value():
    with pytest.raises(ValidationError):
        Record(fields={"bad": object()})

def test_record_roundtrips_json():
    r = Record(fields={"a": 1, "nested": {"_type": "record", "fields": {"b": 2}}})
    dumped = r.model_dump_json()
    again = Record.model_validate_json(dumped)
    assert again == r
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: FAIL with `ImportError: cannot import name 'Record'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/nodes.py
"""Typed payload nodes: a recursive tree with a generic Record floor."""
from __future__ import annotations

from typing import Literal, Union

from pydantic import BaseModel, ConfigDict, Field

Scalar = Union[str, int, float, bool, None]
# A Record field value is a scalar, a list of scalars, or a nested Record.
RecordValue = Union[Scalar, list[Scalar], "Record"]


class _Node(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Record(_Node):
    """The generic floor: a typed bag for engine data not worth a named type."""
    type: Literal["record"] = Field(default="record", alias="_type")
    fields: dict[str, RecordValue] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


Record.model_rebuild()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/nodes.py tests/contract/test_nodes.py
git commit -m "feat(contract): Record generic node (recursive)"
```

---

### Task 3: Composite nodes + the recursive Node union

**Files:**
- Modify: `src/blastbox/contract/nodes.py`
- Test: `tests/contract/test_nodes.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_nodes.py  (append)
from blastbox.contract.nodes import Page, EmbeddedResource, ExtractedText, parse_node
from blastbox.contract.leaf import ArtifactRef, Dimensions, Hash

def test_page_with_children_and_ref():
    p = Page(index=0, dims=Dimensions(width=210, height=297, unit="mm"),
             image=ArtifactRef(id="a0"), hashes=[Hash(algo="phash", value="a"*16)])
    assert p.type == "page" and p.image.id == "a0"

def test_embedded_resource_is_recursive():
    root = EmbeddedResource(
        embedded_path="/", content_type="application/zip", depth=0,
        children=[
            EmbeddedResource(embedded_path="/doc.docx",
                             content_type="application/vnd...", depth=1,
                             children=[ExtractedText(text="hi", char_count=2)]),
            Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                 image=ArtifactRef(id="a1")),
        ],
    )
    assert root.children[0].children[0].type == "extracted_text"
    assert root.children[1].type == "page"

def test_parse_node_dispatches_on_type():
    data = {"_type": "extracted_text", "text": "x", "char_count": 1}
    node = parse_node(data)
    assert isinstance(node, ExtractedText)

def test_mixed_children_roundtrip_json():
    root = EmbeddedResource(embedded_path="/", content_type="x", depth=0,
                            children=[ExtractedText(text="t", char_count=1)])
    again = parse_node(root.model_dump(by_alias=True))
    assert again == root
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: FAIL with `ImportError: cannot import name 'Page'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/nodes.py  (append after Record, before model_rebuild calls)
from typing import Annotated
from pydantic import Field, TypeAdapter
from .leaf import ArtifactRef, Dimensions, Hash, Lang

# Forward-declared recursive child union; engine types register into it (Task 4).
ChildNode = Union["Page", "EmbeddedResource", "ExtractedText", "Record"]


class ExtractedText(_Node):
    type: Literal["extracted_text"] = Field(default="extracted_text", alias="_type")
    text: str = Field(max_length=10_000_000)
    char_count: int = Field(ge=0)
    lang: Lang | None = None
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Page(_Node):
    type: Literal["page"] = Field(default="page", alias="_type")
    index: int = Field(ge=0)
    dims: Dimensions
    image: ArtifactRef
    hashes: list[Hash] = Field(default_factory=list)
    children: list["ChildNode"] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EmbeddedResource(_Node):
    type: Literal["embedded_resource"] = Field(default="embedded_resource", alias="_type")
    embedded_path: str = Field(max_length=4096)
    content_type: str = Field(max_length=255)
    depth: int = Field(ge=0, le=64)
    metadata: Record | None = None
    children: list["ChildNode"] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# Discriminated union over the _type tag for parsing untyped JSON.
Node = Annotated[ChildNode, Field(discriminator="type")]
_NODE_ADAPTER: "TypeAdapter" = None  # built by rebuild_node_union() (Task 4)


def parse_node(data: dict) -> "ChildNode":
    """Parse an untyped dict into the correct node by its _type discriminator."""
    global _NODE_ADAPTER
    if _NODE_ADAPTER is None:
        rebuild_node_union()
    return _NODE_ADAPTER.validate_python(data)


def rebuild_node_union() -> None:
    """(Re)build the discriminated-union adapter. Call after registering types."""
    global _NODE_ADAPTER
    for m in (Record, ExtractedText, Page, EmbeddedResource):
        m.model_rebuild()
    _NODE_ADAPTER = TypeAdapter(Node)
```

Then change the existing trailing `Record.model_rebuild()` line to `rebuild_node_union()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/nodes.py tests/contract/test_nodes.py
git commit -m "feat(contract): composite nodes + recursive discriminated union"
```

---

### Task 4: Engine-type registry

**Files:**
- Modify: `src/blastbox/contract/nodes.py`
- Test: `tests/contract/test_nodes.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_nodes.py  (append)
from typing import Literal as _L
from pydantic import Field as _F
from blastbox.contract.nodes import Page, register_node_type, parse_node

class ClippyShotPage(Page):
    type: _L["clippyshot_page"] = _F(default="clippyshot_page", alias="_type")
    ocr_chars: int = _F(default=0, ge=0)

def test_register_and_parse_engine_type():
    register_node_type(ClippyShotPage)
    node = parse_node({"_type": "clippyshot_page", "index": 0,
                       "dims": {"width": 1, "height": 1, "unit": "px"},
                       "image": {"id": "a0"}, "ocr_chars": 42})
    assert isinstance(node, ClippyShotPage)
    assert node.ocr_chars == 42

def test_unregistered_type_is_rejected():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        parse_node({"_type": "totally_unknown", "x": 1})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: FAIL with `ImportError: cannot import name 'register_node_type'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/nodes.py  (append)
_ENGINE_NODE_TYPES: list[type] = []


def register_node_type(cls: type) -> type:
    """Register an engine-specific node subclass into the parse union.

    The class MUST carry a unique Literal `type` discriminator. After
    registration the union is rebuilt so parse_node() accepts it.
    """
    if cls not in _ENGINE_NODE_TYPES:
        _ENGINE_NODE_TYPES.append(cls)
    rebuild_node_union()
    return cls
```

Then update `rebuild_node_union()` to include registered engine types in the union:

```python
def rebuild_node_union() -> None:
    global _NODE_ADAPTER, Node
    for m in (Record, ExtractedText, Page, EmbeddedResource, *_ENGINE_NODE_TYPES):
        m.model_rebuild()
    members = (Record, ExtractedText, Page, EmbeddedResource, *_ENGINE_NODE_TYPES)
    union = Union[members] if len(members) > 1 else members[0]
    Node = Annotated[union, Field(discriminator="type")]
    _NODE_ADAPTER = TypeAdapter(Node)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_nodes.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/nodes.py tests/contract/test_nodes.py
git commit -m "feat(contract): engine-specific node registry"
```

---

### Task 5: Artifact + Envelope + sealing

**Files:**
- Create: `src/blastbox/contract/envelope.py`
- Test: `tests/contract/test_envelope.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_envelope.py
import pytest
from pathlib import Path
from pydantic import ValidationError
from blastbox.contract.envelope import DeclaredArtifact, seal_envelope, validate_envelope
from blastbox.contract.leaf import Detection
from blastbox.contract.nodes import Page, ExtractedText
from blastbox.contract.leaf import ArtifactRef, Dimensions

def _det():
    return Detection(label="docx", mime="x", confidence=1.0, source="magika")

def test_seal_computes_hash_and_size_and_confines(tmp_path):
    (tmp_path / "page-001.png").write_bytes(b"PNGDATA")
    payload = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                   image=ArtifactRef(id="a0"))
    env = seal_envelope(
        engine="clippyshot", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
        declared=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")],
        warnings=[], payload=payload,
    )
    art = env.artifacts[0]
    assert art.bytes == 7
    assert len(art.sha256) == 64
    assert env.status == "ok"

def test_seal_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="confined"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="../escape", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))

def test_seal_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="nope.png", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))

def test_seal_rejects_unresolved_artifactref(tmp_path):
    payload = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                   image=ArtifactRef(id="MISSING"))
    with pytest.raises(ValueError, match="unresolved"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[], warnings=[], payload=payload)

def test_validate_envelope_rejects_oversized(tmp_path):
    (tmp_path / "f").write_bytes(b"x" * 10)
    env = seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                        declared=[DeclaredArtifact(id="a0", path="f", kind="x")],
                        warnings=[], payload=ExtractedText(text="x", char_count=1))
    with pytest.raises(ValueError, match="exceeds"):
        validate_envelope(env, max_artifact_bytes=5, max_total_bytes=1_000, max_artifacts=10)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_envelope.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blastbox.contract.envelope'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/envelope.py
"""The security envelope: sealed by the worker SDK, re-validated by the host."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .leaf import Detection, Warning
from .nodes import ChildNode, parse_node


class DeclaredArtifact(BaseModel):
    """What an engine declares; the SDK turns it into a sealed Artifact."""
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"\A[A-Za-z0-9._-]{1,128}\Z")
    path: str = Field(max_length=4096)   # outdir-relative
    kind: str = Field(min_length=1, max_length=64)


class Artifact(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str
    path: str
    kind: str
    sha256: str = Field(pattern=r"\A[0-9a-f]{64}\Z")
    bytes: int = Field(ge=0)


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engine: str = Field(min_length=1, max_length=64)
    status: Literal["ok", "rejected", "engine_error"] = "ok"
    input_sha256: str = Field(pattern=r"\A[0-9a-f]{64}\Z")
    detected: Detection
    artifacts: list[Artifact] = Field(default_factory=list)
    warnings: list[Warning] = Field(default_factory=list)
    payload: ChildNode


def _collect_refs(node) -> set[str]:
    """Walk a node tree and collect every ArtifactRef.id it references."""
    refs: set[str] = set()
    img = getattr(node, "image", None)
    if img is not None and hasattr(img, "id"):
        refs.add(img.id)
    for child in getattr(node, "children", []) or []:
        refs |= _collect_refs(child)
    return refs


def seal_envelope(*, engine: str, outdir: Path, input_sha256: str,
                  detected: Detection, declared: list[DeclaredArtifact],
                  warnings: list[Warning], payload: ChildNode,
                  status: str = "ok") -> Envelope:
    """Seal declared artifacts + payload into a validated Envelope.

    Computes sha256/bytes from disk, confines every path under outdir, and
    verifies every ArtifactRef in the payload resolves to a declared id.
    Raises ValueError on any violation — the worker must not emit on failure.
    """
    outdir_resolved = outdir.resolve(strict=False)
    artifacts: list[Artifact] = []
    declared_ids: set[str] = set()
    for d in declared:
        if d.id in declared_ids:
            raise ValueError(f"duplicate artifact id: {d.id}")
        declared_ids.add(d.id)
        target = (outdir / d.path).resolve(strict=False)
        if outdir_resolved != target and outdir_resolved not in target.parents:
            raise ValueError(f"artifact path not confined to outdir: {d.path}")
        if not target.is_file():
            raise ValueError(f"declared artifact file missing or not a regular file: {d.path}")
        data = target.read_bytes()
        artifacts.append(Artifact(id=d.id, path=d.path, kind=d.kind,
                                  sha256=hashlib.sha256(data).hexdigest(),
                                  bytes=len(data)))
    unresolved = _collect_refs(payload) - declared_ids
    if unresolved:
        raise ValueError(f"payload has unresolved ArtifactRef(s): {sorted(unresolved)}")
    return Envelope(engine=engine, status=status, input_sha256=input_sha256,
                    detected=detected, artifacts=artifacts, warnings=warnings,
                    payload=payload)


def validate_envelope(env: Envelope, *, max_artifact_bytes: int,
                      max_total_bytes: int, max_artifacts: int) -> Envelope:
    """Host-side re-validation: enforce count/size bounds. Raises ValueError."""
    if len(env.artifacts) > max_artifacts:
        raise ValueError(f"artifact count {len(env.artifacts)} exceeds {max_artifacts}")
    total = 0
    for a in env.artifacts:
        if a.bytes > max_artifact_bytes:
            raise ValueError(f"artifact {a.id} bytes {a.bytes} exceeds {max_artifact_bytes}")
        total += a.bytes
    if total > max_total_bytes:
        raise ValueError(f"total artifact bytes {total} exceeds {max_total_bytes}")
    return env


def envelope_from_json(raw: bytes, *, max_bytes: int = 4 * 1024 * 1024) -> Envelope:
    """Parse a worker-emitted metadata.json into an Envelope (size-bounded)."""
    if len(raw) > max_bytes:
        raise ValueError(f"metadata json {len(raw)} bytes exceeds {max_bytes}")
    import json
    obj = json.loads(raw)
    obj["payload"] = parse_node(obj["payload"])
    return Envelope.model_validate(obj)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_envelope.py -v`
Expected: PASS (all cases including traversal/missing/unresolved/oversized)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/envelope.py tests/contract/test_envelope.py
git commit -m "feat(contract): Envelope + seal/validate (hash, confine, ref-resolve)"
```

---

### Task 6: Cross-engine tree walker

**Files:**
- Create: `src/blastbox/contract/walk.py`
- Test: `tests/contract/test_walk.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_walk.py
from blastbox.contract.walk import iter_nodes, find_by_type
from blastbox.contract.nodes import EmbeddedResource, ExtractedText, Page
from blastbox.contract.leaf import ArtifactRef, Dimensions

def _tree():
    return EmbeddedResource(embedded_path="/", content_type="application/zip", depth=0,
        children=[
            ExtractedText(text="root", char_count=4),
            EmbeddedResource(embedded_path="/a.docx", content_type="x", depth=1,
                children=[ExtractedText(text="inner", char_count=5),
                          Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                               image=ArtifactRef(id="a0"))]),
        ])

def test_iter_nodes_visits_all():
    assert sum(1 for _ in iter_nodes(_tree())) == 5  # root + 4 descendants

def test_find_by_type_is_engine_agnostic():
    texts = find_by_type(_tree(), ExtractedText)
    assert [t.text for t in texts] == ["root", "inner"]
    pages = find_by_type(_tree(), Page)
    assert len(pages) == 1 and pages[0].image.id == "a0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_walk.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'blastbox.contract.walk'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/walk.py
"""Generic, engine-agnostic walkers over the typed payload tree."""
from __future__ import annotations

from typing import Iterator, TypeVar

_T = TypeVar("_T")


def iter_nodes(root) -> Iterator[object]:
    """Yield root and every descendant node (pre-order)."""
    yield root
    for child in getattr(root, "children", []) or []:
        yield from iter_nodes(child)


def find_by_type(root, node_type: type[_T]) -> list[_T]:
    """All nodes that are instances of node_type (subclasses included)."""
    return [n for n in iter_nodes(root) if isinstance(n, node_type)]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/contract/test_walk.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/walk.py tests/contract/test_walk.py
git commit -m "feat(contract): engine-agnostic tree walkers"
```

---

### Task 7: Public exports + JSON-schema emission

**Files:**
- Modify: `src/blastbox/contract/__init__.py`
- Test: `tests/contract/test_smoke.py` (append)

- [ ] **Step 1: Write the failing test**

```python
# tests/contract/test_smoke.py  (append)
def test_public_api_and_schema():
    from blastbox.contract import (
        Hash, Detection, Page, EmbeddedResource, Record, Envelope,
        seal_envelope, find_by_type, json_schema,
    )
    schema = json_schema()
    assert schema["title"] == "Envelope"
    assert "properties" in schema
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/contract/test_smoke.py::test_public_api_and_schema -v`
Expected: FAIL with `ImportError: cannot import name 'json_schema'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/blastbox/contract/__init__.py  (replace body, keep the module docstring)
from .leaf import Hash, Detection, Warning, ArtifactRef, Dimensions, Lang
from .nodes import (
    Record, ExtractedText, Page, EmbeddedResource,
    parse_node, register_node_type, rebuild_node_union,
)
from .envelope import (
    DeclaredArtifact, Artifact, Envelope,
    seal_envelope, validate_envelope, envelope_from_json,
)
from .walk import iter_nodes, find_by_type


def json_schema() -> dict:
    """Canonical JSON Schema for the Envelope (for non-Python engines)."""
    return Envelope.model_json_schema()


__all__ = [
    "Hash", "Detection", "Warning", "ArtifactRef", "Dimensions", "Lang",
    "Record", "ExtractedText", "Page", "EmbeddedResource",
    "parse_node", "register_node_type", "rebuild_node_union",
    "DeclaredArtifact", "Artifact", "Envelope",
    "seal_envelope", "validate_envelope", "envelope_from_json",
    "iter_nodes", "find_by_type", "json_schema",
]
```

- [ ] **Step 4: Run full suite + typecheck**

Run: `python -m pytest tests/contract -v && python -m mypy src/blastbox/contract`
Expected: all tests PASS; mypy clean (or only known pydantic-plugin notes)

- [ ] **Step 5: Commit**

```bash
git add src/blastbox/contract/__init__.py tests/contract/test_smoke.py
git commit -m "feat(contract): public API + JSON-schema emission"
```

---

## Self-Review

**Spec coverage (§4 of the design):**
- §4.1 Envelope (artifacts, input, status, warnings, payload) → Task 5 ✓
- §4.1 path-confinement, size caps, hash, input-SHA, regular-file → Task 5 (`seal_envelope` confinement/missing-file; `validate_envelope` caps) ✓ — *note: the input-SHA round-trip MATCH against the submitted input is a host-layer check (host has the original); the envelope only carries `input_sha256`. Flagged for the host plan.*
- §4.2 leaf types → Task 1; Record floor → Task 2; composite + recursive union → Task 3; engine registry → Task 4 ✓
- §4.2 artifact-by-reference (ArtifactRef → envelope) → Task 5 (`_collect_refs` + unresolved check) ✓
- §4.2 cross-engine consumers → Task 6 ✓
- §4.3 pydantic canonical + JSON Schema for non-Python engines → Task 7 (`json_schema`, `envelope_from_json`) ✓

**Gaps (deliberately out of scope — they belong to later plans, not the contract lib):**
- The host-side input-SHA *match* (needs the original input — host plan).
- `Detection` production when an engine omits `detect()` (engine/worker plan).
- Hooking `validate_envelope` bounds to `Limits.from_env()` (host plan).

**Placeholder scan:** none — every step has complete code and exact commands.

**Type consistency:** `ChildNode`/`Node`/`parse_node`/`rebuild_node_union` are defined in Task 3 and reused consistently in Tasks 4–7; `DeclaredArtifact`/`Artifact`/`Envelope`/`seal_envelope`/`validate_envelope` defined in Task 5 and exported unchanged in Task 7; `_collect_refs` only reads `.image`/`.children` which exist on `Page`/`EmbeddedResource`. Consistent.
