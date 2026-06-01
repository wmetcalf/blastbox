"""Typed payload nodes: a recursive tree with a generic Record floor."""
from __future__ import annotations

from typing import Annotated, Any, Callable, Literal, Union, get_args

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, TypeAdapter

from .leaf import ArtifactRef, Dimensions, Hash, Lang

Scalar = Union[str, int, float, bool, None]
# A Record field value is a scalar, a list of scalars, or a nested Record.
RecordValue = Union[Scalar, list[Scalar], "Record"]


class _Node(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _parse_children(value: Any) -> Any:
    """Route each child through the *live*, registry-aware node adapter.

    Runs as a ``BeforeValidator`` on the ``children`` fields so that child
    parsing is decoupled from the static ``ChildNode`` union captured at class
    definition.  A statically-reassigned union does NOT work here: pydantic
    bakes a discriminated-union core schema into the ``children`` field when the
    model is built and does not re-resolve a reassigned module-global union on
    ``model_rebuild`` — so registered engine subtypes were never reachable as
    children.  Delegating to ``_NODE_ADAPTER`` (the same adapter ``parse_node``
    uses, rebuilt by ``rebuild_node_union`` to include engine types) fixes that:
    the registry is consulted at validation time, not class-definition time.

    Already-constructed ``_Node`` instances pass through untouched; dicts are
    validated through the live adapter (which rejects unknown ``_type`` and
    enforces ``extra="forbid"``).  Non-list / non-dict values are returned
    unchanged so pydantic emits its normal type/length errors.
    """
    if not isinstance(value, list):
        return value
    if _NODE_ADAPTER is None:
        rebuild_node_union()
    assert _NODE_ADAPTER is not None
    parsed: list[Any] = []
    for item in value:
        if isinstance(item, _Node):
            parsed.append(item)
        elif isinstance(item, dict):
            parsed.append(_NODE_ADAPTER.validate_python(item))
        else:
            # Let the list[Any] validator surface a normal error for this item.
            parsed.append(item)
    return parsed


# A children list whose items are parsed by the live registry-aware adapter
# (via _parse_children) rather than a static union.  Typed list[Any] so pydantic
# does not re-narrow the already-validated _Node instances back to the 4 base
# types; max_length is still enforced because BeforeValidator runs first.
ChildList = Annotated[list[Any], BeforeValidator(_parse_children)]


class Record(_Node):
    """The generic floor: a typed bag for engine data not worth a named type."""
    type: Literal["record"] = Field(default="record", alias="_type")
    fields: dict[str, RecordValue] = Field(default_factory=dict, max_length=4096)


class ExtractedText(_Node):
    type: Literal["extracted_text"] = Field(default="extracted_text", alias="_type")
    text: str = Field(max_length=10_000_000)
    char_count: int = Field(ge=0)
    lang: Lang | None = None


class Page(_Node):
    type: Literal["page"] = Field(default="page", alias="_type")
    index: int = Field(ge=0)
    dims: Dimensions
    image: ArtifactRef
    hashes: list[Hash] = Field(default_factory=list, max_length=32)
    children: ChildList = Field(default_factory=list, max_length=10000)


class EmbeddedResource(_Node):
    type: Literal["embedded_resource"] = Field(default="embedded_resource", alias="_type")
    embedded_path: str = Field(max_length=4096)
    content_type: str = Field(max_length=255)
    depth: int = Field(ge=0, le=64)
    metadata: Record | None = None
    children: ChildList = Field(default_factory=list, max_length=10000)


# Forward-declared recursive child union; engine types register into it (Task 4).
ChildNode = Union[Page, EmbeddedResource, ExtractedText, Record]

# Module-level Node type and adapter; rebuilt by rebuild_node_union().
Node: Any = Annotated[ChildNode, Field(discriminator="type")]
_NODE_ADAPTER: TypeAdapter[Any] | None = None

_ENGINE_NODE_TYPES: list[type[_Node]] = []

# Callbacks invoked after every rebuild_node_union() — allows envelope and
# other modules to re-bind their own models to the live union without
# introducing a circular top-level import (they register lazily at their
# own module-init time).
_REBUILD_CALLBACKS: list[Callable[[], None]] = []


def rebuild_node_union() -> None:
    """(Re)build the discriminated-union adapter. Call after registering types."""
    global _NODE_ADAPTER, Node
    members: tuple[type[_Node], ...] = (
        Page, EmbeddedResource, ExtractedText, Record, *_ENGINE_NODE_TYPES
    )
    for m in members:
        m.model_rebuild()
    if len(members) > 1:
        union: Any = Union[members]  # type: ignore[arg-type]
    else:
        union = members[0]
    Node = Annotated[union, Field(discriminator="type")]
    _NODE_ADAPTER = TypeAdapter(Node)
    for cb in _REBUILD_CALLBACKS:
        cb()


def parse_node(data: dict[str, Any]) -> ChildNode:
    """Parse an untyped dict into the correct node by its _type discriminator."""
    global _NODE_ADAPTER
    if _NODE_ADAPTER is None:
        rebuild_node_union()
    assert _NODE_ADAPTER is not None
    return _NODE_ADAPTER.validate_python(data)  # type: ignore[return-value]


def _discriminator_value(cls: type[_Node]) -> Any:
    """The Literal discriminator value carried by a node class's ``type`` field."""
    field = cls.model_fields.get("type")
    if field is None:
        return None
    args = get_args(field.annotation)
    return args[0] if args else field.default


def register_node_type(cls: type[_Node]) -> type[_Node]:
    """Register an engine-specific node subclass into the parse union.

    The class MUST carry a unique Literal `type` discriminator. After
    registration the union is rebuilt so parse_node() accepts it.

    Idempotent: re-registering the same class is a no-op, and registering a
    class whose discriminator value matches an already-registered engine type
    *replaces* the prior one.  Without the replace, two classes sharing a
    ``_type`` would both enter the union and pydantic would reject the build
    with "mapped to multiple choices" — so this keeps the discriminated union
    well-formed under reloads / duplicate registrations.
    """
    if cls in _ENGINE_NODE_TYPES:
        rebuild_node_union()
        return cls
    disc = _discriminator_value(cls)
    for i, existing in enumerate(_ENGINE_NODE_TYPES):
        if _discriminator_value(existing) == disc:
            _ENGINE_NODE_TYPES[i] = cls
            break
    else:
        _ENGINE_NODE_TYPES.append(cls)
    rebuild_node_union()
    return cls


# Bootstrap: rebuild after all forward refs are defined.
rebuild_node_union()
