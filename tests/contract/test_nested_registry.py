"""Registered engine subtypes must validate as nested children, not just root.

A ``register_node_type``'d ``Page`` subclass is accepted as the root payload
(via the Envelope rebuild path), but historically was *not* accepted nested in
``Page.children`` / ``EmbeddedResource.children`` — those fields were typed
``list[ChildNode]`` where the union was captured at class-definition and never
extended with registered engine types.  These tests pin the fix: a registered
subtype must validate AND round-trip (dump -> parse) as a nested child while the
4 base types keep working and unknown ``_type`` keeps being rejected.
"""
from typing import Literal

import pytest
from pydantic import Field, ValidationError

from blastbox.contract.leaf import ArtifactRef, Dimensions
from blastbox.contract.nodes import (
    EmbeddedResource,
    ExtractedText,
    Page,
    Record,
    parse_node,
    register_node_type,
)
from blastbox.contract.walk import find_by_type


class ClippyShotPage(Page):
    type: Literal["clippyshot_page"] = Field(default="clippyshot_page", alias="_type")
    ocr_chars: int = Field(default=0, ge=0)


# Register once at import time (idempotent in register_node_type).
register_node_type(ClippyShotPage)


def test_registered_subtype_validates_as_nested_child():
    """The reproduce case from the bug report: subtype nested in children."""
    root = EmbeddedResource(
        embedded_path="/", content_type="application/pdf", depth=0,
        children=[
            ClippyShotPage(
                index=0,
                dims=Dimensions(width=210, height=297, unit="mm"),
                image=ArtifactRef(id="p0"),
                ocr_chars=123,
            )
        ],
    )
    parsed = parse_node(root.model_dump(by_alias=True))
    assert type(parsed.children[0]).__name__ == "ClippyShotPage"
    assert parsed.children[0].ocr_chars == 123
    # find_by_type is subclass-aware, so a ClippyShotPage counts as a Page.
    assert len(find_by_type(parsed, Page)) == 1
    assert len(find_by_type(parsed, ClippyShotPage)) == 1


def test_registered_subtype_round_trips_as_nested_child():
    """dump -> parse -> dump is stable and preserves extra fields."""
    root = EmbeddedResource(
        embedded_path="/", content_type="application/pdf", depth=0,
        children=[
            ClippyShotPage(
                index=2,
                dims=Dimensions(width=8.5, height=11, unit="px"),
                image=ArtifactRef(id="p2"),
                ocr_chars=7,
            )
        ],
    )
    parsed = parse_node(root.model_dump(by_alias=True))
    # Reparse the reparsed dump to confirm full stability.
    again = parse_node(parsed.model_dump(by_alias=True))
    assert again == parsed
    assert again.children[0].ocr_chars == 7


def test_base_types_still_validate_as_nested_children():
    """The 4 base node types must still parse correctly as children."""
    root = EmbeddedResource(
        embedded_path="/", content_type="application/zip", depth=0,
        children=[
            Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                 image=ArtifactRef(id="a0")),
            ExtractedText(text="hi", char_count=2),
            Record(fields={"k": "v"}),
            EmbeddedResource(embedded_path="/inner", content_type="x", depth=1),
        ],
    )
    parsed = parse_node(root.model_dump(by_alias=True))
    kinds = [type(c).__name__ for c in parsed.children]
    assert kinds == ["Page", "ExtractedText", "Record", "EmbeddedResource"]


def test_unknown_child_type_is_rejected():
    """An unregistered _type nested as a child must still be rejected."""
    data = {
        "_type": "embedded_resource",
        "embedded_path": "/",
        "content_type": "x",
        "depth": 0,
        "children": [{"_type": "totally_unknown", "x": 1}],
    }
    with pytest.raises(ValidationError):
        parse_node(data)


def test_extra_forbidden_still_enforced_on_child():
    """A base child with an unexpected extra key must still be rejected."""
    data = {
        "_type": "embedded_resource",
        "embedded_path": "/",
        "content_type": "x",
        "depth": 0,
        "children": [{"_type": "extracted_text", "text": "x",
                      "char_count": 1, "bogus": 99}],
    }
    with pytest.raises(ValidationError):
        parse_node(data)


def test_registered_subtype_deeply_nested():
    """A registered subtype must validate several levels deep."""
    leaf = ClippyShotPage(
        index=9,
        dims=Dimensions(width=1, height=1, unit="mm"),
        image=ArtifactRef(id="deep"),
        ocr_chars=5,
    )
    root = EmbeddedResource(
        embedded_path="/", content_type="application/zip", depth=0,
        children=[
            EmbeddedResource(
                embedded_path="/a", content_type="x", depth=1,
                children=[
                    Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                         image=ArtifactRef(id="mid"),
                         children=[leaf]),
                ],
            )
        ],
    )
    parsed = parse_node(root.model_dump(by_alias=True))
    deep = parsed.children[0].children[0].children[0]
    assert type(deep).__name__ == "ClippyShotPage"
    assert deep.ocr_chars == 5
    assert len(find_by_type(parsed, ClippyShotPage)) == 1
