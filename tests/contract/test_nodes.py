from typing import Literal as _L

import pytest
from pydantic import Field as _F
from pydantic import ValidationError

from blastbox.contract.leaf import ArtifactRef, Dimensions, Hash
from blastbox.contract.nodes import (
    EmbeddedResource,
    ExtractedText,
    Page,
    Record,
    parse_node,
    register_node_type,
)


class ClippyShotPage(Page):
    type: _L["clippyshot_page"] = _F(default="clippyshot_page", alias="_type")
    ocr_chars: int = _F(default=0, ge=0)


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

def test_register_and_parse_engine_type():
    register_node_type(ClippyShotPage)
    node = parse_node({"_type": "clippyshot_page", "index": 0,
                       "dims": {"width": 1, "height": 1, "unit": "px"},
                       "image": {"id": "a0"}, "ocr_chars": 42})
    assert isinstance(node, ClippyShotPage)
    assert node.ocr_chars == 42

def test_unregistered_type_is_rejected():
    with pytest.raises(ValidationError):
        parse_node({"_type": "totally_unknown", "x": 1})


# MED-2: list field and dict key count caps
def test_page_children_max_length_rejected():
    """Page.children must reject lists exceeding max_length."""
    from blastbox.contract.nodes import Page, ExtractedText
    from blastbox.contract.leaf import Dimensions, ArtifactRef
    too_many = [ExtractedText(text="x", char_count=1)] * 10001
    with pytest.raises(ValidationError):
        Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
             image=ArtifactRef(id="a0"), children=too_many)


def test_embedded_resource_children_max_length_rejected():
    """EmbeddedResource.children must reject lists exceeding max_length."""
    from blastbox.contract.nodes import ExtractedText
    too_many = [ExtractedText(text="x", char_count=1)] * 10001
    with pytest.raises(ValidationError):
        EmbeddedResource(embedded_path="/", content_type="x", depth=0, children=too_many)


def test_record_fields_key_count_cap():
    """Record.fields must reject dicts exceeding the key-count cap."""
    # 4097 keys should be over the 4096 limit
    big_fields = {f"k{i}": i for i in range(4097)}
    with pytest.raises(ValidationError):
        Record(fields=big_fields)
