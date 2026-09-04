import pytest
from blastbox.contract.walk import iter_nodes, find_by_type
from blastbox.contract.nodes import EmbeddedResource, ExtractedText, Page
from blastbox.contract.leaf import ArtifactRef, Dimensions


def _tree():
    return EmbeddedResource(
        embedded_path="/",
        content_type="application/zip",
        depth=0,
        children=[
            ExtractedText(text="root", char_count=4),
            EmbeddedResource(
                embedded_path="/a.docx",
                content_type="x",
                depth=1,
                children=[
                    ExtractedText(text="inner", char_count=5),
                    Page(
                        index=0,
                        dims=Dimensions(width=1, height=1, unit="px"),
                        image=ArtifactRef(id="a0"),
                    ),
                ],
            ),
        ],
    )


def test_iter_nodes_visits_all():
    assert sum(1 for _ in iter_nodes(_tree())) == 5  # root + 4 descendants


def test_find_by_type_is_engine_agnostic():
    texts = find_by_type(_tree(), ExtractedText)
    assert [t.text for t in texts] == ["root", "inner"]
    pages = find_by_type(_tree(), Page)
    assert len(pages) == 1 and pages[0].image.id == "a0"


# MED-2: iter_nodes must not RecursionError on deep trees; depth guard raises ValueError
def test_iter_nodes_raises_value_error_not_recursion_on_deep_tree():
    """iter_nodes must raise ValueError (not RecursionError) beyond the depth limit."""
    # Build a chain of 200 EmbeddedResource nodes (deeper than the 128-node limit)
    node = ExtractedText(text="leaf", char_count=4)
    for _ in range(200):
        node = EmbeddedResource(
            embedded_path="/",
            content_type="x",
            depth=0,  # type: ignore[arg-type]
            children=[node],
        )
    with pytest.raises(ValueError, match="depth"):
        list(iter_nodes(node))
