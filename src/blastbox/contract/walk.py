"""Generic, engine-agnostic walkers over the typed payload tree."""
from __future__ import annotations

from typing import Iterator, TypeVar

_T = TypeVar("_T")

_MAX_DEPTH = 128


def iter_nodes(root, *, _max_depth: int = _MAX_DEPTH) -> Iterator[object]:
    """Yield root and every descendant node (pre-order).

    Uses an explicit stack to avoid Python recursion limits.  Raises
    ``ValueError`` if the tree is deeper than *_max_depth* (default 128)
    so callers get a clean error instead of a ``RecursionError``.
    """
    # Stack entries are (node, depth)
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > _max_depth:
            raise ValueError(
                f"payload tree exceeds maximum nesting depth of {_max_depth}"
            )
        yield node
        children = getattr(node, "children", None) or []
        # Reverse so left-to-right pre-order is preserved when popping.
        for child in reversed(list(children)):
            stack.append((child, depth + 1))


def find_by_type(root, node_type: type[_T]) -> list[_T]:
    """All nodes that are instances of node_type (subclasses included)."""
    return [n for n in iter_nodes(root) if isinstance(n, node_type)]
