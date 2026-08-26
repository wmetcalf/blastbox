"""The configuration guide is a deliverable, and a malformed row silently DROPS its content.

A markdown table row with more cells than its header renders short: the surplus cell is discarded
by CommonMark/GFM renderers rather than flagged. Two operational warnings -- the one saying
UNKNOWN_GRACE_S=0 does the OPPOSITE thing on the WARMING path, and the one saying the hibernate
timeout now RETIRES the slot rather than re-driving it -- were written into a fourth cell of a
three-column table and were invisible in the rendered guide. Both describe how to lose a warm tier
during a brownout, which is the failure this whole branch exists to prevent.
"""
from pathlib import Path

import pytest

_DOCS = sorted((Path(__file__).resolve().parents[1] / "docs").glob("*.md"))


def _cells(line: str) -> int:
    """Cell count for a pipe-table row, ignoring escaped pipes and pipes inside `code`."""
    stripped = line.strip()
    body = stripped[1:] if stripped.startswith("|") else stripped
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    out, depth, prev = 1, False, ""
    for ch in body:
        if ch == "`":
            depth = not depth
        elif ch == "|" and not depth and prev != "\\":
            out += 1
        prev = ch
    return out


@pytest.mark.parametrize("doc", _DOCS, ids=lambda p: p.name)
def test_every_table_row_has_exactly_the_columns_its_header_declares(doc: Path) -> None:
    lines = doc.read_text().splitlines()
    bad: list[str] = []
    header_cells = None
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s.startswith("|"):
            header_cells = None
            continue
        if set(s) <= set("|-: "):          # the |---|---| separator
            header_cells = _cells(lines[n - 2]) if n >= 2 else None
            continue
        if header_cells is None:
            continue
        got = _cells(line)
        if got != header_cells:
            bad.append(f"{doc.name}:{n} has {got} cells, header declares {header_cells}: "
                       f"{s[:90]}")
    assert not bad, (
        "table rows whose surplus cells are DROPPED by markdown renderers:\n  " + "\n  ".join(bad)
    )
