"""Every periodic loop must stamp its deadline from COMPLETION, not from before the work.

`if now - last >= interval: last = now; do_work()` reads as a rate limit and is not one. When the
work outlasts the interval — which is exactly what happens when the thing it talks to is unhealthy
— the deadline is already overdue the moment the work returns, so the next pass fires immediately
and the loop degrades into a hot retry against a struggling dependency. The interval logic
producing no interval, precisely when it matters.

This branch fixed it three times in three separate loops, one round apart each, because the fix
kept being applied to the loop someone was looking at:

  * VmJobDispatcher._maintenance_loop, canary       (found first)
  * VmJobDispatcher._maintenance_loop, maintenance  (its own sibling, one commit later)
  * Dispatcher._run_forever_serial and
    Dispatcher._run_forever_concurrent               (both siblings, the round after that)

`scripts/pattern_sweep.py` has a P3 pass for stamp-before-call, but it is ADVISORY by design: it
cannot tell a stamp that RECORDS AN EVENT (`self._fail_at = now` at the moment of failure —
correct) from one written before the work it throttles (the bug). This check is narrow enough to
gate: it looks only at loop bodies that BOTH do periodic work AND stamp a `last_*` deadline, where
the ordering is unambiguous.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "blastbox" / "host"
_FILES = (
    pytest.param(_SRC / "dispatch.py", id="dispatch"),
    pytest.param(_SRC / "runtime" / "vm_dispatch.py", id="vm_dispatch"),
)

#: Calls that ARE the periodic work — the thing the deadline is meant to space out.
_WORK = {"_run_maintenance", "self_test", "cb", "_canary_cb"}


def _stamp_sites(path: Path):
    """(function, deadline, stamp_line, work_line) for every periodic block in `path`."""
    tree = ast.parse(path.read_text())
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            stamps = [(s.lineno, s.targets[0].id) for s in node.body
                      if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name)
                      and s.targets[0].id.startswith("last_")]
            work = [(c.lineno, c.func.attr if isinstance(c.func, ast.Attribute)
                     else getattr(c.func, "id", ""))
                    for stmt in node.body for c in ast.walk(stmt) if isinstance(c, ast.Call)]
            work = [(ln, nm) for ln, nm in work if nm in _WORK]
            if not stamps or not work:
                continue
            for stamp_line, deadline in stamps:
                yield fn.name, deadline, stamp_line, min(ln for ln, _ in work)


@pytest.mark.parametrize("path", _FILES)
def test_periodic_deadlines_are_stamped_after_the_work(path):
    """The stamp must follow the call it throttles, in every loop, in every file.

    MUTATION: move any `last_* = time.monotonic()` above its `_run_maintenance()` / probe call ->
    this fails, naming the loop.
    """
    offenders = [
        f"{fn}(): {deadline} stamped at line {stamp} but the work it throttles starts at line "
        f"{work} -- a sweep longer than the interval leaves the deadline already overdue on "
        f"return, so the next pass fires immediately"
        for fn, deadline, stamp, work in _stamp_sites(path)
        if stamp < work
    ]
    assert not offenders, (
        "a periodic deadline is dated from BEFORE the work it spaces out:\n  "
        + "\n  ".join(offenders))


@pytest.mark.parametrize("path", _FILES)
def test_the_scan_actually_finds_the_loops_it_claims_to_check(path):
    """A structural guard that matches nothing passes forever.

    Both files contain periodic loops; if a refactor renames the deadline variables or the work
    callables out from under this scan, it must fail loudly rather than quietly checking nothing.
    """
    sites = list(_stamp_sites(path))
    assert sites, (
        f"{path.name}: found no periodic stamp/work pairs at all. Either the loops moved or the "
        f"names in _WORK are stale -- this guard is now checking nothing and would not notice the "
        f"bug it exists for")
