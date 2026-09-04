"""The container and network dispatchers must perform the SAME startup sequence.

There are two entrypoints that boot a dispatcher — `Dispatcher.run_forever` (container/file) and
the network branch of `_dispatch_cmd` (aws/static/cascade). They have to agree about topology
enforcement, and nothing made them.

Five separate fixes on this branch were applied to one and not its twin before someone noticed:

  * hoisting the blob-store identity log out of the BLASTBOX_CANARY toggle
  * hoisting check_store_coherence out of it (so CANARY=0 stopped silently dropping the hard
    BLASTBOX_REQUIRE_SHARED_BLOB_STORE requirement)
  * hoisting check_blob_target_agreement out of it
  * re-stamping the maintenance deadline from completion
  * deferring the blob-target registration until after the startup probe

Each was found by review, one round apart, always the same shape: the reasoning was written down
in a comment at the first site and the sibling was left as it was. Fixing a sixth instance is worth
less than making the divergence impossible to land, which is what this does.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src" / "blastbox" / "host"

#: The startup steps whose PLACEMENT is part of the contract.
_TOPOLOGY = (
    "describe_blob_store",
    "check_store_coherence",
    "check_blob_target_agreement",
)
_PROBE = ("self_test", "blob_roundtrip")

_ENTRYPOINTS = (
    pytest.param(_SRC / "dispatch.py", "run_forever", id="container"),
    pytest.param(_SRC / "cli.py", "_dispatch_cmd", id="network"),
)


def _startup_sequence(path: Path, func: str) -> list[tuple[int, str, bool]]:
    """(line, step, canary_gated) for each startup step, in source order.

    Nested function bodies are skipped: the network path defines a periodic-canary closure whose
    `blob_roundtrip` runs later from a callback, and counting it as a startup step would make the
    two paths look different when they are not.
    """
    tree = ast.parse(path.read_text())
    parents: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    target = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == func
    )

    def _in_nested_def(node) -> bool:  # noqa: ANN001
        cur = node
        while cur in parents:
            cur = parents[cur]
            if cur is target:
                return False
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return True
        return False

    def _canary_gated(node) -> bool:  # noqa: ANN001
        cur = node
        while cur in parents:
            cur = parents[cur]
            if cur is target:
                return False
            if isinstance(cur, ast.If):
                names = {n.id for n in ast.walk(cur.test) if isinstance(n, ast.Name)}
                if any("canary" in n for n in names):
                    return True
        return False

    out = []
    for node in ast.walk(target):
        if not isinstance(node, ast.Call) or _in_nested_def(node):
            continue
        name = (
            node.func.attr
            if isinstance(node.func, ast.Attribute)
            else getattr(node.func, "id", None)
        )
        if name in _TOPOLOGY + _PROBE:
            out.append((node.lineno, name, _canary_gated(node)))
    return sorted(out)


@pytest.mark.parametrize(("path", "func"), _ENTRYPOINTS)
def test_topology_enforcement_is_never_behind_the_canary_toggle(path, func):
    """BLASTBOX_CANARY turns off the write/read PROBE. It must not turn off enforcement.

    Coupling them meant CANARY=0 silently dropped an explicit hard requirement — documented as
    failing closed — and a dispatcher on a private store started and produced DONE jobs no other
    machine could read.
    """
    seq = _startup_sequence(path, func)
    gated = [(ln, nm) for ln, nm, g in seq if g and nm in _TOPOLOGY]
    assert not gated, (
        f"{func}() gates topology enforcement behind BLASTBOX_CANARY at {gated}; that switch is "
        f"documented as controlling the round-trip probe only, and hiding a fail-closed "
        f"requirement behind an unrelated opt-out is how results become unreadable"
    )


@pytest.mark.parametrize(("path", "func"), _ENTRYPOINTS)
def test_every_entrypoint_performs_the_whole_startup_sequence(path, func):
    """Both dispatchers do all of it, or the one that skips a step is the one that breaks."""
    present = {nm for _, nm, _ in _startup_sequence(path, func)}
    missing = [s for s in _TOPOLOGY if s not in present]
    assert not missing, (
        f"{func}() never calls {missing}; the other dispatcher entrypoint does, so this one boots "
        f"without a check its twin treats as mandatory"
    )
    assert present & set(_PROBE), f"{func}() never runs the startup probe at all"


@pytest.mark.parametrize(("path", "func"), _ENTRYPOINTS)
def test_the_blob_target_is_registered_only_after_the_probe(path, func):
    """Registration PERSISTS, so it must not happen until the store has proven it works.

    A dispatcher pointed at an unreachable bucket used to claim that target and only then fail its
    probe — after which correcting the config was not enough, because the fixed process mismatched
    its own stale registration and needed a `blob-target reset` no operator would think to run.
    """
    seq = _startup_sequence(path, func)
    probe = [ln for ln, nm, _ in seq if nm in _PROBE]
    claim = [ln for ln, nm, _ in seq if nm == "check_blob_target_agreement"]
    assert probe and claim, (
        f"{func}(): need both a probe and a registration to compare ({seq})"
    )
    assert min(claim) > min(probe), (
        f"{func}() registers the blob target at line {min(claim)}, before the startup probe at "
        f"line {min(probe)}; a target that never proved it works must not become the one every "
        f"other process has to match"
    )


def test_both_entrypoints_agree_on_which_steps_are_gated():
    """The parity check itself: same steps, same gating, on both paths.

    Stated as a comparison rather than as two independent expectations, because the failure this
    guards against is DIVERGENCE — one path being changed and the other left behind. A rule written
    only against the path someone happened to edit would not have caught any of the five.
    """
    shape = {}
    for param in _ENTRYPOINTS:
        path, func = param.values
        seq = _startup_sequence(path, func)
        shape[func] = {nm: g for _, nm, g in seq if nm in _TOPOLOGY}

    (a_name, a), (b_name, b) = shape.items()
    assert a == b, (
        f"the two dispatcher entrypoints disagree about topology enforcement.\n"
        f"  {a_name}: {a}\n  {b_name}: {b}\n"
        f"Five fixes on this branch were applied to one path and not the other; if you are "
        f"changing one, change both."
    )
