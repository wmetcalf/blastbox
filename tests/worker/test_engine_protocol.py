"""The Engine protocol must require exactly what its docstring says it requires.

Issue #86: ``detect`` and ``warmup`` were declared as plain methods on the
``Engine`` Protocol. A plain method in a Protocol is a REQUIRED member for
structural typing, so an engine implementing exactly the documented minimum
(``name``, ``formats``, ``detonate``) failed ``isinstance(e, Engine)`` and was
rejected by mypy — contradicting the docstring, the section comment, and all
three ``hasattr``-shaped call sites.
"""

from __future__ import annotations

from pathlib import Path

from blastbox.contract import Detection
from blastbox.limits import Limits
from blastbox.worker.engine import (
    DetonationResult,
    Engine,
    SupportsDetect,
    SupportsWarmup,
)


class MinimalEngine:
    """Exactly what Engine documents as sufficient — nothing more."""

    name = "minimal"
    formats = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        raise NotImplementedError


class FullEngine(MinimalEngine):
    def detect(self, input: Path) -> Detection:
        raise NotImplementedError

    def warmup(self) -> None:
        return None


def test_the_documented_minimum_satisfies_engine():
    """The whole point of #86: this was False."""
    assert isinstance(MinimalEngine(), Engine)


def test_optional_methods_are_not_required_by_engine():
    assert not isinstance(MinimalEngine(), SupportsDetect)
    assert not isinstance(MinimalEngine(), SupportsWarmup)


def test_an_engine_providing_the_optional_methods_is_recognised():
    """The call sites narrow on these, so a real engine must match."""
    full = FullEngine()
    assert isinstance(full, Engine)
    assert isinstance(full, SupportsDetect)
    assert isinstance(full, SupportsWarmup)


def test_optional_methods_reach_an_engine_that_delegates_via_getattr():
    """The harness must keep using hasattr(), not isinstance().

    A runtime-checkable Protocol resolves members against the CLASS, so a wrapper
    that forwards optional methods through __getattr__ answers hasattr() True but
    isinstance() False. Engines load out-of-tree and may well be such wrappers, so
    swapping the harness guards to isinstance would silently stop calling
    detect/warmup on them. This pins the asymmetry that makes that a real hazard.
    """

    class Delegating:
        name = "wrapped"
        formats = frozenset({"*"})

        def __init__(self, inner):
            self._inner = inner

        def detonate(self, input: Path, outdir: Path, limits: Limits):
            raise NotImplementedError

        def __getattr__(self, item):
            return getattr(self._inner, item)

    w = Delegating(FullEngine())
    assert hasattr(w, "detect"), "the wrapper does expose detect"
    assert hasattr(w, "warmup")
    assert not isinstance(w, SupportsDetect), (
        "isinstance cannot see __getattr__-delegated methods — this is exactly why "
        "the harness guards with hasattr"
    )
    assert not isinstance(w, SupportsWarmup)


def test_the_optional_protocols_require_the_engine_members_too():
    """SupportsDetect means "an Engine that also detects", not "anything with detect"."""

    class OnlyDetect:
        def detect(self, input: Path):
            raise NotImplementedError

    assert not isinstance(OnlyDetect(), SupportsDetect)


def test_an_object_missing_a_required_member_is_still_rejected():
    """The protocol must not have been loosened into meaninglessness."""

    class NoDetonate:
        name = "x"
        formats = frozenset({"*"})

    assert not isinstance(NoDetonate(), Engine)
