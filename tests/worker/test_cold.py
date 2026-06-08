"""TDD tests for the generic cold-path worker entrypoint (blastbox.worker.cold).

The reusable equivalent of the FC run_guest.py / gVisor run_warm.py loaders: load
the operator-selected engine from BLASTBOX_ENGINE='module:Class' and run the
harness. A worker image's ENTRYPOINT is `python -m blastbox.worker.cold`.
"""
from __future__ import annotations

import pytest

from blastbox.worker import cold
from blastbox.worker.load import load_engine


class _StubEngine:
    name = "stub"
    formats = frozenset({"*"})

    def detonate(self, input, outdir, limits):  # pragma: no cover - not called here
        raise NotImplementedError


def test_load_engine_resolves_module_class():
    eng = load_engine("tests.worker.test_cold:_StubEngine")
    assert isinstance(eng, _StubEngine)
    assert eng.name == "stub"


def test_load_engine_bad_spec_raises():
    with pytest.raises(ValueError):
        load_engine("no_colon_here")


def test_cold_main_missing_engine_env_returns_nonzero(monkeypatch):
    monkeypatch.delenv("BLASTBOX_ENGINE", raising=False)
    assert cold.main([]) == 4


def test_cold_main_loads_engine_and_delegates_to_harness(monkeypatch):
    captured = {}

    def _spy(engine, argv):
        captured["engine"] = engine
        captured["argv"] = argv
        return 0

    monkeypatch.setattr(cold, "harness_main", _spy)
    monkeypatch.setenv("BLASTBOX_ENGINE", "tests.worker.test_cold:_StubEngine")
    rc = cold.main([])
    assert rc == 0
    assert isinstance(captured["engine"], _StubEngine)
    assert captured["argv"] == []
