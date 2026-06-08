"""TDD for `blastbox dispatch` engine-spec parsing (BLASTBOX_ENGINES).

The default worker_argv must be [] — the engine image's ENTRYPOINT is
self-contained (e.g. `python -m blastbox.worker.cold`); the old ["worker","run"]
default was dead glue (no such command) that harness.main would argparse-reject.
"""
from __future__ import annotations

from blastbox.host.cli import _parse_engine_specs
from blastbox.host.dispatch import EngineSpec


def test_parse_single_engine_default_argv_is_empty():
    specs = _parse_engine_specs("clippyshot=clippyshot-blastbox-worker:runsc")
    assert specs == {
        "clippyshot": EngineSpec(
            name="clippyshot",
            image="clippyshot-blastbox-worker:runsc",
            worker_argv=[],
        )
    }


def test_parse_multiple_engines():
    specs = _parse_engine_specs("a=img1:t, b=img2:t")
    assert set(specs) == {"a", "b"}
    assert specs["a"].worker_argv == []
    assert specs["b"].image == "img2:t"


def test_parse_empty_is_empty():
    assert _parse_engine_specs("") == {}


def test_parse_malformed_ignored():
    assert _parse_engine_specs("noequalsign") == {}
