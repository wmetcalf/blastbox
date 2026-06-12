"""TDD for `blastbox dispatch` engine-spec parsing (BLASTBOX_ENGINES).

The default worker_argv must be [] — the engine image's ENTRYPOINT is
self-contained (e.g. `python -m blastbox.worker.cold`); the old ["worker","run"]
default was dead glue (no such command) that harness.main would argparse-reject.
"""
from __future__ import annotations

from blastbox.host.cli import _parse_engine_specs
from blastbox.host.dispatch import Dispatcher, EngineSpec


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


def test_allowed_param_keys_default_empty():
    specs = _parse_engine_specs("clippyshot=img:t")
    assert specs["clippyshot"].allowed_param_keys == frozenset()


def test_allowed_param_keys_from_env(monkeypatch):
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_CLIPPYSHOT_PARAM_KEYS",
        "CLIPPYSHOT_OCR, CLIPPYSHOT_OCR_ALL ,CLIPPYSHOT_QR",
    )
    specs = _parse_engine_specs("clippyshot=img:t")
    assert specs["clippyshot"].allowed_param_keys == frozenset(
        {"CLIPPYSHOT_OCR", "CLIPPYSHOT_OCR_ALL", "CLIPPYSHOT_QR"}
    )


def test_sanitize_params_allowlist_drops_security_keys():
    """A non-empty allowlist forwards ONLY scanner keys — the inner-sandbox
    downgrade keys (CLIPPYSHOT_SANDBOX / CLIPPYSHOT_WARN_ON_INSECURE) are dropped."""
    allowed = frozenset({"CLIPPYSHOT_OCR", "CLIPPYSHOT_OCR_ALL", "CLIPPYSHOT_QR"})
    out = Dispatcher._sanitize_params(
        {
            "CLIPPYSHOT_OCR": "1",
            "CLIPPYSHOT_OCR_ALL": "1",
            "CLIPPYSHOT_SANDBOX": "bwrap",
            "CLIPPYSHOT_WARN_ON_INSECURE": "0",
            "CLIPPYSHOT_MAX_PAGES": "1000",
        },
        allowed,
    )
    assert out == {"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_OCR_ALL": "1"}


def test_sanitize_params_empty_allowlist_is_legacy_denylist():
    """Empty allowlist preserves legacy behaviour: shape + reserved denylist only,
    so non-reserved keys still pass (back-compat for engines without an allowlist)."""
    out = Dispatcher._sanitize_params(
        {"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_SANDBOX": "bwrap", "BLASTBOX_ENGINE": "evil"}
    )
    assert out == {"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_SANDBOX": "bwrap"}  # BLASTBOX_ reserved
