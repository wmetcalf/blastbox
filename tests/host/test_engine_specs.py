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


def test_allowed_param_keys_default_none_when_unset():
    # UNSET env var -> None (legacy denylist), distinct from a SET-but-empty allowlist.
    specs = _parse_engine_specs("clippyshot=img:t")
    assert specs["clippyshot"].allowed_param_keys is None


def test_allowed_param_keys_set_empty_is_empty_frozenset_not_none(monkeypatch):
    # SET-but-empty -> empty frozenset (blocks ALL client params), NOT None.
    monkeypatch.setenv("BLASTBOX_ENGINE_CLIPPYSHOT_PARAM_KEYS", "")
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


def test_sanitize_params_no_allowlist_is_legacy_denylist():
    """allowed_keys=None (UNSET) preserves legacy behaviour: shape + reserved denylist only,
    so a genuinely non-reserved key still passes. But security-posture keys (CLIPPYSHOT_
    SANDBOX / WARN_ON_INSECURE / DISCLOSE_SECURITY_INTERNALS), the framework prefixes
    (BLASTBOX_/LD_/PYTHON), and resolution keys (PATH/IFS) are reserved UNCONDITIONALLY —
    never client-settable, even with no per-engine allowlist (fail-safe floor)."""
    out = Dispatcher._sanitize_params(
        {
            "CLIPPYSHOT_OCR": "1",               # non-reserved → passes on the legacy path
            "CLIPPYSHOT_SANDBOX": "bwrap",       # reserved: inner-sandbox downgrade
            "CLIPPYSHOT_WARN_ON_INSECURE": "1",  # reserved: insecure-mode fallback
            "BLASTBOX_ENGINE": "evil",           # reserved: framework prefix
            "PATH": "/tmp",                      # reserved: executable resolution hijack
        }
    )
    assert out == {"CLIPPYSHOT_OCR": "1"}


def test_sanitize_params_explicit_empty_allowlist_blocks_all():
    """A SET-but-empty allowlist (frozenset()) is NOT 'unset' — it blocks ALL client params
    (default-deny), the operator's explicit intent. It must not collapse to legacy."""
    out = Dispatcher._sanitize_params({"CLIPPYSHOT_OCR": "1", "FOO": "bar"}, frozenset())
    assert out == {}
