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


def test_reserved_param_keys_default_empty_when_unset():
    # UNSET -> empty frozenset (no engine-declared reserved keys); the generic floor still applies.
    specs = _parse_engine_specs("foo=img:t")
    assert specs["foo"].reserved_param_keys == frozenset()


def test_reserved_param_keys_from_env(monkeypatch):
    # BLASTBOX_ENGINE_<NAME>_RESERVED_KEYS parses like the allowlist. Generic names — the
    # engine OWNS its dangerous keys; blastbox just carries whatever the deploy declares.
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_FOO_RESERVED_KEYS",
        "FOO_JAVA_BIN, FOO_SANDBOX ,FOO_OPTS",
    )
    specs = _parse_engine_specs("foo=img:t")
    assert specs["foo"].reserved_param_keys == frozenset(
        {"FOO_JAVA_BIN", "FOO_SANDBOX", "FOO_OPTS"}
    )


def test_param_keys_env_name_and_keys_are_normalized(monkeypatch):
    """Two normalizations matter for correctness + security:
    - the engine name → env var: hyphens become underscores (env vars can't hold hyphens),
    - keys → UPPERCASE: client keys are uppercase-only, so a lowercase RESERVED entry would
      silently never match and BYPASS the denylist (fail-dangerous); allowlist entries
      uppercase too (a lowercase allowlist entry would fail-closed, also wrong)."""
    monkeypatch.setenv("BLASTBOX_ENGINE_TEST_ENGINE_PARAM_KEYS", "foo_ocr, Foo_Qr")
    monkeypatch.setenv("BLASTBOX_ENGINE_TEST_ENGINE_RESERVED_KEYS", "foo_java_bin, Foo_Sandbox")
    specs = _parse_engine_specs("test-engine=img:t")
    assert specs["test-engine"].allowed_param_keys == frozenset({"FOO_OCR", "FOO_QR"})
    assert specs["test-engine"].reserved_param_keys == frozenset({"FOO_JAVA_BIN", "FOO_SANDBOX"})


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


def test_sanitize_params_generic_floor_is_unconditional():
    """allowed_keys=None (UNSET) = legacy shape+denylist. The ENGINE-AGNOSTIC floor —
    framework/loader/interpreter prefixes (BLASTBOX_/LD_/PYTHON) + executable-resolution
    keys (PATH/IFS) — is reserved UNCONDITIONALLY, for EVERY engine, even with no allowlist.
    A genuinely non-reserved key still passes. (Generic key names: blastbox names no engine.)"""
    out = Dispatcher._sanitize_params(
        {
            "SOME_TOGGLE": "1",          # non-reserved → passes on the legacy path
            "BLASTBOX_ENGINE": "evil",   # reserved: framework prefix
            "LD_PRELOAD": "/tmp/x.so",   # reserved: loader hijack
            "PYTHONPATH": "/tmp",        # reserved: interpreter hijack
            "PATH": "/tmp",              # reserved: executable resolution hijack
            "IFS": " ",                  # reserved: shell field-splitting
        }
    )
    assert out == {"SOME_TOGGLE": "1"}


def test_sanitize_params_engine_reserved_keys_dropped_even_without_allowlist():
    """Engine-OWNED reserved keys (a sandbox selector, a JVM binary/jar/opts path) are
    dropped UNCONDITIONALLY — even with allowed_keys=None — via the per-engine reserved set,
    so blastbox core never names them. Generic placeholders: no engine-specific strings."""
    reserved = frozenset({"ENGINE_SANDBOX", "ENGINE_JAVA_BIN"})
    out = Dispatcher._sanitize_params(
        {
            "ENGINE_TOGGLE": "1",          # not reserved → passes (legacy path, no allowlist)
            "ENGINE_SANDBOX": "weak",      # engine-reserved → dropped
            "ENGINE_JAVA_BIN": "/tmp/evil",  # engine-reserved → dropped
        },
        None,            # no allowlist configured
        reserved,        # the engine's declared reserved set (belt-and-suspenders floor)
    )
    assert out == {"ENGINE_TOGGLE": "1"}


def test_sanitize_params_explicit_empty_allowlist_blocks_all():
    """A SET-but-empty allowlist (frozenset()) is NOT 'unset' — it blocks ALL client params
    (default-deny), the operator's explicit intent. It must not collapse to legacy."""
    out = Dispatcher._sanitize_params({"CLIPPYSHOT_OCR": "1", "FOO": "bar"}, frozenset())
    assert out == {}
