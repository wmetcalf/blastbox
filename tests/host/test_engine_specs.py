"""TDD for `blastbox dispatch` engine-spec parsing (BLASTBOX_ENGINES).

The default worker_argv must be [] — the engine image's ENTRYPOINT is
self-contained (e.g. `python -m blastbox.worker.cold`); the old ["worker","run"]
default was dead glue (no such command) that harness.main would argparse-reject.
"""

from __future__ import annotations

import pytest

from blastbox.host.cli import _parse_engine_specs
from blastbox.host.dispatch import (
    Dispatcher,
    EngineSpec,
    enforce_allowed_runtimes,
    reachable_tiers,
)


class _FakeTier:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeRuntime:
    def __init__(self, dispatch_style="file", kind=None, tiers=None) -> None:
        self.dispatch_style = dispatch_style
        if kind is not None:
            self.kind = kind
        if tiers is not None:
            self.tiers = tiers


class _FakePool:
    def __init__(self, runtime) -> None:
        self.runtime = runtime


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


def test_allowed_runtimes_default_none_when_unset():
    # UNSET -> None (no tier restriction; the engine may run on any dispatcher tier).
    specs = _parse_engine_specs("clippyshot=img:t")
    assert specs["clippyshot"].allowed_runtimes is None


def test_allowed_runtimes_from_env_normalized(monkeypatch):
    # Comma-list, stripped + lowercased, into a frozenset of canonical tier names.
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_CLIPPYSHOT_ALLOWED_RUNTIMES", "cold, Firecracker ,GVISOR"
    )
    specs = _parse_engine_specs("clippyshot=img:t")
    assert specs["clippyshot"].allowed_runtimes == frozenset(
        {"cold", "firecracker", "gvisor"}
    )


def test_allowed_runtimes_set_but_empty_is_unset(monkeypatch):
    # SET-but-empty (the `${VAR:-}` compose idiom) -> None (any tier), NOT an empty set that would
    # make the engine unrunnable on every tier. Differs deliberately from allowed_param_keys.
    for empty in ("", "   ", ",  ,"):
        monkeypatch.setenv("BLASTBOX_ENGINE_CLIPPYSHOT_ALLOWED_RUNTIMES", empty)
        specs = _parse_engine_specs("clippyshot=img:t")
        assert specs["clippyshot"].allowed_runtimes is None, repr(empty)


def test_enforce_allowed_runtimes_error_names_normalized_env_var():
    # Hyphenated engine name -> the suggested env var must normalize '-' to '_' (a shell-valid name).
    engines = {
        "test-engine": EngineSpec(
            "test-engine", "img:t", [], allowed_runtimes=frozenset({"cold"})
        )
    }
    with pytest.raises(
        ValueError, match="BLASTBOX_ENGINE_TEST_ENGINE_ALLOWED_RUNTIMES"
    ):
        enforce_allowed_runtimes(engines, "gvisor")


def test_allowed_runtimes_unknown_tier_raises(monkeypatch):
    # A typo'd/unknown tier name is a config error, not a silently-dropped entry (dropping could
    # leave the set permitting an unintended tier). Fail loudly at parse time.
    monkeypatch.setenv("BLASTBOX_ENGINE_CLIPPYSHOT_ALLOWED_RUNTIMES", "cold,aws-ec3")
    with pytest.raises(ValueError, match="unknown tier"):
        _parse_engine_specs("clippyshot=img:t")


def test_enforce_allowed_runtimes_allows_covered_and_unrestricted():
    engines = {
        "restricted": EngineSpec(
            "restricted", "img:t", [], allowed_runtimes=frozenset({"cold", "gvisor"})
        ),
        "any": EngineSpec(
            "any", "img:t", []
        ),  # allowed_runtimes=None -> no restriction
    }
    enforce_allowed_runtimes(engines, {"cold"})  # both permitted
    enforce_allowed_runtimes(engines, {"cold", "gvisor"})  # reachable set fully covered


def test_enforce_allowed_runtimes_refuses_disallowed_tier():
    engines = {
        "clippyshot": EngineSpec(
            "clippyshot",
            "img:t",
            [],
            allowed_runtimes=frozenset({"cold", "firecracker", "gvisor"}),
        ),
    }
    # A BLASTBOX_POOL_RUNTIME drift onto a public-AWS tier the engine wasn't cleared for must fail closed.
    with pytest.raises(ValueError, match="not permitted on tier.*aws-ec2"):
        enforce_allowed_runtimes(engines, {"aws-ec2"})


def test_enforce_refuses_cold_fallback_tier_not_in_allowlist():
    # Codex P1: a firecracker+cold-fallback dispatcher can run on "cold"; an engine cleared only for
    # firecracker must fail closed because reachable_tiers folds "cold" into the reachable set.
    engines = {
        "clippyshot": EngineSpec(
            "clippyshot", "img:t", [], allowed_runtimes=frozenset({"firecracker"})
        )
    }
    reach = reachable_tiers(
        _FakePool(_FakeRuntime("file")), "firecracker", warm_only=False
    )
    with pytest.raises(ValueError, match="not permitted on tier.*cold"):
        enforce_allowed_runtimes(engines, reach)


def test_enforce_refuses_cascade_overflow_tier():
    # Codex P1: BLASTBOX_POOL_RUNTIME=cascade with static:+aws-ec2: reaches BOTH members; an engine
    # cleared only for static must fail closed on the aws-ec2 overflow tier.
    engines = {
        "eng": EngineSpec("eng", "img:t", [], allowed_runtimes=frozenset({"static"}))
    }
    casc = _FakeRuntime(
        "network", kind="cascade", tiers=[_FakeTier("static"), _FakeTier("aws-ec2")]
    )
    reach = reachable_tiers(_FakePool(casc), "cascade", warm_only=True)
    with pytest.raises(ValueError, match="not permitted on tier.*aws-ec2"):
        enforce_allowed_runtimes(engines, reach)


def test_reachable_tiers_paths():
    # No pool -> cold dispatcher.
    assert reachable_tiers(None, "cold", warm_only=False) == frozenset({"cold"})
    # File-handshake warm dispatcher cold-falls-back unless warm-only.
    assert reachable_tiers(
        _FakePool(_FakeRuntime("file")), "firecracker", warm_only=False
    ) == frozenset({"firecracker", "cold"})
    assert reachable_tiers(
        _FakePool(_FakeRuntime("file")), "firecracker", warm_only=True
    ) == frozenset({"firecracker"})
    # Network-endpoint tiers requeue -> no cold fallback.
    assert reachable_tiers(
        _FakePool(_FakeRuntime("network")), "aws-ec2", warm_only=False
    ) == frozenset({"aws-ec2"})
    # Cascade -> concrete member tiers (+ cold when file-handshake + not warm-only).
    file_casc = _FakeRuntime(
        "file", kind="cascade", tiers=[_FakeTier("firecracker"), _FakeTier("gvisor")]
    )
    assert reachable_tiers(
        _FakePool(file_casc), "cascade", warm_only=False
    ) == frozenset({"firecracker", "gvisor", "cold"})


def test_param_keys_env_name_and_keys_are_normalized(monkeypatch):
    """Two normalizations matter for correctness + security:
    - the engine name → env var: hyphens become underscores (env vars can't hold hyphens),
    - keys → UPPERCASE: client keys are uppercase-only, so a lowercase RESERVED entry would
      silently never match and BYPASS the denylist (fail-dangerous); allowlist entries
      uppercase too (a lowercase allowlist entry would fail-closed, also wrong)."""
    monkeypatch.setenv("BLASTBOX_ENGINE_TEST_ENGINE_PARAM_KEYS", "foo_ocr, Foo_Qr")
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_TEST_ENGINE_RESERVED_KEYS", "foo_java_bin, Foo_Sandbox"
    )
    specs = _parse_engine_specs("test-engine=img:t")
    assert specs["test-engine"].allowed_param_keys == frozenset({"FOO_OCR", "FOO_QR"})
    assert specs["test-engine"].reserved_param_keys == frozenset(
        {"FOO_JAVA_BIN", "FOO_SANDBOX"}
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


def test_sanitize_params_generic_floor_is_unconditional():
    """allowed_keys=None (UNSET) = legacy shape+denylist. The ENGINE-AGNOSTIC floor —
    framework/loader/interpreter prefixes (BLASTBOX_/LD_/PYTHON) + executable-resolution
    keys (PATH/IFS) — is reserved UNCONDITIONALLY, for EVERY engine, even with no allowlist.
    A genuinely non-reserved key still passes. (Generic key names: blastbox names no engine.)"""
    out = Dispatcher._sanitize_params(
        {
            "SOME_TOGGLE": "1",  # non-reserved → passes on the legacy path
            "BLASTBOX_ENGINE": "evil",  # reserved: framework prefix
            "LD_PRELOAD": "/tmp/x.so",  # reserved: loader hijack
            "PYTHONPATH": "/tmp",  # reserved: interpreter hijack
            "PATH": "/tmp",  # reserved: executable resolution hijack
            "IFS": " ",  # reserved: shell field-splitting
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
            "ENGINE_TOGGLE": "1",  # not reserved → passes (legacy path, no allowlist)
            "ENGINE_SANDBOX": "weak",  # engine-reserved → dropped
            "ENGINE_JAVA_BIN": "/tmp/evil",  # engine-reserved → dropped
        },
        None,  # no allowlist configured
        reserved,  # the engine's declared reserved set (belt-and-suspenders floor)
    )
    assert out == {"ENGINE_TOGGLE": "1"}


def test_sanitize_params_explicit_empty_allowlist_blocks_all():
    """A SET-but-empty allowlist (frozenset()) is NOT 'unset' — it blocks ALL client params
    (default-deny), the operator's explicit intent. It must not collapse to legacy."""
    out = Dispatcher._sanitize_params(
        {"CLIPPYSHOT_OCR": "1", "FOO": "bar"}, frozenset()
    )
    assert out == {}


# ---------------------------------------------------------------------------
# Operator DEFAULT params (BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS) — make an
# enablement default a runtime decision in the dispatcher env, not a hardcoded
# engine value. Applied UNDER job.params (job wins), through the same gate.
# ---------------------------------------------------------------------------


def test_default_params_default_empty_when_unset():
    specs = _parse_engine_specs("foo=img:t")
    assert specs["foo"].default_params == {}


def test_default_params_parsed_and_uppercased(monkeypatch):
    """Keys upper-cased (UPPERCASE-only forwardable shape — a lowercase default would
    silently never forward); values kept verbatim; engine name hyphen→underscore."""
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_TEST_ENGINE_DEFAULT_PARAMS",
        "foo_qr=1, Foo_Ocr=0 ,FOO_LANG=eng",
    )
    specs = _parse_engine_specs("test-engine=img:t")
    assert specs["test-engine"].default_params == {
        "FOO_QR": "1",
        "FOO_OCR": "0",
        "FOO_LANG": "eng",
    }


def test_default_params_malformed_entries_skipped(monkeypatch):
    # No '=' and empty-key entries are skipped (warned), like _parse_engine_specs.
    monkeypatch.setenv(
        "BLASTBOX_ENGINE_FOO_DEFAULT_PARAMS",
        "FOO_QR=1, garbage , =novalue, FOO_OCR=0",
    )
    specs = _parse_engine_specs("foo=img:t")
    assert specs["foo"].default_params == {"FOO_QR": "1", "FOO_OCR": "0"}


def test_sanitize_params_default_applied_when_job_omits_key():
    """A defaulted key the job doesn't set is forwarded (the new runtime default)."""
    out = Dispatcher._sanitize_params(
        {},  # job sends nothing
        frozenset({"FOO_QR", "FOO_OCR"}),  # allowlist
        frozenset(),  # no engine-reserved
        {"FOO_QR": "1", "FOO_OCR": "0"},  # operator defaults
    )
    assert out == {"FOO_QR": "1", "FOO_OCR": "0"}


def test_sanitize_params_job_value_overrides_default():
    """A per-job value always beats the operator default (default is a floor, not a cap)."""
    out = Dispatcher._sanitize_params(
        {"FOO_QR": "0"},  # job explicitly turns it off
        frozenset({"FOO_QR"}),
        frozenset(),
        {"FOO_QR": "1"},  # default would turn it on
    )
    assert out == {"FOO_QR": "0"}


def test_sanitize_params_default_must_clear_the_allowlist():
    """Defaults get NO privileged path: a defaulted key absent from the allowlist is dropped,
    exactly as a client param would be. One gate for operator policy and client input alike."""
    out = Dispatcher._sanitize_params(
        {},
        frozenset({"FOO_QR"}),  # only FOO_QR forwardable
        frozenset(),
        {"FOO_QR": "1", "FOO_SECRET": "x"},  # FOO_SECRET not allowlisted
    )
    assert out == {"FOO_QR": "1"}


def test_sanitize_params_default_cannot_set_reserved_key():
    """A defaulted RESERVED key (engine-owned or generic floor) is dropped — an operator
    can't accidentally default a security-posture/code-exec key via this convenience knob."""
    out = Dispatcher._sanitize_params(
        {},
        None,  # legacy (no allowlist)
        frozenset({"FOO_JAVA_BIN"}),  # engine-reserved
        {"FOO_TOGGLE": "1", "FOO_JAVA_BIN": "/tmp/evil", "LD_PRELOAD": "/tmp/x.so"},
    )
    assert out == {"FOO_TOGGLE": "1"}
