"""Tests for blastbox.host.runtime.host_limits — host-aware worker cap computation."""
from __future__ import annotations

import pytest

from blastbox.host.runtime.host_limits import (
    compute_host_defaults,
    apply_host_defaults,
    parse_memory_gb,
)


# ---------------------------------------------------------------------------
# parse_memory_gb
# ---------------------------------------------------------------------------

def test_parse_memory_gb_g_suffix():
    assert parse_memory_gb("4g") == pytest.approx(4.0)


def test_parse_memory_gb_m_suffix():
    assert parse_memory_gb("512m") == pytest.approx(512 / 1024)


def test_parse_memory_gb_k_suffix():
    # 1048576 kB = 1 GiB = 1.0 GB
    assert parse_memory_gb("1048576k") == pytest.approx(1.0)


def test_parse_memory_gb_uppercase():
    assert parse_memory_gb("2G") == pytest.approx(2.0)


def test_parse_memory_gb_empty_returns_zero():
    assert parse_memory_gb("") == 0.0


def test_parse_memory_gb_invalid_returns_zero():
    assert parse_memory_gb("bogus") == 0.0


# ---------------------------------------------------------------------------
# compute_host_defaults — pure computation with injected cpu/mem
# ---------------------------------------------------------------------------

def test_single_cpu_host():
    """1 CPU → concurrency=1, cpus floored at _MIN (1.0)."""
    d = compute_host_defaults(cpu_count=1, mem_gb=8.0, env={})
    assert d.concurrency == 1
    assert d.host_cpus == 1
    assert float(d.worker_cpus) >= 1.0


def test_sixteen_cpu_host():
    """16 CPU → concurrency capped at _MAX_CONCURRENCY (16)."""
    d = compute_host_defaults(cpu_count=16, mem_gb=64.0, env={})
    assert d.concurrency <= 16
    assert d.host_cpus == 16


def test_eight_cpu_host():
    """8 CPU, 32 GB → sensible concurrency and memory."""
    d = compute_host_defaults(cpu_count=8, mem_gb=32.0, env={})
    assert 1 <= d.concurrency <= 8
    # Worker memory must be between floor and ceiling
    mem_gb = parse_memory_gb(d.worker_memory)
    assert 1.0 <= mem_gb <= 4.0


def test_low_memory_host_floors_at_min():
    """Very low memory → worker_memory floored at _MIN_WORKER_MEMORY_GB."""
    d = compute_host_defaults(cpu_count=4, mem_gb=2.0, env={})
    mem_gb = parse_memory_gb(d.worker_memory)
    assert mem_gb >= 1.0


def test_high_memory_host_caps_at_max():
    """Very high memory → worker_memory capped at _MAX_WORKER_MEMORY_GB."""
    d = compute_host_defaults(cpu_count=4, mem_gb=512.0, env={})
    mem_gb = parse_memory_gb(d.worker_memory)
    assert mem_gb <= 4.0


def test_zero_memory_falls_back_to_default():
    """mem_gb=0 (probe failed) → fallback default applied."""
    d = compute_host_defaults(cpu_count=4, mem_gb=0.0, env={})
    # Should still have a non-zero worker_memory
    mem_gb = parse_memory_gb(d.worker_memory)
    assert mem_gb > 0


def test_env_override_worker_memory():
    """BLASTBOX_WORKER_MEMORY env wins over computed value."""
    d = compute_host_defaults(
        cpu_count=4, mem_gb=16.0,
        env={"BLASTBOX_WORKER_MEMORY": "2g"},
    )
    assert d.worker_memory == "2g"


def test_env_override_worker_cpus():
    d = compute_host_defaults(
        cpu_count=8, mem_gb=32.0,
        env={"BLASTBOX_WORKER_CPUS": "3.0"},
    )
    assert d.worker_cpus == "3.0"


def test_env_override_pids_limit():
    d = compute_host_defaults(
        cpu_count=4, mem_gb=16.0,
        env={"BLASTBOX_WORKER_PIDS_LIMIT": "512"},
    )
    assert d.worker_pids_limit == "512"


def test_env_override_concurrency():
    d = compute_host_defaults(
        cpu_count=4, mem_gb=16.0,
        env={"BLASTBOX_DISPATCH_CONCURRENCY": "3"},
    )
    assert d.concurrency == 3


def test_env_concurrency_bad_value_falls_back():
    """Bad concurrency env value → falls back to computed, doesn't crash."""
    d = compute_host_defaults(
        cpu_count=4, mem_gb=16.0,
        env={"BLASTBOX_DISPATCH_CONCURRENCY": "not-a-number"},
    )
    assert d.concurrency >= 1


def test_host_defaults_fields_populated():
    """HostDefaults has expected non-empty fields."""
    d = compute_host_defaults(cpu_count=4, mem_gb=8.0, env={})
    assert d.concurrency >= 1
    assert d.worker_memory  # non-empty string
    assert d.worker_cpus    # non-empty string
    assert d.worker_pids_limit  # non-empty string
    assert d.host_cpus == 4
    assert d.host_mem_gb == pytest.approx(8.0, abs=0.01)


def test_host_defaults_is_frozen():
    d = compute_host_defaults(cpu_count=4, mem_gb=8.0, env={})
    with pytest.raises((AttributeError, TypeError)):
        d.concurrency = 99  # type: ignore[misc]


def test_worker_cpus_is_dotted_float_string():
    """worker_cpus must include a decimal point (docker CLI expects '1.0' not '1')."""
    d = compute_host_defaults(cpu_count=2, mem_gb=8.0, env={})
    assert "." in d.worker_cpus


# ---------------------------------------------------------------------------
# apply_host_defaults — pokes computed values into env dict
# ---------------------------------------------------------------------------

def test_apply_host_defaults_sets_unset_keys():
    env: dict[str, str] = {}
    defaults = apply_host_defaults(cpu_count=4, mem_gb=16.0, env=env)
    assert env.get("BLASTBOX_WORKER_MEMORY") == defaults.worker_memory
    assert env.get("BLASTBOX_WORKER_CPUS") == defaults.worker_cpus
    assert env.get("BLASTBOX_WORKER_PIDS_LIMIT") == defaults.worker_pids_limit
    assert env.get("BLASTBOX_DISPATCH_CONCURRENCY") == str(defaults.concurrency)


def test_apply_host_defaults_does_not_overwrite_set_keys():
    env: dict[str, str] = {"BLASTBOX_WORKER_MEMORY": "1g"}
    apply_host_defaults(cpu_count=4, mem_gb=16.0, env=env)
    # Existing value preserved
    assert env["BLASTBOX_WORKER_MEMORY"] == "1g"


def test_apply_host_defaults_does_not_overwrite_empty_string():
    """An empty-string value (compose sets these when unset) should be treated as unset."""
    env: dict[str, str] = {"BLASTBOX_WORKER_MEMORY": ""}
    apply_host_defaults(cpu_count=4, mem_gb=16.0, env=env)
    # Empty string replaced with computed value
    assert env["BLASTBOX_WORKER_MEMORY"] != ""
