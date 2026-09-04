"""Tests for blastbox.limits."""

from __future__ import annotations

import pytest

from blastbox.limits import Limits


# ---------------------------------------------------------------------------
# Default values are valid
# ---------------------------------------------------------------------------


def test_defaults_valid():
    lim = Limits()
    assert lim.timeout_s > 0
    assert lim.memory_bytes > 0
    assert lim.tmpfs_bytes > 0
    assert lim.max_input_bytes > 0
    assert lim.max_metadata_bytes > 0
    assert lim.max_artifact_bytes > 0
    assert lim.max_total_artifact_bytes > 0
    assert lim.max_artifacts > 0


# ---------------------------------------------------------------------------
# Bounds checking — zero/negative rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "memory_bytes",
        "tmpfs_bytes",
        "max_input_bytes",
        "max_metadata_bytes",
        "max_artifact_bytes",
        "max_total_artifact_bytes",
    ],
)
def test_byte_field_zero_rejected(field):
    with pytest.raises(ValueError, match=field):
        Limits(**{field: 0})


@pytest.mark.parametrize(
    "field",
    [
        "memory_bytes",
        "tmpfs_bytes",
        "max_input_bytes",
        "max_metadata_bytes",
        "max_artifact_bytes",
        "max_total_artifact_bytes",
    ],
)
def test_byte_field_negative_rejected(field):
    with pytest.raises(ValueError, match=field):
        Limits(**{field: -1})


@pytest.mark.parametrize(
    "field",
    [
        "memory_bytes",
        "tmpfs_bytes",
        "max_input_bytes",
        "max_metadata_bytes",
        "max_artifact_bytes",
        "max_total_artifact_bytes",
    ],
)
def test_byte_field_huge_rejected(field):
    # 1000 GiB is above the ceiling
    huge = 1000 * 1024 * 1024 * 1024
    with pytest.raises(ValueError, match=field):
        Limits(**{field: huge})


def test_timeout_zero_rejected():
    with pytest.raises(ValueError, match="timeout_s"):
        Limits(timeout_s=0)


def test_timeout_negative_rejected():
    with pytest.raises(ValueError, match="timeout_s"):
        Limits(timeout_s=-5)


def test_timeout_huge_rejected():
    with pytest.raises(ValueError, match="timeout_s"):
        Limits(timeout_s=100_000)


def test_max_artifacts_zero_rejected():
    with pytest.raises(ValueError, match="max_artifacts"):
        Limits(max_artifacts=0)


def test_max_artifacts_negative_rejected():
    with pytest.raises(ValueError, match="max_artifacts"):
        Limits(max_artifacts=-1)


# ---------------------------------------------------------------------------
# from_env — parse env vars
# ---------------------------------------------------------------------------


def test_from_env_timeout(monkeypatch):
    monkeypatch.setenv("BLASTBOX_TIMEOUT", "120")
    lim = Limits.from_env()
    assert lim.timeout_s == 120


def test_from_env_memory(monkeypatch):
    monkeypatch.setenv("BLASTBOX_MEM", str(4 * 1024 * 1024 * 1024))
    lim = Limits.from_env()
    assert lim.memory_bytes == 4 * 1024 * 1024 * 1024


def test_from_env_max_input(monkeypatch):
    monkeypatch.setenv("BLASTBOX_MAX_INPUT", str(50 * 1024 * 1024))
    lim = Limits.from_env()
    assert lim.max_input_bytes == 50 * 1024 * 1024


def test_net_egress_defaults_off():
    # Fail-closed: a worker has no egress (inner sandbox isolates) unless a policy grants one.
    assert Limits().net_egress is False


def test_net_egress_from_env_truthy(monkeypatch):
    monkeypatch.setenv("BLASTBOX_NET_EGRESS", "1")
    assert Limits.from_env().net_egress is True


def test_net_egress_from_env_fail_closed(monkeypatch):
    # Only an explicit truthy token opens egress; anything else stays OFF (a typo can't net-share).
    for bad in ("0", "false", "no", "off", "", "maybe", "2"):
        monkeypatch.setenv("BLASTBOX_NET_EGRESS", bad)
        assert Limits.from_env().net_egress is False, bad


def test_disclose_security_internals_defaults_off():
    assert Limits().disclose_security_internals is False


def test_disclose_security_internals_fail_closed(monkeypatch):
    # A security flag (True = MORE disclosure) must fail closed: only an explicit truthy token enables it.
    for good in ("1", "true", "YES", " on "):
        monkeypatch.setenv("BLASTBOX_DISCLOSE_SECURITY_INTERNALS", good)
        assert Limits.from_env().disclose_security_internals is True, good
    for bad in ("0", "false", "no", "off", "", "garbage", "2"):
        monkeypatch.setenv("BLASTBOX_DISCLOSE_SECURITY_INTERNALS", bad)
        assert Limits.from_env().disclose_security_internals is False, bad


def test_from_env_non_numeric_names_var(monkeypatch):
    """A non-numeric env value must raise ValueError naming the variable."""
    monkeypatch.setenv("BLASTBOX_TIMEOUT", "notanumber")
    with pytest.raises(ValueError, match="BLASTBOX_TIMEOUT"):
        Limits.from_env()


def test_from_env_non_numeric_byte_field_names_var(monkeypatch):
    monkeypatch.setenv("BLASTBOX_MEM", "oops")
    with pytest.raises(ValueError, match="BLASTBOX_MEM"):
        Limits.from_env()


def test_from_env_overrides_respected():
    lim = Limits.from_env(timeout_s=42)
    assert lim.timeout_s == 42


def test_from_env_bad_value_fails_loudly(monkeypatch):
    monkeypatch.setenv("BLASTBOX_MAX_INPUT", "abc")
    with pytest.raises(ValueError, match="BLASTBOX_MAX_INPUT"):
        Limits.from_env()


# ---------------------------------------------------------------------------
# No engine-specific fields
# ---------------------------------------------------------------------------


def test_no_dpi_field():
    lim = Limits()
    assert not hasattr(lim, "dpi")


def test_no_max_pages_field():
    lim = Limits()
    assert not hasattr(lim, "max_pages")


def test_no_skip_blanks_field():
    lim = Limits()
    assert not hasattr(lim, "skip_blanks")
