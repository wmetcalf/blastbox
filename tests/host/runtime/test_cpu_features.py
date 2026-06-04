"""Tests for blastbox.host.runtime.cpu_features.

Pure parsing, no FC host needed:
- parse_cpu_mismatch extracts the compatible -XX:CPUFeatures value from a real
  warp restore-failure console (the 2026-06-02 incident's actual error text).
- Returns None on a clean boot, on unrelated JVM errors, and on empty input.
- The value charset stops at the token boundary (doesn't swallow trailing text).
- Matches even when the warp message wraps across lines (DOTALL).
- FcCpuFeatureMismatch is a SandboxError, carries .needed, and names the value
  in its message.
"""

from __future__ import annotations

from blastbox.errors import FcCpuFeatureMismatch, SandboxError
from blastbox.host.runtime.cpu_features import (
    CpuFeatureMismatch,
    parse_cpu_mismatch,
)

# The actual guest serial console from the 2026-06-02 incident (RedTusk 8838962).
_REAL_MISMATCH = """\
[    0.412][crac] Restore failed due to incompatible or missing CPU features, \
try using -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint.
[    0.413][crac] Failed to restore from /app/checkpoint
Error: Could not create the Java Virtual Machine.
"""

_CLEAN_BOOT = """\
[    0.380][crac] Restore: loaded image from /app/checkpoint
[    0.401] redtusk-worker READY
"""


def test_parses_real_mismatch_value():
    mm = parse_cpu_mismatch(_REAL_MISMATCH)
    assert mm is not None
    assert isinstance(mm, CpuFeatureMismatch)
    assert mm.needed == "0x102100055bbd7,0x1c8"
    assert "incompatible or missing CPU features" in mm.raw_line


def test_clean_boot_returns_none():
    assert parse_cpu_mismatch(_CLEAN_BOOT) is None


def test_unrelated_jvm_error_returns_none():
    # A JVM that died for a different reason must NOT be misread as a CPU
    # mismatch — that would send the operator chasing the wrong fix.
    other = "Error: Could not create the Java Virtual Machine.\nOOM killed.\n"
    assert parse_cpu_mismatch(other) is None


def test_empty_and_none_safe():
    assert parse_cpu_mismatch("") is None
    assert parse_cpu_mismatch(None) is None  # type: ignore[arg-type]


def test_value_stops_at_token_boundary():
    # Trailing prose ("on checkpoint.") must not be captured into the value.
    mm = parse_cpu_mismatch(_REAL_MISMATCH)
    assert mm is not None
    assert mm.needed.endswith("0x1c8")
    assert "checkpoint" not in mm.needed
    assert " " not in mm.needed


def test_matches_across_wrapped_lines():
    wrapped = (
        "incompatible or missing CPU features,\n"
        "       try using -XX:CPUFeatures=0xdead,0xbeef on checkpoint.\n"
    )
    mm = parse_cpu_mismatch(wrapped)
    assert mm is not None
    assert mm.needed == "0xdead,0xbeef"


def test_error_is_sandbox_error_and_names_value():
    err = FcCpuFeatureMismatch("0x102100055bbd7,0x1c8", detail="some console line")
    assert isinstance(err, SandboxError)
    assert err.needed == "0x102100055bbd7,0x1c8"
    assert "-XX:CPUFeatures=0x102100055bbd7,0x1c8" in str(err)
    assert "some console line" in str(err)


def test_parse_then_raise_roundtrip():
    # The intended consumer pattern: parse a console, build the actionable error.
    mm = parse_cpu_mismatch(_REAL_MISMATCH)
    assert mm is not None
    err = FcCpuFeatureMismatch(mm.needed, detail=mm.raw_line)
    assert err.needed == mm.needed
    assert mm.needed in str(err)
