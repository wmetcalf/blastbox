"""Generic resource limits for sandboxed detonation workers."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, fields


_ENV_PREFIX = "BLASTBOX_"

# Map field name → env-var suffix.  All engine-specific limits (dpi,
# max_pages, width, height, skip_blanks, …) live in the engine's own config,
# not here.
_ENV_MAP = {
    "timeout_s": "TIMEOUT",
    "memory_bytes": "MEM",
    "tmpfs_bytes": "TMPFS",
    "max_input_bytes": "MAX_INPUT",
    "max_metadata_bytes": "MAX_METADATA",
    "max_artifact_bytes": "MAX_ARTIFACT",
    "max_total_artifact_bytes": "MAX_TOTAL_ARTIFACTS",
    "max_artifacts": "MAX_ARTIFACTS",
    "disclose_security_internals": "DISCLOSE_SECURITY_INTERNALS",
}

# Fields that need non-int coercion from env strings.
_ENV_COERCE: dict[str, Callable[[str], object]] = {
    "disclose_security_internals": lambda s: s.lower() not in ("0", "false", "no"),
}

# Hard ceilings — prevent a hostile or fat-fingered env var from silently
# disabling a cap (e.g. MAX_INPUT=0) or wrapping to a nonsensical value.
# 256 GiB is well above any legitimate use; 65536 artifacts likewise.
_MAX_BYTES_CEILING = 256 * 1024 * 1024 * 1024
_MAX_ARTIFACTS_CEILING = 65536
_MAX_TIMEOUT_S = 3600


@dataclass(frozen=True)
class Limits:
    """Strict-by-default generic resource + output-trust caps.

    All engine-specific limits (DPI, page count, image dimensions, …) belong
    in the engine's own configuration object, not here.
    """

    timeout_s: int = 120
    # Virtual address space limit — large enough for typical worker processes
    # without silently disabling the guard; the Docker --memory flag provides
    # the real RSS cap.
    memory_bytes: int = 8 * 1024 * 1024 * 1024  # 8 GiB VADDR
    tmpfs_bytes: int = 1024 * 1024 * 1024  # 1 GiB
    max_input_bytes: int = 100 * 1024 * 1024  # 100 MiB
    # Caps on what the worker is allowed to write back / expose:
    max_metadata_bytes: int = 4 * 1024 * 1024   # 4 MiB
    max_artifact_bytes: int = 50 * 1024 * 1024  # 50 MiB per artifact
    max_total_artifact_bytes: int = 500 * 1024 * 1024  # 500 MiB total
    max_artifacts: int = 1000
    disclose_security_internals: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_s <= _MAX_TIMEOUT_S:
            raise ValueError(
                f"timeout_s must be in [1, {_MAX_TIMEOUT_S}], got {self.timeout_s}"
            )
        if not 1 <= self.max_artifacts <= _MAX_ARTIFACTS_CEILING:
            raise ValueError(
                f"max_artifacts must be in [1, {_MAX_ARTIFACTS_CEILING}], "
                f"got {self.max_artifacts}"
            )
        for name in (
            "memory_bytes",
            "tmpfs_bytes",
            "max_input_bytes",
            "max_metadata_bytes",
            "max_artifact_bytes",
            "max_total_artifact_bytes",
        ):
            val = getattr(self, name)
            if not 1 <= val <= _MAX_BYTES_CEILING:
                raise ValueError(
                    f"{name} must be in [1, {_MAX_BYTES_CEILING}], got {val}"
                )

    @classmethod
    def from_env(cls, **overrides) -> "Limits":
        """Build a Limits instance from ``BLASTBOX_*`` environment variables.

        Fails loudly — raises ``ValueError`` naming the offending variable —
        if a variable is present but cannot be parsed.
        """
        values: dict = {}
        for f in fields(cls):
            env_key = _ENV_PREFIX + _ENV_MAP[f.name]
            raw = os.environ.get(env_key)
            if raw is not None:
                coerce = _ENV_COERCE.get(f.name, int)
                try:
                    values[f.name] = coerce(raw)
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"invalid value for {env_key}={raw!r}: {exc}"
                    ) from exc
        values.update(overrides)
        return cls(**values)
