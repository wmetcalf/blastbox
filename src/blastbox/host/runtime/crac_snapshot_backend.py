"""CRaC ``SnapshotBackend`` — JVM checkpoint/restore warm tier (Phase 3 groundwork).

A third ``SnapshotBackend`` (alongside the FC mem-snapshot + gVisor C/R tiers) for
warm **JVM** workers — redtusk and any future Java detonation engine. Mirrors
``FcSnapshotBackend``: a thin adapter delegating spawn/checkpoint/restore to a
``CracSnapshotLauncher``, driven by the existing backend-agnostic ``SnapshotManager``.

See ``docs/specs/2026-06-08-crac-snapshot-backend.md``.

PROVISIONAL — the CRaC argv (``jcmd JDK.checkpoint`` / ``-XX:CRaCRestoreFrom``) is
the standard CRaC pattern, but redtusk's exact CRaC wiring (CRaC-in-FC vs standalone,
criu capabilities vs ``--cap-drop=ALL``) MUST be ground-truthed in Phase 4 before this
is wired into any deployed pool. Unit-mockable now; not deployment-ready.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blastbox.host.runtime.fc_snapshot import SnapshotRestoreError


@dataclass(frozen=True)
class CracSnapshotArtifact:
    """The built warm snapshot: a CRaC image directory. OPAQUE to ``SnapshotManager``
    — only the CRaC backend + launcher ever inspect it."""

    image_dir: Path


@dataclass(frozen=True)
class CracConfig:
    """Operator-configured CRaC tunables (never job-derived)."""

    java_bin: str = "java"
    jcmd_bin: str = "jcmd"
    criu_bin: str = "criu"
    # The Java engine entrypoint to boot + warm + checkpoint, e.g. ("-jar", "engine.jar").
    engine_argv: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "CracConfig":
        raw = os.environ.get("BLASTBOX_CRAC_ENGINE_ARGV", "").strip()
        # shlex.split so quoted args survive (e.g. -Dprop="a b", a -cp with spaces).
        engine_argv = tuple(shlex.split(raw)) if raw else ()
        return cls(
            java_bin=os.environ.get("BLASTBOX_CRAC_JAVA_BIN", "java"),
            jcmd_bin=os.environ.get("BLASTBOX_CRAC_JCMD_BIN", "jcmd"),
            criu_bin=os.environ.get("BLASTBOX_CRAC_CRIU_BIN", "criu"),
            engine_argv=engine_argv,
        )


class CracSnapshotBackend:
    """CRaC ``SnapshotBackend`` — thin adapter over a ``CracSnapshotLauncher``."""

    def __init__(self, base_dir: Path, launcher: Any) -> None:
        self._base_dir = Path(base_dir)
        self._launcher = launcher

    def available(self) -> bool:
        """Fail-closed: True only if a CRaC JVM + criu are present (delegated)."""
        return bool(self._launcher.available())

    def boot_base(self) -> Any:
        """Boot the base JVM (whose handle ``checkpoint(dest)`` snapshots it)."""
        return self._launcher.boot_base()

    def restore_in(self, slot_workdir: Path, artifact: object) -> Any:
        """Restore a warm JVM per slot from the CRaC image the build side produced."""
        if not isinstance(artifact, CracSnapshotArtifact):
            # Explicit raise (survives ``python -O``); fails closed with a typed error.
            raise SnapshotRestoreError(
                f"CracSnapshotBackend.restore_in expected CracSnapshotArtifact, "
                f"got {type(artifact).__name__}"
            )
        return self._launcher.restore_in(Path(slot_workdir), artifact)
