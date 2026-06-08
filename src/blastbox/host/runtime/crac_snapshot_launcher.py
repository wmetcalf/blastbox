"""CRaC launcher for the snapshot tier (Phase 3 groundwork).

Spawns the base JVM (``java -XX:CRaCCheckpointTo=<dir> <engine-argv>``), checkpoints
it (``jcmd <pid> JDK.checkpoint`` → the JVM writes its CRaC image + exits), and
restores per slot (``java -XX:CRaCRestoreFrom=<dir>``). All host-touching deps
(process spawn, jcmd run, ``which`` probes, READY signal) are injected so the
boot/checkpoint/restore orchestration is unit-tested without a real CRaC JVM —
exactly how ``FcSnapshotLauncher`` is tested without a real Firecracker.

PROVISIONAL: see ``crac_snapshot_backend.py`` — the argv is the standard CRaC
pattern; redtusk's exact wiring must be ground-truthed in Phase 4.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable


def crac_boot_argv(java_bin: str, checkpoint_dir: str, engine_argv: list[str]) -> list[str]:
    """``java -XX:CRaCCheckpointTo=<dir> <engine-argv>`` — the base JVM to warm + checkpoint."""
    return [java_bin, f"-XX:CRaCCheckpointTo={checkpoint_dir}", *engine_argv]


def crac_checkpoint_argv(jcmd_bin: str, pid: int) -> list[str]:
    """``jcmd <pid> JDK.checkpoint`` — tell the warmed base JVM to write its image + exit."""
    return [jcmd_bin, str(pid), "JDK.checkpoint"]


def crac_restore_argv(java_bin: str, image_dir: str) -> list[str]:
    """``java -XX:CRaCRestoreFrom=<image>`` — restore a warm JVM from the checkpoint."""
    return [java_bin, f"-XX:CRaCRestoreFrom={image_dir}"]


class _CracHandle:
    """A launched JVM (base = checkpointable; restore = per-slot)."""

    def __init__(
        self,
        proc: Any,
        *,
        checkpoint_dir: str | None = None,
        jcmd_bin: str | None = None,
        runner: Callable[..., Any] | None = None,
        ready_check: Callable[[float], None] | None = None,
    ) -> None:
        self.proc = proc
        # Only the BASE handle carries these — it's the one that gets checkpoint()ed.
        self._checkpoint_dir = checkpoint_dir
        self._jcmd_bin = jcmd_bin
        self._runner = runner
        self._ready_check = ready_check

    def wait_ready(self, timeout_s: float) -> None:
        if self._ready_check is not None:
            self._ready_check(timeout_s)

    def checkpoint(self, dest_dir: Path) -> object:
        """``jcmd JDK.checkpoint`` the warmed JVM; it writes its CRaC image to the
        ``-XX:CRaCCheckpointTo`` dir (set at boot) and exits. That dir IS the opaque
        artifact the manager round-trips to ``restore_in``."""
        from blastbox.host.runtime.crac_snapshot_backend import CracSnapshotArtifact

        if self._checkpoint_dir is None or self._jcmd_bin is None or self._runner is None:
            raise RuntimeError("checkpoint() called on a non-base CRaC handle")
        self._runner(
            crac_checkpoint_argv(self._jcmd_bin, self.proc.pid),
            check=True,
            capture_output=True,
        )
        # The JVM wrote its image to the boot-time -XX:CRaCCheckpointTo dir; relocate it
        # UNDER the manager-provided dest_dir so the artifact lives where the manager
        # expects (FC/gVisor parity — they persist to dest_dir too). Real runtime: wait
        # for the JVM to finish writing before moving (a Phase-4 detail with a real JVM).
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        image = dest / "cracimg"
        src = Path(self._checkpoint_dir)
        if src.resolve() != image.resolve():
            if image.exists():
                shutil.rmtree(image, ignore_errors=True)
            shutil.move(str(src), str(image))
        return CracSnapshotArtifact(image)

    def kill(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class CracSnapshotLauncher:
    """Spawns ``java`` processes for the CRaC snapshot build + restore.

    Host-touching deps are injected so boot/checkpoint/restore is unit-tested.
    """

    def __init__(
        self,
        cfg: Any,
        base_dir: Path,
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        runner: Callable[..., Any] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        ready_check_factory: Callable[[Path], Callable[[float], None]] | None = None,
    ) -> None:
        self._cfg = cfg
        self._base_dir = Path(base_dir)
        self._popen = popen
        self._runner = runner
        self._which = which
        self._ready_check_factory = ready_check_factory

    def available(self) -> bool:
        """Fail-closed: a CRaC-capable JVM (java + jcmd) AND criu must be present.

        (A real deployment would also probe ``java -XX:CRaCCheckpointTo=...`` support
        and criu's required capability — left for Phase 4 against a real CRaC JVM.)
        """
        return all(
            bool(self._which(b))
            for b in (self._cfg.java_bin, self._cfg.jcmd_bin, self._cfg.criu_bin)
        )

    def _spawn_env(self) -> dict[str, str]:
        """Env for the spawned JVMs. The JVM's CRaC machinery invokes ``criu`` off
        ``PATH``; if a custom ``criu_bin`` dir is configured, prepend it so both
        checkpoint and restore find the right binary."""
        env = os.environ.copy()
        criu = Path(self._cfg.criu_bin)
        if criu.parent != Path("."):
            env["PATH"] = f"{criu.parent.resolve()}{os.pathsep}{env.get('PATH', '')}"
        return env

    def boot_base(self) -> _CracHandle:
        """Boot the base JVM (with ``-XX:CRaCCheckpointTo``) for warming + checkpoint."""
        if not self._cfg.engine_argv:
            # `java` with no application exits with a help message → a cryptic
            # checkpoint failure later. Fail loud and early.
            raise ValueError(
                "CRaC engine_argv is empty; cannot boot a base JVM without an application"
            )
        workdir = self._base_dir / "base"
        checkpoint_dir = workdir / "cracimg"
        # Clean any stale image from a previous/failed build so criu gets a clean slate.
        if checkpoint_dir.exists():
            shutil.rmtree(checkpoint_dir, ignore_errors=True)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        proc = self._popen(
            crac_boot_argv(self._cfg.java_bin, str(checkpoint_dir), list(self._cfg.engine_argv)),
            cwd=str(workdir),
            env=self._spawn_env(),
        )
        ready = self._ready_check_factory(workdir) if self._ready_check_factory else None
        return _CracHandle(
            proc,
            checkpoint_dir=str(checkpoint_dir),
            jcmd_bin=self._cfg.jcmd_bin,
            runner=self._runner,
            ready_check=ready,
        )

    def restore_in(self, slot_workdir: Path, artifact: Any) -> _CracHandle:
        """Restore a fresh warm JVM in ``slot_workdir`` from the CRaC image."""
        slot_workdir = Path(slot_workdir)
        slot_workdir.mkdir(parents=True, exist_ok=True)
        proc = self._popen(
            crac_restore_argv(self._cfg.java_bin, str(artifact.image_dir)),
            cwd=str(slot_workdir),
            env=self._spawn_env(),
        )
        return _CracHandle(proc)
