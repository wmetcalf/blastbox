"""GvisorSnapshotBackend — runsc checkpoint/restore as a SnapshotBackend.

Drives `runsc` directly (containerd/CRI checkpoint is unimplemented upstream; the
dispatcher already drives the runtime directly). The warm container runs the worker
entrypoint (serve_warm + FileWarmControl); it writes `ready` into the bind-mounted
control dir, which we poll before checkpointing. I/O is bind mounts (in/ ro, out/
rw, ctrl/ rw) — no vsock, no ext4. All runsc calls go through an injected `run`.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class GvisorConfig:
    runsc_bin: str
    root: Path                  # runsc --root state dir
    image_rootfs: Path          # OCI rootfs for the warm container
    network: str                # "none" | "sandbox"
    warm_argv: list[str]        # the warm worker entrypoint argv (inside the container)
    ignore_cgroups: bool = True
    platform: str | None = None
    ld_preload: str | None = None                 # soffice tier: /opt/clippyshot/accept-retry.so
    cpu_features_annotation: str | None = None     # dev.gvisor.internal.cpufeatures (pinning)
    extra_env: list[str] = field(default_factory=list)


def _runsc(cfg: GvisorConfig) -> list[str]:
    a = [cfg.runsc_bin, "-root", str(cfg.root), f"-network={cfg.network}"]
    if cfg.ignore_cgroups:
        a.append("-ignore-cgroups")
    if cfg.platform:
        a.append(f"-platform={cfg.platform}")
    return a


def _oci_config(cfg: GvisorConfig, workdir: Path, *, in_ro: bool) -> dict:
    """A self-contained OCI spec (config.json) for the warm/restore container with
    per-slot bind mounts. Pure (no runsc spec needed) so it's unit-testable."""
    env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"]
    if cfg.ld_preload:
        env.append(f"LD_PRELOAD={cfg.ld_preload}")
    env.extend(cfg.extra_env)
    spec: dict = {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": list(cfg.warm_argv),
            "env": env,
            "cwd": "/",
            "capabilities": {
                k: ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_KILL",
                    "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE"]
                for k in ("bounding", "effective", "permitted")
            },
        },
        "root": {"path": str(cfg.image_rootfs), "readonly": True},
        "hostname": "warm",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             "options": ["rw", "nosuid", "nodev", "size=512m"]},
            {"destination": "/in", "type": "bind", "source": str(workdir / "in"),
             "options": ["rbind", "ro" if in_ro else "rw"]},
            {"destination": "/out", "type": "bind", "source": str(workdir / "out"),
             "options": ["rbind", "rw"]},
            {"destination": "/ctrl", "type": "bind", "source": str(workdir / "ctrl"),
             "options": ["rbind", "rw"]},
        ],
        "linux": {"namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount")]},
    }
    if cfg.cpu_features_annotation:
        spec["annotations"] = {"dev.gvisor.internal.cpufeatures": cfg.cpu_features_annotation}
    return spec


def _write_oci_config(cfg: GvisorConfig, workdir: Path, *, in_ro: bool) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "config.json").write_text(
        json.dumps(_oci_config(cfg, workdir, in_ro=in_ro), indent=2), encoding="utf-8"
    )


def _default_run(argv: list[str], **kw: Any) -> int:
    return subprocess.run(argv, check=True, **kw).returncode


def _default_run_text(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=False).stdout


def _default_ready_wait(ctrl_dir: Path, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if (ctrl_dir / "ready").exists():
            return
        time.sleep(0.2)
    raise TimeoutError(f"warm base not READY within {timeout_s}s ({ctrl_dir})")


class GvisorBootHandle:
    def __init__(
        self,
        cfg: GvisorConfig,
        run: Callable[..., int],
        cid: str,
        base_dir: Path,
        ctrl_dir: Path,
        ready_wait: Callable[[Path, float], None],
    ) -> None:
        self._cfg = cfg
        self._run = run
        self._cid = cid
        self._base = base_dir
        self._ctrl = ctrl_dir
        self._ready = ready_wait

    def wait_ready(self, timeout_s: float) -> None:
        self._ready(self._ctrl, timeout_s)

    def checkpoint(self, dest_dir: Path) -> object:
        img = Path(dest_dir) / "checkpoint"
        img.mkdir(parents=True, exist_ok=True)
        self._run([*_runsc(self._cfg), "checkpoint", "-image-path", str(img), self._cid])
        return str(img)

    def kill(self) -> None:
        try:
            self._run([*_runsc(self._cfg), "delete", "-force", self._cid])
        except Exception:
            pass


class GvisorRestoreHandle:
    def __init__(
        self,
        cfg: GvisorConfig,
        run: Callable[..., int],
        cid: str,
        slot_workdir: Path,
        run_text: Callable[[list[str]], str] = _default_run_text,
    ) -> None:
        self._cfg = cfg
        self._run = run
        self._run_text = run_text
        self._cid = cid
        self.slot_workdir = Path(slot_workdir)
        self.control_dir = self.slot_workdir / "ctrl"
        self.output_dir = self.slot_workdir / "out"
        self.input_dir = self.slot_workdir / "in"

    def alive(self) -> bool:
        """True iff the restored container is still running (via runsc state)."""
        import json as _json
        try:
            out = self._run_text([*_runsc(self._cfg), "state", self._cid])
            status = _json.loads(out).get("status", "")
            return status in ("running", "created")
        except Exception:  # noqa: BLE001
            return False

    def kill(self) -> None:
        for argv in (["kill", self._cid, "KILL"], ["delete", "-force", self._cid]):
            try:
                self._run([*_runsc(self._cfg), *argv])
            except Exception:
                pass


class GvisorSnapshotBackend:
    def __init__(
        self,
        cfg: GvisorConfig,
        *,
        run: Callable[..., int] = _default_run,
        run_text: Callable[[list[str]], str] = _default_run_text,
        ready_wait: Callable[[Path, float], None] = _default_ready_wait,
        probe: Callable[[], bool] | None = None,
    ) -> None:
        self._cfg = cfg
        self._run = run
        self._run_text = run_text
        self._ready = ready_wait
        self._probe = probe

    def available(self) -> bool:
        if self._probe is not None:
            return self._probe()
        return shutil.which(self._cfg.runsc_bin) is not None

    def boot_base(self) -> GvisorBootHandle:
        base = self._cfg.root.parent / "gvisor-base"
        ctrl = base / "ctrl"
        for d in (base / "in", base / "out", ctrl):
            d.mkdir(parents=True, exist_ok=True)
        cid = "warm-base"
        _write_oci_config(self._cfg, base, in_ro=True)
        self._run(
            [*_runsc(self._cfg), "run", "-detach", "-bundle", str(base), cid],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return GvisorBootHandle(self._cfg, self._run, cid, base, ctrl, self._ready)

    def restore_in(self, slot_workdir: Path, artifact: object) -> GvisorRestoreHandle:
        wd = Path(slot_workdir)
        for sub in ("in", "out", "ctrl"):
            (wd / sub).mkdir(parents=True, exist_ok=True)
        cid = f"slot-{uuid.uuid4().hex[:12]}"
        _write_oci_config(self._cfg, wd, in_ro=True)
        self._run(
            [*_runsc(self._cfg), "restore", "-image-path", str(artifact),
             "-detach", "-bundle", str(wd), cid],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return GvisorRestoreHandle(self._cfg, self._run, cid, wd, self._run_text)
