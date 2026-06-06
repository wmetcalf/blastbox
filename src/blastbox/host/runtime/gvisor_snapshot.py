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
    # Run the untrusted-document worker as NON-ROOT with NO capabilities (parity with the
    # docker `--user`/`--cap-drop=ALL` and FC `setpriv 65532` tiers). The per-slot out/ + ctrl/
    # bind mounts are chmod'd writable for this uid by the backend; HOME=/tmp (tmpfs) and the
    # UserInstallation under /tmp keep soffice happy unprivileged.
    uid: int = 65532
    gid: int = 65532


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
            "user": {"uid": cfg.uid, "gid": cfg.gid},
            "args": list(cfg.warm_argv),
            "env": env,
            "cwd": "/",
            # Non-root + no capabilities + no-new-privs: a malicious doc / soffice parser bug
            # runs unprivileged, matching the docker + FC tiers and the design's stated invariant.
            "noNewPrivileges": True,
            "capabilities": {
                k: []
                for k in ("bounding", "effective", "permitted", "inheritable", "ambient")
            },
        },
        "root": {"path": str(cfg.image_rootfs), "readonly": True},
        "hostname": "warm",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
             "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
             # mode=1777 (sticky world-writable like a real /tmp) so the NON-ROOT worker can
             # write soffice's profile + the OSL UNO pipe under /tmp.
             "options": ["rw", "nosuid", "nodev", "mode=1777", "size=512m"]},
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


def _prepare_slot_dirs(cfg: GvisorConfig, workdir: Path) -> None:
    """Create the per-slot bind-mount dirs. ``out/`` and ``ctrl/`` are shared scratch between
    the NON-ROOT container uid (writes output + ready/done) and the host services (the
    dispatcher writes go.json / reads done; the trust gate reads output) — which run under
    different uids — so they are mode 0o777. This is safe because the parent
    (``/var/lib/blastbox/...``, deploy concern) MUST be root-owned 0700, making the 0o777 leaf
    reachable only by root + the mapped container uid (via the bind mount), not other local
    users. ``in/`` is read-only and only needs world-traversable (0o755).

    We also clamp ``workdir`` itself to 0o700 (belt-and-suspenders): even if the deploy parent
    is lax, an unprivileged local user can't traverse INTO this slot dir to reach the 0o777
    leaves. The container's gofer (and the host pool service) own/traverse it regardless."""
    workdir.mkdir(parents=True, exist_ok=True)
    workdir.chmod(0o700)
    in_dir = workdir / "in"
    in_dir.mkdir(parents=True, exist_ok=True)
    in_dir.chmod(0o755)
    for sub in ("out", "ctrl"):
        d = workdir / sub
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o777)


def _default_run(argv: list[str], **kw: Any) -> int:
    return subprocess.run(argv, check=True, **kw).returncode


def _default_run_text(argv: list[str]) -> str:
    # Bounded: alive() runs this from the pool's liveness path (serially over IDLE slots),
    # so a hung `runsc state` must not block claim/promote. `runsc state` is a fast query;
    # 3s caps the per-call stall (and thus the N-slot aggregate). Timeout/error → "" (not-alive).
    try:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=3
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _default_ready_wait(ctrl_dir: Path, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if (ctrl_dir / "ready").exists():
            return
        time.sleep(0.2)
    raise TimeoutError(f"warm base not READY within {timeout_s}s ({ctrl_dir})")


def _best_effort_delete(cfg: GvisorConfig, run: Callable[..., int], cid: str) -> None:
    """Tear down a (possibly half-created) runsc container: kill then force-delete,
    swallowing errors. Used on failure + reap paths where the container may or may not
    exist — a `runsc run`/`restore` that fails partway can still register container state
    under ``-root`` (with its sandbox/gofer processes), which would otherwise leak because
    the caller never gets a handle to reap it."""
    for argv in (["kill", cid, "KILL"], ["delete", "-force", cid]):
        try:
            run([*_runsc(cfg), *argv])
        except Exception:
            pass


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
        _best_effort_delete(self._cfg, self._run, self._cid)
        shutil.rmtree(self._base, ignore_errors=True)  # don't leave the base bundle dir behind


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
        """True iff the restored container is actually RUNNING (via runsc state).

        Deliberately excludes ``"created"``: after ``runsc restore -detach`` a healthy warm
        worker resumes to ``"running"``; a container still in ``"created"`` never started its
        init, so promoting it to IDLE (is_ready) or claiming it would hand a job to a wedged
        slot that then hangs until the worker timeout. Only ``"running"`` counts as live."""
        import json as _json
        try:
            out = self._run_text([*_runsc(self._cfg), "state", self._cid])
            status = _json.loads(out).get("status", "")
            return status == "running"
        except Exception:  # noqa: BLE001
            return False

    def kill(self) -> None:
        _best_effort_delete(self._cfg, self._run, self._cid)


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
        # Unique per build so two pool processes sharing this -root parent (e.g. a
        # restart-overlap: the old process still tearing down while the new one boots)
        # don't collide on a fixed base bundle dir / cid and stomp each other's base.
        token = uuid.uuid4().hex[:12]
        base = self._cfg.root.parent / f"gvisor-base-{token}"
        _prepare_slot_dirs(self._cfg, base)
        ctrl = base / "ctrl"
        cid = f"warm-base-{token}"
        _write_oci_config(self._cfg, base, in_ro=True)
        try:
            self._run(
                [*_runsc(self._cfg), "run", "-detach", "-bundle", str(base), cid],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            # No boot handle is returned on failure, so nothing reaps the base — drop any
            # registered runsc state for this cid AND remove the bundle dir so neither leaks.
            _best_effort_delete(self._cfg, self._run, cid)
            shutil.rmtree(base, ignore_errors=True)
            raise
        return GvisorBootHandle(self._cfg, self._run, cid, base, ctrl, self._ready)

    def restore_in(self, slot_workdir: Path, artifact: object) -> GvisorRestoreHandle:
        wd = Path(slot_workdir)
        _prepare_slot_dirs(self._cfg, wd)
        cid = f"slot-{uuid.uuid4().hex[:12]}"
        _write_oci_config(self._cfg, wd, in_ro=True)
        try:
            self._run(
                [*_runsc(self._cfg), "restore", "-image-path", str(artifact),
                 "-detach", "-bundle", str(wd), cid],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            # A partially-failed `runsc restore` can leave registered container state (with
            # its sandbox/gofer processes) under -root. No handle is returned on failure, and
            # the manager only knows the slot dir — not this cid — so tear it down here before
            # re-raising, or it orphans an unmanaged sandbox.
            _best_effort_delete(self._cfg, self._run, cid)
            raise
        return GvisorRestoreHandle(self._cfg, self._run, cid, wd, self._run_text)
