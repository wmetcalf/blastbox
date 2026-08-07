"""GvisorSnapshotBackend — runsc checkpoint/restore as a SnapshotBackend.

Drives `runsc` directly (containerd/CRI checkpoint is unimplemented upstream; the
dispatcher already drives the runtime directly). The warm container runs the worker
entrypoint (serve_warm + FileWarmControl); it writes `ready` into the bind-mounted
control dir, which we poll before checkpointing. I/O is bind mounts (in/ ro, out/
rw, ctrl/ rw) — no vsock, no ext4. All runsc calls go through an injected `run`.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from blastbox.host.runtime.snapshot_backend import (
    generation_owner,
    owner_alive,
    owner_token,
)

_log = logging.getLogger(__name__)

# Root-level filename the warm container packs its /out tree into so a C/R-restored container's
# nested output (subdirs the restored process's stale gofer/VFS view doesn't write through to the
# host bind source) still reaches the host. A leading '.' keeps it out of the way; the host strips
# it after extracting, and it is never a declared artifact (engine manifests don't reference it).
WARM_OUTPUT_ARCHIVE = ".blastbox_warm_output.tar"


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
    # Bound the untrusted worker's process + fd count at the OCI layer. The sentry enforces
    # process.rlimits even though `-ignore-cgroups` disables cgroup pids/memory, so without
    # these a malicious doc could fork-bomb / exhaust fds and degrade the whole pool (the FC
    # tier bounds via the microVM; this tier had no equivalent). These are GENEROUS
    # defense-in-depth bounds, not tight quotas: the docker tier proved 256 procs / 4096 fds
    # sufficient for the whole corpus, but that limit covers a single conversion — here the warm
    # worker tree (python + soffice + pdfium multiprocessing sharding across cores) shares ONE
    # limit, so we leave ample headroom while still capping a fork-bomb / fd-exhaustion well below
    # host exhaustion. 0/None omits a limit. Worker-level MEMORY is intentionally NOT bounded here
    # (RLIMIT_AS on the whole python/pdfium tree risks false VADDR kills); it stays bounded
    # per-soffice by the inner sandbox's RLIMIT_AS and, recommended, a host memory cgroup.
    rlimit_nproc: int | None = 4096
    rlimit_nofile: int | None = 65536


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
            # POSIX shared memory. The /dev tmpfs above shadows the rootfs's /dev/shm, so
            # without this multiprocessing.SemLock() fails (FileNotFoundError/PermissionError)
            # — which breaks pypdfium2's multiprocessing page-render pool on multi-page PDFs.
            {"destination": "/dev/shm", "type": "tmpfs", "source": "tmpfs",
             "options": ["rw", "nosuid", "nodev", "mode=1777", "size=256m"]},
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
    # Resource bounds for the untrusted worker (gVisor sentry honors these even under
    # -ignore-cgroups). NPROC caps a fork-bomb; NOFILE caps fd-exhaustion. See GvisorConfig.
    rlimits = []
    if cfg.rlimit_nproc:
        rlimits.append({"type": "RLIMIT_NPROC", "hard": cfg.rlimit_nproc, "soft": cfg.rlimit_nproc})
    if cfg.rlimit_nofile:
        rlimits.append({"type": "RLIMIT_NOFILE", "hard": cfg.rlimit_nofile, "soft": cfg.rlimit_nofile})
    if rlimits:
        spec["process"]["rlimits"] = rlimits
    if cfg.cpu_features_annotation:
        spec["annotations"] = {"dev.gvisor.internal.cpufeatures": cfg.cpu_features_annotation}
    return spec


def _write_oci_config(cfg: GvisorConfig, workdir: Path, *, in_ro: bool) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "config.json").write_text(
        json.dumps(_oci_config(cfg, workdir, in_ro=in_ro), indent=2), encoding="utf-8"
    )


_warned_lax_parents: set[str] = set()


def _warn_if_lax_parent(workdir: Path) -> None:
    """One-time warning if the slot dir's parent is group/other-writable. The 0o700 slot leaf
    already blocks other local users from reaching the 0o777 out/ctrl scratch (you can't traverse
    INTO a 0o700 dir you don't own), so this is defense-in-depth/observability — it surfaces a lax
    deploy (the parent should be root-owned 0700) instead of letting the old comment-only
    assumption pass silently."""
    parent = workdir.parent
    key = str(parent)
    if key in _warned_lax_parents:
        return
    try:
        mode = parent.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o022:  # group- or other-writable
        _warned_lax_parents.add(key)
        _log.warning(
            "gVisor warm state parent %s is group/other-writable (mode %o); slot dirs are 0o700 "
            "so this is not an exposure, but lock the deploy parent to root-owned 0700.",
            parent, mode,
        )


def _prepare_slot_dirs(cfg: GvisorConfig, workdir: Path) -> None:
    """Create the per-slot bind-mount dirs. ``out/`` and ``ctrl/`` are shared scratch between
    the NON-ROOT container uid (writes output + ready/done) and the host services (the dispatcher
    writes go.json / reads done; the trust gate reads output) — which run under different uids —
    so they are mode 0o777. ``in/`` is read-only (0o755).

    The 0o777 leaves are protected by the slot ``workdir`` being **0o700**: another local user
    can't traverse into a 0o700 dir it doesn't own, so it can't reach out/ctrl — independent of
    the deploy parent's perms. The leaf is created **mode 0o700 atomically** (0o700 has no
    group/other bits, so the umask can only further restrict it — there is NO mkdir-then-chmod
    window where it is briefly group/other-traversable). ``_warn_if_lax_parent`` additionally
    surfaces a lax deploy parent as observability."""
    workdir = Path(workdir)
    workdir.parent.mkdir(parents=True, exist_ok=True)
    _warn_if_lax_parent(workdir)
    workdir.mkdir(mode=0o700, exist_ok=True)
    workdir.chmod(0o700)  # exact 0o700 even if it pre-existed (mkdir mode is a no-op on exist)
    in_dir = workdir / "in"
    in_dir.mkdir(mode=0o755, exist_ok=True)
    in_dir.chmod(0o755)
    for sub in ("out", "ctrl"):
        d = workdir / sub
        d.mkdir(exist_ok=True)
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


def _default_cr_capable(runsc_bin: str) -> bool:
    """Fail-closed capability probe: the runsc binary must advertise BOTH the ``checkpoint``
    and ``restore`` subcommands. An older/stripped/CRI-only build that lacks C/R must not be
    selected and then fail at restore time. ``runsc help`` lists subcommands; capture stdout+
    stderr (which stream it lands on is build-dependent) and cap the stall. Any error/timeout →
    not capable (don't select a runsc that can't C/R)."""
    try:
        r = subprocess.run(
            [runsc_bin, "help"], capture_output=True, text=True, check=False, timeout=5
        )
    except (subprocess.SubprocessError, OSError):
        return False
    out = r.stdout + r.stderr
    return "checkpoint" in out and "restore" in out


def _default_ready_wait(ctrl_dir: Path, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if (ctrl_dir / "ready").exists():
            return
        time.sleep(0.2)
    raise TimeoutError(f"warm base not READY within {timeout_s}s ({ctrl_dir})")


def _best_effort_delete(cfg: GvisorConfig, run: Callable[..., int], cid: str) -> bool:
    """Tear down a (possibly half-created) runsc container: kill then force-delete,
    swallowing errors. Used on failure + reap paths where the container may or may not
    exist — a `runsc run`/`restore` that fails partway can still register container state
    under ``-root`` (with its sandbox/gofer processes), which would otherwise leak because
    the caller never gets a handle to reap it.

    Returns True when at least one teardown command SUCCEEDED. Callers that must not reclaim
    resources a live sandbox still uses check this rather than assuming a clean return."""
    ok = False
    for argv in (["kill", cid, "KILL"], ["delete", "-force", cid]):
        try:
            run([*_runsc(cfg), *argv])
            ok = True
        except Exception:
            pass
    # REPORT it. Swallowing every failure made kill() return normally even when both the kill and
    # the force-delete failed, so the reap's `sandbox_gone` guard stayed True and released the
    # generation pin anyway -- the guard was defeated by the layer beneath it (PR #82).
    return ok


class GvisorBootHandle:
    def __init__(
        self,
        cfg: GvisorConfig,
        run: Callable[..., int],
        cid: str,
        base_dir: Path,
        ctrl_dir: Path,
        ready_wait: Callable[[Path, float], None],
        stranded: list[str] | None = None,
    ) -> None:
        # Partial checkpoint directories whose cleanup failed. OWNED BY THE BACKEND and shared in:
        # SnapshotManager kills and abandons this handle after a failed checkpoint, so a list held
        # here alone is discarded with it and the retry never fires (PR #82).
        self._stranded_partials: list[str] = stranded if stranded is not None else []
        self._cfg = cfg
        self._run = run
        self._cid = cid
        self._base = base_dir
        self._ctrl = ctrl_dir
        self._ready = ready_wait

    def wait_ready(self, timeout_s: float) -> None:
        self._ready(self._ctrl, timeout_s)

    def checkpoint(self, dest_dir: Path) -> object:
        # Retry anything a previous failed checkpoint could not remove; no artifact was returned
        # for those, so nothing else can discover them.
        if self._stranded_partials:
            still: list[str] = []
            for leftover in self._stranded_partials:
                retry_errs: list[str] = []
                shutil.rmtree(leftover, onerror=lambda fn, p, exc: retry_errs.append(str(p)))
                if retry_errs:
                    still.append(leftover)
            # IN PLACE. Rebinding detaches this handle from the launcher/backend list it was
            # given, so every later extend() lands on a private copy and the next handle -- which
            # still holds the original -- never sees those files. That silently undid the
            # durability fix this list exists for (PR #82).
            self._stranded_partials[:] = still

        # GENERATION-STAMPED, never a fixed "checkpoint" path. restore_in() reads this directory
        # for the whole life of a `runsc restore`, so a rebuild writing the SAME path can
        # overwrite files an in-flight restore is still consuming -- it fails, or worse observes
        # a mix of two checkpoints. A pin stops the old generation being DELETED; only a distinct
        # path stops it being OVERWRITTEN. FC's mem/snapshot pair got this; gVisor did not
        # (upstream, PR #82).
        gen = f"{owner_token()}-{time.monotonic_ns():019d}"
        img = Path(dest_dir) / f"checkpoint-{gen}"
        img.mkdir(parents=True, exist_ok=True)
        try:
            self._run([*_runsc(self._cfg), "checkpoint", "-image-path", str(img), self._cid])
        except BaseException:
            # runsc can write part of the checkpoint and then fail. No artifact is returned, so
            # SnapshotManager never learns this directory exists and can never retire or discard
            # it -- and because every attempt now gets a unique name, each async retry leaves
            # another partial checkpoint behind instead of overwriting the last (upstream, PR #82).
            errs: list[str] = []
            shutil.rmtree(img, onerror=lambda fn, p, exc: errs.append(str(p)))
            if errs:
                # ...and if the cleanup ITSELF fails, nothing can rediscover the directory either.
                # Record it for the next checkpoint's sweep rather than dropping it, exactly as the
                # FC launcher does for its partial files.
                self._stranded_partials.append(str(img))
                _log.warning("gvisor_snapshot: could not remove partial checkpoint %s", img)
            raise
        return str(img)

    def kill(self) -> None:
        if not _best_effort_delete(self._cfg, self._run, self._cid):
            # The sandbox may still exist. Raise so the caller's guard retains the generation pin
            # instead of reclaiming a checkpoint a live sandbox may still be restoring from.
            raise RuntimeError(f"could not confirm teardown of runsc container {self._cid}")
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

    def archive_output(self) -> bool:
        """Pack the container's ``/out`` tree into a ROOT-level archive ``/out/<WARM_OUTPUT_ARCHIVE>``.

        A C/R-restored gVisor container propagates FILES written at the ``/out`` root to the host
        bind source, but NOT directories it creates post-restore (the restored process's gofer/VFS
        view is stale) — so an engine whose output is a TREE (e.g. RedTusk's ``rmeta/``) loses
        everything below ``/out`` from the host's view. We exec a ``tar`` as a FRESH process INSIDE
        the still-alive container (a fresh exec gets a consistent view of ``/out``, unlike the
        restored worker) writing the archive at the ``/out`` ROOT; that single root file DOES
        propagate, so the host can read+extract it (see ``materialize_warm_output``). Best-effort:
        returns False if the exec fails (caller then falls back to whatever the bind mount carried).
        """
        cmd = (
            f"cd /out && rm -f {WARM_OUTPUT_ARCHIVE} && "
            f"tar cf {WARM_OUTPUT_ARCHIVE} --exclude={WARM_OUTPUT_ARCHIVE} . && sync"
        )
        try:
            self._run([*_runsc(self._cfg), "exec", self._cid, "sh", "-c", cmd])
            return True
        except Exception:  # noqa: BLE001 — materialize must never raise; fall back to the bind mount
            return False

    def kill(self) -> None:
        if not _best_effort_delete(self._cfg, self._run, self._cid):
            # The sandbox may still exist. Raise so the caller's guard retains the generation pin
            # instead of reclaiming a checkpoint a live sandbox may still be restoring from.
            raise RuntimeError(f"could not confirm teardown of runsc container {self._cid}")


class GvisorSnapshotBackend:
    def sweep_orphan_generations(self, base_dir: Path) -> int:
        """Reclaim ``checkpoint-<gen>`` dirs left behind by a dispatcher that is gone.

        gVisor got generation stamping (so a rebuild can never overwrite a checkpoint an
        in-flight restore is still reading) and reference-counted reclamation for the
        generations it supersedes IN THIS PROCESS -- but nothing swept the ones a PREVIOUS
        process left. Nothing retires the current artifact at shutdown, so every restart, clean
        or not, stranded a whole runsc checkpoint directory that no code path could ever
        rediscover. The FC tier has swept its ``warm-*`` files since generations were introduced;
        this side only ever got the other half (upstream, PR #82).

        ``base_dir`` is the manager's checkpoint root -- the same dir it hands ``checkpoint()``.
        This backend only learns that path at checkpoint time, which is far too late for a sweep
        that has to run BEFORE the first build consumes the space.

        Deliberately conservative, exactly as the FC sweep is: a directory is removed ONLY when
        its owning process is provably gone. Deleting a generation a LIVE dispatcher is still
        restoring from is far worse than the leak, so unknown ownership counts as alive.
        """
        root = Path(base_dir)
        if not root.exists():
            return 0
        removed = 0
        failed: list[str] = []
        for path in root.glob("checkpoint-*"):
            token = generation_owner(path.name, prefix="checkpoint-")
            if token is None or token == owner_token() or owner_alive(token):
                continue
            # NOT ignore_errors: SnapshotManager latches "swept" on a clean return, so reporting
            # success for a tree we could not remove disables reclamation for the whole process.
            errs: list[str] = []
            shutil.rmtree(path, onerror=lambda fn, p, exc: errs.append(f"{p}: {exc[1]}"))
            if errs:
                failed.append("; ".join(errs))
                _log.warning("gvisor_snapshot: could not sweep orphan checkpoint %s", path)
            else:
                removed += 1
        if removed:
            _log.info("gvisor_snapshot.swept_orphan_generations count=%d", removed)
        if failed:
            raise OSError("could not sweep orphan checkpoints: " + "; ".join(failed))
        return removed

    def discard(self, artifact: object) -> None:
        """Remove a fully drained checkpoint generation.

        Generation stamping and reclamation are two halves of one mechanism: stamping alone just
        turns "one directory that gets overwritten" into "a new directory every rebuild that
        nothing ever deletes". SnapshotManager reclaims retired artifacts only through this hook,
        so without it every superseded runsc checkpoint stayed on disk until the filesystem
        filled (upstream, PR #82). Called only once the refcount for this artifact reaches zero,
        i.e. no live sandbox is still restoring from it.
        """
        path = Path(str(artifact))
        if not path.name.startswith("checkpoint-"):
            # Refuse anything that is not one of OUR generation dirs: this deletes a tree, and
            # an unexpected artifact shape must never turn into an rmtree of something else.
            _log.warning("gvisor_snapshot: refusing to discard unexpected artifact %r", artifact)
            return
        # NOT ignore_errors: SnapshotManager._discard treats a normal return as CONFIRMED
        # cleanup and drops the artifact from _retired, so silently swallowing a transient
        # EIO/EROFS here means this checkpoint directory is never retried and rebuilds accumulate
        # them until the filesystem fills. Same fix as the FC backend's unlink (PR #82).
        errors: list[str] = []
        shutil.rmtree(path, onerror=lambda fn, p, exc: errors.append(f"{p}: {exc[1]}"))
        if errors:
            raise OSError("could not remove checkpoint generation: " + "; ".join(errors))

    def __init__(
        self,
        cfg: GvisorConfig,
        *,
        run: Callable[..., int] = _default_run,
        run_text: Callable[[list[str]], str] = _default_run_text,
        ready_wait: Callable[[Path, float], None] = _default_ready_wait,
        probe: Callable[[], bool] | None = None,
        cr_capable: Callable[[str], bool] = _default_cr_capable,
    ) -> None:
        self._cfg = cfg
        self._run = run
        self._run_text = run_text
        self._ready = ready_wait
        self._probe = probe
        self._cr_capable = cr_capable
        # Durable across boot handles: SnapshotManager kills and abandons a handle after a failed
        # checkpoint, so a retry list held on the handle is discarded with it (PR #82).
        self._stranded_partials: list[str] = []

    def available(self) -> bool:
        # `probe` is a full override (tests/embedders); honor it verbatim.
        if self._probe is not None:
            return self._probe()
        # Fail-closed seam contract: the binary must EXIST and advertise checkpoint+restore.
        # Checking mere existence would fail-open — selecting gVisor on a runsc that can't C/R,
        # then erroring at restore time instead of falling back at selection.
        if shutil.which(self._cfg.runsc_bin) is None:
            return False
        return self._cr_capable(self._cfg.runsc_bin)

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
        return GvisorBootHandle(self._cfg, self._run, cid, base, ctrl, self._ready, stranded=self._stranded_partials)

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
        except Exception as exc:
            # A partially-failed `runsc restore` can leave registered container state (with
            # its sandbox/gofer processes) under -root. No handle is returned on failure, and
            # the manager only knows the slot dir — not this cid — so tear it down here before
            # re-raising, or it orphans an unmanaged sandbox.
            if not _best_effort_delete(self._cfg, self._run, cid):
                # Signal it on the ORIGINAL error: SnapshotManager reads this to decide whether
                # the checkpoint may be reclaimed. Ignoring the result meant the manager unpinned
                # even though an unmanaged sandbox might still be using the generation (PR #82).
                exc.kill_failed = True  # type: ignore[attr-defined]
            raise
        return GvisorRestoreHandle(self._cfg, self._run, cid, wd, self._run_text)
