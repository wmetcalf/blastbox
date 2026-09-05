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
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from blastbox.worker.warm import AckCapability
from blastbox.host.runtime.snapshot_backend import (
    generation_owner,
    hold_owner_lease,
    owner_alive,
    prune_owner_lease,
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


class GvisorCommandError(RuntimeError):
    """A runsc command failed, carrying the command's own stderr.

    `SnapshotManager.build()` wraps whatever escapes into `SnapshotBuildError`
    using `str(exc)`, so what this carries is what the operator finally reads.
    """


def _with_runsc_stderr(exc: BaseException, what: str) -> BaseException:
    """``exc`` carrying the failing command's OWN stderr, when it captured any.

    `runsc run` and `runsc restore` used to discard stderr, so the only output an
    operator saw came from the TEARDOWN that follows a failure -- `runsc kill` and
    `runsc delete` against a container that was never created, which print
    `FetchSpec failed: loading container: file does not exist`. That is what a
    failed gVisor boot reported, and it says nothing about why the boot failed.

    Measured on a host where the base genuinely cannot boot, the real messages
    are specific and immediately actionable:

        cannot create gofer process: gofer: fork/exec /proc/self/exe:
            permission denied
        cannot create sandbox: cannot read client sync file:
            waiting for sandbox to start: EOF

    Truncated from the END: runsc's useful line is the last one.
    """
    err = getattr(exc, "stderr", None)
    if not err:
        return exc
    if isinstance(err, bytes):
        err = err.decode("utf-8", "replace")
    tail = err.strip()[-600:]
    if not tail:
        return exc
    return GvisorCommandError(f"{what} failed: {tail}")


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


def read_base_ack_capability(ctrl_dir: Path) -> bool:
    """Does the warm BASE advertise the start-marker protocol?

    Read once, at base build, and that is the only chance: a gVisor restore gets a FRESH ctrl/
    bind dir, and the checkpointed worker resumes PAST its one-time signal_ready(), so it never
    writes `ready` again. Learning the capability from a restored slot is therefore impossible,
    and learning it from a completed job fails on precisely the base that is wedged from its
    first restore -- the one the fast repair exists for.

    Confined like every other read of this worker-writable directory: `ready` is written by the
    base container, and ctrl/ is bind-mounted 0o777.
    """
    from blastbox.contract.envelope import read_confined_regular_bytes
    try:
        raw = read_confined_regular_bytes(ctrl_dir, "ready", max_bytes=4096)
    except (OSError, ValueError):
        return False
    return "ack=1" in raw.decode("utf-8", "replace")


def read_setup_breadcrumb(ctrl_dir: Path, *, max_bytes: int = 4096) -> str | None:
    """The cause `run_warm.py` left behind when engine setup died before signal_ready().

    The guest writes `ctrl/setup_error` for exactly one reason, in its own words: "the host
    only sees a bare ready-timeout ... so the failure is diagnosable". Nothing read it. The
    host reported `warm base not READY within 120.0s` and then rmtree'd the bundle -- taking
    the explanation with it -- so the breadcrumb was write-only and the operator was left with
    a timeout and no cause. Measured on toolz2 against a fleet clippyshot rootfs.

    Confined exactly like `read_base_ack_capability`: ctrl/ is bind-mounted 0o777 and this
    content is worker-written, so it is read as a confined regular file, capped, and
    sanitised to printable ASCII before it reaches a log line or an exception message.
    """
    # `read_confined_regular_bytes` REJECTS anything over the cap, which for a diagnostic is
    # the wrong trade: an oversized breadcrumb would leave the operator with no cause at all,
    # which is the very failure this function exists to end. Read through the same confined,
    # TOCTOU-safe fd and TRUNCATE instead.
    from blastbox.contract.envelope import open_confined_regular_fd
    try:
        fd = open_confined_regular_fd(ctrl_dir, "setup_error")
    except (OSError, ValueError):
        return None
    try:
        raw = os.read(fd, max_bytes)
    except OSError:
        return None
    finally:
        os.close(fd)
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return None
    # One line, printable only. A worker-controlled string must not smuggle control characters
    # or newlines into an operator's log.
    flat = " ".join(text.split())
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in flat)


def _default_ready_wait(ctrl_dir: Path, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if (ctrl_dir / "ready").exists():
            return
        time.sleep(0.2)
    # Read the breadcrumb BEFORE anything tears the bundle down: the caller's failure path
    # kills the container and removes this directory, so this is the only moment it exists.
    cause = read_setup_breadcrumb(ctrl_dir)
    detail = f": {cause}" if cause else ""
    raise TimeoutError(f"warm base not READY within {timeout_s}s ({ctrl_dir}){detail}")


def _best_effort_delete(cfg: GvisorConfig, run: Callable[..., int], cid: str) -> bool:
    """Tear down a (possibly half-created) runsc container: kill then force-delete,
    swallowing errors. Used on failure + reap paths where the container may or may not
    exist — a `runsc run`/`restore` that fails partway can still register container state
    under ``-root`` (with its sandbox/gofer processes), which would otherwise leak because
    the caller never gets a handle to reap it.

    Returns True when at least one teardown command SUCCEEDED. Callers that must not reclaim
    resources a live sandbox still uses check this rather than assuming a clean return."""
    ok = False
    problems: list[str] = []
    for argv in (["kill", cid, "KILL"], ["delete", "-force", cid]):
        try:
            # CAPTURED, not discarded. Against a container that was never
            # created runsc prints `FetchSpec failed: loading container: file
            # does not exist`, and because this teardown follows a failed boot
            # that line was the only stderr an operator saw -- describing the
            # cleanup rather than the failure. But this helper also runs from
            # kill() during ORDINARY reaping, where the container did exist and
            # a teardown failure is the actionable thing: discarding both
            # streams would leave "could not confirm teardown" with no reason.
            # So: capture always, and report only when NOTHING succeeded.
            run([*_runsc(cfg), *argv],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            ok = True
        except Exception as exc:  # noqa: BLE001 - best effort by contract
            detail = getattr(exc, "stderr", None)
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", "replace")
            problems.append(f"{argv[0]}: {(detail or exc).__str__().strip()[-200:]}")
    if not ok and problems:
        _log.warning("gvisor_snapshot: teardown of %s failed -- %s", cid, "; ".join(problems))
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
        ack_capable: "AckCapability | None" = None,
        ack_generation: "int | None" = None,
        stranded: list[str] | None = None,
        run_text: Callable[[list[str]], str] = _default_run_text,
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
        self._run_text = run_text
        self._ack_capable: "AckCapability | None" = ack_capable
        # The generation this BUILD started under -- INJECTED by boot_base, which samples it
        # before `runsc run`. Sampling it here was too late: constructing this handle is the LAST
        # thing boot_base does, so an invalidate_base() landing during the (slow) launch advanced
        # the generation first, and the retiring build stamped itself with the REPLACEMENT's.
        # SnapshotManager then rejects its artifact via _build_epoch, but its readiness
        # advertisement had already taught a generation it knows nothing about -- so a
        # replacement bundle WITHOUT the protocol inherits `capable`, its absent start markers
        # read as proof the guest never ran, and a healthy base is invalidated on repeat.
        # None is MEANINGFUL: an unidentifiable build teaches nothing (#92).
        self._ack_gen = ack_generation

    def _container_status(self) -> str:
        """`runsc state` for this base, or "" if it cannot be determined."""
        try:
            return str(json.loads(self._run_text([*_runsc(self._cfg), "state", self._cid]))
                       .get("status", ""))
        except Exception:  # noqa: BLE001 - a diagnostic must never mask the failure it explains
            return ""

    def wait_ready(self, timeout_s: float) -> None:
        try:
            self._ready(self._ctrl, timeout_s)
        except TimeoutError as exc:
            # A guest that DIED cannot ever write `ready`, so waiting out the budget taught
            # nothing and reported nothing. Measured on toolz2: run_warm.py hit
            # `ModuleNotFoundError: No module named 'blastbox'` at IMPORT -- before main(), so
            # before it could drop the setup_error breadcrumb -- the container was gone in under
            # a second, and the host still sat for 120s and then said only "not READY within
            # 120.0s". The status separates "too slow" from "already dead", which want opposite
            # fixes: a longer budget, or a corrected warm argv/interpreter.
            status = self._container_status()
            if status and status != "running":
                raise TimeoutError(
                    f"{exc}; the base container is {status} -- it exited before signalling "
                    f"READY, so no budget would have helped (check the warm argv/interpreter "
                    f"for this rootfs)"
                ) from exc
            raise
        # THE ONLY CHANCE to learn it. A restore gets a fresh ctrl/ and the checkpointed worker
        # resumes past its one-time signal_ready(), so `ready` is never written again -- and a
        # base wedged from its first restore never completes a job either. Read it here, while
        # the base is still the live container that wrote it.
        if self._ack_capable is not None and read_base_ack_capability(self._ctrl):
            # OBSERVE, not learn. Readiness proves this guest speaks the protocol; it does not
            # prove the pool will ever run a slot from it. checkpoint() may still fail, in which
            # case SnapshotManager publishes nothing -- and a capability taught here would
            # outlive a base that never existed. If the worker bundle is then rolled back, the
            # retry's plain readiness marker cannot clear it, and the older image's missing start
            # markers are read as PROVEN non-starts: a document hang invalidates an
            # ACK-incapable base instead of staying UNKNOWN. Confirmed in checkpoint().
            self._ack_capable.observe(self._ack_gen)

    @property
    def ack_generation(self) -> "int | None":
        """The generation this build was stamped with. Read by SnapshotManager to confirm the
        deferred ACK advertisement once -- and only once -- this build's artifact is PUBLISHED."""
        return self._ack_gen

    def checkpoint(self, dest_dir: Path) -> object:
        # Retry anything a previous failed checkpoint could not remove; no artifact was returned
        # for those, so nothing else can discover them. Also attempted BEFORE the base boots (see
        # boot_base) -- reaching only this point is too late when the leftovers filled the disk.
        _retry_stranded_partials(self._stranded_partials)

        # GENERATION-STAMPED, never a fixed "checkpoint" path. restore_in() reads this directory
        # for the whole life of a `runsc restore`, so a rebuild writing the SAME path can
        # overwrite files an in-flight restore is still consuming -- it fails, or worse observes
        # a mix of two checkpoints. A pin stops the old generation being DELETED; only a distinct
        # path stops it being OVERWRITTEN. FC's mem/snapshot pair got this; gVisor did not
        # (upstream, PR #82).
        # Take the lease BEFORE the first generation exists, and REFUSE to write one without it.
        # Not best-effort: the sweep's rule is that a lease nobody holds proves its owner dead, so
        # an uncovered checkpoint can be reclaimed by another dispatcher while this process's
        # sandboxes are still restoring from it (upstream, PR #82).
        if not hold_owner_lease(dest_dir):
            raise RuntimeError(
                f"refusing to write a checkpoint generation without a lease in {dest_dir}: "
                f"another dispatcher could reclaim it while this one is still using it"
            )
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


def _retry_stranded_partials(stranded: "list[str]") -> None:
    """Re-attempt removal of partial checkpoints a previous failed attempt could not delete.

    MUTATED IN PLACE: rebinding would detach the caller from the backend-owned list, so later
    appends land on a private copy the next handle never sees.
    """
    if not stranded:
        return
    still: list[str] = []
    for leftover in stranded:
        errs: list[str] = []
        shutil.rmtree(leftover, onerror=lambda fn, p, exc: errs.append(str(p)))
        if errs:
            still.append(leftover)
    stranded[:] = still


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
        reclaimed_owners: set[str] = set()
        failed_owners: set[str] = set()
        for path in root.glob("checkpoint-*"):
            token = generation_owner(path.name, prefix="checkpoint-")
            # lease_dir: proved by a flock on the shared filesystem, never by a pid -- two
            # dispatcher containers overlapping through a rolling deployment both see themselves
            # as pid 1, and the /proc rule would call the live one dead (upstream, PR #82).
            if (token is None or token == owner_token()
                    or owner_alive(token, lease_dir=root)):
                continue
            # NOT ignore_errors: SnapshotManager latches "swept" on a clean return, so reporting
            # success for a tree we could not remove disables reclamation for the whole process.
            errs: list[str] = []
            shutil.rmtree(path, onerror=lambda fn, p, exc: errs.append(f"{p}: {exc[1]}"))
            if errs:
                failed.append("; ".join(errs))
                failed_owners.add(token)
                _log.warning("gvisor_snapshot: could not sweep orphan checkpoint %s", path)
            else:
                removed += 1
                reclaimed_owners.add(token)
        # AFTER the loop, and only for owners whose every checkpoint is actually gone: pruning
        # the lease of an owner whose rmtree FAILED leaves the retry with nothing to prove death
        # with, so it skips that checkpoint forever (upstream, PR #82).
        for token in reclaimed_owners - failed_owners:
            prune_owner_lease(root, token)
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
        ack_capable: "AckCapability | None" = None,
        epoch_sampler: "Callable[[], int | None] | None" = None,
        probe: Callable[[], bool] | None = None,
        cr_capable: Callable[[str], bool] = _default_cr_capable,
    ) -> None:
        self._cfg = cfg
        self._run = run
        self._run_text = run_text
        self._ready = ready_wait
        self._ack_capable: "AckCapability | None" = ack_capable
        # Reads SnapshotManager.build_epoch. Injected because the backend is constructed before
        # the manager, and because the backend must not own an identity of its own -- that is the
        # two-counter mistake issue #92 removes.
        self._epoch_sampler: "Callable[[], int | None] | None" = epoch_sampler
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
        # BEFORE the bundle dir is written. The retry used to run only in checkpoint(), which
        # happens after a successful boot -- so a stranded checkpoint big enough to fill the
        # filesystem blocked the boot that would have reached the cleanup, and the tier stayed
        # cold permanently. Same fix as the FC launcher; a retry is worthless if the condition it
        # fixes is what stops you reaching it (upstream, PR #82).
        _retry_stranded_partials(self._stranded_partials)
        # BEFORE `runsc run` -- see GvisorBootHandle.__init__. The generation that is current when
        # the build STARTS is the one this base can honestly speak for; anything sampled after the
        # launch may already belong to the base that replaced it.
        ack_gen = self._epoch_sampler() if self._epoch_sampler is not None else None
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
                stderr=subprocess.PIPE,
            )
        except BaseException as boot_exc:
            # BaseException, matching restore_in and build()'s teardown: an interrupt or
            # cancellation during `runsc run` still leaves registered container state behind, and
            # no boot handle is returned on failure, so nothing else can ever reap it (PR #82).
            #
            # Nothing reaps the base — drop any registered runsc state for this cid AND remove
            # the bundle dir so neither leaks.
            if not _best_effort_delete(self._cfg, self._run, cid):
                # UNCONFIRMED: both teardown commands failed, so the sandbox/gofer processes may
                # still be live. Ignoring that result and removing the bundle anyway forgot the
                # only cid anything could retry, and every later build retry leaked another base.
                # Keep both for the next attempt (upstream, PR #82).
                self._stranded_partials.append(str(base))
                _log.warning("gvisor_snapshot: base %s could not be confirmed deleted; retaining "
                             "its bundle for retry", cid)
                raise _with_runsc_stderr(boot_exc, "runsc run") from boot_exc
            shutil.rmtree(base, ignore_errors=True)
            raise _with_runsc_stderr(boot_exc, "runsc run") from boot_exc
        return GvisorBootHandle(self._cfg, self._run, cid, base, ctrl, self._ready,
                                run_text=self._run_text,
                                ack_capable=self._ack_capable,
                                ack_generation=ack_gen,
                                stranded=self._stranded_partials)

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
                stderr=subprocess.PIPE,
            )
        except BaseException as exc:
            # BaseException, not Exception. A KeyboardInterrupt, SystemExit or task cancellation
            # during `runsc restore` skipped this handler entirely -- yet the command may already
            # have registered a container and spawned its sandbox/gofer processes. Worse,
            # SnapshotManager.restore() then saw an escaping exception with no kill_failed marker
            # and UNPINNED the checkpoint, so a later invalidation could delete a generation the
            # untracked sandbox was still using. Same reasoning as build()'s teardown, which was
            # widened for exactly this (upstream, PR #82).
            #
            # A partially-failed `runsc restore` can leave registered container state (with
            # its sandbox/gofer processes) under -root. No handle is returned on failure, and
            # the manager only knows the slot dir — not this cid — so tear it down here before
            # re-raising, or it orphans an unmanaged sandbox.
            if not _best_effort_delete(self._cfg, self._run, cid):
                # Signal it on the ORIGINAL error: SnapshotManager reads this to decide whether
                # the checkpoint may be reclaimed. Ignoring the result meant the manager unpinned
                # even though an unmanaged sandbox might still be using the generation (PR #82).
                exc.kill_failed = True  # type: ignore[attr-defined]
                # ...and RETAIN it. kill_failed keeps the generation pinned, but the manager then
                # discards the cid and removes the slot workdir, so nothing could ever retry the
                # teardown OR release that pin: repeated restores leaked sandbox/gofer processes
                # and the checkpoint could never be reclaimed. Same retention the base-boot path
                # now does (upstream, PR #82).
                self._stranded_partials.append(str(wd))
                _log.warning("gvisor_snapshot: restore sandbox %s could not be confirmed deleted; "
                             "retaining its bundle for retry", cid)
            # Same treatment as the base boot: `CalledProcessError.__str__` does
            # not include captured stderr, so without this the manager reports a
            # bare non-zero exit -- and now that the teardown is quiet, that
            # would be ALL the operator gets. `kill_failed` travels with it:
            # SnapshotManager reads that flag to decide whether the checkpoint
            # may be reclaimed, and dropping it would unpin a generation an
            # unmanaged sandbox may still be using.
            enriched = _with_runsc_stderr(exc, "runsc restore")
            if enriched is exc:
                raise
            if getattr(exc, "kill_failed", False):
                enriched.kill_failed = True  # type: ignore[attr-defined]
            raise enriched from exc
        return GvisorRestoreHandle(self._cfg, self._run, cid, wd, self._run_text)
