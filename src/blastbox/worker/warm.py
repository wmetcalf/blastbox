"""Worker service lifecycle — warm protocol.

A warm worker pre-pays startup cost (``engine.warmup()``) **before** any
untrusted input exists, signals READY to the host, waits for exactly one job,
processes it through the identical harness/trust path as the cold-path worker,
signals DONE, and exits.

Warm ≠ reuse: one untrusted document per disposable slot.

Public API
----------
- ``WarmJobSpec``     — input/output paths + params for the one job.
- ``WarmControl``     — Protocol: ``signal_ready`` / ``wait_for_go`` / ``signal_done``.
- ``WarmTimeout``     — raised by ``wait_for_go`` when no job arrives in time.
- ``FileWarmControl`` — container-friendly file-based handshake implementation.
- ``HostWarmControl`` — host-side counterpart: ``signal_go`` / ``wait_for_done``.
- ``serve_warm``      — the top-level warm lifecycle function.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from blastbox.errors import HOST_RESOURCE_ERRNOS
from blastbox.errors import WarmTimeout
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation

if TYPE_CHECKING:
    from blastbox.worker.engine import Engine

logger = logging.getLogger(__name__)

# Polling interval for FileWarmControl.wait_for_go
_POLL_INTERVAL_S: float = 0.05

# A jump in CLOCK_MONOTONIC larger than this between two poll ticks cannot be a
# normal sleep — it means the sandbox was checkpoint/restored (gVisor C/R, FC
# snapshot), which advances the monotonic clock by the time spent checkpointed.
# When detected, the idle countdown is restarted so a restore from a snapshot
# older than the idle timeout does not instantly abandon the job it was handed.
_RESTORE_JUMP_S: float = 5.0


class _RestoreAwareDeadline:
    """An idle-timeout deadline that survives a checkpoint/restore clock-jump.

    A warm worker is checkpointed BLOCKED waiting for its single job. gVisor C/R
    (and, defensively, FC snapshot restore) can advance CLOCK_MONOTONIC by the
    wall-time spent checkpointed; a deadline computed *before* the checkpoint is
    then already-expired the instant the worker resumes and would abandon the
    job the host just handed it (empty output → "metadata.json not found").
    :meth:`expired` watches for a monotonic leap far larger than the caller's
    poll cadence — which can only be a restore, never a normal sleep/accept tick
    — and restarts the countdown, so a restored worker behaves like a freshly
    ready one.

    Both the deadline and the leap reference are seeded from a SINGLE
    ``time.monotonic()`` sample, so a checkpoint can never land *between* two
    samples and desync them (which would hide the very jump being watched for).
    """

    __slots__ = ("_timeout", "_deadline", "_last")

    def __init__(self, timeout_s: float) -> None:
        self._timeout = timeout_s
        self._restart(time.monotonic())

    def _restart(self, now: float) -> None:
        self._deadline = now + self._timeout
        self._last = now

    def expired(self) -> bool:
        """Whether the idle timeout has genuinely elapsed; call once per tick.

        A monotonic jump greater than ``_RESTORE_JUMP_S`` since the previous call
        is treated as a restore: the countdown restarts and this returns ``False``
        (the worker is effectively freshly ready).
        """
        now = time.monotonic()
        if now - self._last > _RESTORE_JUMP_S:
            self._restart(now)
            return False
        self._last = now
        return now >= self._deadline


# ---------------------------------------------------------------------------
# WarmJobSpec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WarmJobSpec:
    """Specification for the single job a warm worker will process."""

    input_path: Path
    """Absolute path to the (staged) input file."""

    output_dir: Path
    """Absolute path to the output directory for artifacts + metadata.json."""

    params: dict[str, str] = field(default_factory=dict)
    """Optional engine-specific string parameters forwarded from the host."""


# ---------------------------------------------------------------------------
# WarmControl protocol
# ---------------------------------------------------------------------------


class WarmControl(Protocol):
    """Host↔warm-worker handshake abstraction.

    Implementations must be injectable (so ``serve_warm`` is unit-testable
    with no real container / filesystem).
    """

    def signal_ready(self) -> None:
        """Notify the host that this slot is warm and ready to accept one job."""
        ...

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        """Block until the host delivers a job spec, then return it.

        Raises:
            WarmTimeout: if no job arrives within ``timeout_s`` seconds.
        """
        ...

    def signal_done(self, *, status: str) -> None:
        """Notify the host that this slot has finished (or failed).

        ``status`` is a short ASCII string, e.g. ``"ok"``, ``"idle_timeout"``,
        ``"warmup_error"``.  The host uses it to decide whether to reap or
        replace the slot.
        """
        ...


# ---------------------------------------------------------------------------
# FileWarmControl
# ---------------------------------------------------------------------------


class FileWarmControl:
    """Container-friendly file-based implementation of ``WarmControl``.

    Handshake files under ``control_dir``:

    * ``ready``    — written (atomically) by the worker after warmup.
    * ``go.json``  — written by the host when a job is ready; contains
                     ``{"input_path": "...", "output_dir": "...", "params": {...}}``.
    * ``done``     — written (atomically) by the worker; contains the status
                     string as plain text.

    All writes use a temp-file + ``os.replace`` (atomic rename) so the host
    never observes a half-written signal file.
    """

    def __init__(self, control_dir: Path) -> None:
        self._dir = control_dir

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _atomic_write(self, name: str, content: str) -> None:
        """Write *content* to ``control_dir/<name>`` atomically via temp+rename."""
        target = self._dir / name
        tmp = self._dir / f".{name}.tmp"
        try:
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, target)
        except Exception:
            # Best-effort cleanup of the temp file on failure
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # WarmControl implementation
    # ------------------------------------------------------------------

    def signal_ready(self) -> None:
        """Atomically create ``control_dir/ready``."""
        # Advertise the start-marker capability HERE, before any job. Learning it only from a
        # completed marker leaves a base that is wedged from its first slot permanently UNKNOWN --
        # so the fast repair can never arm on exactly the base it exists to repair. An older host
        # only checks that `ready` exists, so the extra line is invisible to it.
        self._atomic_write("ready", "ready\nack=1\n")

    def wait_for_go(self, *, timeout_s: float) -> WarmJobSpec:
        """Poll for ``control_dir/go.json`` until present or ``timeout_s`` elapsed.

        Parses ``go.json`` (``input_path``, ``output_dir``, ``params``), validates
        that paths are absolute and exist, then returns a ``WarmJobSpec``.

        Raises:
            WarmTimeout: if ``go.json`` does not appear before the deadline.
        """
        go_path = self._dir / "go.json"
        # This worker is checkpointed BLOCKED in this loop (at "ready"); a restore
        # from a snapshot older than `timeout_s` resumes with the monotonic clock
        # already advanced past the original deadline, which would instantly raise
        # WarmTimeout and abandon the job the host just handed us (empty output ->
        # "metadata.json not found"). _RestoreAwareDeadline restarts the countdown
        # when it detects the restore jump, so the worker is "freshly ready".
        deadline = _RestoreAwareDeadline(timeout_s)

        while True:
            if go_path.exists():
                try:
                    raw = go_path.read_text(encoding="utf-8")
                    data = json.loads(raw)
                except (OSError, json.JSONDecodeError) as exc:
                    raise WarmTimeout(f"go.json unreadable: {exc}") from exc

                input_path = Path(data["input_path"])
                output_dir = Path(data["output_dir"])

                # Light sanity checks — the host controls these paths
                if not input_path.is_absolute():
                    raise ValueError(f"input_path is not absolute: {input_path}")
                if not output_dir.is_absolute():
                    raise ValueError(f"output_dir is not absolute: {output_dir}")
                if not input_path.exists():
                    raise ValueError(f"input_path does not exist: {input_path}")
                if not output_dir.exists():
                    raise ValueError(f"output_dir does not exist: {output_dir}")

                params: dict[str, str] = data.get("params", {})
                # Mark that we HAVE the job, before any work starts. `done` arriving late is
                # indistinguishable from a guest that never woke up, so without this a wedged
                # base is only found by failing 2 x warm_size real jobs at the full timeout.
                #
                # A FAILED WRITE ABORTS THE JOB, exactly as the vsock ack does -- and the comment
                # that first stood here, claiming the host would keep UNKNOWN, was wrong in the
                # same way it was wrong there. Once another slot has taught the runtime that this
                # image marks starts, the host initialises later controls to "not started"; a
                # swallowed write failure then means the worker runs the document while the host
                # records False, and three such filesystem hiccups on distinct slots convict a
                # base whose workers all ran. If we cannot promise the host we started, we do not
                # start.
                if data.get("ack"):
                    try:
                        self._atomic_write(WARM_STARTED, "1")
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("warm.started_marker failed: %s — refusing the job", exc)
                        # HOST-I/O ATTRIBUTION, the same flag `done` already carries. ctrl/ is a
                        # bind mount: if the HOST filesystem is full, read-only or erroring, this
                        # write fails on every slot at once -- and the host has already set
                        # guest_started=False, so without this the storage incident would convict
                        # a perfectly healthy base three slots later. The abort is still right;
                        # blaming the worker for it is not.
                        _exc = WarmTimeout(f"could not mark job start: {exc}")
                        _exc.host_io = True  # type: ignore[attr-defined]
                        raise _exc from exc
                return WarmJobSpec(
                    input_path=input_path,
                    output_dir=output_dir,
                    params=params,
                )

            if deadline.expired():
                raise WarmTimeout(
                    f"no job arrived within {timeout_s}s idle timeout"
                )

            time.sleep(_POLL_INTERVAL_S)

    def signal_done(self, *, status: str) -> None:
        """Atomically create ``control_dir/done`` containing the status string."""
        self._atomic_write("done", status)


# ---------------------------------------------------------------------------
# HostWarmControl (host side)
# ---------------------------------------------------------------------------


# Polling interval for HostWarmControl.wait_for_done
_HOST_POLL_INTERVAL_S: float = 0.05


#: Written by the worker the moment it HAS a job and before it starts work. The file-protocol
#: twin of the vsock WARM_ACK frame, and it exists for the same reason: `done` arriving late is
#: indistinguishable from a guest that never woke up, so without this a wedged gVisor base is
#: only discovered by failing 2 x warm_size real jobs at the full worker timeout. Unlike the
#: vsock ack there is no ordering hazard -- an old host simply never looks at the file.
WARM_STARTED = "started"


#: Written by the writability probe. Must be non-empty so the probe allocates a data block:
#: a filesystem with inodes but no data blocks accepts an empty file and fails a real write.
_PROBE_PAYLOAD = b"blastbox-writability-probe\n"

#: How often the host re-probes ctrl/ writability WHILE waiting for a start marker. The probe is
#: a real create+rename+unlink, so it is throttled rather than run every 50 ms poll; 1 s samples a
#: 300 s worker timeout finely enough to catch a blip while costing one tmpfs write per second
#: per waiting slot.
_CTRL_PROBE_INTERVAL_S: float = 1.0


class AckCapability:
    """Does the artifact a slot was RESTORED FROM advertise the start signal?

    Keyed by the PUBLISHED ARTIFACT, identified by ``SnapshotManager._build_epoch`` -- which that
    manager already bumps inside ``invalidate()``, under ``_build_lock``, ATOMICALLY with retiring
    the artifact, and re-reads under the same lock to reject a build that was superseded while it
    ran.

    This class used to keep a SECOND counter of its own, advanced from the runtime wrappers at a
    different moment under a different lock. Nothing held the two in step except hand-written
    ordering at each call site, and that produced eight distinct defects in PR #90 -- the set
    outliving the base, a retired control resurrecting it, the stamp taken at claim instead of
    spawn, ``reset()`` running before the artifact was retired, the stamp sampled after the
    launch, a build that never published teaching its generation, and a failed build teaching its
    own retry. Each fix closed one drift window and exposed the next, because the key was always
    something ADJACENT to the artifact rather than the artifact itself (issue #92).

    There is now one identity, and it is the artifact's. The properties that used to need
    careful ordering are facts:

    * a build that never publishes cannot teach anything -- only :meth:`publish` promotes, and it
      is called at the one point where the artifact becomes live;
    * publishing an artifact that did NOT advertise clears the flag, so a replacement built from
      a rolled-back worker cannot inherit its predecessor's capability. That is what ``reset()``
      was for, and why there is no longer a ``reset()`` to call in the wrong order;
    * a retired slot's late ack names an epoch that is no longer published, so it is ignored
      rather than believed.
    """

    __slots__ = ("_epoch", "_capable", "_lock", "_pending", "_scoped")

    def __init__(self, *, artifact_scoped: bool = False) -> None:
        #: True when this capability describes SNAPSHOT ARTIFACTS, even before the first one is
        #: published. Without it, a capability that has not published yet is indistinguishable
        #: from the plain (no-artifact) runtime -- and a snapshot runtime handed a manager with
        #: no capability of its own built exactly that: a fallback nothing ever publishes into,
        #: so every ack taught it unconditionally, capable_for() answered True for ANY epoch, and
        #: (with reset() gone) nothing ever cleared it. A replacement built from an older worker
        #: is then convicted for markers it never promised to write.
        self._scoped = artifact_scoped
        #: Epoch of the artifact that is CURRENTLY published. None means no artifact lifecycle at
        #: all -- the plain (non-snapshot) FC runtime boots every slot fresh, so there is one
        #: image and nothing to tell apart.
        self._epoch: "int | None" = None
        self._capable = False
        #: Epochs whose base build ADVERTISED but whose artifact has not been shown usable yet.
        #: Readiness necessarily precedes checkpoint(), so believing it there let a build that
        #: never published teach the capability permanently.
        self._pending: set = set()
        # LOCKED, because the compare and the mutation are one decision. Unsynchronised, a slot
        # reporting its ack could pass the epoch check, have publish() install a different
        # artifact underneath it, and then set _capable=True anyway -- re-enabling capability for
        # a replacement that never advertised it.
        self._lock = threading.Lock()

    def __bool__(self) -> bool:
        """Capability of the currently published artifact.

        Prefer :meth:`capable_for`: a caller holding a slot knows WHICH artifact it restored from,
        and that is the question worth asking.
        """
        with self._lock:
            return self._capable

    def capable_for(self, epoch: "int | None") -> bool:
        """Did the artifact of THIS epoch advertise the protocol?

        The question a slot actually has. An epoch that is no longer the published one answers
        False -- not because that base was incapable, but because this capability is not about it,
        and UNKNOWN convicts nothing.
        """
        with self._lock:
            if self._epoch is None:
                # Nothing published yet. For an artifact-scoped capability that is UNKNOWN, not
                # "ask the flag" -- there is no artifact for the flag to be about.
                return False if self._scoped else self._capable
            return self._capable and epoch == self._epoch

    def learn(self, epoch: "int | None" = None) -> None:
        """A LIVE slot acked: evidence about the artifact it was restored from.

        In snapshot mode an UNSTAMPED ack (``epoch is None``) teaches nothing, exactly as
        :meth:`capable_for` answers UNKNOWN for it. Accepting it here meant a late ack from a
        retired -- or simply unidentifiable -- slot could resurrect capability for a SILENT
        replacement, after which that replacement's missing markers read as proven non-starts and
        convict a healthy base. A caller that cannot say which artifact its slot came from has not
        supplied evidence about any artifact.

        With no artifact lifecycle at all (the plain FC runtime) there is one image and nothing to
        tell apart, so an unstamped ack is the only kind there is and it does teach.
        """
        with self._lock:
            if self._epoch is None and not self._scoped:
                self._capable = True
            elif epoch is not None and epoch == self._epoch:
                self._capable = True

    def begin_build(self) -> None:
        """A new BUILD ATTEMPT is starting: forget what the last one advertised.

        A failed build is retried by ``ensure_build_started()`` with no invalidation in between,
        so attempts share an epoch. Without this, attempt 1 advertising and then failing to
        checkpoint left its observation behind for attempt 2 -- possibly a ROLLED-BACK,
        ACK-incapable worker -- to publish and consume.
        """
        with self._lock:
            self._pending.clear()

    def observe(self, epoch: "int | None" = None) -> None:
        """A base build ADVERTISED -- recorded, deliberately not yet believed.

        Readiness proves the guest speaks the protocol. It does not prove the pool will ever run
        a slot from that guest: checkpoint() can still fail, and a good checkpoint is discarded
        when an invalidation landed while the build ran.
        """
        with self._lock:
            self._pending.add(epoch)

    def publish(self, epoch: "int | None") -> None:
        """The manager INSTALLED the artifact built under ``epoch``. Believe it, or stop believing.

        The whole arbitration, in one place: the flag becomes whatever THIS artifact advertised.
        An artifact that stayed silent therefore RETIRES its predecessor's capability rather than
        inheriting it, with no separate reset to sequence correctly.
        """
        with self._lock:
            self._capable = epoch in self._pending
            self._epoch = epoch
            self._pending.clear()


class HostWarmControl:
    """Host-side counterpart to ``FileWarmControl``.

    Handshake files under ``control_dir``:

    * ``go.json``  — written (atomically) by the host when a job is assigned;
                     contains ``{"input_path": "...", "output_dir": "...",
                     "params": {...}}``.
    * ``started``  — written by the worker when it picks the job up, if go.json asked
                     (``"ack": true``); proves the guest ran, as opposed to never waking.
    * ``done``     — written by the worker; contains the status string.

    All writes use a temp-file + ``os.replace`` (atomic rename), symmetric
    with ``FileWarmControl``.
    """

    #: None = UNKNOWN (no marker seen: an older worker image). True = the worker confirmed it
    #: has the job. Never guessed -- twin of firecracker.VsockHostWarmControl.guest_started.
    guest_started: "bool | None" = None

    def __init__(self, control_dir: Path,
                 *, ack_capable: "AckCapability | None" = None,
                 ack_generation: "int | None" = None) -> None:
        self._dir = control_dir
        # Shared with the runtime; true once the CURRENT base has been seen to advertise.
        self._ack_capable = ack_capable if ack_capable is not None else AckCapability()
        # The SLOT's generation, taken at spawn -- see VsockHostWarmControl for why construction
        # time is the wrong moment. Falls back only when the caller cannot say.
        # None is MEANINGFUL: "no artifact lifecycle" (plain tier) or "unidentifiable, teaches
        # nothing" (snapshot slot). No current-generation fallback exists to reach for (#92).
        self._ack_gen = ack_generation
        #: Latched: ctrl/ was seen UNWRITABLE at some point while this control waited. A storage
        #: incident that clears before the deadline is otherwise undetectable -- see
        #: wait_for_done.
        self._ctrl_io_fault = False

    def _atomic_write(self, name: str, content: str) -> None:
        """Write *content* to ``control_dir/<name>`` atomically AND symlink-safely.

        control_dir is WORKER-WRITABLE (the gVisor tier bind-mounts ctrl/ at 0o777), so a worker
        could pre-plant ``.<name>.tmp`` or ``<name>`` as a symlink to redirect this HOST-authored
        write to clobber an outside file. ``atomic_write_confined`` uses a random
        ``O_EXCL|O_NOFOLLOW`` temp + ``renameat`` so the write can never follow a worker symlink."""
        from blastbox.contract.envelope import atomic_write_confined
        # 0o644: control files are HOST-authored but READ BY THE WORKER, which runs as a DIFFERENT
        # uid on the gVisor tier (65532) — 0o600 would make go.json unreadable and hang the warm
        # job. Not secret (the worker already knows its own job); the per-slot 0o700 ctrl dir keeps
        # other local users out.
        atomic_write_confined(self._dir, name, content.encode("utf-8"), mode=0o644)

    def signal_go(self, spec: WarmJobSpec, *, deadline: float | None = None) -> None:
        """Atomically write ``control_dir/go.json`` with the job spec.

        Symmetric with ``FileWarmControl.wait_for_go``.
        The payload matches the format parsed by that method:
        ``{"input_path": str, "output_dir": str, "params": dict}``.

        ``deadline`` is accepted for a uniform signal_go signature but unused: the go.json write
        is instant (no network), so the file-trigger warm path is bounded by wait_for_done.
        """
        payload = json.dumps(
            {
                # Ask the worker to mark that it picked the job up. Unknown keys are ignored by
                # older workers, which then simply never write the marker.
                "ack": True,
                "input_path": str(spec.input_path),
                "output_dir": str(spec.output_dir),
                "params": spec.params,
            }
        )
        self._atomic_write("go.json", payload)

    def _started_marker_present(self) -> bool:
        """Is ``ctrl/started`` there, as a REGULAR file, without following a link out of ctrl/?

        ``Path.exists()`` follows symlinks. ctrl/ is WORKER-WRITABLE on the gVisor tier (bind
        mounted 0o777), so a compromised worker could point `started` at any host path and have
        this poll stat it -- a control-boundary violation on its own, and against a target on a
        blocking automount or a FIFO it pins the dispatch thread far outside ``timeout_s``, which
        is the one thing this loop must never allow. `ready` and `done` have been read through the
        confined helper since PR #82; this probe was missed.

        A symlinked, special or non-regular marker is NOT a start. It is a worker violating the
        protocol, and reading it as "the guest ran" would excuse the very base this repairs.
        """
        from blastbox.contract.envelope import open_confined_regular_fd

        try:
            os.close(open_confined_regular_fd(self._dir, WARM_STARTED))
        except (OSError, ValueError):
            # FileNotFoundError (not written yet) is the ordinary case and is an OSError;
            # ELOOP/ENOTDIR (symlink or non-dir component) and ValueError (not a regular file)
            # are violations. Neither is a start.
            return False
        return True

    def _ctrl_writable(self) -> bool:
        """Can THIS host still write into the control dir?

        The question a missing start marker cannot answer on its own: a full or read-only ctrl/
        silences every worker at once, so treating that silence as "the guest never started"
        convicts a healthy base across the whole pool during a storage incident.
        """
        from blastbox.contract.envelope import atomic_write_confined

        # CONFINED, and the name is RANDOM. `.bb-probe-<pid>` was predictable, and write_bytes()
        # follows a symlink -- so a worker could pre-plant one in this 0o777 bind mount and have
        # the host truncate any file it can reach, the moment a timeout ran this check. That is a
        # host-side arbitrary-truncation primitive handed over by a health probe. The confined
        # helper creates its temp relative to a dirfd with O_CREAT|O_EXCL|O_NOFOLLOW and renames
        # over the destination without following it; the random name means there is nothing to
        # pre-plant against either.
        name = f".bb-probe-{uuid.uuid4().hex}"
        try:
            # NON-EMPTY on purpose. A filesystem out of DATA BLOCKS but with an inode to spare
            # accepts a zero-byte file while the worker's `started` and `done` writes fail with
            # ENOSPC -- so an empty probe reported the mount writable during the exact incident it
            # exists to detect, and the host went back to blaming the guest. Probe the resource
            # whose failure is being diagnosed.
            atomic_write_confined(self._dir, name, _PROBE_PAYLOAD, mode=0o600)
        except Exception:  # noqa: BLE001 - OSError, or a confinement violation; both mean "no"
            return False
        # CLEANUP MUST NOT RETURN. A `return` inside a finally silently discards the value the
        # try block already produced -- so when the write failed AND this open failed (ctrl/ gone,
        # or the filesystem returning EIO), the cleanup's True overrode the probe's False and the
        # host went on to blame the guest for a control-filesystem outage. Best-effort, no verdict.
        try:
            dfd = os.open(self._dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            return True          # the write DID succeed; only the tidy-up could not run
        try:
            os.unlink(name, dir_fd=dfd)
        except OSError:
            pass
        finally:
            os.close(dfd)
        return True

    def wait_for_done(self, *, timeout_s: float) -> str:
        """Poll ``control_dir/done`` until present or ``timeout_s`` elapsed.

        Returns the status string written by the worker.

        Raises:
            WarmTimeout: if ``done`` does not appear before the deadline.
        """
        from blastbox.contract.envelope import read_confined_regular_bytes

        deadline = time.monotonic() + timeout_s
        # Per-WAIT, not per-control: a control reused for a second job must not inherit the first
        # job's storage incident and excuse a genuine wedge.
        self._ctrl_io_fault = False
        next_ctrl_probe = deadline + 1.0   # replaced below once we know we are waiting
        # LEARN CAPABILITY FIRST, from the READINESS marker rather than from a completed job. A
        # base wedged from its first slot never finishes anything, so learning only from a written
        # start-marker left it permanently UNKNOWN -- inert on exactly the base this repairs. But
        # `ready` is written when the slot WARMS, which a wedged base still does, so the
        # advertisement survives the wedge.
        # CONFINED READ. ctrl/ is WORKER-WRITABLE on the gVisor tier (bind-mounted 0o777), so a
        # compromised worker could replace `ready` with a FIFO, a symlink to a blocking device, or
        # a huge file. A plain read_text() follows all three, has no size cap, and runs BEFORE the
        # timeout loop -- so it could pin the dispatcher indefinitely or exhaust host memory
        # outside timeout_s entirely. `done` has been read through the confined helper for exactly
        # this reason since PR #82; this read must be too.
        try:
            _rdy = read_confined_regular_bytes(
                self._dir, "ready", max_bytes=4096).decode("utf-8", "replace")
        except (OSError, ValueError):
            _rdy = ""
        if "ack=1" in _rdy:
            self._ack_capable.learn(self._ack_gen)
        # SET ONLY HERE, where the host actually waits to find out -- same rule as the vsock twin.
        # Claiming "never started" anywhere earlier convicts a base for a job nobody listened for.
        if self._ack_capable.capable_for(self._ack_gen):
            self.guest_started = False
            # Only an ack-capable image can produce the "no start marker" verdict that needs
            # excusing, so only that case pays for the probes.
            next_ctrl_probe = time.monotonic() + _CTRL_PROBE_INTERVAL_S

        while True:
            if self.guest_started is not True and self._started_marker_present():
                # The worker picked the job up. Whatever fails after this is about the DOCUMENT,
                # not about whether the base can produce a working guest.
                self.guest_started = True
                self._ack_capable.learn(self._ack_gen)
            try:
                # Symlink-safe, capped, confined read: ctrl/ is WORKER-WRITABLE on the gVisor tier,
                # so a hostile worker could symlink `done` at a host file (info disclosure) or a
                # FIFO/huge file (block/pressure the single-threaded dispatcher). O_NOFOLLOW +
                # S_ISREG + a 4 KiB cap defeat that; a non-regular/oversized done fails closed.
                raw = read_confined_regular_bytes(self._dir, "done", max_bytes=4096)
                return raw.decode("utf-8", "replace").strip()
            except FileNotFoundError:
                pass  # not signalled yet → keep polling
            except ValueError as exc:
                # The worker wrote something unreadable: a verdict about IT.
                raise WarmTimeout(f"invalid done file: {exc}") from exc
            except OSError as exc:
                # EMFILE/EIO/ENOMEM reading ctrl/done is THIS HOST failing, and the dispatcher
                # convicts on WarmTimeout -- flag those so a host-side failure is not charged to a
                # worker that may have completed perfectly. But ctrl/ is WORKER-WRITABLE (the
                # gVisor tier bind-mounts it 0o777), so a worker-created symlink or non-directory
                # at `done` raises ELOOP/ENOTDIR from the confinement check: a concrete violation,
                # and flagging it host_io meant repeated ones never advanced burnout (PR #82).
                err = WarmTimeout(f"could not read done file: {exc}")
                if exc.errno in HOST_RESOURCE_ERRNOS:
                    err.host_io = True  # type: ignore[attr-defined]
                raise err from exc

            # SAMPLE WHILE WAITING, and latch. The deadline probe below can only ask "is ctrl/
            # writable NOW", so a transient ENOSPC/EROFS that silenced the worker's `started` and
            # `done` writes and then cleared was invisible: the host saw a healthy filesystem and
            # charged the outage to the worker. The worker cannot tell us -- serve_warm() raises
            # its host_io WarmTimeout inside the guest, and an unwritable ctrl/ is by definition
            # a channel it cannot use. Probing the shared filesystem ourselves is the only way to
            # learn it, and it has to be done DURING the window, not after it.
            if self.guest_started is False and time.monotonic() >= next_ctrl_probe:
                writable = self._ctrl_writable()
                # STAMPED AFTER the probe it throttles, never before. The probe writes to a
                # filesystem that may be sick and can block for seconds; a stamp taken before the
                # call it bounds is the exact defect this branch exists to fix, one layer down.
                next_ctrl_probe = time.monotonic() + _CTRL_PROBE_INTERVAL_S
                if not writable:
                    self._ctrl_io_fault = True

            if time.monotonic() >= deadline:
                # HOST-OBSERVABLE ATTRIBUTION. Flagging the worker's own exception is useless
                # here: serve_warm() catches it and tries to write `idle_timeout`, so nothing the
                # worker knows ever reaches us -- and if ctrl/ is full or read-only it cannot tell
                # us anything at all, by definition. But we share that filesystem, so we can ask
                # it ourselves. An unwritable ctrl/ means the silence is the STORAGE, not the
                # guest, and "never started" would convict a healthy base on every slot at once.
                if self.guest_started is False and (self._ctrl_io_fault
                                                    or not self._ctrl_writable()):
                    logger.warning("warm.ctrl_unwritable dir=%s latched=%s — not attributing the "
                                 "missing start marker to the worker",
                                 self._dir, self._ctrl_io_fault)
                    self.guest_started = None
                    err = WarmTimeout(
                        f"warm worker did not signal done within {timeout_s}s "
                        f"(control dir is unwritable)")
                    err.host_io = True  # type: ignore[attr-defined]
                    raise err
                raise WarmTimeout(
                    f"warm worker did not signal done within {timeout_s}s"
                )

            time.sleep(_HOST_POLL_INTERVAL_S)


# ---------------------------------------------------------------------------
# serve_warm
# ---------------------------------------------------------------------------


def serve_warm(
    engine: "Engine",
    *,
    control: WarmControl,
    limits: Limits,
    idle_timeout_s: float = 600.0,
) -> int:
    """Warm worker lifecycle: warmup() → READY → wait one job → run_detonation → DONE → exit.

    Exactly one job is processed — this function never loops back to fetch a
    second job.  The disposable-slot guarantee is enforced structurally: there
    is no loop and ``wait_for_go`` is called exactly once after the warmup
    succeeds.

    Flow
    ----
    1. Call ``engine.warmup()`` if the engine has it — **before** any input
       exists, so the warm state is captured in a pristine context.
       On failure → ``signal_done(status="warmup_error")`` + exit non-zero.
    2. ``control.signal_ready()`` — host can now dispatch a job to this slot.
    3. ``spec = control.wait_for_go(timeout_s=idle_timeout_s)`` — block for
       exactly one job.  On ``WarmTimeout`` → ``signal_done(status="idle_timeout")``
       + exit 0 (the slot self-retires).
    4. ``rc = run_detonation(engine, ...)`` — identical to the cold path; output
       is host-trust-validatable unchanged.
    5. ``control.signal_done(status="ok")`` + return ``rc``.

    Returns:
        0 on success or idle timeout; non-zero on warmup failure or harness
        internal error.
    """
    # ------------------------------------------------------------------
    # Step 1: warmup (pre-input — no untrusted data exists at this point)
    # ------------------------------------------------------------------
    if hasattr(engine, "warmup"):
        try:
            engine.warmup()
        except Exception as exc:  # noqa: BLE001
            logger.error("engine.warmup() failed: %s", exc)
            try:
                control.signal_done(status="warmup_error")
            except Exception as sig_exc:  # noqa: BLE001
                logger.error("signal_done(warmup_error) failed: %s", sig_exc)
            return 1

    # ------------------------------------------------------------------
    # Step 2: signal that this slot is ready to accept one job
    # ------------------------------------------------------------------
    control.signal_ready()

    # ------------------------------------------------------------------
    # Step 3: wait for exactly one job (no loop — one job per disposable slot)
    # ------------------------------------------------------------------
    try:
        spec = control.wait_for_go(timeout_s=idle_timeout_s)
    except WarmTimeout as to_exc:
        # Log the underlying cause too — distinguishes a genuine timeout ("timed out")
        # from an immediate accept() error (e.g. a vsock device issue post-restore).
        logger.info(
            "warm slot idle timeout after %.1fs; retiring (%s)", idle_timeout_s, to_exc
        )
        try:
            control.signal_done(status="idle_timeout")
        except Exception as sig_exc:  # noqa: BLE001
            logger.error("signal_done(idle_timeout) failed: %s", sig_exc)
        return 0

    # NOTE on snapshot RNG: a job arriving means this worker was just restored from
    # the warm snapshot, which clones the base VM's kernel CRNG state. We do NOT
    # reseed in userspace here — the worker is privilege-dropped (see
    # deploy/firecracker/init), so it can't credit entropy/force a reseed. The
    # reseed is the kernel's job via VMGenID, which the snapshot tier requires a
    # >= 5.18 guest kernel for (enforced in select_snapshot_runtime).

    # ------------------------------------------------------------------
    # Step 4: process the one job through the unchanged cold-path harness
    # ------------------------------------------------------------------
    # The warm process's environment is frozen at snapshot time, so per-job params
    # can't arrive as container `-e` env the way the cold path gets them. Apply the
    # dispatcher-allowlisted params (e.g. clippyshot's CLIPPYSHOT_* scanner toggles)
    # to os.environ here — before detonation — so engine.detonate honours them. The
    # dispatcher already restricts these to the engine's allowlist; the key-shape
    # check is belt-and-braces against a malformed go.json.
    for _k, _v in (spec.params or {}).items():
        if isinstance(_k, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", _k):
            os.environ[_k] = str(_v)

    rc: int = 1
    try:
        rc = run_detonation(
            engine,
            input_path=spec.input_path,
            output_dir=spec.output_dir,
            limits=limits,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("run_detonation raised unexpectedly: %s", exc)
        rc = 1

    # ------------------------------------------------------------------
    # Step 5: signal done — always reached for the one job
    # ------------------------------------------------------------------
    try:
        control.signal_done(status="ok")
    except Exception as sig_exc:  # noqa: BLE001
        logger.error("signal_done(ok) failed: %s", sig_exc)

    return rc
