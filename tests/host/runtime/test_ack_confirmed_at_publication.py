"""A base's ACK advertisement is believable only once its artifact is PUBLISHED.

Both backends learn "does this image advertise the start signal?" from the base build's readiness
marker. Readiness happens long before anyone knows whether the build yields a usable artifact:
checkpoint() can fail, and even a good checkpoint is DISCARDED when an invalidate_base() landed
while the build ran (SnapshotManager rejects it via _build_epoch).

Believing it at readiness left the capability permanently true for a base no slot could ever be
restored from. Roll the worker bundle back before the automatic retry and the older, ACK-incapable
image inherits that `capable`: its missing start markers are then read as PROVEN non-starts, so a
document-induced hang invalidates a perfectly healthy base instead of staying UNKNOWN.
"""

from pathlib import Path

import types

import pytest

from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotBuildInvalidated,
    SnapshotManager,
)
from blastbox.worker.warm import AckCapability

EPOCH0 = 0   # SnapshotManager starts at build epoch 0


class _Boot:
    """A base build that advertises ACK at readiness, as a real one does."""

    def __init__(self, cap, gen, *, checkpoint_fails=False, on_ready=None, advertises=True):
        self.ack_generation = gen
        self._cap = cap
        self._fails = checkpoint_fails
        self._on_ready = on_ready
        self._advertises = advertises
        self.killed = False

    def wait_ready(self, timeout_s):
        if self._advertises:
            self._cap.observe(self.ack_generation)  # the guest advertises
        if self._on_ready is not None:
            self._on_ready()

    def checkpoint(self, dest_dir):
        if self._fails:
            raise SnapshotBuildError("runsc checkpoint failed")
        return object()

    def kill(self):
        self.killed = True


class _Backend:
    def __init__(self, boot):
        self._boot = boot

    def boot_base(self):
        return self._boot


def _mgr(tmp_path, cap, boot):
    return SnapshotManager(Path(tmp_path), _Backend(boot), ack_capable=cap)


def test_a_published_build_confirms_its_advertisement(tmp_path):
    """Positive control -- without this the others pass on a capability that is never set."""
    cap = AckCapability()
    mgr = _mgr(tmp_path, cap, _Boot(cap, EPOCH0))
    mgr.build()
    assert cap.capable_for(EPOCH0), "a base that advertised AND published must be believed"


def test_a_build_whose_checkpoint_fails_confirms_nothing(tmp_path):
    cap = AckCapability()
    boot = _Boot(cap, EPOCH0, checkpoint_fails=True)
    with pytest.raises(SnapshotBuildError):
        _mgr(tmp_path, cap, boot).build()
    assert not cap.capable_for(EPOCH0), (
        "the build advertised and then produced no artifact; nothing can ever be restored from "
        "it, so its capability must not outlive it")


def test_a_build_rejected_at_publication_confirms_nothing(tmp_path):
    """invalidate_base() landed mid-build: the artifact is discarded, so the advertisement is
    about a base that was never installed."""
    cap = AckCapability()
    mgr = None

    def _invalidate_midflight():
        mgr.invalidate()                 # bumps _build_epoch; this build is now doomed.
        # No cap.reset() any more, and that is the point: there is one identity, and
        # invalidate() already moved it (issue #92).

    boot = _Boot(cap, EPOCH0, on_ready=_invalidate_midflight)
    mgr = _mgr(tmp_path, cap, boot)
    with pytest.raises(SnapshotBuildInvalidated):
        mgr.build()
    assert not cap.capable_for(EPOCH0), "a build whose artifact was rejected still taught its replacement"


def test_a_build_that_never_advertised_stays_unknown(tmp_path):
    """An older worker image simply never writes the advertisement; publication alone must not
    invent one."""
    cap = AckCapability()

    class _Silent(_Boot):
        def wait_ready(self, timeout_s):
            pass                          # no observe()

    _mgr(tmp_path, cap, _Silent(cap, EPOCH0)).build()
    assert not cap.capable_for(EPOCH0), "publication must confirm an advertisement, never manufacture one"


def test_a_rejection_alone_blocks_the_confirmation(tmp_path):
    """The generation gate is NOT enough on its own, because the two do not move together.

    invalidate_base() retires the artifact first (drop(), which bumps _build_epoch) and advances
    the ACK generation second (reset()) -- deliberately, so that the residual error is a MISSED
    advertisement rather than a wrongly-credited one. A build publishing between those two steps
    is therefore rejected while its stamp is still current, and the generation gate waves it
    through. Publication is the check that catches it."""
    cap = AckCapability()
    mgr = None

    def _artifact_retired_but_generation_not_yet_moved():
        mgr.invalidate()          # drop(): _build_epoch moves, this build is doomed
        # ...and reset() has NOT run yet, so EPOCH0 is unchanged.

    boot = _Boot(cap, EPOCH0, on_ready=_artifact_retired_but_generation_not_yet_moved)
    mgr = _mgr(tmp_path, cap, boot)
    with pytest.raises(SnapshotBuildInvalidated):
        mgr.build()

    assert not cap.capable_for(EPOCH0), (
        "the artifact was discarded, so no slot can ever be restored from this base -- its "
        "advertisement must not be credited to whatever replaces it")


def test_pending_observations_do_not_accumulate(tmp_path):
    """Every rebuild that advertises and fails leaves an observation behind. Without a purge that
    is one dict entry per generation for the life of the dispatcher -- small, but unbounded, and a
    warm tier rebuilds for days."""
    cap = AckCapability()
    for e in range(50):
        cap.observe(e)
        cap.publish(e)          # each rebuild installs a new artifact
    assert len(cap._pending) <= 1, (
        f"pending observations accumulated across rebuilds: {len(cap._pending)}")


def test_a_failed_attempt_does_not_teach_the_retry(tmp_path):
    """Pending observations are keyed by GENERATION, and consecutive build ATTEMPTS share one:
    ensure_build_started() retries a failed build with no invalidation in between, so nothing
    advances the generation.

    Attempt 1 advertises and then fails to checkpoint. Attempt 2 is a ROLLED-BACK, ACK-incapable
    worker and publishes fine. Without scoping, attempt 2's confirm() consumes attempt 1's
    observation and the new base is marked capable on the strength of an image it never ran --
    after which its missing start markers are read as proven non-starts and a healthy
    mixed-version base is invalidated. That is the failure the deferred-confirmation fix was
    supposed to prevent, one layer in."""
    cap = AckCapability()

    class _TwoAttempts:
        """One backend, two boot handles: the first advertises and dies, the second is silent."""

        def __init__(self):
            self.n = 0

        def boot_base(self):
            self.n += 1
            if self.n == 1:
                return _Boot(cap, EPOCH0, checkpoint_fails=True)
            return _Boot(cap, EPOCH0, advertises=False)

    backend = _TwoAttempts()
    mgr = SnapshotManager(Path(tmp_path), backend, ack_capable=cap)

    with pytest.raises(SnapshotBuildError):
        mgr.build()                       # attempt 1: advertised, then failed
    assert not cap.capable_for(EPOCH0), "precondition: a failed build teaches nothing"

    mgr.build()                           # attempt 2: silent, and publishes
    assert not cap.capable_for(EPOCH0), (
        "the rolled-back base inherited a capability advertised by the attempt it replaced")


def test_a_retry_that_advertises_is_still_believed(tmp_path):
    """Control: scoping must not throw away the retry's OWN advertisement."""
    cap = AckCapability()

    class _TwoAttempts:
        def __init__(self):
            self.n = 0

        def boot_base(self):
            self.n += 1
            return _Boot(cap, EPOCH0, checkpoint_fails=(self.n == 1))

    mgr = SnapshotManager(Path(tmp_path), _TwoAttempts(), ack_capable=cap)
    with pytest.raises(SnapshotBuildError):
        mgr.build()
    mgr.build()
    assert cap.capable_for(EPOCH0), "the retry advertised and published; that must be believed"


def test_an_injected_manager_shares_its_capability_with_the_runtime(tmp_path):
    """The base-readiness listener lives with the backend/manager; the per-slot controls live
    with the runtime. They are one answer only if both hold the SAME object.

    A runtime built around an INJECTED manager cannot construct that listener itself, and used to
    manufacture its own AckCapability instead. The published base then advertised ACK while every
    restored slot read `capable` as false -- so missing starts stay UNKNOWN and the three-slot
    fast repair is silently disabled, on precisely the custom wiring an operator chose on
    purpose."""
    from blastbox.host.runtime.fc_snapshot_runtime import select_snapshot_runtime
    from blastbox.host.runtime.gvisor_snapshot_runtime import select_gvisor_snapshot_runtime

    cap = AckCapability()
    mgr = SnapshotManager(Path(tmp_path), _Backend(_Boot(cap, EPOCH0)), ack_capable=cap)

    fc = select_snapshot_runtime(cfg=object(), manager=mgr)
    assert fc._ack_capable is cap, "the FC runtime manufactured its own capability"

    gv = select_gvisor_snapshot_runtime(manager=mgr)
    assert gv._ack_capable is cap, "the gVisor runtime manufactured its own capability"


def test_a_manager_double_without_the_seam_still_works(tmp_path):
    """Injected test doubles are not real managers; they must not break the selector."""
    from blastbox.host.runtime.gvisor_snapshot_runtime import select_gvisor_snapshot_runtime

    class _Double:
        def build(self): return None

    gv = select_gvisor_snapshot_runtime(manager=_Double())
    assert gv._ack_capable is not None, "the runtime must fall back to its own capability"


def test_an_unstamped_ack_teaches_nothing_in_snapshot_mode():
    """capable_for(None) is UNKNOWN, so learn(None) must be too.

    Accepting it let a late ack from a retired -- or simply unidentifiable -- slot resurrect
    capability for a SILENT replacement, after which that replacement's missing markers read as
    proven non-starts and convict a healthy base. A caller that cannot say which artifact its slot
    came from has not supplied evidence about any artifact."""
    cap = AckCapability()
    cap.publish(1)                       # a silent artifact is installed
    assert cap.capable_for(1) is False

    cap.learn(None)                      # an unidentifiable slot acks
    assert cap.capable_for(1) is False, (
        "an unstamped ack resurrected capability for a base that never advertised")

    cap.learn(1)                         # ...a properly stamped one still teaches
    assert cap.capable_for(1) is True


def test_an_unstamped_ack_still_teaches_the_plain_runtime():
    """With no artifact lifecycle there is one image and nothing to tell apart, so an unstamped
    ack is the only kind there is."""
    cap = AckCapability()                # never published: the plain FC runtime
    cap.learn(None)
    assert bool(cap) is True
    assert cap.capable_for(None) is True


def test_the_slot_is_stamped_with_the_artifact_restore_actually_pinned(tmp_path):
    """build_epoch answers "what is current now". Between that read and restore()'s selection an
    invalidation plus a replacement build can complete, pairing the slot with the wrong identity:
    capable_for() then answers False forever and the fast repair is silently off for that slot
    during exactly the rebuild churn it exists for."""
    cap = AckCapability()
    mgr = _mgr(tmp_path, cap, _Boot(cap, EPOCH0))
    mgr.build()

    class _Handle:
        slot_workdir = str(tmp_path)

    mgr._backend.restore_in = lambda wd, art: _Handle()
    mgr.restore("slot-a")
    assert mgr.pinned_epoch("slot-a") == 0, "the epoch must be the one restore() pinned"
    assert mgr.pinned_epoch("never-restored") is None


def test_the_capability_is_installed_with_the_artifact_not_after_it(tmp_path):
    """prepare()/acquire_built() can expose and restore the new artifact the instant _artifact is
    assigned. Publishing after the lock was released left a window where a job dispatched against
    the NEW base evaluated capable_for() against the PREVIOUS epoch and read UNKNOWN."""
    cap = AckCapability()
    seen = []

    mgr = _mgr(tmp_path, cap, _Boot(cap, EPOCH0))
    real = type(mgr)._install_ack

    def _spy(self, epoch):
        # At this instant the artifact is already assigned; the capability must be too by the
        # time the lock is released.
        seen.append((self._artifact is not None, self._build_lock.locked()))
        return real(self, epoch)

    # Patch the INSTANCE, not the class: pytest-randomly is installed and reorders execution,
    # so a global patch on SnapshotManager is cross-test shared state waiting to bite.
    mgr._install_ack = types.MethodType(_spy, mgr)
    mgr.build()

    assert seen == [(True, True)], (
        f"the capability must be installed under the SAME lock that assigns the artifact, got {seen}")


def test_a_hand_assembled_stack_gets_its_epoch_source_wired(tmp_path):
    """An embedder builds backend + manager directly and hands both the same capability. There is
    no reason for them to know about an internal epoch sampler, and without it every advertisement
    is recorded under None while publication uses an integer -- so the capability can never become
    true and the fast repair is silently off. Wiring that only holds when the caller remembers is
    not wiring."""
    cap = AckCapability()

    class _BackendNeedingASampler(_Backend):
        def __init__(self, boot):
            super().__init__(boot)
            self._epoch_sampler = None

    be = _BackendNeedingASampler(_Boot(cap, EPOCH0))
    assert be._epoch_sampler is None
    mgr = SnapshotManager(Path(tmp_path), be, ack_capable=cap)

    assert be._epoch_sampler is not None, "the manager must bind its own epoch source"
    assert be._epoch_sampler() == mgr.build_epoch


def test_the_pinned_epoch_is_dropped_when_the_slot_is_reaped(tmp_path):
    """Only a FAILED restore went through _unpin(), so on the normal reap path the epoch entry
    was never dropped -- one dict entry per slot ever restored, for the life of a dispatcher that
    recycles slots continuously."""
    cap = AckCapability()
    mgr = _mgr(tmp_path, cap, _Boot(cap, EPOCH0))
    mgr.build()

    class _Handle:
        slot_workdir = str(tmp_path)

    mgr._backend.restore_in = lambda wd, art: _Handle()
    for i in range(25):
        mgr.restore(f"slot-{i}")
    assert len(mgr._pin_epoch) == 25

    for i in range(25):
        mgr.release(f"slot-{i}")
    assert mgr._pin_epoch == {}, (
        f"reaped slots left {len(mgr._pin_epoch)} epoch entries behind")


def test_a_raising_pinned_epoch_does_not_strand_the_microvm(tmp_path):
    """restore() has already returned a live microVM and reserved its generation pin, but no Slot
    exists yet -- so anything that raises between those points strands both until the process
    restarts. An injected manager's pinned_epoch() takes a lock and can raise."""
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    killed = []
    wd = tmp_path / "slots" / "s"
    wd.mkdir(parents=True)
    (wd / "vsock.sock").touch()

    class _Handle:
        vsock_uds = str(wd / "vsock.sock")

        def kill(self):
            killed.append(True)

    class _Manager:
        build_epoch = 3
        released: list = []

        def acquire_built(self):
            pass

        def restore(self, slot_id):
            return _Handle()

        def pinned_epoch(self, slot_id):
            raise RuntimeError("manager lock timed out")

        def release(self, slot_id):
            self.released.append(slot_id)

    rt = object.__new__(SnapshotSlotRuntime)
    rt._manager = _Manager()
    rt._ack_capable = AckCapability()
    rt._settle_s = 0.0
    rt._clock = lambda: 0.0
    rt._restored_at = {}
    rt._handles = {}
    rt._lock = __import__("threading").Lock()

    with pytest.raises(RuntimeError):
        SnapshotSlotRuntime.spawn(rt)

    assert killed, "the live microVM was left running with no Slot to reap it"
    assert _Manager.released, "the generation pin was stranded"


def test_a_snapshot_runtimes_fallback_capability_is_never_plain_mode():
    """A snapshot runtime handed a manager with no capability of its own used to build a fallback
    that the manager NEVER publishes into. Its _epoch stayed None -- indistinguishable from the
    plain, no-artifact runtime -- so any ack taught it unconditionally, capable_for() answered
    True for EVERY epoch, and with reset() deleted nothing ever cleared it. A replacement built
    from an older worker without start markers is then convicted for markers it never promised."""
    # TWO INDEPENDENT GUARDS, asserted independently. Checking only the end result let each one
    # mask the other's absence: learn() refusing to teach hides capable_for()'s fallback, and
    # capable_for() refusing to answer hides that learn() taught. Mutating either alone then
    # changed nothing observable, which is a test proving neither.

    # GUARD 1 -- learn() must not set the flag at all.
    scoped = AckCapability(artifact_scoped=True)
    scoped.learn(None)                       # an ack from some restored slot
    assert bool(scoped) is False, (
        "an unstamped ack taught an artifact-scoped capability that has published nothing")

    # GUARD 2 -- even WITH the flag set, capable_for() must answer UNKNOWN while nothing is
    # published. Forced directly, so this assertion does not depend on guard 1.
    forced = AckCapability(artifact_scoped=True)
    object.__setattr__(forced, "_capable", True)
    assert forced.capable_for(7) is False, (
        "an artifact-scoped capability answered from the bare flag with no artifact published")
    assert forced.capable_for(None) is False

    plain = AckCapability()                  # the plain FC runtime: no artifact lifecycle
    plain.learn(None)
    assert plain.capable_for(None) is True, "the no-artifact runtime must still learn"


def test_a_scoped_capability_still_works_once_an_artifact_publishes():
    """Control: scoping must not deafen it permanently."""
    cap = AckCapability(artifact_scoped=True)
    cap.observe(2)
    cap.publish(2)
    assert cap.capable_for(2) is True
    assert cap.capable_for(1) is False


def test_both_snapshot_runtimes_build_scoped_fallbacks():
    """The wiring half: the runtimes must ASK for a scoped fallback, or the guard above is inert
    in the place it exists for."""
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    fc = object.__new__(SnapshotSlotRuntime)
    SnapshotSlotRuntime.__init__(fc, object(), object(), ack_capable=None)
    gv = object.__new__(GvisorSnapshotSlotRuntime)
    GvisorSnapshotSlotRuntime.__init__(gv, object(), ack_capable=None)

    for name, rt in (("fc", fc), ("gvisor", gv)):
        rt._ack_capable.learn(None)
        assert rt._ack_capable.capable_for(3) is False, (
            f"{name}: the fallback fell into plain mode and is capable for any epoch")


def test_a_gvisor_epoch_lookup_failure_does_not_leak_the_sandbox():
    """Registering the handle in _handles does NOT make it reapable: every lookup there is keyed
    by a Slot the pool already holds, and nothing enumerates the dict for orphans. With no Slot
    returned, a live sandbox and its generation pin are unreachable for the life of the process."""
    import threading

    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    killed, released = [], []

    class _Handle:
        slot_workdir = "/tmp/does-not-matter"

        def kill(self):
            killed.append(True)

    class _Manager:
        def acquire_built(self):
            pass

        def restore(self, slot_id):
            return _Handle()

        def pinned_epoch(self, slot_id):
            raise RuntimeError("manager lock timed out")

        def release(self, slot_id):
            released.append(slot_id)

    rt = object.__new__(GvisorSnapshotSlotRuntime)
    rt._mgr = _Manager()
    rt._ack_capable = AckCapability(artifact_scoped=True)
    rt._settle_s = 0.0
    rt._clock = lambda: 0.0
    rt._restored_at = {}
    rt._handles = {}
    rt._lock = threading.Lock()

    with pytest.raises(RuntimeError):
        GvisorSnapshotSlotRuntime.spawn(rt)

    assert killed, "the live sandbox was left running with no Slot to reap it"
    assert released, "the generation pin was stranded"


def test_a_repair_does_not_inherit_a_failed_builds_backoff(tmp_path):
    """invalidate() clears _retry_not_before because a deliberate repair is not a retry of a build
    that just failed. But it does so under a SEPARATE lock hold, and the async build spends its
    whole boot+wait_ready window outside the lock -- so a repair landing after a build failed but
    before its except handler ran was overwritten. The replacement build was then refused for
    build_retry_backoff_s, prepare() kept returning False, and every job fell to the cold tier for
    30s immediately after the repair meant to restore warm capacity."""
    import threading
    import time as _t

    booted = threading.Event()

    class _NeverReady:
        def wait_ready(self, t):
            raise RuntimeError("never ready")

        def kill(self):
            pass

    class _Backend:
        _epoch_sampler = _launcher = None

        def boot_base(self):
            booted.set()
            _t.sleep(0.05)
            return _NeverReady()

    mgr = SnapshotManager(Path(tmp_path), _Backend(), build_retry_backoff_s=30.0)
    mgr.ensure_build_started()
    assert booted.wait(5)
    _t.sleep(0.02)
    mgr.invalidate()                      # the deliberate repair, landing mid-failure
    _t.sleep(0.4)

    assert _t.monotonic() >= mgr._retry_not_before, (
        "the repair inherited the failed build's cold window")
    assert mgr._build_error is None, "the superseded build's error was resurrected"


def test_a_genuinely_failed_build_still_backs_off(tmp_path):
    """Control: the superseded-check must not disarm the backoff for a build nothing superseded."""
    import time as _t

    class _NeverReady:
        def wait_ready(self, t):
            raise RuntimeError("never ready")

        def kill(self):
            pass

    class _Backend:
        _epoch_sampler = _launcher = None

        def boot_base(self):
            return _NeverReady()

    mgr = SnapshotManager(Path(tmp_path), _Backend(), build_retry_backoff_s=30.0)
    mgr.ensure_build_started()
    for _ in range(200):
        if mgr._build_error is not None:
            break
        _t.sleep(0.01)
    assert mgr._build_error is not None, "a real failure must still be recorded"
    assert _t.monotonic() < mgr._retry_not_before, "a real failure must still back off"


def test_the_production_capabilities_are_artifact_scoped():
    """Scoping only the runtime FALLBACK protected the misconfigured wiring and left the
    configured one open: the capabilities select_*() hands to SnapshotManager -- the ones publish()
    actually moves -- were unscoped, so before the first publish one learn() made capable_for()
    answer True for EVERY epoch."""
    import inspect

    from blastbox.host.runtime import fc_snapshot_runtime as fcm
    from blastbox.host.runtime import gvisor_snapshot_runtime as gvm

    for mod in (fcm, gvm):
        src = inspect.getsource(mod)
        bare = [ln.strip() for ln in src.splitlines()
                if "AckCapability()" in ln and "ack_capable is not None" not in ln]
        assert not bare, (
            f"{mod.__name__} builds an UNSCOPED snapshot capability: {bare}")


def test_the_bound_epoch_sampler_does_not_re_enter_the_build_lock():
    """The sampler the manager binds into the backend closes over `self`. Bound as
    `lambda: self.build_epoch` it re-enters _build_lock -- a PLAIN Lock -- so any caller that
    samples while holding it self-deadlocks the build thread. Nothing does today; this pins it so
    nothing starts."""
    import threading
    from pathlib import Path as _P

    from blastbox.host.runtime.fc_snapshot import SnapshotManager
    from blastbox.worker.warm import AckCapability

    class _Backend:
        _epoch_sampler = None
        _ack_sampler = None

    be = _Backend()
    mgr = SnapshotManager(_P("/tmp"), be, ack_capable=AckCapability(artifact_scoped=True))
    assert be._epoch_sampler is not None, "precondition: the manager bound its epoch source"

    # Sample WHILE holding _build_lock. A re-locking sampler hangs here forever.
    done = threading.Event()
    result = {}

    def _sample_under_the_lock():
        with mgr._build_lock:
            result["epoch"] = be._epoch_sampler()
        done.set()

    threading.Thread(target=_sample_under_the_lock, daemon=True).start()
    assert done.wait(2.0), "the bound sampler re-entered _build_lock and deadlocked"
    assert result["epoch"] == 0


def test_the_manager_binds_the_epoch_source_through_to_the_launcher(tmp_path):
    """The FC backend delegates the base build to a LAUNCHER, and it is the launcher that samples
    the epoch. Binding only the backend leaves the sampler that actually runs unset -- so the base
    advertises observe(None) while the manager publishes an integer, capable_for() is False
    forever, and the three-slot fast repair is silently dead on the real tier."""
    cap = AckCapability(artifact_scoped=True)

    class _Launcher:
        _ack_sampler = None
        _epoch_sampler = None

    class _BackendWithLauncher(_Backend):
        def __init__(self, boot):
            super().__init__(boot)
            self._launcher = _Launcher()
            self._epoch_sampler = None
            self._ack_sampler = None

    be = _BackendWithLauncher(_Boot(cap, EPOCH0))
    mgr = SnapshotManager(Path(tmp_path), be, ack_capable=cap)

    assert be._launcher._ack_sampler is not None, "the LAUNCHER's sampler was never bound"
    assert be._launcher._ack_sampler() == mgr.build_epoch
    assert be._epoch_sampler is not None and be._epoch_sampler() == mgr.build_epoch


def test_both_snapshot_runtimes_forward_the_slot_epoch_to_the_control():
    """The last hop. spawn() stamps the slot and AckCapability.capable_for() is pinned
    exhaustively, but nothing asserted that host_warm_control FORWARDS the stamp into the control
    that evaluates it. Replacing both forwarding sites with ack_generation=None left the entire
    suite green -- and a control whose _ack_gen is None answers capable_for(None) == False against
    an artifact-scoped capability, so guest_started never becomes False and the fast repair is
    inert on both warm tiers."""
    from types import SimpleNamespace

    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime
    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    slot = SimpleNamespace(slot_id="s1", ack_generation=4,
                           control_dir=Path("/tmp/x/ctrl"), output_dir=Path("/tmp/x/out"))

    fc = object.__new__(SnapshotSlotRuntime)
    fc._ack_capable = AckCapability(artifact_scoped=True)
    assert SnapshotSlotRuntime.host_warm_control(fc, slot)._ack_gen == 4, (
        "the FC runtime dropped the slot's artifact epoch on the way to the control")

    gv = object.__new__(GvisorSnapshotSlotRuntime)
    gv._ack_capable = AckCapability(artifact_scoped=True)
    ctl = GvisorSnapshotSlotRuntime.host_warm_control(gv, slot)
    inner = getattr(ctl, "_inner", ctl)
    assert inner._ack_gen == 4, (
        "the gVisor runtime dropped the slot's artifact epoch on the way to the control")


def test_a_failed_restore_drops_its_pinned_epoch(tmp_path):
    """The _unpin() path -- a restore that never produced a handle. Deleting its _pin_epoch.pop
    was silent across the whole suite: the reap-path test only ever reaps slots that DID restore,
    so the failed-restore leak (one dict entry per failed restore, forever) had no coverage."""
    from blastbox.host.runtime.fc_snapshot import SnapshotRestoreError

    cap = AckCapability(artifact_scoped=True)
    mgr = _mgr(tmp_path, cap, _Boot(cap, EPOCH0))
    mgr.build()

    def _boom(wd, art):
        raise SnapshotRestoreError("restore failed")

    mgr._backend.restore_in = _boom
    for i in range(15):
        with pytest.raises(SnapshotRestoreError):
            mgr.restore(f"doomed-{i}")

    assert mgr._pin_epoch == {}, (
        f"failed restores left {len(mgr._pin_epoch)} epoch entries behind")
    assert mgr._pins == {}, "…and their pins too"


def test_a_manager_without_pinned_epoch_is_loud(tmp_path, caplog):
    """getattr(manager, "pinned_epoch", lambda _s: None) degrades silently, and in snapshot mode
    that is fatal to the feature rather than fail-safe: every slot carries ack_generation=None,
    capable_for(None) is False for the life of the process, and the fast repair never runs. The
    sampler seam got a defensive auto-bind on this exact reasoning; this side is called
    unconditionally, so it must at least say so."""
    import logging
    import threading

    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    wd = tmp_path / "slots" / "s"
    wd.mkdir(parents=True)
    (wd / "vsock.sock").touch()

    class _Handle:
        vsock_uds = str(wd / "vsock.sock")

        def kill(self):
            pass

    class _OldManager:                       # no pinned_epoch at all
        def acquire_built(self):
            pass

        def restore(self, slot_id):
            return _Handle()

    rt = object.__new__(SnapshotSlotRuntime)
    rt._manager = _OldManager()
    rt._ack_capable = AckCapability(artifact_scoped=True)
    rt._settle_s = 0.0
    rt._clock = lambda: 0.0
    rt._restored_at = {}
    rt._handles = {}
    rt._lock = threading.Lock()

    with caplog.at_level(logging.WARNING):
        slot = SnapshotSlotRuntime.spawn(rt)

    assert slot.ack_generation is None
    assert any("manager_without_pinned_epoch" in r.message for r in caplog.records), (
        "the runtime disabled the fast repair without saying so")


def test_a_failed_replacement_build_still_arms_the_backoff(tmp_path):
    """_build_worker used to take its OWN read of the epoch before calling build(), while build()
    samples _build_epoch itself. An invalidate() landing between those two reads made a genuinely
    failed REPLACEMENT build look superseded: no _build_error recorded, no backoff armed, and the
    next pool tick immediately relaunched another full base boot -- a hot retry loop of the most
    expensive operation the tier has.

    The epoch a failure is judged against must be the one the attempt ACTUALLY ran under."""
    import time as _t

    class _Boom:
        def wait_ready(self, t):
            raise RuntimeError("the replacement build genuinely failed")

        def kill(self):
            pass

    class _Backend2:
        _epoch_sampler = _launcher = None

        def boot_base(self):
            return _Boom()

    mgr = SnapshotManager(Path(tmp_path), _Backend2(), build_retry_backoff_s=30.0)

    # A repair lands in the window: after the worker begins, before build() samples the epoch.
    real_build = mgr.build

    def _invalidate_then_build():
        mgr.invalidate()
        return real_build()

    mgr.build = _invalidate_then_build
    mgr._build_worker()

    assert mgr._build_error is not None, (
        "the replacement build failed on its own merits and was written off as superseded")
    assert _t.monotonic() < mgr._retry_not_before, (
        "no backoff armed -- the next tick relaunches a full base boot immediately")


def test_a_build_superseded_mid_flight_still_skips_the_backoff(tmp_path):
    """Control: a build invalidated WHILE running must still retry at once, not back off."""
    import time as _t

    class _InvalidatesDuringBoot:
        def __init__(self, mgr_box):
            self._box = mgr_box
            self._epoch_sampler = self._launcher = None

        def boot_base(self):
            self._box[0].invalidate()          # the repair lands mid-build
            raise RuntimeError("boot failed after the repair landed")

    box: list = []
    mgr = SnapshotManager(Path(tmp_path), _InvalidatesDuringBoot(box),
                          build_retry_backoff_s=30.0)
    box.append(mgr)
    mgr._build_worker()

    assert mgr._build_error is None, "a superseded build must not record its error"
    assert _t.monotonic() >= mgr._retry_not_before, (
        "a superseded build must not delay the replacement")


def test_a_failure_before_the_epoch_is_sampled_is_judged_genuine(tmp_path):
    """_retry_undead_bases(), _base_dir.mkdir() and _sweep_retired() all run BEFORE build() samples
    the epoch. Publishing the sample to instance state meant such a failure left the PREVIOUS
    attempt's epoch behind -- STALE, not None -- so the None-guard never fired, an invalidation
    between attempts made it compare unequal, and a persistent ENOSPC was reclassified as
    'superseded' and retried on every single tick.

    The epoch now travels ON the failure, so a failure raised before the sample carries nothing and
    absence reads as genuine."""
    import time as _t

    class _Boom:
        def wait_ready(self, t):
            raise RuntimeError("attempt 1 fails")

        def kill(self):
            pass

    class _Backend3:
        _epoch_sampler = _launcher = None

        def boot_base(self):
            return _Boom()

    mgr = SnapshotManager(Path(tmp_path), _Backend3(), build_retry_backoff_s=30.0)
    mgr._build_worker()                       # attempt 1 samples epoch 0 and fails
    mgr.invalidate()                          # a repair lands BETWEEN attempts -> epoch 1
    mgr._retry_not_before = 0.0
    mgr._build_error = None

    def _enospc(*a, **k):
        raise OSError("ENOSPC")

    mgr._base_dir = type("P", (), {"mkdir": _enospc,
                                   "__truediv__": lambda s, o: s})()
    mgr._build_worker()                       # attempt 2 dies BEFORE the sample

    assert mgr._build_error is not None, (
        "a pre-sample failure was written off as superseded using the previous attempt's epoch")
    assert _t.monotonic() < mgr._retry_not_before, (
        "no backoff armed -- a persistent filesystem fault is retried on every tick")


def test_a_failure_after_the_sample_still_carries_its_epoch(tmp_path):
    """Control: the attribute must actually be attached, or the test above passes for free."""
    class _Boom:
        def wait_ready(self, t):
            raise RuntimeError("boom")

        def kill(self):
            pass

    class _Backend4:
        _epoch_sampler = _launcher = None

        def boot_base(self):
            return _Boom()

    mgr = SnapshotManager(Path(tmp_path), _Backend4(), build_retry_backoff_s=30.0)
    try:
        mgr.build()
    except Exception as exc:
        assert getattr(exc, "attempt_epoch", None) == 0, (
            "the failure did not carry the epoch its attempt ran under")
    else:
        raise AssertionError("expected the build to fail")
