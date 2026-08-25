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

import pytest

from blastbox.host.runtime.fc_snapshot import (
    SnapshotBuildError,
    SnapshotBuildInvalidated,
    SnapshotManager,
)
from blastbox.worker.warm import AckCapability


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
    mgr = _mgr(tmp_path, cap, _Boot(cap, cap.generation))
    mgr.build()
    assert cap, "a base that advertised AND published must be believed"


def test_a_build_whose_checkpoint_fails_confirms_nothing(tmp_path):
    cap = AckCapability()
    boot = _Boot(cap, cap.generation, checkpoint_fails=True)
    with pytest.raises(SnapshotBuildError):
        _mgr(tmp_path, cap, boot).build()
    assert not cap, (
        "the build advertised and then produced no artifact; nothing can ever be restored from "
        "it, so its capability must not outlive it")


def test_a_build_rejected_at_publication_confirms_nothing(tmp_path):
    """invalidate_base() landed mid-build: the artifact is discarded, so the advertisement is
    about a base that was never installed."""
    cap = AckCapability()
    mgr = None

    def _invalidate_midflight():
        mgr.invalidate()                 # bumps _build_epoch; this build is now doomed
        cap.reset()                      # ...as the runtimes do on invalidate_base

    boot = _Boot(cap, cap.generation, on_ready=_invalidate_midflight)
    mgr = _mgr(tmp_path, cap, boot)
    with pytest.raises(SnapshotBuildInvalidated):
        mgr.build()
    assert not cap, "a build whose artifact was rejected still taught its replacement"


def test_a_build_that_never_advertised_stays_unknown(tmp_path):
    """An older worker image simply never writes the advertisement; publication alone must not
    invent one."""
    cap = AckCapability()

    class _Silent(_Boot):
        def wait_ready(self, timeout_s):
            pass                          # no observe()

    _mgr(tmp_path, cap, _Silent(cap, cap.generation)).build()
    assert not cap, "publication must confirm an advertisement, never manufacture one"


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
        # ...and reset() has NOT run yet, so cap.generation is unchanged.

    boot = _Boot(cap, cap.generation, on_ready=_artifact_retired_but_generation_not_yet_moved)
    mgr = _mgr(tmp_path, cap, boot)
    with pytest.raises(SnapshotBuildInvalidated):
        mgr.build()

    assert not cap, (
        "the artifact was discarded, so no slot can ever be restored from this base -- its "
        "advertisement must not be credited to whatever replaces it")


def test_pending_observations_do_not_accumulate(tmp_path):
    """Every rebuild that advertises and fails leaves an observation behind. Without a purge that
    is one dict entry per generation for the life of the dispatcher -- small, but unbounded, and a
    warm tier rebuilds for days."""
    cap = AckCapability()
    for _ in range(50):
        cap.observe(cap.generation)
        cap.reset()
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
                return _Boot(cap, cap.generation, checkpoint_fails=True)
            return _Boot(cap, cap.generation, advertises=False)

    backend = _TwoAttempts()
    mgr = SnapshotManager(Path(tmp_path), backend, ack_capable=cap)

    with pytest.raises(SnapshotBuildError):
        mgr.build()                       # attempt 1: advertised, then failed
    assert not cap, "precondition: a failed build teaches nothing"

    mgr.build()                           # attempt 2: silent, and publishes
    assert not cap, (
        "the rolled-back base inherited a capability advertised by the attempt it replaced")


def test_a_retry_that_advertises_is_still_believed(tmp_path):
    """Control: scoping must not throw away the retry's OWN advertisement."""
    cap = AckCapability()

    class _TwoAttempts:
        def __init__(self):
            self.n = 0

        def boot_base(self):
            self.n += 1
            return _Boot(cap, cap.generation, checkpoint_fails=(self.n == 1))

    mgr = SnapshotManager(Path(tmp_path), _TwoAttempts(), ack_capable=cap)
    with pytest.raises(SnapshotBuildError):
        mgr.build()
    mgr.build()
    assert cap, "the retry advertised and published; that must be believed"


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
    mgr = SnapshotManager(Path(tmp_path), _Backend(_Boot(cap, cap.generation)), ack_capable=cap)

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
