"""A base build must be stamped with the generation it STARTED under, not the one it finished in.

Both warm backends learn "does this image advertise the start signal?" from the base build's
readiness advertisement, and both used to sample the generation for that stamp at the END of a
slow launch -- gVisor when it constructed the boot handle (after `runsc run`), Firecracker when
it bound the READY listener (after _spawn and the whole API boot sequence).

An invalidate_base() landing inside that window advances the generation first. The retiring build
then stamps itself with the REPLACEMENT's generation: SnapshotManager still rejects its artifact
via _build_epoch, but the advertisement has already been believed, so a replacement image WITHOUT
the protocol inherits `capable`. Its absent start markers are then read as proof the guest never
ran, and a healthy base is invalidated over and over.

Sampling before the launch makes the residual error the SAFE one: a stale stamp is ignored by
learn(), capability stays UNKNOWN, and UNKNOWN convicts nothing.
"""

import pytest

from blastbox.worker.warm import AckCapability
from blastbox.host.runtime import gvisor_snapshot as gs
from blastbox.host.runtime.fc_snapshot_launcher import (
    FcSnapshotLauncher,
    _ready_factory_kwargs,
)


def test_the_gvisor_base_is_stamped_before_runsc_run(tmp_path, monkeypatch):
    cap = AckCapability()
    # The build epoch now comes from SnapshotManager, the one identity that moves atomically with
    # the artifact (issue #92). The backend only SAMPLES it -- it owns no counter of its own.
    epoch = [7]
    started_at = epoch[0]

    monkeypatch.setattr(gs, "_prepare_slot_dirs", lambda cfg, base: base.mkdir(parents=True))
    monkeypatch.setattr(gs, "_write_oci_config", lambda cfg, base, in_ro=True: None)
    monkeypatch.setattr(gs, "_runsc", lambda cfg: ["runsc"])

    def _run(argv, **kw):
        # THE WINDOW: the base is replaced while `runsc run` is still going, so the manager's
        # epoch moves under the build.
        epoch[0] += 1
        return 0

    be = object.__new__(gs.GvisorSnapshotBackend)
    be._cfg = type("C", (), {"root": tmp_path / "root" / "r"})()
    be._run = _run
    be._ready = lambda ctrl, tmo: None
    be._ack_capable = cap
    be._epoch_sampler = lambda: epoch[0]
    be._stranded_partials = []

    handle = be.boot_base()

    assert handle._ack_gen == started_at, (
        "the handle carries the generation current when the build FINISHED; a build that is "
        "already being discarded must not be able to teach its replacement")
    # And the consequence: its advertisement is ignored, so capability stays UNKNOWN.
    cap.observe(handle._ack_gen)
    cap.publish(epoch[0])          # the REPLACEMENT is what actually publishes
    assert not cap.capable_for(epoch[0]), "a retired build taught the replacement epoch"


def test_the_fc_base_is_stamped_before_the_microvm_spawns(tmp_path, monkeypatch):
    import blastbox.host.runtime.fc_snapshot_launcher as fsl

    cap = AckCapability()
    epoch = [7]
    started_at = epoch[0]
    seen: dict = {}

    monkeypatch.setattr(fsl, "api_boot_sequence", lambda cfg: [])

    lch = object.__new__(FcSnapshotLauncher)
    lch._cfg = object()
    lch._base_dir = tmp_path
    lch._stranded_partials = []
    lch._mem_dir = tmp_path
    lch._make_outdisk = lambda p: None
    lch._copy_outdisk = lambda a, b: None
    lch._ack_sampler = lambda: epoch[0]

    def _factory(path, ack_generation=None):
        seen["gen"] = ack_generation
        return lambda tmo: None

    lch._ready_check_factory = _factory

    def _spawn(workdir):
        workdir.mkdir(parents=True, exist_ok=True)
        # THE WINDOW: the base is replaced during the (slow) microVM launch + API boot.
        epoch[0] += 1
        return (type("P", (), {"pid": 1})(),
                type("A", (), {"put": lambda self, *a, **k: None})())

    lch._spawn = _spawn

    lch.boot_base()

    assert seen["gen"] == started_at, (
        "the READY listener was stamped with the generation current at BIND time, after the "
        "spawn -- so an invalidation during the launch is credited to the replacement")
    cap.observe(seen["gen"])
    cap.publish(epoch[0])          # the REPLACEMENT is what actually publishes
    assert not cap.capable_for(epoch[0]), "a retired base build taught the replacement epoch"


@pytest.mark.parametrize("factory, expected", [
    (lambda p: None, {}),                                  # legacy one-arg seam (CRaC, doubles)
    (lambda p, ack_generation=None: None, {"ack_generation": 7}),
    (lambda p, **kw: None, {"ack_generation": 7}),
    (lambda p, *, ack_generation=None: None, {"ack_generation": 7}),
])
def test_a_legacy_ready_factory_is_never_handed_the_new_kwarg(factory, expected):
    """ready_check_factory is a public seam; one-argument callables must keep working."""
    assert _ready_factory_kwargs(factory, ack_generation=7) == expected


def test_no_stamp_means_no_kwarg():
    assert _ready_factory_kwargs(lambda p, ack_generation=None: None,
                                 ack_generation=None) == {}


def test_the_snapshot_runtime_stamps_the_slot_with_the_pinned_epoch(tmp_path):
    """The RUNTIME half of the same invariant. Testing only the manager left this wiring free to
    go back to sampling build_epoch before restore() -- a mutation proved it -- which is the
    'fix inert in the runtime it was written for' miss this PR has hit repeatedly.

    build_epoch answers "what is current now"; an invalidation plus replacement build completing
    between that read and restore()'s selection pairs the slot with the wrong artifact, and
    capable_for() then answers False forever for it."""
    from blastbox.host.runtime.fc_snapshot_runtime import SnapshotSlotRuntime

    wd = tmp_path / "slots" / "s"
    wd.mkdir(parents=True)
    (wd / "vsock.sock").touch()

    class _Handle:
        vsock_uds = str(wd / "vsock.sock")

        def kill(self):
            pass

    class _Manager:
        """A rebuild landed between a build_epoch read and restore()'s selection."""
        build_epoch = 9                      # what is current NOW
        def acquire_built(self):
            pass
        def restore(self, slot_id):
            return _Handle()
        def pinned_epoch(self, slot_id):
            return 4                         # what this slot ACTUALLY restored from

    rt = object.__new__(SnapshotSlotRuntime)
    rt._manager = _Manager()
    rt._ack_capable = AckCapability()
    rt._settle_s = 0.0
    rt._clock = lambda: 0.0
    rt._restored_at = {}
    rt._handles = {}
    rt._lock = __import__("threading").Lock()

    slot = SnapshotSlotRuntime.spawn(rt)
    assert slot.ack_generation == 4, (
        f"the slot must carry the epoch restore() pinned, not the current one; got "
        f"{slot.ack_generation}")


def test_the_gvisor_runtime_also_stamps_the_slot_with_the_pinned_epoch(tmp_path):
    """The twin. Every round of this work that fixed one backend and left the other untested had
    the untested one come back as the next finding, so the gVisor half is pinned explicitly."""
    import threading

    from blastbox.host.runtime.gvisor_snapshot_runtime import GvisorSnapshotSlotRuntime

    wd = tmp_path / "slots" / "s"
    wd.mkdir(parents=True)

    class _Handle:
        slot_workdir = str(wd)

    class _Manager:
        build_epoch = 9                      # what is current NOW
        def acquire_built(self):
            pass
        def restore(self, slot_id):
            return _Handle()
        def pinned_epoch(self, slot_id):
            return 4                         # what this slot ACTUALLY restored from

    rt = object.__new__(GvisorSnapshotSlotRuntime)
    rt._mgr = _Manager()
    rt._ack_capable = AckCapability()
    rt._settle_s = 0.0
    rt._clock = lambda: 0.0
    rt._restored_at = {}
    rt._handles = {}
    rt._lock = threading.Lock()

    slot = GvisorSnapshotSlotRuntime.spawn(rt)
    assert slot.ack_generation == 4, (
        f"the slot must carry the epoch restore() pinned, not the current one; got "
        f"{slot.ack_generation}")
