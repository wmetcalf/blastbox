"""The snapshot seam is a structural contract.

``@runtime_checkable`` lets ``issubclass``/``isinstance`` verify method NAMES at runtime;
SIGNATURE conformance is enforced statically by mypy (``SnapshotManager`` calls the backend
positionally and is type-checked against these Protocols). This test guards the NAME contract
for the REAL backends + handles, so renaming/dropping a seam method can't silently break it —
unlike a hand-written fake, which would tautologically "conform" to whatever it copies."""

from blastbox.host.runtime.snapshot_backend import (
    BootHandle,
    RestoreHandle,
    SnapshotBackend,
)


def test_real_backends_satisfy_the_seam():
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotBackend
    from blastbox.host.runtime.gvisor_snapshot import (
        GvisorBootHandle,
        GvisorRestoreHandle,
        GvisorSnapshotBackend,
    )

    # Both runtimes' backends expose available()/boot_base()/restore_in()...
    assert issubclass(GvisorSnapshotBackend, SnapshotBackend)
    assert issubclass(FcSnapshotBackend, SnapshotBackend)
    # ...and the concrete handles expose the lifecycle methods the manager/runtime call.
    assert issubclass(GvisorBootHandle, BootHandle)
    assert issubclass(GvisorRestoreHandle, RestoreHandle)
