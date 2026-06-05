from pathlib import Path
from blastbox.host.runtime.snapshot_backend import SnapshotBackend, BootHandle, RestoreHandle

def test_protocols_are_runtime_checkable():
    # A minimal fake satisfies the Protocols structurally.
    class FakeBoot:
        def wait_ready(self, timeout_s: float) -> None: ...
        def checkpoint(self, dest_dir: Path) -> object: return {"art": str(dest_dir)}
        def kill(self) -> None: ...
    class FakeRestore:
        def kill(self) -> None: ...
    class FakeBackend:
        def available(self) -> bool: return True
        def boot_base(self) -> BootHandle: return FakeBoot()
        def restore_in(self, slot_workdir: Path, artifact: object) -> RestoreHandle: return FakeRestore()
    b = FakeBackend()
    assert isinstance(b, SnapshotBackend)
    assert isinstance(b.boot_base(), BootHandle)
    assert isinstance(b.restore_in(Path("/x"), {"art": "y"}), RestoreHandle)
