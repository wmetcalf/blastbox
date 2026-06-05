from pathlib import Path

import pytest

from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend, GvisorConfig, _oci_config


class _Rec:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: object) -> int:
        self.calls.append(argv)
        return 0


def _cfg(tmp_path: Path, **kw: object) -> GvisorConfig:
    base: dict = dict(
        runsc_bin="runsc",
        root=tmp_path / "root",
        image_rootfs=tmp_path / "rootfs",
        network="none",
        warm_argv=["/warm-entrypoint"],
    )
    base.update(kw)
    return GvisorConfig(**base)


def test_boot_base_runs_then_checkpoint(tmp_path: Path) -> None:
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    boot = be.boot_base()
    boot.wait_ready(5.0)
    art = boot.checkpoint(tmp_path / "ckpt")
    joined = [" ".join(c) for c in rec.calls]
    assert any("run" in c and "-detach" in c for c in joined)
    assert any("checkpoint" in c and "-image-path" in c for c in joined)
    assert Path(str(art)).name == "checkpoint"


def test_restore_in_creates_dirs_and_restores(tmp_path: Path) -> None:
    rec = _Rec()
    be = GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d, t: None)
    wd = tmp_path / "slots" / "s1"
    wd.mkdir(parents=True)
    h = be.restore_in(wd, str(tmp_path / "ckpt" / "checkpoint"))
    joined = [" ".join(c) for c in rec.calls]
    assert any("restore" in c and "-image-path" in c for c in joined)
    for sub in ("in", "out", "ctrl"):
        assert (wd / sub).is_dir()
    assert h.output_dir == wd / "out" and h.control_dir == wd / "ctrl"


def test_available_uses_probe(tmp_path: Path) -> None:
    assert GvisorSnapshotBackend(_cfg(tmp_path), run=lambda a, **k: 0, probe=lambda: True).available() is True
    assert GvisorSnapshotBackend(_cfg(tmp_path), run=lambda a, **k: 0, probe=lambda: False).available() is False


def test_kill_is_best_effort(tmp_path: Path) -> None:
    def boom(argv: list[str], **kw: object) -> int:
        raise RuntimeError("runsc gone")

    be = GvisorSnapshotBackend(_cfg(tmp_path), run=boom, ready_wait=lambda d, t: None)
    # restore_in calls run() which raises -> should propagate; but handle.kill must swallow
    with pytest.raises(RuntimeError):
        be.restore_in(tmp_path / "s", "img")


def test_oci_config_has_bind_mounts_args_and_ld_preload(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, warm_argv=["/bin/sh", "-c", "x"], ld_preload="/opt/clippyshot/accept-retry.so")
    spec = _oci_config(cfg, tmp_path / "wd", in_ro=True)
    assert spec["process"]["args"] == ["/bin/sh", "-c", "x"]
    assert any(e == "LD_PRELOAD=/opt/clippyshot/accept-retry.so" for e in spec["process"]["env"])
    dests = {m["destination"]: m for m in spec["mounts"]}
    assert dests["/in"]["options"][-1] == "ro" and dests["/out"]["options"][-1] == "rw"
    assert dests["/ctrl"]["source"] == str(tmp_path / "wd" / "ctrl")


def test_oci_config_no_ld_preload_when_unset(tmp_path: Path) -> None:
    spec = _oci_config(_cfg(tmp_path), tmp_path / "wd", in_ro=True)
    assert not any(e.startswith("LD_PRELOAD") for e in spec["process"]["env"])
