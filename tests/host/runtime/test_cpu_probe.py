"""Tests for blastbox.host.runtime.cpu_probe.

The live microVM boot is exercised end-to-end WITHOUT a real Firecracker via the
injectable ``subprocess_runner`` seam: a fake runner writes a canned guest
console to the log the probe polls, and a fake Popen drives the exit/poll path.
What's covered:
- classify_probe_console: mismatch → MISMATCH(value); restore-reached + no error
  → COMPATIBLE; never-reached-restore → INCONCLUSIVE; required ok-marker absent
  → INCONCLUSIVE.
- build_probe_config_json: single read-only root disk, vcpu=1, console=ttyS0, no
  output disk / vsock.
- probe_guest_cpu_features: mismatch / compatible / inconclusive / timeout paths;
  argv is a no-shell list; missing kernel/rootfs → CpuProbeError; the throwaway
  VM is always terminated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host.runtime.cpu_probe import (
    CpuProbeConfig,
    CpuProbeError,
    ProbeStatus,
    build_probe_config_json,
    classify_probe_console,
    probe_guest_cpu_features,
)

_REAL_MISMATCH = (
    "[    0.412][crac] Restore failed due to incompatible or missing CPU "
    "features, try using -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint.\n"
    "Error: Could not create the Java Virtual Machine.\n"
)
# A successful restore prints "warp: Restore successful!" (confirmed live on toolz2).
_COMPATIBLE = "init: bound vsock\n0.539615: warp: Restore successful!\n"
_NO_CRAC = "[    0.10] Kernel panic - not syncing: VFS: Unable to mount root\n"


# --------------------------------------------------------------------------- #
# Pure classification
# --------------------------------------------------------------------------- #


def test_classify_mismatch():
    r = classify_probe_console(_REAL_MISMATCH)
    assert r.status is ProbeStatus.MISMATCH
    assert r.needed == "0x102100055bbd7,0x1c8"


def test_classify_compatible_on_success_marker():
    assert classify_probe_console(_COMPATIBLE).status is ProbeStatus.COMPATIBLE


def test_classify_inconclusive_without_success_or_mismatch():
    # No success marker and no mismatch → never claim COMPATIBLE.
    assert classify_probe_console(_NO_CRAC).status is ProbeStatus.INCONCLUSIVE
    assert classify_probe_console("").status is ProbeStatus.INCONCLUSIVE
    # [crac] alone (the old, wrong "attempt" heuristic) is NOT enough.
    assert classify_probe_console("[crac] restoring...\n").status is ProbeStatus.INCONCLUSIVE


def test_classify_custom_ok_marker():
    assert classify_probe_console(
        "worker is up\n", restore_ok_marker="worker is up"
    ).status is ProbeStatus.COMPATIBLE


def test_mismatch_wins_over_success_marker():
    both = _REAL_MISMATCH + "warp: Restore successful!\n"
    assert classify_probe_console(both).status is ProbeStatus.MISMATCH


# --------------------------------------------------------------------------- #
# Config JSON
# --------------------------------------------------------------------------- #


def test_invalid_restore_ok_marker_rejected():
    with pytest.raises(ValueError):
        CpuProbeConfig(fc_bin="firecracker", kernel="/k", rootfs="/r", restore_ok_marker="(unclosed")


def test_config_json_single_ro_root_disk_no_extras():
    cfg = CpuProbeConfig(fc_bin="firecracker", kernel="/k", rootfs="/r", mem_mib=1024)
    j = build_probe_config_json(cfg)
    assert j["drives"] == [
        {"drive_id": "rootfs", "path_on_host": "/r", "is_root_device": True, "is_read_only": True}
    ]
    assert "vsock" not in j  # probe needs no control plane
    assert j["machine-config"]["vcpu_count"] == 1
    assert j["machine-config"]["mem_size_mib"] == 1024
    assert "console=ttyS0" in j["boot-source"]["boot_args"]
    assert j["boot-source"]["kernel_image_path"] == "/k"


# --------------------------------------------------------------------------- #
# Live orchestration via fakes
# --------------------------------------------------------------------------- #


class _FakePopen:
    def __init__(self, *, exits: bool) -> None:
        self._code: int | None = 0 if exits else None
        self.killed = False

    def poll(self) -> int | None:
        return self._code

    def kill(self) -> None:
        self.killed = True
        self._code = -9

    def wait(self, timeout: float | None = None) -> int:
        return self._code if self._code is not None else 0


def _runner(console: str, *, exits: bool = True, capture: list | None = None):
    holder: dict[str, _FakePopen] = {}

    def run(argv, *, stdout, stderr):
        if capture is not None:
            capture.append(argv)
        stdout.write(console)
        stdout.flush()
        proc = _FakePopen(exits=exits)
        holder["proc"] = proc
        return proc

    run.holder = holder  # type: ignore[attr-defined]
    return run


def _cfg(tmp_path: Path, **kw) -> CpuProbeConfig:
    kernel = tmp_path / "vmlinux"
    rootfs = tmp_path / "rootfs.ext4"
    kernel.write_bytes(b"")
    rootfs.write_bytes(b"")
    return CpuProbeConfig(fc_bin="firecracker", kernel=str(kernel), rootfs=str(rootfs), **kw)


def _no_clock():
    # Deadline computed once (#1=0.0), then loop sees 100.0 → past any timeout.
    seq = iter([0.0, 100.0])
    last = [0.0]

    def m() -> float:
        try:
            last[0] = next(seq)
        except StopIteration:
            pass
        return last[0]

    return m


def test_probe_mismatch(tmp_path: Path):
    r = probe_guest_cpu_features(
        _cfg(tmp_path), work_dir=tmp_path / "w",
        subprocess_runner=_runner(_REAL_MISMATCH), sleep=lambda *_: None,
    )
    assert r.status is ProbeStatus.MISMATCH
    assert r.needed == "0x102100055bbd7,0x1c8"


def test_probe_compatible(tmp_path: Path):
    r = probe_guest_cpu_features(
        _cfg(tmp_path), work_dir=tmp_path / "w",
        subprocess_runner=_runner(_COMPATIBLE), sleep=lambda *_: None,
    )
    assert r.status is ProbeStatus.COMPATIBLE
    assert r.needed is None


def test_probe_inconclusive_when_vm_exits_without_restore(tmp_path: Path):
    r = probe_guest_cpu_features(
        _cfg(tmp_path), work_dir=tmp_path / "w",
        subprocess_runner=_runner(_NO_CRAC), sleep=lambda *_: None,
    )
    assert r.status is ProbeStatus.INCONCLUSIVE


def test_probe_timeout_terminates_and_is_inconclusive(tmp_path: Path):
    runner = _runner("", exits=False)  # never writes, never exits
    r = probe_guest_cpu_features(
        _cfg(tmp_path, timeout_s=25.0), work_dir=tmp_path / "w",
        subprocess_runner=runner, sleep=lambda *_: None, monotonic=_no_clock(),
    )
    assert r.status is ProbeStatus.INCONCLUSIVE
    assert runner.holder["proc"].killed is True  # type: ignore[attr-defined]


def test_probe_argv_is_no_shell_list(tmp_path: Path):
    cap: list = []
    probe_guest_cpu_features(
        _cfg(tmp_path), work_dir=tmp_path / "w",
        subprocess_runner=_runner(_COMPATIBLE, capture=cap), sleep=lambda *_: None,
    )
    argv = cap[0]
    assert argv[:3] == ["firecracker", "--no-api", "--config-file"]
    assert argv[3].endswith("probe-fc-config.json")
    assert (tmp_path / "w" / "probe-fc-config.json").is_file()


def test_probe_missing_rootfs_raises(tmp_path: Path):
    kernel = tmp_path / "vmlinux"
    kernel.write_bytes(b"")
    cfg = CpuProbeConfig(fc_bin="firecracker", kernel=str(kernel), rootfs="/no/such/rootfs")
    with pytest.raises(CpuProbeError):
        probe_guest_cpu_features(cfg, work_dir=tmp_path / "w")
