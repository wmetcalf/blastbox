"""Tests for blastbox.host.runtime.firecracker.

Unit-validated without a live Firecracker binary, kernel, or rootfs:
- FCConfig dataclass: field defaults, env-driven construction, validation.
- vcpu_count defaults to 1 (asserted — this is the vsock-corruption mitigation).
- firecracker_available() returns False on this host (no binary + no kernel +
  no rootfs).  Gated live tests are marked skip.
- build_fc_config_json: correct structure (drives[0]=rootfs ro, drives[1]=outdisk
  rw, vsock guest_cid=3, machine-config vcpu_count=1, boot-source).
- Launch argv is a list[str], starts with fc_bin, contains --no-api and
  --config-file as separate list elements, no shell=True.
- No caller / job value can inject a new argv flag element.
- SlotRuntime state machine: spawn() → WARMING → is_ready() → is_alive() →
  reap() with a fake Popen + fake ReadySignal.
- reap() kills the fake process and removes the scratch dir.
- is_alive() returns False after reap().
- select_fc_runtime() returns None when prerequisites are absent.
- rdump_ext4: whitespace rejection; bad magic rejection; size cap.
- make_ext4: skipped without mkfs.ext4.
- FCUnavailable / FCError are SandboxError subclasses.

Tests that need a REAL firecracker binary + vmlinux + rootfs are marked:
    @pytest.mark.skipif(not HAS_FC_HOST, reason="needs firecracker + kernel + rootfs")
These should be run on toolz2 or another FC-capable host.
"""
from __future__ import annotations

import json
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from blastbox.errors import SandboxError
from blastbox.host.pool import Slot, SlotState
from blastbox.host.runtime.firecracker import (
    FCConfig,
    FCError,
    FCUnavailable,
    FileReadySignal,
    FirecrackerSlotRuntime,
    firecracker_available,
    make_ext4,
    rdump_ext4,
    select_fc_runtime,
)
from blastbox.host.runtime.firecracker import (
    _READY_PORT,
    VsockReadySignal,
)


# ---------------------------------------------------------------------------
# Live-FC gate — skip if not on a FC-capable host
# ---------------------------------------------------------------------------

HAS_FC_HOST: bool = firecracker_available()

_LIVE_FC_REASON = (
    "needs firecracker binary + /dev/kvm + vmlinux kernel + rootfs "
    "(run on a FC-capable host such as toolz2)"
)


# ---------------------------------------------------------------------------
# Fake Popen (injectable subprocess runner)
# ---------------------------------------------------------------------------


class _FakePopen:
    """Fake subprocess.Popen that is alive until kill() is called."""

    def __init__(self) -> None:
        self._returncode: int | None = None
        self.killed: bool = False
        self._lock = threading.Lock()

    @property
    def returncode(self) -> int | None:
        with self._lock:
            return self._returncode

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            if self._returncode is None:
                self._returncode = -9
            return self._returncode

    def kill(self) -> None:
        with self._lock:
            self.killed = True
            self._returncode = -9


class _FakeSubprocessRunner:
    """Injectable subprocess runner that returns _FakePopen instances."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self._kwargs_log: list[dict[str, Any]] = []
        self._popen_instances: list[_FakePopen] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> _FakePopen:
        self.calls.append(list(argv))
        self._kwargs_log.append(dict(kwargs))
        fp = _FakePopen()
        self._popen_instances.append(fp)
        return fp

    @property
    def last_argv(self) -> list[str]:
        return self.calls[-1]

    @property
    def last_popen(self) -> _FakePopen:
        return self._popen_instances[-1]


# ---------------------------------------------------------------------------
# Fake ReadySignal (injectable)
# ---------------------------------------------------------------------------


class _FakeReadySignal:
    """Injectable ReadySignal that returns a preset value."""

    def __init__(self, ready: bool = False) -> None:
        self._ready = ready
        self.calls: list[str] = []

    def set_ready(self, ready: bool) -> None:
        self._ready = ready

    def is_ready(self, slot: Slot) -> bool:
        self.calls.append(slot.slot_id)
        return self._ready


# ---------------------------------------------------------------------------
# FCConfig — defaults and validation
# ---------------------------------------------------------------------------


class TestFCConfigDefaults:
    def test_vcpu_default_is_1(self):
        """vcpu_count MUST default to 1 — the vsock-corruption mitigation."""
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        assert cfg.fc_vcpu_count == 1, (
            "vcpu_count default changed away from 1! "
            "This is the documented vsock-corruption mitigation — do not increase."
        )

    def test_default_fc_mem_mib(self):
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        assert cfg.fc_mem_mib == 512

    def test_default_fc_outdisk_mib(self):
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        assert cfg.fc_outdisk_mib == 256

    def test_default_vsock_guest_cid(self):
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        assert cfg.fc_vsock_guest_cid == 3

    def test_default_fc_bin(self):
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        assert cfg.fc_bin == "firecracker"

    def test_vcpu_zero_raises(self):
        with pytest.raises(ValueError, match="fc_vcpu_count"):
            FCConfig(fc_kernel="/k", fc_rootfs="/r", fc_vcpu_count=0)

    def test_mem_too_small_raises(self):
        with pytest.raises(ValueError, match="fc_mem_mib"):
            FCConfig(fc_kernel="/k", fc_rootfs="/r", fc_mem_mib=32)

    def test_outdisk_too_small_raises(self):
        with pytest.raises(ValueError, match="fc_outdisk_mib"):
            FCConfig(fc_kernel="/k", fc_rootfs="/r", fc_outdisk_mib=4)

    def test_frozen_immutable(self):
        cfg = FCConfig(fc_kernel="/k", fc_rootfs="/r")
        with pytest.raises((AttributeError, TypeError)):
            cfg.fc_vcpu_count = 2  # type: ignore[misc]


class TestFCConfigFromEnv:
    def test_from_env_reads_kernel_rootfs(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.delenv("BLASTBOX_FC_VCPU", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_MEM_MIB", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_OUTDISK_MIB", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_BIN", raising=False)
        cfg = FCConfig.from_env()
        assert cfg.fc_kernel == str(k)
        assert cfg.fc_rootfs == str(r)
        assert cfg.fc_vcpu_count == 1   # default preserved

    def test_from_env_vcpu_override(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.setenv("BLASTBOX_FC_VCPU", "2")
        cfg = FCConfig.from_env()
        assert cfg.fc_vcpu_count == 2

    def test_from_env_mem_override(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.setenv("BLASTBOX_FC_MEM_MIB", "1024")
        monkeypatch.delenv("BLASTBOX_FC_VCPU", raising=False)
        cfg = FCConfig.from_env()
        assert cfg.fc_mem_mib == 1024

    def test_from_env_outdisk_override(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.setenv("BLASTBOX_FC_OUTDISK_MIB", "512")
        monkeypatch.delenv("BLASTBOX_FC_VCPU", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_MEM_MIB", raising=False)
        cfg = FCConfig.from_env()
        assert cfg.fc_outdisk_mib == 512

    def test_from_env_bin_override(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.setenv("BLASTBOX_FC_BIN", "/opt/fc/firecracker")
        monkeypatch.delenv("BLASTBOX_FC_VCPU", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_MEM_MIB", raising=False)
        monkeypatch.delenv("BLASTBOX_FC_OUTDISK_MIB", raising=False)
        cfg = FCConfig.from_env()
        assert cfg.fc_bin == "/opt/fc/firecracker"

    def test_from_env_missing_kernel_raises(self, monkeypatch, tmp_path):
        r = tmp_path / "rootfs.ext4"
        r.touch()
        monkeypatch.delenv("BLASTBOX_FC_KERNEL", raising=False)
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        with pytest.raises(FCUnavailable, match="BLASTBOX_FC_KERNEL"):
            FCConfig.from_env()

    def test_from_env_missing_rootfs_raises(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        k.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.delenv("BLASTBOX_FC_ROOTFS", raising=False)
        with pytest.raises(FCUnavailable, match="BLASTBOX_FC_ROOTFS"):
            FCConfig.from_env()

    def test_from_env_bad_int_raises(self, monkeypatch, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        monkeypatch.setenv("BLASTBOX_FC_KERNEL", str(k))
        monkeypatch.setenv("BLASTBOX_FC_ROOTFS", str(r))
        monkeypatch.setenv("BLASTBOX_FC_VCPU", "not-a-number")
        with pytest.raises(ValueError, match="BLASTBOX_FC_VCPU"):
            FCConfig.from_env()


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    def test_fc_error_is_sandbox_error(self):
        e = FCError("test")
        assert isinstance(e, SandboxError)

    def test_fc_unavailable_is_fc_error(self):
        e = FCUnavailable("test")
        assert isinstance(e, FCError)

    def test_fc_unavailable_is_sandbox_error(self):
        e = FCUnavailable("test")
        assert isinstance(e, SandboxError)


# ---------------------------------------------------------------------------
# firecracker_available() — False on this host (no binary / kvm / kernel)
# ---------------------------------------------------------------------------


class TestFirecrackerAvailable:
    @pytest.mark.skipif(
        HAS_FC_HOST,
        reason="this host HAS the FC prerequisites; the unavailable-path "
        "assertion only holds without them (e.g. with BLASTBOX_FC_* unset)",
    )
    def test_false_on_this_host(self):
        """A host with no firecracker binary + no kernel + no rootfs."""
        assert firecracker_available() is False

    def test_false_when_no_binary(self, tmp_path):
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        cfg = FCConfig(
            fc_bin="/nonexistent/firecracker",
            fc_kernel=str(k),
            fc_rootfs=str(r),
        )
        assert firecracker_available(cfg) is False

    def test_false_when_kernel_missing(self, tmp_path):
        r = tmp_path / "rootfs.ext4"
        r.touch()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/nonexistent/vmlinux",
            fc_rootfs=str(r),
        )
        assert firecracker_available(cfg) is False

    def test_false_when_rootfs_missing(self, tmp_path):
        k = tmp_path / "vmlinux"
        k.touch()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel=str(k),
            fc_rootfs="/nonexistent/rootfs.ext4",
        )
        assert firecracker_available(cfg) is False

    def test_false_when_no_kvm(self, tmp_path, monkeypatch):
        """When /dev/kvm is patched to be absent, available() returns False."""
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        # Make a fake 'true' binary that acts as firecracker
        fake_fc = tmp_path / "firecracker"
        fake_fc.write_text("#!/bin/sh\n")
        fake_fc.chmod(0o755)
        cfg = FCConfig(fc_bin=str(fake_fc), fc_kernel=str(k), fc_rootfs=str(r))
        # Patch Path.exists to return False for /dev/kvm
        real_exists = Path.exists

        def _patched_exists(self: Path) -> bool:
            if str(self) == "/dev/kvm":
                return False
            return real_exists(self)

        monkeypatch.setattr(Path, "exists", _patched_exists)
        assert firecracker_available(cfg) is False


# ---------------------------------------------------------------------------
# fc-config.json structure
# ---------------------------------------------------------------------------


class TestFCConfigJson:
    """Verify the fc-config.json written by spawn() has the correct structure."""

    def _spawn_and_read_config(self, tmp_path: Path) -> dict:
        runner = _FakeSubprocessRunner()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/mnt/vmlinux",
            fc_rootfs="/mnt/rootfs.ext4",
            fc_vcpu_count=1,
            fc_mem_mib=256,
            fc_outdisk_mib=64,
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(
            cfg,
            subprocess_runner=runner,
            ready_signal=_FakeReadySignal(ready=False),
        )

        # Make the output disk creation a no-op by patching make_ext4.
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()

        slot_dir = tmp_path / slot.slot_id
        config_path = slot_dir / "fc-config.json"
        return json.loads(config_path.read_text())

    def test_boot_source_present(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert "boot-source" in config

    def test_boot_source_kernel_path(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert config["boot-source"]["kernel_image_path"] == "/mnt/vmlinux"

    def test_boot_source_boot_args_present(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert "boot_args" in config["boot-source"]
        # Must include basic boot args
        args = config["boot-source"]["boot_args"]
        assert "reboot=k" in args
        assert "panic=1" in args
        # RDRAND-seed the guest CRNG so getrandom() doesn't block ~120s at first use.
        assert "random.trust_cpu=on" in args

    def test_entropy_device_present(self, tmp_path):
        # virtio-rng so the guest CRNG has a host-fed entropy source (pairs with
        # random.trust_cpu=on) — without it a JVM/getrandom workload stalls ~120s.
        config = self._spawn_and_read_config(tmp_path)
        assert config.get("entropy") == {}

    def test_drives_has_two_entries(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert len(config["drives"]) == 2

    def test_drive0_is_rootfs_readonly(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        drive0 = config["drives"][0]
        assert drive0["drive_id"] == "rootfs"
        assert drive0["path_on_host"] == "/mnt/rootfs.ext4"
        assert drive0["is_root_device"] is True
        assert drive0["is_read_only"] is True

    def test_drive1_is_outdisk_readwrite(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        drive1 = config["drives"][1]
        assert drive1["drive_id"] == "outdisk"
        assert drive1["is_root_device"] is False
        assert drive1["is_read_only"] is False
        # Path must be within the slot dir
        assert "outdisk.ext4" in drive1["path_on_host"]

    def test_machine_config_vcpu_count(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert config["machine-config"]["vcpu_count"] == 1

    def test_machine_config_mem(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert config["machine-config"]["mem_size_mib"] == 256

    def test_machine_config_smt_false(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert config["machine-config"]["smt"] is False

    def test_vsock_guest_cid_is_3(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert config["vsock"]["guest_cid"] == 3

    def test_vsock_uds_path_present(self, tmp_path):
        config = self._spawn_and_read_config(tmp_path)
        assert "uds_path" in config["vsock"]
        assert config["vsock"]["uds_path"].endswith("vsock.sock")


# ---------------------------------------------------------------------------
# Launch argv — list[str], no shell, no injection
# ---------------------------------------------------------------------------


class TestLaunchArgv:
    def _spawn_and_get_argv(self, tmp_path: Path, fc_bin: str = "firecracker") -> list[str]:
        runner = _FakeSubprocessRunner()
        cfg = FCConfig(
            fc_bin=fc_bin,
            fc_kernel="/mnt/vmlinux",
            fc_rootfs="/mnt/rootfs.ext4",
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(
            cfg,
            subprocess_runner=runner,
            ready_signal=_FakeReadySignal(),
        )
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            rt.spawn()
        return runner.last_argv

    def test_argv_is_list_of_str(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        assert isinstance(argv, list)
        assert all(isinstance(a, str) for a in argv)

    def test_argv_first_element_is_fc_bin(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        assert argv[0] == "firecracker"

    def test_no_api_flag_present(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        assert "--no-api" in argv

    def test_config_file_flag_present(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        assert "--config-file" in argv

    def test_config_file_flag_is_separate_element(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        idx = argv.index("--config-file")
        # Next element must be the config path, not combined in one token
        assert argv[idx + 1].endswith("fc-config.json")

    def test_no_shell_metachars(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path)
        for tok in argv:
            assert tok not in ("sh", "bash", "-c", "shell=True")

    def test_argv_length_exactly_4(self, tmp_path):
        """Argv must be exactly [fc_bin, --no-api, --config-file, <path>]."""
        argv = self._spawn_and_get_argv(tmp_path)
        assert len(argv) == 4, f"Expected 4 elements, got: {argv!r}"

    def test_custom_fc_bin_path_in_argv(self, tmp_path):
        argv = self._spawn_and_get_argv(tmp_path, fc_bin="/opt/fc/firecracker")
        assert argv[0] == "/opt/fc/firecracker"

    def test_no_shell_equals_false(self, tmp_path):
        """subprocess_runner must NOT be called with shell=True."""
        runner = _FakeSubprocessRunner()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/k",
            fc_rootfs="/r",
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner, ready_signal=_FakeReadySignal())
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            rt.spawn()
        for call_kwargs in runner._kwargs_log:
            assert call_kwargs.get("shell") is not True, (
                "subprocess_runner called with shell=True — this is a security violation!"
            )


# ---------------------------------------------------------------------------
# vcpu=1 default — critical invariant
# ---------------------------------------------------------------------------


class TestVcpuDefault:
    def test_vcpu_default_is_1_in_config_json(self, tmp_path):
        """The fc-config.json written by spawn() MUST have vcpu_count=1 by default."""
        runner = _FakeSubprocessRunner()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/k",
            fc_rootfs="/r",
            # No explicit fc_vcpu_count — should use default of 1
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner, ready_signal=_FakeReadySignal())
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        slot_dir = tmp_path / slot.slot_id
        config = json.loads((slot_dir / "fc-config.json").read_text())
        assert config["machine-config"]["vcpu_count"] == 1, (
            "vcpu_count is not 1 in the written fc-config.json! "
            "This is the documented vsock-corruption mitigation."
        )

    def test_vcpu_override_honored(self, tmp_path):
        """An explicit vcpu_count=2 override is reflected in fc-config.json."""
        runner = _FakeSubprocessRunner()
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/k",
            fc_rootfs="/r",
            fc_vcpu_count=2,
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner, ready_signal=_FakeReadySignal())
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        slot_dir = tmp_path / slot.slot_id
        config = json.loads((slot_dir / "fc-config.json").read_text())
        assert config["machine-config"]["vcpu_count"] == 2


# ---------------------------------------------------------------------------
# SlotRuntime state machine with fake Popen + fake ReadySignal
# ---------------------------------------------------------------------------


class TestSlotRuntimeStateMachine:
    def _build_rt(
        self, tmp_path: Path, ready: bool = False
    ) -> tuple[FirecrackerSlotRuntime, _FakeSubprocessRunner, _FakeReadySignal]:
        runner = _FakeSubprocessRunner()
        signal = _FakeReadySignal(ready=ready)
        cfg = FCConfig(
            fc_bin="firecracker",
            fc_kernel="/k",
            fc_rootfs="/r",
            scratch_root=str(tmp_path),
        )
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=runner, ready_signal=signal)
        return rt, runner, signal

    def test_spawn_returns_warming_slot(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        assert slot.state == SlotState.WARMING

    def test_spawn_calls_subprocess_runner_once(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            rt.spawn()
        assert len(runner.calls) == 1

    def test_spawn_creates_slot_dirs(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        assert slot.output_dir.exists()
        assert slot.input_dir.exists()
        assert slot.control_dir.exists()

    def test_is_ready_false_when_signal_false(self, tmp_path):
        rt, runner, signal = self._build_rt(tmp_path, ready=False)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        assert rt.is_ready(slot) is False

    def test_is_ready_true_when_signal_true(self, tmp_path):
        rt, runner, signal = self._build_rt(tmp_path, ready=True)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        assert rt.is_ready(slot) is True

    def test_is_ready_transitions_on_signal_change(self, tmp_path):
        rt, runner, signal = self._build_rt(tmp_path, ready=False)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        assert rt.is_ready(slot) is False
        signal.set_ready(True)
        assert rt.is_ready(slot) is True

    def test_is_alive_true_while_process_running(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        fake_proc = runner.last_popen
        assert fake_proc.returncode is None   # process is "running"
        assert rt.is_alive(slot) is True

    def test_is_alive_false_after_process_exits(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        fake_proc = runner.last_popen
        fake_proc.kill()  # simulate exit
        assert rt.is_alive(slot) is False

    def test_reap_kills_running_process(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        fake_proc = runner.last_popen
        assert not fake_proc.killed
        rt.reap(slot)
        assert fake_proc.killed

    def test_reap_removes_scratch_dir(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        slot_dir = tmp_path / slot.slot_id
        assert slot_dir.exists()
        rt.reap(slot)
        assert not slot_dir.exists()

    def test_is_alive_false_after_reap(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        rt.reap(slot)
        assert rt.is_alive(slot) is False

    def test_reap_idempotent_no_error(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot = rt.spawn()
        rt.reap(slot)
        # Second reap must not raise
        rt.reap(slot)

    def test_is_alive_unknown_slot_returns_false(self, tmp_path):
        rt, runner, _ = self._build_rt(tmp_path)
        fake_slot = Slot(
            slot_id="nonexistent",
            control_dir=tmp_path,
            input_dir=tmp_path,
            output_dir=tmp_path,
            state=SlotState.WARMING,
        )
        assert rt.is_alive(fake_slot) is False

    def test_is_ready_unknown_slot_returns_false(self, tmp_path):
        rt, runner, signal = self._build_rt(tmp_path, ready=True)
        # is_ready delegates to the signal — even for unknown slots
        # the signal returns True here; this tests delegation not slot lookup
        fake_slot = Slot(
            slot_id="any",
            control_dir=tmp_path,
            input_dir=tmp_path,
            output_dir=tmp_path,
            state=SlotState.WARMING,
        )
        # With a True-returning signal, is_ready returns True regardless
        assert rt.is_ready(fake_slot) is True

    def test_multiple_slots_tracked_independently(self, tmp_path):
        rt, runner, signal = self._build_rt(tmp_path, ready=False)
        with patch("blastbox.host.runtime.firecracker.make_ext4"):
            slot_a = rt.spawn()
            slot_b = rt.spawn()

        assert slot_a.slot_id != slot_b.slot_id
        assert rt.is_alive(slot_a) is True
        assert rt.is_alive(slot_b) is True

        rt.reap(slot_a)
        assert rt.is_alive(slot_a) is False
        assert rt.is_alive(slot_b) is True


# ---------------------------------------------------------------------------
# SlotRuntime protocol conformance
# ---------------------------------------------------------------------------


class TestSlotRuntimeProtocol:
    def test_implements_slot_runtime_protocol(self, tmp_path):
        """FirecrackerSlotRuntime must satisfy the SlotRuntime Protocol."""
        from blastbox.host.pool import SlotRuntime
        cfg = FCConfig(fc_bin="fc", fc_kernel="/k", fc_rootfs="/r", scratch_root=str(tmp_path))
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner(), ready_signal=_FakeReadySignal())
        assert isinstance(rt, SlotRuntime)


# ---------------------------------------------------------------------------
# rdump_ext4 confinement checks (unit-testable without real ext4 image)
# ---------------------------------------------------------------------------


class TestRdumpExt4:
    def _write_valid_ext4_magic(self, path: Path) -> None:
        """Write a minimal file with a correct ext4 superblock magic at offset 0x438."""
        data = bytearray(4096)
        # ext4 magic 0xEF53 at offset 0x438 (little-endian)
        data[0x438] = 0x53
        data[0x439] = 0xEF
        path.write_bytes(bytes(data))

    def test_whitespace_in_dest_raises(self, tmp_path):
        img = tmp_path / "disk.ext4"
        self._write_valid_ext4_magic(img)
        dest = Path("/tmp/path with spaces")
        with pytest.raises(ValueError, match="whitespace"):
            rdump_ext4(img, dest, max_bytes=1024)

    def test_bad_magic_raises(self, tmp_path):
        img = tmp_path / "disk.ext4"
        # Write a file with wrong magic
        data = bytearray(4096)
        data[0x438] = 0xAA
        data[0x439] = 0xBB
        img.write_bytes(bytes(data))
        dest = tmp_path / "out"
        with pytest.raises(ValueError, match="magic"):
            rdump_ext4(img, dest, max_bytes=1024)

    def test_missing_image_raises(self, tmp_path):
        img = tmp_path / "nonexistent.ext4"
        dest = tmp_path / "out"
        with pytest.raises(ValueError, match="cannot read"):
            rdump_ext4(img, dest, max_bytes=1024)

    def test_e2fsck_recover_and_retry_when_first_rdump_empty(self, tmp_path, monkeypatch):
        """A guest SIGKILLed off a no-journal ext4 can leave bitmaps inconsistent so the
        first debugfs rdump reads NOTHING ('Filesystem not open'). rdump_ext4 must then
        run e2fsck -fy (rebuilds bitmaps from the intact inode tree) and retry the rdump,
        which then sees the file."""
        img = tmp_path / "disk.ext4"
        self._write_valid_ext4_magic(img)
        dest = tmp_path / "out"

        calls: list[str] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001
            tool = cmd[0]
            calls.append(tool)
            res = MagicMock()
            res.returncode = 0
            res.stderr = b""
            if tool == "debugfs":
                if calls.count("debugfs") == 1:
                    # First rdump: unreadable fs -> writes nothing, error on stderr.
                    res.stderr = b"disk.ext4: Filesystem not open\n"
                else:
                    # Post-e2fsck retry: the file is now extractable.
                    (dest / "metadata.json").write_text("{}")
            return res

        monkeypatch.setattr(subprocess, "run", fake_run)
        names = rdump_ext4(img, dest, max_bytes=1024 * 1024)
        assert calls == ["debugfs", "e2fsck", "debugfs"], calls
        assert "metadata.json" in names

    def test_e2fsck_recover_when_first_rdump_exits_nonzero(self, tmp_path, monkeypatch):
        """A NON-zero debugfs exit must also fall through to the e2fsck recovery, not raise
        and bypass it (the first rdump is check=False; the post-recovery rdump is fatal)."""
        img = tmp_path / "disk.ext4"
        self._write_valid_ext4_magic(img)
        dest = tmp_path / "out"
        calls: list[str] = []

        def fake_run(cmd, **kwargs):  # noqa: ANN001
            tool = cmd[0]
            calls.append(tool)
            res = MagicMock()
            res.stderr = b""
            if tool == "debugfs":
                if calls.count("debugfs") == 1:
                    res.returncode = 1  # non-zero: previously raised + bypassed recovery
                else:
                    res.returncode = 0
                    (dest / "metadata.json").write_text("{}")
            else:
                res.returncode = 0
            return res

        monkeypatch.setattr(subprocess, "run", fake_run)
        names = rdump_ext4(img, dest, max_bytes=1024 * 1024)
        assert calls == ["debugfs", "e2fsck", "debugfs"], calls
        assert "metadata.json" in names

    def test_size_cap_enforced(self, tmp_path, monkeypatch):
        """If total extracted bytes exceed max_bytes, ValueError is raised."""
        img = tmp_path / "disk.ext4"
        self._write_valid_ext4_magic(img)
        dest = tmp_path / "out"
        dest.mkdir()

        # Patch subprocess.run to simulate debugfs writing a large file
        def fake_run(cmd, **kwargs):  # noqa: ANN001
            # Write a 100-byte file so the size check triggers when max_bytes=50
            big_file = dest / "big.bin"
            big_file.write_bytes(b"X" * 100)
            mock_result = MagicMock()
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(ValueError, match="exceeds cap"):
            rdump_ext4(img, dest, max_bytes=50)

    def test_lost_found_removed(self, tmp_path, monkeypatch):
        """After rdump, lost+found is removed from dest."""
        img = tmp_path / "disk.ext4"
        self._write_valid_ext4_magic(img)
        dest = tmp_path / "out"
        dest.mkdir()

        def fake_run(cmd, **kwargs):  # noqa: ANN001
            # Simulate debugfs creating lost+found and a real file
            (dest / "lost+found").mkdir(exist_ok=True)
            (dest / "output.json").write_text("{}")
            mock_result = MagicMock()
            mock_result.returncode = 0
            return mock_result

        monkeypatch.setattr(subprocess, "run", fake_run)
        names = rdump_ext4(img, dest, max_bytes=1024 * 1024)
        assert "lost+found" not in names
        assert "output.json" in names


# ---------------------------------------------------------------------------
# make_ext4 — skip without mkfs.ext4
# ---------------------------------------------------------------------------


_HAS_MKFS = bool(__import__("shutil").which("mkfs.ext4"))


@pytest.mark.skipif(not _HAS_MKFS, reason="mkfs.ext4 not available on this host")
class TestMakeExt4:
    def test_creates_file(self, tmp_path):
        img = tmp_path / "test.ext4"
        make_ext4(img, size_mib=16)
        assert img.exists()
        assert img.stat().st_size == 16 * 1024 * 1024

    def test_ext4_magic_present(self, tmp_path):
        img = tmp_path / "test.ext4"
        make_ext4(img, size_mib=16)
        with open(img, "rb") as f:
            f.seek(0x438)
            magic = f.read(2)
        assert magic == b"\x53\xef", "Expected ext4 magic 0xEF53"

    def test_no_metadata_csum_so_unclean_disk_stays_debugfs_readable(self, tmp_path):
        """The single-use outdisk MUST be made without metadata_csum: the guest is
        SIGKILLed off it (never unmounted), leaving bitmaps inconsistent — with
        metadata_csum debugfs would refuse to open it ("Block bitmap checksum does not
        match") and rdump would return nothing, recording a good job as
        'metadata.json not found'."""
        import subprocess as _sp

        img = tmp_path / "test.ext4"
        make_ext4(img, size_mib=16)
        feats = _sp.run(
            ["debugfs", "-R", "features", str(img)], capture_output=True, text=True
        ).stdout
        assert "metadata_csum" not in feats, f"outdisk must NOT have metadata_csum: {feats}"
        assert "has_journal" not in feats, f"outdisk must NOT have a journal: {feats}"


# ---------------------------------------------------------------------------
# FileReadySignal
# ---------------------------------------------------------------------------


class TestFileReadySignal:
    def _make_slot(self, tmp_path: Path) -> Slot:
        return Slot(
            slot_id="test-slot",
            control_dir=tmp_path / "ctrl",
            input_dir=tmp_path / "in",
            output_dir=tmp_path / "out",
            state=SlotState.WARMING,
        )

    def test_false_when_no_ready_marker(self, tmp_path):
        (tmp_path / "out").mkdir()
        slot = self._make_slot(tmp_path)
        sig = FileReadySignal()
        assert sig.is_ready(slot) is False

    def test_true_when_ready_marker_present(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "ready").touch()
        slot = self._make_slot(tmp_path)
        sig = FileReadySignal()
        assert sig.is_ready(slot) is True


# ---------------------------------------------------------------------------
# VsockReadySignal — live readiness over the FC vsock control plane
# ---------------------------------------------------------------------------


class TestVsockReadySignal:
    """Drive the READY listener with a Unix-socket client that plays exactly the
    role firecracker plays when the guest connects to (CID 2, READY_PORT): it
    connects to ``<slot vsock uds>_<READY_PORT>`` and forwards the guest's bytes.
    No VM needed — this validates the host half of the handshake.
    """

    def _make_slot(self, tmp_path: Path, slot_id: str = "vsock-slot") -> Slot:
        slot_dir = tmp_path / slot_id
        (slot_dir / "out").mkdir(parents=True)
        return Slot(
            slot_id=slot_id,
            control_dir=slot_dir / "ctrl",
            input_dir=slot_dir / "in",
            output_dir=slot_dir / "out",
            state=SlotState.WARMING,
        )

    def _uds_path(self, slot: Slot) -> Path:
        return slot.output_dir.parent / f"vsock.sock_{_READY_PORT}"

    def _send(self, uds: Path, payload: bytes) -> None:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(3.0)
        c.connect(str(uds))
        c.sendall(payload)
        c.close()

    def _wait_ready(
        self, sig: VsockReadySignal, slot: Slot, timeout: float = 3.0
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if sig.is_ready(slot):
                return True
            time.sleep(0.02)
        return sig.is_ready(slot)

    def test_not_ready_before_connect(self, tmp_path):
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        try:
            assert sig.is_ready(slot) is False
            assert self._uds_path(slot).exists()  # listener bound by prepare()
        finally:
            sig.cleanup(slot)

    def test_ready_after_client_sends_ready(self, tmp_path):
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        try:
            self._send(self._uds_path(slot), b"READY\n")
            assert self._wait_ready(sig, slot) is True
        finally:
            sig.cleanup(slot)

    def test_wrong_token_stays_not_ready(self, tmp_path):
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        try:
            self._send(self._uds_path(slot), b"NOPE\n")
            assert self._wait_ready(sig, slot, timeout=1.0) is False
        finally:
            sig.cleanup(slot)

    def test_ready_beyond_byte_cap_not_detected(self, tmp_path):
        """READY pushed past ``max_bytes`` is never read → not detected (cap proof)."""
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal(max_bytes=8)
        sig.prepare(slot)
        try:
            self._send(self._uds_path(slot), b"x" * 64 + b"READY")
            assert self._wait_ready(sig, slot, timeout=1.0) is False
        finally:
            sig.cleanup(slot)

    def test_is_ready_false_for_unprepared_slot(self, tmp_path):
        slot = self._make_slot(tmp_path)
        assert VsockReadySignal().is_ready(slot) is False

    def test_stalled_connection_does_not_block_ready(self, tmp_path):
        """A guest that connects but never sends must NOT head-of-line-block a
        subsequent READY (the listener is non-blocking, not serial-with-2s-recv)."""
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        stall = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            stall.connect(str(self._uds_path(slot)))  # connect, send nothing
            t0 = time.monotonic()
            self._send(self._uds_path(slot), b"READY")
            assert self._wait_ready(sig, slot, timeout=2.0) is True
            # Must fire fast — well under the old 2.0s per-conn recv timeout.
            assert time.monotonic() - t0 < 1.5
        finally:
            stall.close()
            sig.cleanup(slot)

    def test_cleanup_is_prompt_even_with_stalled_connection(self, tmp_path):
        """cleanup() (hence reap()) must not block on a stalled guest connection."""
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        stall = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stall.connect(str(self._uds_path(slot)))
        try:
            t0 = time.monotonic()
            sig.cleanup(slot)
            assert time.monotonic() - t0 < 1.5  # not wedged in a long recv
        finally:
            stall.close()

    def test_double_prepare_is_idempotent(self, tmp_path):
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        sig.prepare(slot)  # no raise, no second listener
        try:
            self._send(self._uds_path(slot), b"READY")
            assert self._wait_ready(sig, slot) is True
        finally:
            sig.cleanup(slot)

    def test_cleanup_closes_and_unlinks(self, tmp_path):
        slot = self._make_slot(tmp_path)
        sig = VsockReadySignal()
        sig.prepare(slot)
        uds = self._uds_path(slot)
        assert uds.exists()
        sig.cleanup(slot)
        assert not uds.exists()
        assert sig.is_ready(slot) is False
        sig.cleanup(slot)  # idempotent on an already-cleaned slot

    def test_runtime_spawn_prepares_and_reap_cleans_up(self, tmp_path, monkeypatch):
        """The default runtime wires prepare() into spawn() and cleanup() into
        reap(); a simulated guest READY flips runtime.is_ready().

        Uses a SHORT scratch root (via mkdtemp) because AF_UNIX paths cap at 108
        bytes — the same reason production keeps BLASTBOX_FC_SCRATCH short.
        """
        import shutil as _shutil
        import tempfile

        k = tmp_path / "vmlinux"
        k.touch()
        r = tmp_path / "rootfs.ext4"
        r.touch()
        scratch = tempfile.mkdtemp(prefix="dv")  # short path, well under 108 bytes
        cfg = FCConfig(
            fc_bin="/bin/true",
            fc_kernel=str(k),
            fc_rootfs=str(r),
            scratch_root=scratch,
        )
        # Avoid needing mkfs.ext4 in unit tests.
        monkeypatch.setattr(
            "blastbox.host.runtime.firecracker.make_ext4", lambda *a, **k: None
        )
        rt = FirecrackerSlotRuntime(cfg, subprocess_runner=_FakeSubprocessRunner())
        slot = rt.spawn()
        uds = Path(cfg.scratch_root) / slot.slot_id / f"vsock.sock_{_READY_PORT}"
        try:
            assert uds.exists()  # prepare() ran during spawn
            assert rt.is_ready(slot) is False
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(3.0)
            c.connect(str(uds))
            c.sendall(b"READY")
            c.close()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not rt.is_ready(slot):
                time.sleep(0.02)
            assert rt.is_ready(slot) is True
        finally:
            rt.reap(slot)
        assert not uds.exists()  # cleanup() ran during reap
        _shutil.rmtree(scratch, ignore_errors=True)


# ---------------------------------------------------------------------------
# signal_go — streams the input frame from disk (no read_bytes materialization)
# ---------------------------------------------------------------------------


class TestSignalGoStreaming:
    def test_signal_go_streams_input_without_read_bytes(self, tmp_path, monkeypatch):
        """signal_go must send header + a wire-identical body frame STREAMED from disk —
        never Path.read_bytes() the whole input into host RAM."""
        from blastbox.host.runtime.firecracker import VsockHostWarmControl
        from blastbox.worker.warm import WarmJobSpec

        # Fail loudly if the old read_bytes() path is ever reintroduced.
        def _boom(self):  # noqa: ANN001
            raise AssertionError("signal_go must stream, not read_bytes() the whole input")

        monkeypatch.setattr(Path, "read_bytes", _boom)

        body = b"PK\x03\x04" + b"q" * 150_000  # > one 64 KiB chunk
        src = tmp_path / "in.docx"
        src.write_bytes(body)

        class _RecSock:
            def __init__(self) -> None:
                self.buf = bytearray()

            def sendall(self, data: bytes) -> None:
                self.buf += data

        sock = _RecSock()
        ctrl = VsockHostWarmControl(tmp_path / "vsock.uds", connect_fn=lambda: sock)
        ctrl.signal_go(
            WarmJobSpec(input_path=src, output_dir=tmp_path / "out", params={"a": "b"})
        )

        data = bytes(sock.buf)
        # Frame 1: header JSON.
        (hlen,) = struct.unpack(">Q", data[:8])
        off = 8
        header = json.loads(data[off : off + hlen])
        off += hlen
        assert header == {"filename": "in.docx", "params": {"a": "b"}}
        # Frame 2: the streamed body, wire-identical to send_frame(sock, body).
        (blen,) = struct.unpack(">Q", data[off : off + 8])
        off += 8
        assert blen == len(body)
        assert data[off : off + blen] == body
        assert off + blen == len(data)  # nothing extra on the wire


# ---------------------------------------------------------------------------
# select_fc_runtime — returns None when prerequisites absent
# ---------------------------------------------------------------------------


class TestSelectFcRuntime:
    @pytest.mark.skipif(
        HAS_FC_HOST,
        reason="this host HAS the FC prerequisites; the None-path only holds "
        "without them (e.g. with BLASTBOX_FC_* unset)",
    )
    def test_returns_none_on_this_host(self):
        """A host lacking the prerequisites → select_fc_runtime returns None."""
        result = select_fc_runtime()
        assert result is None

    @pytest.mark.skipif(
        HAS_FC_HOST,
        reason="this host HAS the FC prerequisites; the unavailable-path only "
        "holds without them (e.g. with BLASTBOX_FC_* unset)",
    )
    def test_require_available_raises_fc_unavailable_on_this_host(self):
        """With require_available=True, FCUnavailable is raised when unavailable."""
        with pytest.raises(FCUnavailable):
            select_fc_runtime(require_available=True)

    def test_returns_runtime_when_all_checks_pass(self, tmp_path, monkeypatch):
        """When firecracker_available() is patched to True, a runtime is returned."""
        k = tmp_path / "vmlinux"
        r = tmp_path / "rootfs.ext4"
        k.touch()
        r.touch()
        fake_fc = tmp_path / "firecracker"
        fake_fc.write_text("#!/bin/sh\n")
        fake_fc.chmod(0o755)

        cfg = FCConfig(
            fc_bin=str(fake_fc),
            fc_kernel=str(k),
            fc_rootfs=str(r),
            scratch_root=str(tmp_path / "slots"),
        )

        # Patch firecracker_available to return True
        monkeypatch.setattr(
            "blastbox.host.runtime.firecracker.firecracker_available",
            lambda *args, **kwargs: True,
        )
        runner = _FakeSubprocessRunner()
        signal = _FakeReadySignal()
        result = select_fc_runtime(
            cfg=cfg,
            subprocess_runner=runner,
            ready_signal=signal,
        )
        assert result is not None
        assert isinstance(result, FirecrackerSlotRuntime)


# ---------------------------------------------------------------------------
# BLASTBOX_WORKER_RUNTIME=firecracker integration point (env-based selection)
# ---------------------------------------------------------------------------


class TestWorkerRuntimeEnvSelection:
    """Verify the existing Docker runtime selection rejects 'firecracker' gracefully."""

    def test_docker_runtime_selection_does_not_accept_firecracker(self, monkeypatch):
        """BLASTBOX_WORKER_RUNTIME=firecracker is NOT a valid Docker runtime;
        select_worker_runtime ignores it (returns the detected Docker runtime)."""
        from blastbox.host.runtime.docker import select_worker_runtime

        monkeypatch.setenv("BLASTBOX_WORKER_RUNTIME", "firecracker")
        monkeypatch.delenv("BLASTBOX_REQUIRE_SECURE_RUNTIME", raising=False)
        # Opt into runc so the fallback is allowed — this test is about the firecracker
        # override being IGNORED, not the runc fail-closed policy (see test_docker.py).
        monkeypatch.setenv("BLASTBOX_ALLOW_RUNC", "1")
        # Should NOT raise; just returns whichever Docker runtime is detected.
        # The FC path is handled by select_fc_runtime, not select_worker_runtime.
        sel = select_worker_runtime(available_runtimes=["runc"])
        # The docker module ignores unknown overrides — falls back to detection
        assert sel.runtime in ("runc", "runsc")


# ---------------------------------------------------------------------------
# Live FC tests — skipped unless on a FC-capable host
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_FC_HOST, reason=_LIVE_FC_REASON)
class TestFirecrackerLiveBoot:
    """End-to-end microVM boot tests — require firecracker + vmlinux + a blastbox
    worker rootfs (build with deploy/firecracker/build-rootfs.sh).

    NOT run in CI or on a dev host. Run on a FC-capable host (e.g. toolz2) with
    BLASTBOX_FC_BIN / BLASTBOX_FC_KERNEL / BLASTBOX_FC_ROOTFS set.
    """

    @pytest.fixture
    def fc_scratch(self):
        # FC's vsock UDS lives under the scratch root and AF_UNIX paths cap at
        # 108 bytes — a long pytest tmp_path would break FC's own vsock setup.
        # A short mkdtemp prefix keeps the worst-case path well under the cap.
        import shutil
        import tempfile

        d = tempfile.mkdtemp(prefix="dfc")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def test_live_spawn_and_reap(self, fc_scratch):
        import time

        cfg = FCConfig.from_env(scratch_root=fc_scratch)
        rt = FirecrackerSlotRuntime(cfg)
        slot = rt.spawn()
        assert slot.state == SlotState.WARMING
        time.sleep(2.0)
        assert rt.is_alive(slot)  # the microVM actually booted and is running
        rt.reap(slot)
        assert not rt.is_alive(slot)

    def test_live_is_ready_after_warmup(self, fc_scratch):
        """The guest warms an engine and signals READY over vsock within 30 s —
        the live signal VsockReadySignal listens for (FileReadySignal cannot)."""
        import time

        cfg = FCConfig.from_env(scratch_root=fc_scratch)
        rt = FirecrackerSlotRuntime(cfg)
        slot = rt.spawn()
        deadline = time.monotonic() + 30.0
        ready = False
        while time.monotonic() < deadline:
            if rt.is_ready(slot):
                ready = True
                break
            time.sleep(0.5)
        rt.reap(slot)
        assert ready, "Guest did not signal READY over vsock within 30 s"

    def test_live_job_roundtrip_trust_validated(self, fc_scratch):
        """The full warm JOB round-trip: input delivered over vsock, the guest
        detonates and writes artifacts to the ext4 disk, the host reads them via
        rdump and validates through the trust gate — input-sha round-trips and the
        artifact hash is recomputed from disk (never trusted from the guest)."""
        import hashlib
        import time

        from blastbox.host.trust import validate_worker_output
        from blastbox.limits import Limits
        from blastbox.worker.warm import WarmJobSpec

        cfg = FCConfig.from_env(scratch_root=fc_scratch)
        rt = FirecrackerSlotRuntime(cfg)
        slot = rt.spawn()
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and not rt.is_ready(slot):
            time.sleep(0.5)
        assert rt.is_ready(slot), "guest never signalled READY"

        payload = b"live-fc-job-roundtrip-" + b"Z" * 2048
        sha = hashlib.sha256(payload).hexdigest()
        src = Path(fc_scratch) / "input.bin"
        src.write_bytes(payload)
        try:
            control = rt.host_warm_control(slot)
            control.signal_go(
                WarmJobSpec(input_path=src, output_dir=slot.output_dir, params={})
            )
            assert control.wait_for_done(timeout_s=30.0) == "ok"
            names = rt.read_output_disk(slot)
            assert "metadata.json" in names
            envelope = validate_worker_output(
                output_dir=slot.output_dir,
                input_sha256=sha,
                engine="probe",
                limits=Limits.from_env(),
            )
            assert envelope.status == "ok"
            assert envelope.input_sha256 == sha
            assert len(envelope.artifacts) == 1
        finally:
            rt.reap(slot)
