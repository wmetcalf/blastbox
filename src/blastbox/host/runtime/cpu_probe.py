"""Probe a Firecracker guest for its CRaC-compatible CPU feature value.

A CRaC "warp" checkpoint must be created with a ``-XX:CPUFeatures`` value that
is a subset of what the *restore* environment (the microVM guest) exposes. The
build host can't observe the guest's feature set — that's the whole bug this
module exists to kill — so we *ask the guest* by booting it once and reading the
answer off the serial console.

The JVM has no in-guest "print my features" flag (``-XX:CPUFeatures`` accepts
only a literal ``0xNUM,0xNUM``), so the only reliable signal is the warp restore
error itself: boot a checkpoint whose pinned features the guest can't satisfy and
the engine prints ``try using -XX:CPUFeatures=<value>`` — the exact value to bake
in. :func:`parse_cpu_mismatch` (in :mod:`~blastbox.host.runtime.cpu_features`)
extracts it.

This is the reusable core of the build-time auto-bake: a consumer builds a
checkpoint *without* a guest pin (capturing the build host's broader set), calls
:func:`probe_guest_cpu_features`, and if the result is ``MISMATCH`` rebuilds the
checkpoint pinned to ``result.needed``. ``COMPATIBLE`` means the unpinned
checkpoint already restores in the guest (no pin needed); ``INCONCLUSIVE`` means
the VM never reached the restore stage (bad kernel/rootfs/timeout) and the caller
must NOT silently treat that as "no pin needed".

It is generic on purpose: any JVM-on-Firecracker consumer passes its own kernel,
rootfs, and boot args. The live boot reuses the same ``firecracker --no-api
--config-file`` recipe as the warm tier; the ``subprocess_runner`` seam makes the
whole orchestration unit-testable without a real microVM.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from blastbox.errors import SandboxError
from blastbox.host.runtime.cpu_features import parse_cpu_mismatch

_log = logging.getLogger("blastbox.host.runtime.cpu_probe")

# A successful warp restore prints "warp: Restore successful!" on the guest
# console (empirically confirmed on toolz2). That positive marker — NOT the
# "[crac]" tag, which only shows up on the *failure* path — is what proves the
# checkpoint actually restored in this guest. Absent both this and a CPU-feature
# mismatch, the boot is INCONCLUSIVE (we never claim COMPATIBLE on a guess).
_DEFAULT_RESTORE_OK_MARKER = r"(?i)Restore successful"

# How much of the console to keep for diagnostics in the result.
_CONSOLE_TAIL_BYTES = 4000


class CpuProbeError(SandboxError):
    """The probe could not run (missing kernel/rootfs/binary, launch failure)."""


class ProbeStatus(str, Enum):
    MISMATCH = "mismatch"          # restore aborted on CPU features; .needed is set
    COMPATIBLE = "compatible"      # restore got past the CPU check; no pin needed
    INCONCLUSIVE = "inconclusive"  # VM never reached the restore stage / no signal


@dataclass(frozen=True)
class CpuProbeResult:
    status: ProbeStatus
    needed: str | None      # the -XX:CPUFeatures value to pin (MISMATCH only)
    console_tail: str       # tail of the guest console, for diagnostics


@dataclass(frozen=True)
class CpuProbeConfig:
    """One-shot probe-microVM configuration.

    ``kernel``/``rootfs`` are host paths. ``rootfs`` must boot to a JVM that
    attempts a CRaC warp restore (e.g. an unpinned/over-broad checkpoint). All
    other fields default to the warm-tier conventions.
    """

    fc_bin: str
    kernel: str
    rootfs: str
    # Mirror the prod boot cmdline (incl. random.trust_cpu=on) so the probe boots
    # like the real warm/cold VMs it is vouching for.
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off init=/init ro random.trust_cpu=on"
    vcpu_count: int = 1          # vsock-corruption mitigation; matches the warm tier
    mem_mib: int = 1024          # boot at the SAME mem as prod so restore behaves the same
    timeout_s: float = 25.0
    restore_ok_marker: str = _DEFAULT_RESTORE_OK_MARKER  # regex proving a clean restore

    def __post_init__(self) -> None:
        # Fail fast + clearly if a caller overrides restore_ok_marker with an
        # invalid pattern, rather than raising a cryptic re.error deep in the poll.
        try:
            re.compile(self.restore_ok_marker)
        except re.error as exc:
            raise ValueError(f"restore_ok_marker is not a valid regex: {exc}") from exc


SubprocessRunner = Callable[..., "subprocess.Popen[bytes]"]


def _default_subprocess_runner(argv: list[str], **kwargs: object) -> "subprocess.Popen[bytes]":
    return subprocess.Popen(argv, **kwargs)  # type: ignore[call-overload]


def build_probe_config_json(cfg: CpuProbeConfig) -> dict:
    """Minimal FC config for a one-shot probe: a single read-only root disk, no
    output disk, no vsock — we only need the guest console up to the restore."""
    return {
        "boot-source": {
            "kernel_image_path": cfg.kernel,
            "boot_args": cfg.boot_args,
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": cfg.rootfs,
                "is_root_device": True,
                "is_read_only": True,
            },
        ],
        "machine-config": {
            "vcpu_count": cfg.vcpu_count,
            "mem_size_mib": cfg.mem_mib,
            "smt": False,
        },
        # virtio-rng entropy device — MUST mirror the prod cold/warm boots (see
        # firecracker.py / fc_snapshot_launcher.py). The boot_args carry
        # random.trust_cpu=on, but on a host without RDRAND (or where the
        # hypervisor doesn't pass it through) trust_cpu alone can't seed the
        # CRNG, so the JVM's getrandom() blocks ~120s during the restore and the
        # probe times out at timeout_s (25s) as a false INCONCLUSIVE — even
        # though the real prod VMs (which DO have this device) would succeed.
        # Empty body = no rate limiter.
        "entropy": {},
    }


def classify_probe_console(
    console: str,
    *,
    restore_ok_marker: str = _DEFAULT_RESTORE_OK_MARKER,
) -> CpuProbeResult:
    """Pure classification of a captured guest console. See :class:`ProbeStatus`.

    A CPU-feature mismatch wins (it names the value to pin); otherwise the restore
    is COMPATIBLE only if it printed the success marker — anything else (panic,
    early init failure, timeout before the restore) is INCONCLUSIVE, never a
    silent COMPATIBLE.
    """
    tail = console[-_CONSOLE_TAIL_BYTES:]
    mismatch = parse_cpu_mismatch(console)
    if mismatch is not None:
        return CpuProbeResult(ProbeStatus.MISMATCH, mismatch.needed, tail)
    if re.search(restore_ok_marker, console):
        return CpuProbeResult(ProbeStatus.COMPATIBLE, None, tail)
    return CpuProbeResult(ProbeStatus.INCONCLUSIVE, None, tail)


def _console_is_terminal(console: str, cfg: CpuProbeConfig) -> bool:
    """True once the console carries a decisive signal — lets us stop early
    instead of always waiting out ``timeout_s``."""
    if parse_cpu_mismatch(console) is not None:
        return True
    if re.search(cfg.restore_ok_marker, console):
        return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _terminate(proc: "subprocess.Popen[bytes]") -> None:
    try:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001 — best-effort teardown of a throwaway VM
        pass


def probe_guest_cpu_features(
    cfg: CpuProbeConfig,
    *,
    work_dir: str | Path,
    subprocess_runner: SubprocessRunner = _default_subprocess_runner,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    poll_interval_s: float = 0.25,
) -> CpuProbeResult:
    """Boot a one-shot probe microVM and classify its CRaC restore.

    Raises :class:`CpuProbeError` on missing prerequisites or launch failure —
    never silently returns COMPATIBLE, which would reproduce the original bug.
    """
    for label, p in (("kernel", cfg.kernel), ("rootfs", cfg.rootfs)):
        if not p or not Path(p).is_file():
            raise CpuProbeError(f"probe {label} not found: {p!r}")

    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    config_path = work / "probe-fc-config.json"
    config_path.write_text(json.dumps(build_probe_config_json(cfg), indent=2), encoding="utf-8")
    log_path = work / "probe-fc.log"

    # ALWAYS a list, NEVER shell=True; fc_bin is the only source of the binary.
    argv: list[str] = [cfg.fc_bin, "--no-api", "--config-file", str(config_path)]
    _log.info("cpu_probe.launch argv=%r timeout_s=%s", argv, cfg.timeout_s)

    deadline = monotonic() + cfg.timeout_s
    try:
        with open(log_path, "w") as log_fh:
            try:
                proc = subprocess_runner(argv, stdout=log_fh, stderr=subprocess.STDOUT)
            except OSError as exc:
                raise CpuProbeError(f"failed to launch firecracker: {exc}") from exc
            try:
                while True:
                    if _console_is_terminal(_read_text(log_path), cfg):
                        break
                    if proc.poll() is not None:  # VM exited; do a final read below
                        break
                    if monotonic() >= deadline:
                        _log.warning("cpu_probe.timeout after %ss", cfg.timeout_s)
                        break
                    sleep(poll_interval_s)
            finally:
                _terminate(proc)
    except CpuProbeError:
        raise
    except OSError as exc:
        raise CpuProbeError(f"probe I/O error: {exc}") from exc

    result = classify_probe_console(
        _read_text(log_path),
        restore_ok_marker=cfg.restore_ok_marker,
    )
    _log.info("cpu_probe.result status=%s needed=%s", result.status.value, result.needed)
    return result
