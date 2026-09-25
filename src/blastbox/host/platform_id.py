"""What a warm artifact is valid ON: architecture, CPU, runtime.

The rootfs stamp records which blastbox built an artifact. That is half the
compatibility question. The other half is the machine, and it is the half that
fails most obscurely.

A warm artifact is a frozen machine state, so it is only valid for a
*(blastbox, arch, CPU, runtime)* tuple:

* Firecracker compares the CPU **vendor** on every snapshot restore -- the
  vendor id is printed on both sides of every `/snapshot/load` in our logs.
* A CRaC checkpoint records the CPU **feature set** of the host that made it.
  Restore it where a feature is missing and the JVM dies with the generic
  "Could not create the Java Virtual Machine": the slot simply never signals
  READY, and surfaces as an opaque warmup timeout. `cpu_features.py` exists only
  to recover the real reason by parsing it back out of a serial console
  afterwards.
* An ext4 Firecracker rootfs is not a runsc directory tree, and an aarch64
  rootfs will not boot on x86_64 at all.

This module is the comparison. What a given ARTIFACT is bound to is the caller's
call: a rootfs holds no CPU state (its snapshot is taken on the deploying host),
so `rootfs_stamp.platform_of` passes only architecture and runtime, and the CPU
fields are compared only for artifacts that carry checkpoint state.

Severity is per field, because the fields differ in kind. An architecture or
vendor mismatch cannot work and is refused. A runtime version difference usually
can and is reported. An artifact recording NOTHING predates this check and is
allowed with a warning -- the same rule the rootfs stamp uses, for the same
reason: refusing every artifact built before the check existed takes a fleet
offline on upgrade, which is worse than the failure being prevented.
"""

from __future__ import annotations

import os
import platform as _stdlib_platform
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

#: Severities, worst first. REFUSE means the artifact cannot run here.
REFUSE = "refuse"
WARN = "warn"


@dataclass(frozen=True)
class Finding:
    """One field's verdict."""

    field: str
    severity: str
    message: str

    @property
    def fatal(self) -> bool:
        return self.severity == REFUSE


@dataclass(frozen=True)
class HostPlatform:
    """The machine an artifact was baked on, or is being restored on."""

    arch: str = ""
    cpu_vendor: str = ""
    cpu_model: str = ""
    runtime: str = ""
    runtime_version: str = ""
    kernel: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: object) -> "HostPlatform":
        if not isinstance(raw, dict):
            return cls()
        known = {f: raw.get(f, "") for f in cls.__dataclass_fields__}
        return cls(**{k: ("" if v is None else str(v)) for k, v in known.items()})

    def is_empty(self) -> bool:
        return not any(asdict(self).values())


def _cpuinfo_fields(text: str) -> tuple[str, str]:
    """(vendor, model) from /proc/cpuinfo's FIRST processor block."""
    vendor = model = ""
    for line in text.splitlines():
        if not line.strip():
            if vendor or model:
                break  # end of the first block
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "vendor_id" and not vendor:
            vendor = value
        elif key == "model name" and not model:
            model = value
    return vendor, model


def host_platform(
    *,
    runtime: str = "",
    runtime_version: str = "",
    cpuinfo: str | Path = "/proc/cpuinfo",
) -> HostPlatform:
    """Capture this machine. Never raises: an unreadable field is "" , not a crash."""
    vendor = model = ""
    try:
        vendor, model = _cpuinfo_fields(Path(cpuinfo).read_text())
    except OSError:
        pass
    return HostPlatform(
        arch=_stdlib_platform.machine(),
        cpu_vendor=vendor,
        cpu_model=model,
        runtime=runtime,
        runtime_version=runtime_version,
        kernel=_stdlib_platform.release(),
    )


def compare(recorded: HostPlatform, live: HostPlatform) -> list[Finding]:
    """Why ``recorded`` may not run on ``live``. Empty means no objection.

    A field absent on EITHER side is not compared: "" means "not recorded", and
    treating an unrecorded value as a mismatch would refuse every older artifact.
    """
    out: list[Finding] = []
    if recorded.is_empty():
        return [
            Finding(
                "platform",
                WARN,
                "this artifact records no platform, so it cannot be checked against "
                "this host; rebuild it with `blastbox build-images` to record the "
                "architecture and runtime it is valid on",
            )
        ]

    def both(name: str) -> tuple[str, str] | None:
        a, b = getattr(recorded, name), getattr(live, name)
        return (a, b) if a and b else None

    if (pair := both("arch")) and pair[0] != pair[1]:
        out.append(
            Finding(
                "arch",
                REFUSE,
                f"built for {pair[0]}, this host is {pair[1]}: a rootfs for another "
                f"architecture cannot boot here",
            )
        )
    if (pair := both("cpu_vendor")) and pair[0] != pair[1]:
        out.append(
            Finding(
                "cpu_vendor",
                REFUSE,
                f"baked on {pair[0]}, this host is {pair[1]}: Firecracker compares the "
                f"CPU vendor on every snapshot restore, and a CRaC checkpoint carries "
                f"the feature set of the machine that made it",
            )
        )
    if (pair := both("runtime")) and pair[0] != pair[1]:
        out.append(
            Finding(
                "runtime",
                REFUSE,
                f"built for the {pair[0]} tier, offered to {pair[1]}: an ext4 "
                f"Firecracker rootfs is not a runsc directory tree",
            )
        )
    if (pair := both("runtime_version")) and pair[0] != pair[1]:
        out.append(
            Finding(
                "runtime_version",
                WARN,
                f"baked against {recorded.runtime or 'runtime'} {pair[0]}, this host "
                f"runs {pair[1]}: snapshot formats are version-sensitive",
            )
        )
    if (pair := both("cpu_model")) and pair[0] != pair[1]:
        out.append(
            Finding(
                "cpu_model",
                WARN,
                f"baked on {pair[0]!r}, this host is {pair[1]!r}: same vendor, but a "
                f"CRaC checkpoint may still require features this model lacks "
                f"(the restore prints the -XX:CPUFeatures= value to use)",
            )
        )
    if (pair := both("kernel")) and pair[0] != pair[1]:
        out.append(
            Finding("kernel", WARN, f"baked on kernel {pair[0]}, this host runs {pair[1]}")
        )
    return out


def refusals(findings: Sequence[Finding]) -> list[Finding]:
    return [f for f in findings if f.fatal]


def summarise(findings: Sequence[Finding]) -> str:
    """One line per finding, worst first."""
    ordered = sorted(findings, key=lambda f: 0 if f.fatal else 1)
    return "; ".join(f"{f.field}: {f.message}" for f in ordered)


def firecracker_runtime_version(fc_bin: str = "firecracker", *, run: Runner | None = None) -> str:
    """`firecracker --version` as a bare version, or "" when it cannot be read."""
    path = shutil.which(fc_bin) or fc_bin
    if not os.access(path, os.X_OK):
        return ""
    runner = run or _default_runner
    try:
        proc = runner([path, "--version"], capture_output=True, text=True)
    except Exception:  # noqa: BLE001 - diagnostic only
        return ""
    match = re.search(r"v?(\d+\.\d+\.\d+)", (proc.stdout or "") + (proc.stderr or ""))
    return match.group(1) if match else ""


def runsc_runtime_version(runsc_bin: str = "runsc", *, run: Runner | None = None) -> str:
    path = shutil.which(runsc_bin) or runsc_bin
    if not os.access(path, os.X_OK):
        return ""
    runner = run or _default_runner
    try:
        proc = runner([path, "--version"], capture_output=True, text=True)
    except Exception:  # noqa: BLE001 - diagnostic only
        return ""
    match = re.search(r"release-(\S+)", (proc.stdout or "") + (proc.stderr or ""))
    return match.group(1) if match else ""


def _default_runner(
    argv: Sequence[str], **kwargs: object
) -> "subprocess.CompletedProcess[str]":  # pragma: no cover - thin wrapper
    return subprocess.run(list(argv), check=False, **kwargs)  # type: ignore[call-overload,no-any-return]


__all__ = [
    "REFUSE",
    "WARN",
    "Finding",
    "HostPlatform",
    "compare",
    "firecracker_runtime_version",
    "host_platform",
    "refusals",
    "runsc_runtime_version",
    "summarise",
]
