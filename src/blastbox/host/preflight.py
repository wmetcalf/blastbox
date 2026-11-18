"""Read-only host preflight for blastbox agent/dispatcher hosts.

``blastbox preflight`` answers "is this host prepared for the tiers it will run?" before a
dispatcher is started on it, and reports PASS / WARN / FAIL per check with a pointer into
``docs/HOST-PREP.md``. It complements ``blastbox doctor`` (which reports what is already
*running*); this reports what the *host* provides.

It never modifies the host. Every file it touches is read; every command it spawns is checked
against :data:`_READ_ONLY_ARGV` by :meth:`RealHost.run` before it is executed, so a future
check cannot quietly shell out to ``systemctl`` or ``apparmor_parser`` -- the remediation for
each finding is printed for the operator to run, never run here.

All host access goes through :class:`HostView`, so every check is unit-tested against a fake
host (``tests/host/test_preflight.py``) with no dependence on the machine running the tests.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

DOC = "docs/HOST-PREP.md"

#: Tier vocabulary, in canonical (report) order.
TIERS: tuple[str, ...] = ("docker", "gvisor", "firecracker", "remote")
_LOCAL_TIERS = ["docker", "gvisor", "firecracker"]
_REMOTE_POOL_RUNTIMES = {
    "static", "cascade", "aws-ec2", "aws-ec2-hibernate", "aws-lambda-microvm",
    "aws-lambda-snapstart",
}

_DEFAULT_JOB_ROOT = "/var/lib/blastbox/jobs"

# The ONLY command shapes preflight may spawn: (argv[1:]) tails, binary-agnostic because the
# binary path comes from PATH or an env knob. Each is a pure query.
_READ_ONLY_ARGV: frozenset[tuple[str, ...]] = frozenset({
    ("--version",),                                         # firecracker / runsc
    ("version", "--format", "{{.Server.Version}}"),         # docker
    ("info", "--format", "{{json .Runtimes}}"),             # docker
    ("show", "-p", "NTPSynchronized", "--value"),           # timedatectl
    ("-n", "tracking"),                                     # chronyc
})
_READ_ONLY_BINARIES = frozenset({"docker", "runsc", "firecracker", "timedatectl", "chronyc"})

_RUN_TIMEOUT_S = 15.0
_READ_CHUNK = 64 * 1024
_READ_CAP = 4 * 1024 * 1024


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str
    doc: str = ""          # "docs/HOST-PREP.md#anchor", printed as the fix pointer


class NotReadOnly(RuntimeError):
    """A command outside the read-only allowlist was asked for. A preflight bug, never a host
    condition: raising (rather than returning None) makes it fail tests loudly."""


def is_read_only(argv: Sequence[str]) -> bool:
    """True iff ``argv`` is one of the pure queries preflight is allowed to spawn."""
    if not argv:
        return False
    if tuple(argv[1:]) not in _READ_ONLY_ARGV:
        return False
    # --version is allowed for any configured binary (BLASTBOX_FC_BIN may be renamed);
    # the subcommand forms only for the tool they belong to.
    base = os.path.basename(argv[0])
    return tuple(argv[1:]) == ("--version",) or base in _READ_ONLY_BINARIES


class HostView:
    """Everything preflight reads from the host. Subclassed by tests with a fake."""

    env: Mapping[str, str]

    def read(self, path: str) -> str | None:
        raise NotImplementedError

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def rw_access(self, path: str) -> bool:
        raise NotImplementedError

    def which(self, name: str) -> str | None:
        """Resolved executable path for a name or an absolute path; None if not executable."""
        raise NotImplementedError

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        """Run a read-only query; None if it could not be spawned or timed out."""
        raise NotImplementedError


class RealHost(HostView):
    def __init__(self) -> None:
        self.env = os.environ

    def read(self, path: str) -> str | None:
        # Chunked: a /proc/sys handler fails ONE large read() with ENOMEM (a 4 MiB read of
        # max_user_namespaces does), which would make every sysctl look absent.
        parts: list[str] = []
        total = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                while total < _READ_CAP:
                    chunk = fh.read(min(_READ_CHUNK, _READ_CAP - total))
                    if not chunk:
                        break
                    parts.append(chunk)
                    total += len(chunk)
        except OSError:
            return None
        return "".join(parts)

    def exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def rw_access(self, path: str) -> bool:
        return os.access(path, os.R_OK | os.W_OK)

    def which(self, name: str) -> str | None:
        if os.path.isabs(name):
            return name if os.path.isfile(name) and os.access(name, os.X_OK) else None
        return shutil.which(name)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        if not is_read_only(argv):
            raise NotReadOnly(f"preflight refused a non-read-only command: {list(argv)!r}")
        try:
            return subprocess.run(list(argv), capture_output=True, text=True,
                                  timeout=_RUN_TIMEOUT_S, check=False)
        except (OSError, subprocess.SubprocessError):
            return None


# --- tier resolution --------------------------------------------------------------------

def resolve_tiers(requested: Sequence[str], env: Mapping[str, str]) -> list[str]:
    """The tiers to check, in canonical order.

    Explicit ``--tier`` values win (``all`` = every tier). Otherwise: the cold docker
    dispatcher always, plus the tier ``BLASTBOX_POOL_RUNTIME`` selects; with nothing
    configured, every local tier (a host being prepared has not chosen yet).
    """
    chosen: set[str] = set()
    for t in requested:
        t = t.strip().lower()
        if t == "all":
            chosen.update(TIERS)
        elif t in TIERS:
            chosen.add(t)
        else:
            raise ValueError(f"unknown tier {t!r}; expected one of {', '.join(TIERS)}, all")
    if not requested:
        pool = env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower()
        if not pool:
            chosen.update(_LOCAL_TIERS)
        else:
            chosen.add("docker")
            if pool in ("firecracker", "gvisor"):
                chosen.add(pool)
            elif pool in _REMOTE_POOL_RUNTIMES:
                chosen.add("remote")
    return [t for t in TIERS if t in chosen]


# --- helpers ----------------------------------------------------------------------------

def _first_line(text: str | None) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() not in ("", "0", "false", "no", "off")


def _loaded_profiles(host: HostView) -> set[str] | None:
    """Loaded AppArmor profile names, or None when securityfs is unreadable (root-only)."""
    raw = host.read("/sys/kernel/security/apparmor/profiles")
    if raw is None:
        return None
    return {line.split(" (", 1)[0].strip() for line in raw.splitlines() if line.strip()}


def _sysctl(host: HostView, path: str) -> str | None:
    raw = host.read(path)
    return raw.strip() if raw is not None else None


def _under_tmp(path: str) -> bool:
    norm = os.path.normpath(path)
    return norm == "/tmp" or norm.startswith("/tmp/") or norm == "/var/tmp" \
        or norm.startswith("/var/tmp/")


# --- checks -----------------------------------------------------------------------------

def _check_docker(host: HostView) -> Check:
    doc = f"{DOC}#plain-docker-cold-tier"
    docker = host.which("docker")
    if docker is None:
        return Check("docker", Status.FAIL, "docker CLI not found on PATH", doc)
    proc = host.run([docker, "version", "--format", "{{.Server.Version}}"])
    if proc is None:
        return Check("docker", Status.FAIL, "docker version did not complete", doc)
    if proc.returncode != 0:
        why = _first_line(proc.stderr) or _first_line(proc.stdout) or f"rc={proc.returncode}"
        return Check("docker", Status.FAIL, f"daemon unreachable: {why}", doc)
    return Check("docker", Status.PASS, f"daemon reachable (server {_first_line(proc.stdout)})")


def _check_docker_runsc(host: HostView) -> Check:
    doc = f"{DOC}#gvisor-runsc"
    env = host.env
    runc_consented = (env.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower() == "runc"
                      and _truthy(env.get("BLASTBOX_ALLOW_RUNC"))
                      and not _truthy(env.get("BLASTBOX_REQUIRE_SECURE_RUNTIME")))
    missing = Status.WARN if runc_consented else Status.FAIL
    fix = ("install it with `sudo runsc install` then `sudo systemctl reload docker` "
           "(SIGHUP -- never restart, which stops every running container)")
    docker = host.which("docker")
    proc = host.run([docker, "info", "--format", "{{json .Runtimes}}"]) if docker else None
    if proc is None or proc.returncode != 0:
        return Check("docker-runsc-runtime", missing,
                     "could not read docker's runtimes (docker unreachable?)", doc)
    try:
        parsed = json.loads(proc.stdout.strip() or "{}")
    except json.JSONDecodeError:
        parsed = {}
    names = {str(k).strip().lower() for k in (parsed if isinstance(parsed, (dict, list)) else [])}
    if "runsc" in names:
        return Check("docker-runsc-runtime", Status.PASS, "runsc is a registered docker runtime")
    extra = " (runc explicitly consented, degraded mode)" if runc_consented else \
        " -- the dispatcher fails closed without it"
    return Check("docker-runsc-runtime", missing,
                 f"runsc is not a registered docker runtime{extra}; {fix}", doc)


def _check_runsc_binary(host: HostView) -> Check:
    doc = f"{DOC}#gvisor-runsc"
    name = host.env.get("BLASTBOX_GVISOR_RUNSC", "").strip() or "runsc"
    path = host.which(name)
    if path is None:
        return Check("runsc", Status.FAIL, f"runsc binary {name!r} not found/executable", doc)
    proc = host.run([path, "--version"])
    ver = _first_line(proc.stdout if proc else "") or "version unknown"
    return Check("runsc", Status.PASS, f"{path}: {ver}")


def _check_kvm(host: HostView) -> Check:
    doc = f"{DOC}#firecracker"
    if not host.exists("/dev/kvm"):
        return Check("kvm", Status.FAIL,
                     "/dev/kvm missing: no hardware virtualisation (BIOS VT-x/AMD-V, "
                     "kvm_intel/kvm_amd module, or nested virt on a VM host)", doc)
    if not host.rw_access("/dev/kvm"):
        return Check("kvm", Status.FAIL,
                     f"/dev/kvm not read/write for uid {os.getuid()}: add the dispatcher user "
                     "to the kvm group (or pass --device /dev/kvm to its container)", doc)
    return Check("kvm", Status.PASS, "/dev/kvm present and read/write")


def _check_firecracker(host: HostView) -> Check:
    from blastbox.host.runtime.firecracker import _MIN_FC_VERSION  # noqa: PLC0415

    doc = f"{DOC}#firecracker"
    name = host.env.get("BLASTBOX_FC_BIN", "").strip() or "firecracker"
    path = host.which(name)
    if path is None:
        return Check("firecracker", Status.FAIL,
                     f"firecracker binary {name!r} not found/executable", doc)
    proc = host.run([path, "--version"])
    text = (proc.stdout + proc.stderr) if proc else ""
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)", text)
    minimum = ".".join(map(str, _MIN_FC_VERSION))
    if not m:
        return Check("firecracker", Status.WARN,
                     f"{path}: could not parse a version (need >= {minimum})", doc)
    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    shown = ".".join(map(str, ver))
    if ver < _MIN_FC_VERSION:
        return Check("firecracker", Status.FAIL,
                     f"{path}: v{shown} is older than the required v{minimum} "
                     "(virtio-rng entropy device DoS on older releases)", doc)
    return Check("firecracker", Status.PASS, f"{path}: v{shown}")


def _check_fc_guest(host: HostView) -> Check:
    doc = f"{DOC}#firecracker"
    kernel = host.env.get("BLASTBOX_FC_KERNEL", "").strip()
    rootfs = host.env.get("BLASTBOX_FC_ROOTFS", "").strip()
    if not kernel and not rootfs:
        return Check("fc-guest", Status.WARN,
                     "BLASTBOX_FC_KERNEL/BLASTBOX_FC_ROOTFS unset here (check from the FC "
                     "dispatcher's environment to verify the guest artifacts)", doc)
    missing = [f"{k}={v or '<unset>'}" for k, v in
               (("BLASTBOX_FC_KERNEL", kernel), ("BLASTBOX_FC_ROOTFS", rootfs))
               if not v or not host.exists(v)]
    if missing:
        return Check("fc-guest", Status.FAIL, "missing guest artifact: " + ", ".join(missing),
                     doc)
    return Check("fc-guest", Status.PASS, f"kernel {kernel}, rootfs {rootfs}")


def _check_snapshot_age(host: HostView) -> Check:
    doc = f"{DOC}#clock-and-aged-warm-checkpoints"
    raw = host.env.get("BLASTBOX_SNAPSHOT_MAX_AGE_S", "").strip()
    if raw == "0":
        return Check("snapshot-age", Status.WARN,
                     "BLASTBOX_SNAPSHOT_MAX_AGE_S=0 disables warm-base refresh: a checkpoint "
                     "restored long after it was taken sees its monotonic clock jump and "
                     "every job hangs (the ~24h warm outage)", doc)
    return Check("snapshot-age", Status.PASS,
                 f"warm bases refresh after {raw or '21600 (default)'}s")


def _needs_userns(env: Mapping[str, str]) -> list[str]:
    why = []
    sandbox = env.get("BLASTBOX_SANDBOX", "").strip().lower()
    if sandbox in ("bwrap", "nsjail"):
        why.append(f"BLASTBOX_SANDBOX={sandbox}")
    if env.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower() == "runc":
        why.append("BLASTBOX_WORKER_RUNTIME=runc (inner nsjail/bwrap)")
    if _truthy(env.get("BLASTBOX_GVISOR_ROOTLESS")):
        why.append("BLASTBOX_GVISOR_ROOTLESS")
    return why


def _check_userns(host: HostView) -> Check:
    doc = f"{DOC}#apparmor-and-user-namespaces"
    restrict = _sysctl(host, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    max_ns = _sysctl(host, "/proc/sys/user/max_user_namespaces")
    clone = _sysctl(host, "/proc/sys/kernel/unprivileged_userns_clone")
    shown = ", ".join(f"{k}={v}" for k, v in (
        ("apparmor_restrict_unprivileged_userns", restrict),
        ("max_user_namespaces", max_ns),
        ("unprivileged_userns_clone", clone)) if v is not None) or "no userns sysctls readable"
    needs = _needs_userns(host.env)
    if max_ns == "0" or clone == "0":
        status = Status.FAIL if needs else Status.WARN
        return Check("userns", status,
                     f"{shown}: unprivileged user namespaces are off; nsjail/bwrap inner "
                     f"sandboxes cannot start" + (f" ({'; '.join(needs)})" if needs else ""),
                     doc)
    if restrict == "1" and needs:
        loaded = _loaded_profiles(host)
        wanted = {"blastbox-bwrap", "blastbox-nsjail"}
        if loaded is not None and wanted <= loaded:
            return Check("userns", Status.PASS,
                         f"{shown}; scoped blastbox-bwrap/blastbox-nsjail profiles loaded")
        state = "not loaded" if loaded is not None else "unverifiable (securityfs is root-only)"
        return Check("userns", Status.WARN,
                     f"{shown}; {'; '.join(needs)} needs the scoped deploy/apparmor profiles "
                     f"({state})", doc)
    note = " (fine: rootful runsc and firecracker do not use host user namespaces)" \
        if restrict == "1" else ""
    return Check("userns", Status.PASS, shown + note)


def _check_apparmor(host: HostView) -> Check:
    doc = f"{DOC}#apparmor-and-user-namespaces"
    raw = _sysctl(host, "/sys/module/apparmor/parameters/enabled")
    if raw is None:
        return Check("apparmor", Status.WARN,
                     "AppArmor not present (another LSM?): docker-default is not applied to "
                     "runsc/worker processes and no child profile can be attached", doc)
    if raw.upper().startswith("Y"):
        return Check("apparmor", Status.PASS, "AppArmor enabled")
    return Check("apparmor", Status.WARN,
                 "AppArmor disabled: docker-default is not applied to runsc/worker processes "
                 "and no child profile can be attached", doc)


def _check_bwrap_stock_profile(host: HostView) -> Check:
    doc = f"{DOC}#the-stock-bwrap-userns-restrict-profile"
    path = "/etc/apparmor.d/bwrap-userns-restrict"
    disabled = host.exists("/etc/apparmor.d/disable/bwrap-userns-restrict")
    loaded_names = _loaded_profiles(host)
    loaded = None if loaded_names is None else bool({"bwrap", "unpriv_bwrap"} & loaded_names)
    present = host.exists(path)
    if not present and not loaded:
        return Check("bwrap-userns-restrict", Status.PASS, "stock profile not installed")
    if disabled:
        if loaded:
            return Check("bwrap-userns-restrict", Status.WARN,
                         "stock profile is disabled for next boot but still loaded; unload it: "
                         f"sudo apparmor_parser -R {path}", doc)
        suffix = "" if loaded is not None else " (load state unverifiable without root)"
        return Check("bwrap-userns-restrict", Status.PASS, "stock profile disabled" + suffix)
    return Check("bwrap-userns-restrict", Status.WARN,
                 "Ubuntu's stock bwrap-userns-restrict profile is active: it confines what "
                 "bwrap-based engines can do inside their namespace; see the guide for when to "
                 "disable it", doc)


def _check_clock(host: HostView) -> Check:
    doc = f"{DOC}#clock-and-aged-warm-checkpoints"
    tdc = host.which("timedatectl")
    if tdc:
        proc = host.run([tdc, "show", "-p", "NTPSynchronized", "--value"])
        if proc is not None and proc.returncode == 0:
            val = _first_line(proc.stdout).lower()
            if val == "yes":
                return Check("clock", Status.PASS, "NTP synchronized (timedatectl)")
            if val == "no":
                return Check("clock", Status.WARN,
                             "clock NOT synchronized (timedatectl NTPSynchronized=no)", doc)
    chronyc = host.which("chronyc")
    if chronyc:
        proc = host.run([chronyc, "-n", "tracking"])
        if proc is not None and proc.returncode == 0:
            m = re.search(r"^Leap status\s*:\s*(.+)$", proc.stdout, re.MULTILINE)
            leap = m.group(1).strip() if m else ""
            if leap.lower() == "normal":
                return Check("clock", Status.PASS, "synchronized (chrony leap status Normal)")
            return Check("clock", Status.WARN,
                         f"chrony leap status {leap or 'unknown'!r} (not synchronized)", doc)
    return Check("clock", Status.WARN,
                 "could not determine clock sync (no timedatectl/chronyc answer)", doc)


def _check_cpu_flags(host: HostView) -> Check:
    doc = f"{DOC}#cpu-features"
    raw = host.read("/proc/cpuinfo")
    if raw is None:
        return Check("cpu-flags", Status.WARN, "/proc/cpuinfo unreadable", doc)
    flags: set[str] = set()
    for line in raw.splitlines():
        key, _, val = line.partition(":")
        if key.strip() == "flags":
            flags.update(val.split())
    if "avx512vbmi" in flags:
        return Check("cpu-flags", Status.WARN,
                     "avx512vbmi present: run JVM engines with -XX:-UseBASE64Intrinsics "
                     "(CVE-2026-114938 'Java4Shell'); also pins CRaC/warm CPU features", doc)
    return Check("cpu-flags", Status.PASS, "no CPU flags of note (avx512vbmi absent)")


def _check_scratch(host: HostView, tiers: Sequence[str]) -> Check:
    doc = f"{DOC}#disk-and-scratch"
    env = host.env
    dirs = [("BLASTBOX_JOB_ROOT", env.get("BLASTBOX_JOB_ROOT", "").strip() or _DEFAULT_JOB_ROOT)]
    if "firecracker" in tiers or "gvisor" in tiers:
        for knob in ("BLASTBOX_SNAPSHOT_MEM_DIR", "BLASTBOX_GVISOR_ROOT"):
            if env.get(knob, "").strip():
                dirs.append((knob, env[knob].strip()))
    on_tmp = [f"{k}={v}" for k, v in dirs if _under_tmp(v)]
    if on_tmp:
        return Check("scratch", Status.WARN,
                     "under /tmp (tmpfiles cleanup / tmpfs size / reboot loses sealed "
                     "results): " + ", ".join(on_tmp), doc)
    job_root = dirs[0][1]
    if not host.exists(job_root):
        return Check("scratch", Status.WARN, f"job root {job_root} does not exist", doc)
    return Check("scratch", Status.PASS, ", ".join(f"{k}={v}" for k, v in dirs))


def run_preflight(host: HostView, tiers: Sequence[str]) -> list[Check]:
    """Run every check relevant to ``tiers``. Pure reads; never raises on host state."""
    t = set(tiers)
    out: list[Check] = []
    if t & {"docker", "gvisor"}:
        out.append(_check_docker(host))
        out.append(_check_docker_runsc(host))
    if "gvisor" in t:
        out.append(_check_runsc_binary(host))
    if "firecracker" in t:
        out.append(_check_kvm(host))
        out.append(_check_firecracker(host))
        out.append(_check_fc_guest(host))
    if t & {"gvisor", "firecracker"}:
        out.append(_check_snapshot_age(host))
    out.append(_check_apparmor(host))
    out.append(_check_bwrap_stock_profile(host))
    out.append(_check_userns(host))
    out.append(_check_clock(host))
    out.append(_check_cpu_flags(host))
    out.append(_check_scratch(host, tiers))
    return out


# --- output -----------------------------------------------------------------------------

def exit_code(checks: Sequence[Check], *, strict: bool = False) -> int:
    if any(c.status is Status.FAIL for c in checks):
        return 1
    if strict and any(c.status is Status.WARN for c in checks):
        return 1
    return 0


def _counts(checks: Sequence[Check]) -> dict[str, int]:
    return {s.value: sum(1 for c in checks if c.status is s) for s in Status}


def render_text(checks: Sequence[Check], tiers: Sequence[str]) -> str:
    width = max((len(c.name) for c in checks), default=0)
    lines = [f"blastbox host preflight (read-only) -- tiers: {', '.join(tiers)}"]
    for c in checks:
        lines.append(f"{c.status.value}  {c.name:<{width}}  {c.detail}")
        if c.status is not Status.PASS and c.doc:
            lines.append(f"      {'':<{width}}  -> see {c.doc}")
    n = _counts(checks)
    lines.append(f"summary: {n['PASS']} pass, {n['WARN']} warn, {n['FAIL']} fail")
    return "\n".join(lines) + "\n"


def render_json(checks: Sequence[Check], tiers: Sequence[str]) -> str:
    return json.dumps({
        "tiers": list(tiers),
        "ok": exit_code(checks) == 0,
        "counts": _counts(checks),
        "checks": [{"name": c.name, "status": c.status.value, "detail": c.detail,
                    "doc": c.doc} for c in checks],
    }, indent=2, sort_keys=True)
