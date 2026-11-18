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
import math
import os
import re
import shutil
import subprocess
from collections.abc import Collection, Mapping, Sequence
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
    ("help",),                                              # runsc C/R probe
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
    base = os.path.basename(argv[0])
    # --version and help (the runsc C/R probe) are allowed for any configured binary: the
    # path comes from an operator knob (BLASTBOX_FC_BIN / BLASTBOX_GVISOR_RUNSC) and may be
    # renamed; the subcommand forms only for the tool they belong to.
    return tuple(argv[1:]) in (("--version",), ("help",)) or base in _READ_ONLY_BINARIES


class HostView:
    """Everything preflight reads from the host. Subclassed by tests with a fake."""

    env: Mapping[str, str]
    euid: int

    def read(self, path: str) -> str | None:
        raise NotImplementedError

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def rw_access(self, path: str) -> bool:
        raise NotImplementedError

    def which(self, name: str) -> str | None:
        """Resolved executable path for a name or an absolute path; None if not executable."""
        raise NotImplementedError

    def listdir(self, path: str) -> list[str] | None:
        """Entry names of a directory; None if it cannot be listed."""
        raise NotImplementedError

    def realpath(self, path: str) -> str:
        """``path`` with symlinks resolved (AppArmor attaches to the resolved executable)."""
        raise NotImplementedError

    def is_file(self, path: str) -> bool:
        """True for a regular file (following symlinks; a dangling link or directory is not)."""
        raise NotImplementedError

    def guest_kernel_version(self, path: str) -> tuple[int, int] | None:
        """``(major, minor)`` from a vmlinux banner; None when unknown."""
        raise NotImplementedError

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        """Run a read-only query; None if it could not be spawned or timed out."""
        raise NotImplementedError


class RealHost(HostView):
    def __init__(self) -> None:
        self.env = os.environ
        self.euid = os.geteuid()

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

    def listdir(self, path: str) -> list[str] | None:
        try:
            return os.listdir(path)
        except OSError:
            return None

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def guest_kernel_version(self, path: str) -> tuple[int, int] | None:
        from blastbox.host.runtime.firecracker import guest_kernel_version  # noqa: PLC0415

        return guest_kernel_version(path)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        if not is_read_only(argv):
            raise NotReadOnly(f"preflight refused a non-read-only command: {list(argv)!r}")
        try:
            return subprocess.run(list(argv), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=_RUN_TIMEOUT_S, check=False)
        except (OSError, subprocess.SubprocessError):
            return None


# --- tier resolution --------------------------------------------------------------------

def resolve_tiers(requested: Sequence[str], env: Mapping[str, str]) -> list[str]:
    """The tiers to check, in canonical order.

    Explicit ``--tier`` values win (``all`` = every tier). Otherwise: the tier(s)
    ``BLASTBOX_POOL_RUNTIME`` selects, plus the cold docker tier on a local (file-handshake)
    dispatcher that is not warm-only; with nothing configured, every local tier (a host being
    prepared has not chosen yet).
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
            members = [pool]
            if pool == "cascade":
                # A cascade's members are whatever BLASTBOX_POOL_TIERS lists ("firecracker:2,
                # aws-ec2:4"), and local members need their local checks.
                # Names as given: the dispatcher matches them case-sensitively and skips an
                # overflow member it cannot select, so a mis-cased one adds no tier.
                members = [item.partition(":")[0].strip()
                           for item in env.get("BLASTBOX_POOL_TIERS", "").split(",")
                           if item.strip()]
            for member in members:
                if member in ("firecracker", "gvisor"):
                    chosen.add(member)
                elif member in _REMOTE_POOL_RUNTIMES:
                    chosen.add("remote")
            # The cold docker path exists only on a file-handshake (local) dispatcher that is not
            # warm-only; network-endpoint pools requeue instead (dispatch.py, "no cold path").
            warm_only = env.get("BLASTBOX_DISPATCH_WARM_ONLY", "").strip().lower() in (
                "1", "true", "yes", "on")
            if not (chosen & {"remote"}) and not warm_only:
                chosen.add("docker")
    return [t for t in TIERS if t in chosen]


# --- helpers ----------------------------------------------------------------------------

def _first_line(text: str | None) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() not in ("", "0", "false", "no", "off")


def _docker_flag(val: str | None) -> bool:
    """Truthiness exactly as ``runtime/docker.py`` reads BLASTBOX_ALLOW_RUNC /
    BLASTBOX_REQUIRE_SECURE_RUNTIME (``off`` counts as SET there)."""
    return (val or "").strip().lower() not in ("", "0", "false", "no")


def _loaded_profiles(host: HostView) -> set[str] | None:
    """Loaded AppArmor profile names, or None when securityfs is unreadable (root-only)."""
    raw = host.read("/sys/kernel/security/apparmor/profiles")
    if raw is None:
        return None
    return {line.split(" (", 1)[0].strip() for line in raw.splitlines() if line.strip()}


def _sysctl(host: HostView, path: str) -> str | None:
    raw = host.read(path)
    return raw.strip() if raw is not None else None


def _tmpfs(host: HostView, path: str) -> bool:
    """Whether ``path`` lives on a tmpfs: the longest /proc/mounts mountpoint containing it, the
    LAST such entry winning (an over-mount hides what is under it)."""
    best, fstype = -1, ""
    for line in (host.read("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mnt = parts[1]
        inside = path == mnt or path.startswith(mnt.rstrip("/") + "/")
        if inside and len(mnt) >= best:
            best, fstype = len(mnt), parts[2]
    return fstype == "tmpfs"


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
    forced = env.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower()
    runc_allowed = (_docker_flag(env.get("BLASTBOX_ALLOW_RUNC"))
                    and not _docker_flag(env.get("BLASTBOX_REQUIRE_SECURE_RUNTIME")))
    if forced == "runc":
        # select_worker_runtime() honours the forced runtime even when runsc is registered,
        # and _finalize_runtime() refuses runc without consent: every cold job is refused.
        if not runc_allowed:
            return Check("docker-runsc-runtime", Status.FAIL,
                         "BLASTBOX_WORKER_RUNTIME=runc forces plain runc, which the dispatcher "
                         "refuses (needs BLASTBOX_ALLOW_RUNC=1 and no "
                         "BLASTBOX_REQUIRE_SECURE_RUNTIME); unset it to use runsc", doc)
        return Check("docker-runsc-runtime", Status.WARN,
                     "BLASTBOX_WORKER_RUNTIME=runc with BLASTBOX_ALLOW_RUNC=1: cold workers run "
                     "WITHOUT gVisor (explicit degraded mode)", doc)
    # Auto-selection falls back to runc when runsc is missing; that runs only with consent.
    # A forced runsc never falls back, so its absence fails whatever the consent.
    missing = Status.WARN if runc_allowed and forced != "runsc" else Status.FAIL
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
    extra = " (runc explicitly consented, degraded mode)" if runc_allowed else \
        " -- the dispatcher fails closed without it"
    return Check("docker-runsc-runtime", missing,
                 f"runsc is not a registered docker runtime{extra}; {fix}", doc)


def _check_runsc_binary(host: HostView) -> Check:
    doc = f"{DOC}#gvisor-runsc"
    # Exactly as gvisor_snapshot_runtime reads it: no strip, and set-but-empty is NOT "runsc"
    # (a compose ${BLASTBOX_GVISOR_RUNSC:-} passes ""), so mirror that instead of masking it.
    name = host.env.get("BLASTBOX_GVISOR_RUNSC", "runsc")
    path = host.which(name) if name and name == name.strip() else None
    if path is None:
        return Check("runsc", Status.FAIL, f"runsc binary {name!r} not found/executable", doc)
    proc = host.run([path, "--version"])
    if proc is None:
        return Check("runsc", Status.FAIL, f"{path} --version did not run (spawn failure or "
                     "timeout)", doc)
    if proc.returncode != 0:
        why = _first_line(proc.stderr) or _first_line(proc.stdout) or f"rc={proc.returncode}"
        return Check("runsc", Status.FAIL, f"{path} --version failed: {why}", doc)
    ver = _first_line(proc.stdout) or "version unknown"
    # The warm tier's own capability probe (gvisor_snapshot._default_cr_capable): `runsc help`
    # must list both checkpoint and restore, else the tier is refused.
    helped = host.run([path, "help"])
    text = (helped.stdout + helped.stderr) if helped is not None else ""
    if "checkpoint" not in text or "restore" not in text:
        return Check("runsc", Status.FAIL,
                     f"{path} ({ver}) does not list checkpoint/restore in `runsc help`; the "
                     "gVisor warm tier needs both and refuses this build", doc)
    return Check("runsc", Status.PASS, f"{path}: {ver} (checkpoint/restore available)")


_KNOWN_POOL_RUNTIMES = {"none", "firecracker", "gvisor", "cascade", *_REMOTE_POOL_RUNTIMES}


def _check_pool_runtime(host: HostView) -> Check | None:
    """An unknown BLASTBOX_POOL_RUNTIME (or cascade member) is refused by the dispatcher; the
    tier preflight would have checked for it is unknowable, so say so instead of passing."""
    doc = f"{DOC}#what-each-tier-needs"
    if "BLASTBOX_POOL_RUNTIME" in host.env and not host.env["BLASTBOX_POOL_RUNTIME"].strip():
        # PoolConfig.from_env defaults only an ABSENT variable to "none"; a set-but-empty one
        # (compose ${BLASTBOX_POOL_RUNTIME:-}) is runtime "" and select_runtime_by_name refuses it.
        return Check("pool-runtime", Status.FAIL,
                     "BLASTBOX_POOL_RUNTIME is set but empty; the dispatcher refuses runtime '' "
                     "(unset it, or set none)", doc)
    pool = host.env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower()
    warm_only = host.env.get("BLASTBOX_DISPATCH_WARM_ONLY", "").strip().lower() in (
        "1", "true", "yes", "on")
    if warm_only and pool in ("", "none"):
        return Check("pool-runtime", Status.FAIL,
                     "BLASTBOX_DISPATCH_WARM_ONLY is set but there is no warm pool "
                     "(BLASTBOX_POOL_RUNTIME unset/none); the dispatcher refuses to start", doc)
    if not pool:
        return None
    if pool not in _KNOWN_POOL_RUNTIMES:
        return Check("pool-runtime", Status.FAIL,
                     f"BLASTBOX_POOL_RUNTIME={pool!r} is not a known runtime "
                     f"({', '.join(sorted(_KNOWN_POOL_RUNTIMES))})", doc)
    if pool == "cascade":
        from blastbox.host.runtime.cascade import _parse_tiers  # noqa: PLC0415

        try:
            # The dispatcher's own parser: 'backend:capacity', capacity >= 1, names as given
            # (select_runtime_by_name is case-sensitive).
            members = [name for name, _cap in _parse_tiers(host.env.get("BLASTBOX_POOL_TIERS", ""))]
        except Exception as exc:  # noqa: BLE001 -- CascadeMisconfigured; report, never raise
            return Check("pool-runtime", Status.FAIL, f"BLASTBOX_POOL_TIERS: {exc}", doc)
        if not members:
            return Check("pool-runtime", Status.FAIL,
                         "BLASTBOX_POOL_RUNTIME=cascade but BLASTBOX_POOL_TIERS is empty", doc)
        def _bad(m: str) -> bool:
            return m in ("cascade", "none") or m not in _KNOWN_POOL_RUNTIMES

        if _bad(members[0]):
            return Check("pool-runtime", Status.FAIL,
                         f"BLASTBOX_POOL_TIERS primary {members[0]!r} is unknown/invalid; the "
                         "dispatcher refuses the cascade", doc)
        dropped = [m for m in members[1:] if _bad(m)]
        members = [m for m in members if not _bad(m)]
        local = {m for m in members if m in ("firecracker", "gvisor")}
        if local and len(local) != len(set(members)):
            return Check("pool-runtime", Status.FAIL,
                         "BLASTBOX_POOL_TIERS mixes file-handshake (firecracker/gvisor) and "
                         "network-endpoint (static/aws-*) tiers; the dispatcher refuses a mixed "
                         "cascade", doc)
        if dropped:
            # build_cascade_runtime skips an unavailable overflow tier at startup and boots
            # on the rest -- a typo there silently shrinks the pool.
            return Check("pool-runtime", Status.WARN,
                         f"BLASTBOX_POOL_TIERS overflow member(s) {', '.join(dropped)} are unknown; "
                         f"the dispatcher skips them and runs on {', '.join(members)}", doc)
        return Check("pool-runtime", Status.PASS, f"cascade of {', '.join(members)}")
    return Check("pool-runtime", Status.PASS, f"BLASTBOX_POOL_RUNTIME={pool}")


def _check_gvisor_rootfs(host: HostView) -> Check:
    """The exported rootfs tree the warm gVisor tier boots its base from (read exactly as
    gvisor_snapshot_runtime does: raw, default /var/lib/blastbox/gvisor-rootfs)."""
    doc = f"{DOC}#gvisor-runsc"
    rootfs = host.env.get("BLASTBOX_GVISOR_ROOTFS", "/var/lib/blastbox/gvisor-rootfs")
    entries = host.listdir(rootfs) if rootfs else None
    if entries:
        return Check("gvisor-rootfs", Status.PASS, f"rootfs {rootfs}")
    pool = host.env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower()
    selected = pool == "gvisor" or (pool == "cascade" and "gvisor" in _cascade_members(host.env))
    return Check("gvisor-rootfs", Status.FAIL if selected else Status.WARN,
                 f"gVisor rootfs {rootfs!r} is missing or empty: the warm tier cannot boot a base"
                 + ("" if selected else " (check from the gVisor dispatcher's environment)"),
                 doc)


def _check_gvisor_rootless(host: HostView) -> Check | None:
    """The warm gVisor tier refuses BLASTBOX_GVISOR_ROOTLESS outright: it needs ``runsc
    restore``, which gVisor does not support rootless. No AppArmor/userns prep fixes that."""
    raw = host.env.get("BLASTBOX_GVISOR_ROOTLESS", "").strip().lower()
    if raw not in ("1", "true", "yes", "on"):
        return None
    return Check("gvisor-rootless", Status.FAIL,
                 "BLASTBOX_GVISOR_ROOTLESS is set, but the warm gVisor tier needs `runsc "
                 "restore`, which gVisor does not support rootless; the tier refuses to start. "
                 "Run it rootful (unset BLASTBOX_GVISOR_ROOTLESS)", f"{DOC}#gvisor-runsc")


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
    if host.euid == 0:
        return Check("kvm", Status.PASS,
                     "/dev/kvm present (running as root, so the dispatcher user's access is "
                     "NOT verified: it must be in the kvm group)", doc)
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
        # firecracker_available() treats an unknown version as unusable: the tier is refused.
        why = "did not run" if proc is None else f"printed no version (rc={proc.returncode})"
        return Check("firecracker", Status.FAIL,
                     f"{path} --version {why}; the runtime refuses a firecracker whose version "
                     f"it cannot read (need >= {minimum})", doc)
    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    shown = ".".join(map(str, ver))
    if ver < _MIN_FC_VERSION:
        return Check("firecracker", Status.FAIL,
                     f"{path}: v{shown} is older than the required v{minimum} "
                     "(virtio-rng entropy device DoS on older releases)", doc)
    return Check("firecracker", Status.PASS, f"{path}: v{shown}")


def _primary_pool(env: Mapping[str, str]) -> str:
    pool = env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower()
    if pool == "cascade":
        members = _cascade_members(env)
        pool = members[0] if members else ""
    return pool


def _cascade_members(env: Mapping[str, str]) -> list[str]:
    """Member names as the dispatcher's parser sees them (empty items skipped, case kept)."""
    return [item.partition(":")[0].strip()
            for item in env.get("BLASTBOX_POOL_TIERS", "").split(",") if item.strip()]


def _check_fc_guest(host: HostView) -> Check:
    doc = f"{DOC}#firecracker"
    kernel = host.env.get("BLASTBOX_FC_KERNEL", "").strip()
    rootfs = host.env.get("BLASTBOX_FC_ROOTFS", "").strip()
    if not kernel and not rootfs:
        if _primary_pool(host.env) == "firecracker":
            # This IS the FC dispatcher's environment: FCConfig.from_env refuses it.
            return Check("fc-guest", Status.FAIL,
                         "BLASTBOX_POOL_RUNTIME selects Firecracker but BLASTBOX_FC_KERNEL/"
                         "BLASTBOX_FC_ROOTFS are unset; the dispatcher refuses to start", doc)
        if (host.env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower() == "cascade"
                and "firecracker" in _cascade_members(host.env)[1:]):
            return Check("fc-guest", Status.WARN,
                         "this cascade lists firecracker as an overflow tier but "
                         "BLASTBOX_FC_KERNEL/BLASTBOX_FC_ROOTFS are unset: the dispatcher skips "
                         "that tier at startup", doc)
        return Check("fc-guest", Status.WARN,
                     "BLASTBOX_FC_KERNEL/BLASTBOX_FC_ROOTFS unset here (check from the FC "
                     "dispatcher's environment to verify the guest artifacts)", doc)
    missing = [f"{k}={v or '<unset>'}" for k, v in
               (("BLASTBOX_FC_KERNEL", kernel), ("BLASTBOX_FC_ROOTFS", rootfs))
               if not v or not host.is_file(v)]
    if missing:
        return Check("fc-guest", Status.FAIL,
                     "missing guest artifact (not a regular file): " + ", ".join(missing), doc)
    from blastbox.host.runtime.firecracker import _MIN_SNAPSHOT_KERNEL  # noqa: PLC0415

    # The warm snapshot tier (BLASTBOX_POOL_WARM_SNAPSHOT, read as pool_config._bool does)
    # refuses a detectably pre-5.18 guest: restored clones would share CRNG state.
    raw = host.env.get("BLASTBOX_POOL_WARM_SNAPSHOT", "").strip().lower()
    warm = bool(raw) and raw not in ("0", "false", "no", "off")
    kver = host.guest_kernel_version(kernel) if warm else None
    if kver is not None and kver < _MIN_SNAPSHOT_KERNEL:
        need = ".".join(map(str, _MIN_SNAPSHOT_KERNEL))
        return Check("fc-guest", Status.FAIL,
                     f"BLASTBOX_POOL_WARM_SNAPSHOT is on but guest kernel {kernel} is "
                     f"{kver[0]}.{kver[1]}; the snapshot tier needs >= {need} (VMGenID reseeds "
                     "the CRNG on restore) and refuses to start", doc)
    return Check("fc-guest", Status.PASS, f"kernel {kernel}, rootfs {rootfs}")


def _float_or_none(raw: str) -> float | None:
    try:
        return float(raw)
    except ValueError:
        return None


def _check_snapshot_age(host: HostView) -> Check:
    doc = f"{DOC}#clock-and-aged-warm-checkpoints"
    from blastbox.host.runtime.fc_snapshot import DEFAULT_SNAPSHOT_MAX_AGE_S  # noqa: PLC0415

    raw = host.env.get("BLASTBOX_SNAPSHOT_MAX_AGE_S", "").strip()
    default = DEFAULT_SNAPSHOT_MAX_AGE_S
    # env_knobs.max_age_env's rule, without its stderr log line (which would land in --json
    # 2>&1 output): blank = default; unparseable, non-finite or negative = default; 0 disables.
    parsed = _float_or_none(raw) if raw else default
    value = parsed if parsed is not None and math.isfinite(parsed) and parsed >= 0 else default
    if value <= 0:
        return Check("snapshot-age", Status.WARN,
                     f"BLASTBOX_SNAPSHOT_MAX_AGE_S={raw} disables warm-base refresh: a checkpoint "
                     "restored long after it was taken sees its monotonic clock jump and "
                     "every job hangs (the ~24h warm outage)", doc)
    if value >= 86400:
        return Check("snapshot-age", Status.WARN,
                     f"BLASTBOX_SNAPSHOT_MAX_AGE_S={raw}: warm bases may age a day or more before "
                     "refresh, past the restore clock-jump edge (the ~24h warm outage)", doc)
    if raw and value == default and _float_or_none(raw) != default:
        return Check("snapshot-age", Status.WARN,
                     f"BLASTBOX_SNAPSHOT_MAX_AGE_S={raw!r} is invalid; the runtime ignores it "
                     f"and uses {default:g}s", doc)
    return Check("snapshot-age", Status.PASS,
                 f"warm bases refresh after {value:g}s" + ("" if raw else " (default)"))


def _needs_userns(env: Mapping[str, str], tiers: Collection[str] = ("docker",)) -> list[str]:
    why = []
    sandbox = env.get("BLASTBOX_SANDBOX", "").strip().lower()
    # A remote-only dispatcher runs no worker here: its sandbox knob is the remote host's concern.
    # The host-kernel inner sandbox runs only on the cold docker tier (FC guests have their own
    # kernel, gVisor's Sentry implements namespaces itself; remote runs elsewhere).
    if sandbox in ("bwrap", "nsjail") and "docker" in tiers:
        why.append(f"BLASTBOX_SANDBOX={sandbox}")
    # Only the cold docker path reads BLASTBOX_WORKER_RUNTIME (runtime/docker.py).
    if "docker" in tiers and env.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower() == "runc":
        why.append("BLASTBOX_WORKER_RUNTIME=runc (inner nsjail/bwrap)")
    # BLASTBOX_GVISOR_ROOTLESS is not counted: the warm gVisor tier refuses it outright
    # (gvisor-rootless FAIL), and it needs blastbox-runsc, not the bwrap/nsjail profiles.
    return why


def _profile_attachment_mismatches(host: HostView) -> list[str]:
    """For each installed scoped profile, the binary it attaches to vs the one PATH resolves.
    A profile attached to /usr/local/bin/nsjail confers nothing on /usr/bin/nsjail."""
    out = []
    for tool in ("bwrap", "nsjail"):
        raw = host.read(f"/etc/apparmor.d/blastbox-{tool}")
        m = re.search(rf"^\s*profile\s+blastbox-{tool}\s+(/\S+)", raw or "", re.MULTILINE)
        binary = host.which(tool)
        if m and binary and host.realpath(binary) != m.group(1):
            out.append(f"blastbox-{tool} attaches {m.group(1)}, {tool} is {binary} "
                       f"(resolves to {host.realpath(binary)})")
    return out


def _check_userns(host: HostView, tiers: Collection[str] = ("docker",)) -> Check:
    doc = f"{DOC}#apparmor-and-user-namespaces"
    restrict = _sysctl(host, "/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    max_ns = _sysctl(host, "/proc/sys/user/max_user_namespaces")
    clone = _sysctl(host, "/proc/sys/kernel/unprivileged_userns_clone")
    shown = ", ".join(f"{k}={v}" for k, v in (
        ("apparmor_restrict_unprivileged_userns", restrict),
        ("max_user_namespaces", max_ns),
        ("unprivileged_userns_clone", clone)) if v is not None) or "no userns sysctls readable"
    needs = _needs_userns(host.env, tiers)
    if max_ns == "0" or clone == "0":
        status = Status.FAIL if needs else Status.PASS
        return Check("userns", status,
                     f"{shown}: unprivileged user namespaces are off; nsjail/bwrap inner "
                     f"sandboxes cannot start" + (f" ({'; '.join(needs)})" if needs else ""),
                     doc)
    if restrict == "1" and needs:
        loaded = _loaded_profiles(host)
        sandbox = host.env.get("BLASTBOX_SANDBOX", "").strip().lower()
        wanted = ({f"blastbox-{sandbox}"} if sandbox in ("bwrap", "nsjail")
                  else {"blastbox-bwrap", "blastbox-nsjail"})
        if loaded is not None and wanted <= loaded:
            mismatched = _profile_attachment_mismatches(host)
            if mismatched:
                return Check("userns", Status.WARN,
                             f"{shown}; scoped profiles are loaded but attach to another path "
                             f"than the binary in use: {'; '.join(mismatched)} (the kernel still "
                             "denies its user namespace; edit the profile's attachment path)",
                             doc)
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


def _check_bwrap_stock_profile(host: HostView, tiers: Collection[str] = ("docker",)) -> Check:
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
    # The stock profile attaches to bwrap only: nsjail and rootless runsc are unaffected.
    env = host.env
    needs = []
    if env.get("BLASTBOX_SANDBOX", "").strip().lower() == "bwrap":
        needs.append("BLASTBOX_SANDBOX=bwrap")
    if ("docker" in tiers and env.get("BLASTBOX_WORKER_RUNTIME", "").strip().lower() == "runc"
            and env.get("BLASTBOX_SANDBOX", "").strip().lower() != "nsjail"):
        needs.append("BLASTBOX_WORKER_RUNTIME=runc (inner bwrap)")
    if not needs:
        return Check("bwrap-userns-restrict", Status.PASS,
                     "stock profile active (irrelevant here: nothing configured runs host bwrap; "
                     "see the guide if an engine nests bwrap outside runsc/Firecracker)")
    return Check("bwrap-userns-restrict", Status.WARN,
                 f"Ubuntu's stock bwrap-userns-restrict profile is active and {'; '.join(needs)} "
                 "runs host namespace sandboxes: it confines what bwrap-based engines can do "
                 "inside their namespace; see the guide for when to disable it", doc)


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
    problems: list[str] = []
    # The dispatcher reads BLASTBOX_JOB_ROOT raw (Path(os.environ.get(..., default))): a
    # set-but-empty value is its working directory and a padded one is a relative path.
    raw_root = env.get("BLASTBOX_JOB_ROOT")
    if raw_root is not None and (not raw_root.strip() or raw_root != raw_root.strip()):
        problems.append(f"BLASTBOX_JOB_ROOT={raw_root!r} is empty or padded: the dispatcher uses "
                        "it unstripped (empty = its working directory)")
    job_root = (raw_root or "").strip() or _DEFAULT_JOB_ROOT
    dirs = [("BLASTBOX_JOB_ROOT", job_root)]
    raw_gv = env.get("BLASTBOX_GVISOR_ROOT")
    if "gvisor" in tiers and raw_gv is not None and (not raw_gv.strip() or raw_gv != raw_gv.strip()):
        problems.append(f"BLASTBOX_GVISOR_ROOT={raw_gv!r} is empty or padded: the gVisor runtime "
                        "uses it unstripped (empty = its working directory)")
    knobs = []
    if "firecracker" in tiers or "gvisor" in tiers:
        knobs.append("BLASTBOX_SNAPSHOT_MEM_DIR")
    if "gvisor" in tiers:
        knobs.append("BLASTBOX_GVISOR_ROOT")   # only the warm gVisor tier reads it
    for knob in knobs:
        if env.get(knob, "").strip():
            dirs.append((knob, env[knob].strip()))
    # Resolved too: a job root symlinked into /tmp is under /tmp.
    on_tmp = [f"{k}={v}" + ("" if _under_tmp(v) else f" (-> {host.realpath(v)})")
              for k, v in dirs if _under_tmp(v) or _under_tmp(host.realpath(v))]
    if on_tmp:
        problems.append("under /tmp (tmpfiles cleanup / tmpfs size / reboot loses sealed "
                        "results): " + ", ".join(on_tmp))
    if not host.exists(job_root):
        problems.append(f"job root {job_root} does not exist")
    if problems:
        return Check("scratch", Status.WARN, "; ".join(problems), doc)
    return Check("scratch", Status.PASS, ", ".join(f"{k}={v}" for k, v in dirs))


def _check_fc_scratch(host: HostView) -> Check:
    """Separate from ``scratch`` so the unfixable hard-wired path can be ``--ack``ed alone."""
    doc = f"{DOC}#disk-and-scratch"
    if _tmpfs(host, "/tmp/blastbox-fc-slots"):
        # FCConfig.scratch_root is hard-wired to /tmp/blastbox-fc-slots (no knob): every slot's
        # outdisk/in/sockets, and warm-*.mem unless BLASTBOX_SNAPSHOT_MEM_DIR moves it.
        return Check("fc-scratch", Status.WARN,
                     "tmpfs holds /tmp/blastbox-fc-slots: the Firecracker slot scratch is hard-wired to "
                     "/tmp/blastbox-fc-slots (slot disks, and warm-*.mem unless "
                     "BLASTBOX_SNAPSHOT_MEM_DIR is set): RAM-backed and capped", doc)
    return Check("fc-scratch", Status.PASS, "/tmp/blastbox-fc-slots is not on tmpfs")


# --- running sandbox processes ------------------------------------------------------------

_RUNSC_ROLES = ("runsc-sandbox", "runsc-gofer")
_IDENTITY_UID_MAP = ["0", "0", "4294967295"]
#: Capabilities worth naming when a sandbox process holds them as real host root.
_NOTABLE_CAPS = {1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 18: "SYS_CHROOT", 21: "SYS_ADMIN",
                 12: "NET_ADMIN", 19: "SYS_PTRACE"}
_SHOW_PIDS = 5
_UNKNOWN = "unknown (run as root)"


@dataclass(frozen=True)
class _Proc:
    pid: str
    role: str            # "runsc-sandbox" | "runsc-gofer" | "firecracker"
    argv: tuple[str, ...]


def _sandbox_processes(host: HostView) -> list[_Proc]:
    """Running runsc sandbox/gofer and firecracker processes, found by argv[0] (runsc re-execs
    itself with argv[0] ``runsc-sandbox``/``runsc-gofer``; its comm is often just ``exe``) or
    by comm. Reads only world-readable ``/proc/<pid>/cmdline`` and ``comm``."""
    found: list[_Proc] = []
    # A renamed VMM (BLASTBOX_FC_BIN=/opt/fc/fc-v1.16) is still a firecracker.
    fc_name = os.path.basename(host.env.get("BLASTBOX_FC_BIN", "").strip()) or None
    for pid in sorted((n for n in host.listdir("/proc") or [] if n.isdigit()), key=int):
        raw = host.read(f"/proc/{pid}/cmdline")
        argv = tuple(a for a in (raw or "").split("\0") if a)
        names = {_first_line(host.read(f"/proc/{pid}/comm"))}
        if argv:
            names.add(os.path.basename(argv[0]))
        for role in (*_RUNSC_ROLES, "firecracker"):
            if role in names or (role == "firecracker" and fc_name and fc_name in names):
                found.append(_Proc(pid, role, argv))
                break
    return found


def _status_field(host: HostView, pid: str, key: str) -> str | None:
    raw = host.read(f"/proc/{pid}/status")
    if raw is None:
        return None
    for line in raw.splitlines():
        k, _, v = line.partition(":")
        if k.strip() == key:
            return v.strip()
    return None


def _caps(host: HostView, pid: str) -> list[str]:
    raw = _status_field(host, pid, "CapEff")
    try:
        mask = int(raw or "0", 16)
    except ValueError:
        return []
    return [name for bit, name in sorted(_NOTABLE_CAPS.items()) if mask & (1 << bit)]


def _pids(procs: Sequence[_Proc]) -> str:
    shown = ", ".join(f"{p.role} {p.pid}" for p in procs[:_SHOW_PIDS])
    return shown + (f" (+{len(procs) - _SHOW_PIDS} more)" if len(procs) > _SHOW_PIDS else "")


def _check_runsc_host_root(host: HostView, procs: Sequence[_Proc]) -> Check:
    doc = f"{DOC}#runsc-processes-and-host-root"
    runsc = [p for p in procs if p.role in _RUNSC_ROLES]
    if not runsc:
        return Check("runsc-host-root", Status.PASS,
                     "no running runsc-sandbox/runsc-gofer processes to inspect")
    root: list[str] = []
    unknown: list[_Proc] = []
    for p in runsc:
        uid_map = host.read(f"/proc/{p.pid}/uid_map")
        uid = _status_field(host, p.pid, "Uid")
        if uid_map is None or uid is None:
            unknown.append(p)
            continue
        identity = uid_map.split() == _IDENTITY_UID_MAP
        if identity and uid.split()[:1] == ["0"]:
            caps = _caps(host, p.pid)
            root.append(f"{p.role} {p.pid}" + (f" [{','.join(caps)}]" if caps else ""))
    if root:
        shown = ", ".join(root[:_SHOW_PIDS]) + (
            f" (+{len(root) - _SHOW_PIDS} more)" if len(root) > _SHOW_PIDS else "")
        return Check("runsc-host-root", Status.WARN,
                     f"{len(root)} runsc process(es) run as real host root (identity uid_map, "
                     f"uid 0): {shown}. A sandbox escape lands as host root with those "
                     "capabilities; a user-namespace-remapped setup (a separate remapped docker "
                     "daemon, or containerd per-container mappings) is recommended, pending a "
                     "spike", doc)
    if unknown:
        return Check("runsc-host-root", Status.WARN,
                     f"{_UNKNOWN}: cannot read uid_map/status of {_pids(unknown)}", doc)
    return Check("runsc-host-root", Status.PASS,
                 f"{len(runsc)} runsc process(es), none real host root")


def _jailed(p: _Proc) -> bool | None:
    """True when firecracker was started by the jailer, which always passes ``--start-time-us``
    to the firecracker it execs. A non-``/`` root proves nothing (a docker container has one
    too). None when the argv could not be read."""
    if not p.argv:
        return None
    return "--start-time-us" in p.argv


def _apparmor_on(host: HostView) -> bool:
    raw = host.read("/sys/module/apparmor/parameters/enabled")
    return raw is not None and raw.strip().upper().startswith("Y")


def _apparmor_shaped(label: str) -> bool:
    text = label.strip()
    return text == "unconfined" or (text.endswith(")") and " (" in text)


def _is_unconfined(label: str) -> bool:
    """``unconfined``, or a profile in ``(unconfined)`` / ``(complain)`` mode: the name alone
    says nothing -- the shipped deploy/apparmor profiles are all flags=(unconfined), and
    complain mode only logs (the same name-vs-mode mistake docker.py fixed in #159)."""
    name, _, mode = label.strip().partition(" (")
    return name == "unconfined" or mode.rstrip(")").strip() in ("unconfined", "complain")


def _check_sandbox_confinement(host: HostView, procs: Sequence[_Proc]) -> Check:
    doc = f"{DOC}#confining-firecracker-and-runsc-processes"
    if not procs:
        return Check("sandbox-confinement", Status.PASS,
                     "no running firecracker/runsc processes to inspect")
    unconfined: list[_Proc] = []
    unjailed: list[_Proc] = []
    unknown: list[_Proc] = []
    foreign: list[_Proc] = []
    for p in procs:
        # attr/apparmor/current is AppArmor's own label under LSM stacking; attr/current is the
        # display LSM's (an SELinux context on a non-AppArmor host), so only trust an
        # AppArmor-shaped value there.
        label = host.read(f"/proc/{p.pid}/attr/apparmor/current")
        if label is None:
            label = host.read(f"/proc/{p.pid}/attr/current")
            if label is not None and not _apparmor_shaped(label):
                foreign.append(p)   # another LSM's label: no AppArmor label exists to check
                label = ""
        if label is None and not _apparmor_on(host):
            foreign.append(p)       # AppArmor is off: there is no label to read, as root or not
            label = ""
        if label is None:
            unknown.append(p)
        elif label == "":
            pass
        elif _is_unconfined(label):
            unconfined.append(p)
        if p.role == "firecracker":
            jailed = _jailed(p)
            if jailed is None and p not in unknown:
                unknown.append(p)
            elif jailed is False:
                unjailed.append(p)
    problems = []
    if unconfined:
        problems.append(f"not confined by AppArmor (unconfined, or a profile in unconfined/"
                        f"complain mode): {_pids(unconfined)}")
    if unjailed:
        problems.append(f"firecracker without the jailer: {_pids(unjailed)}")
    if problems:
        return Check("sandbox-confinement", Status.WARN,
                     "; ".join(problems) + ". Slots share one scratch tree (other slots' "
                     "disks and API/vsock sockets); run firecracker under the jailer with a "
                     "per-slot AppArmor profile so one VMM cannot reach another slot", doc)
    if foreign:
        return Check("sandbox-confinement", Status.WARN,
                     f"no AppArmor label on {_pids(foreign)} (another LSM is active, or "
                     "AppArmor is off): AppArmor confinement cannot be verified", doc)
    if unknown:
        return Check("sandbox-confinement", Status.WARN,
                     f"{_UNKNOWN}: cannot read the AppArmor label or argv of {_pids(unknown)}",
                     doc)
    return Check("sandbox-confinement", Status.PASS,
                 f"{len(procs)} process(es) confined" + (
                     " (firecracker jailed)" if any(p.role == "firecracker" for p in procs)
                     else ""))


_TIER_CHECKS = {
    "firecracker": ("kvm", "firecracker", "fc-guest"),
    # gvisor-rootfs is not a startup gate: the runtime boots a missing/unstamped rootfs anyway.
    "gvisor": ("runsc", "gvisor-rootless"),
}


def _overflow_only_tiers(env: Mapping[str, str]) -> set[str]:
    """Local tiers this env's cascade lists only as OVERFLOW members: build_cascade_runtime
    skips an overflow tier that is unavailable at startup and boots on the rest."""
    if env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower() != "cascade":
        return set()
    members = _cascade_members(env)
    if not members:
        return set()
    return {m for m in members[1:] if m in _TIER_CHECKS and m != members[0]}


def _downgrade_overflow(checks: list[Check], env: Mapping[str, str]) -> list[Check]:
    overflow = _overflow_only_tiers(env)
    names = {n: tier for tier in overflow for n in _TIER_CHECKS[tier]}
    out = []
    for c in checks:
        tier = names.get(c.name)
        # firecracker_available() only checks that /dev/kvm EXISTS: a non-rw one is admitted
        # and every spawn fails, so only "missing" is a skip.
        gate = c.name != "kvm" or c.detail.startswith("/dev/kvm missing")
        if tier and gate and c.status is Status.FAIL:
            c = Check(c.name, Status.WARN,
                      f"{c.detail} -- {tier} is an overflow tier of this cascade, so the "
                      "dispatcher skips it at startup and runs without it", c.doc)
        out.append(c)
    return out


def _downgrade_unselected(checks: list[Check], env: Mapping[str, str]) -> list[Check]:
    """Without --tier and with no pool configured, the local tiers are checked as a preview: the
    dispatcher (BLASTBOX_POOL_RUNTIME unset = none) runs cold docker only, so a warm tier's FAIL
    is advice, not a refusal."""
    if env.get("BLASTBOX_POOL_RUNTIME", "").strip().lower() not in ("", "none"):
        return checks
    names = {n for tier_checks in _TIER_CHECKS.values() for n in tier_checks} | {
        "gvisor-rootfs"}
    return [Check(c.name, Status.WARN,
                  f"{c.detail} -- not selected: BLASTBOX_POOL_RUNTIME is unset, so the dispatcher "
                  "runs cold docker only (check with --tier to gate on it)", c.doc)
            if c.name in names and c.status is Status.FAIL else c for c in checks]


def run_preflight(host: HostView, tiers: Sequence[str], *, explicit: bool = True) -> list[Check]:
    """Run every check relevant to ``tiers``. Pure reads; never raises on host state."""
    t = set(tiers)
    out: list[Check] = []
    pool = _check_pool_runtime(host)
    if pool is not None:
        out.append(pool)
    if "docker" in t:
        # The warm gVisor tier drives runsc directly against an exported rootfs; docker is
        # needed only for the cold docker tier.
        out.append(_check_docker(host))
        out.append(_check_docker_runsc(host))
    if "gvisor" in t:
        out.append(_check_runsc_binary(host))
        out.append(_check_gvisor_rootfs(host))
        rootless = _check_gvisor_rootless(host)
        if rootless is not None:
            out.append(rootless)
    if "firecracker" in t:
        out.append(_check_kvm(host))
        out.append(_check_firecracker(host))
        out.append(_check_fc_guest(host))
    if t & {"gvisor", "firecracker"}:
        out.append(_check_snapshot_age(host))
    if t & {"docker", "gvisor", "firecracker"}:
        roles: set[str] = set()
        if t & {"docker", "gvisor"}:
            roles.update(_RUNSC_ROLES)
        if "firecracker" in t:
            roles.add("firecracker")
        procs = [p for p in _sandbox_processes(host) if p.role in roles]
        if t & {"docker", "gvisor"}:
            out.append(_check_runsc_host_root(host, procs))
        out.append(_check_sandbox_confinement(host, procs))
    local = bool(t - {"remote"})
    if local:   # a remote-only dispatcher runs no worker, runsc or JVM engine here
        out.append(_check_apparmor(host))
        out.append(_check_bwrap_stock_profile(host, t))
        out.append(_check_userns(host, t))
    out.append(_check_clock(host))
    if local:
        out.append(_check_cpu_flags(host))
    out.append(_check_scratch(host, tiers))
    if "firecracker" in t:
        out.append(_check_fc_scratch(host))
    out = _downgrade_overflow(out, host.env)
    return out if explicit else _downgrade_unselected(out, host.env)


# --- output -----------------------------------------------------------------------------

def exit_code(checks: Sequence[Check], *, strict: bool = False,
              ack: Collection[str] = ()) -> int:
    """1 on any FAIL; under ``strict`` also on any WARN whose check name is not in ``ack``
    (``--ack NAME``: a WARN the operator has reviewed, e.g. cpu-flags once JVM engines run
    with -XX:-UseBASE64Intrinsics). A FAIL can never be acknowledged."""
    if any(c.status is Status.FAIL for c in checks):
        return 1
    if strict and any(c.status is Status.WARN and c.name not in ack for c in checks):
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


def render_json(checks: Sequence[Check], tiers: Sequence[str], *, strict: bool = False,
                ack: Collection[str] = ()) -> str:
    return json.dumps({
        "tiers": list(tiers),
        "strict": strict,
        "acknowledged": sorted(ack),
        "ok": exit_code(checks, strict=strict, ack=ack) == 0,
        "counts": _counts(checks),
        "checks": [{"name": c.name, "status": c.status.value, "detail": c.detail,
                    "doc": c.doc} for c in checks],
    }, indent=2, sort_keys=True)
