"""Host LSM detection for the confinement tier -- DETECTION AND REPORTING ONLY.

The confinement tier (later PRs) will put the HOST-side sandbox processes -- runsc's CLI, gofer
and sentry; firecracker -- into blastbox's own LSM policy, because runsc ignores the OCI
``apparmorProfile``/``selinuxLabel`` and firecracker has no LSM hook. Nothing here enters a
domain, loads a policy or changes the host: it answers "what does this host offer, and which LSM
WOULD each sandbox kind be confined with", for ``blastbox preflight`` and for the signed receipt.

Selection, per sandbox kind ("gvisor" | "firecracker"):

    SELinux (enforcing)  >  AppArmor (enabled)  >  Landlock (firecracker only)  >  none

SELinux in permissive mode only logs, so it is never selected (AL2023 ships permissive).
Landlock is not offered for gVisor: runsc mounts, which a Landlock domain forbids.

``BLASTBOX_CONFINEMENT``: ``auto`` (default; best available, else none), ``require`` (fail
closed when a kind this host runs has no usable LSM), ``off``. Anything else is an error, never
"off": a typo must not be what disables confinement.

Degrades cleanly: a container without securityfs (``/sys/kernel/security`` unmounted) falls
back to ``/sys/module/apparmor`` and ``/sys/fs/selinux``; a kernel without Landlock answers
ENOSYS/EOPNOTSUPP (ABI 0); a missing tool is reported absent, never raised.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

ENV_MODE = "BLASTBOX_CONFINEMENT"
MODES = ("auto", "require", "off")
#: "cold" is runsc launched by dockerd (``docker run --runtime=...``); "gvisor" is the warm tier's
#: runsc and "firecracker" the VMM, both launched by the dispatcher itself.
KINDS = ("cold", "gvisor", "firecracker")

#: First runsc release that ships the Sentry as its own binary (``gvisor-bin/gvisor_sentry``):
#: only then can AppArmor give the sentry a domain separate from the CLI and gofer.
SPLIT_SENTRY_RELEASE = 20261012
#: apparmor_parser 4.0.1 (measured with kernel 6.8) compiles ``audit deny umount,`` paired with
#: another ``audit deny`` mount-class rule into ALLOW mount.
AA_PARSER_MOUNT_BUG = (4, 0, 1)

_LSM = "/sys/kernel/security/lsm"
_AA_ENABLED = "/sys/module/apparmor/parameters/enabled"
_SE_ENFORCE = "/sys/fs/selinux/enforce"
_AA_SELF = ("/proc/self/attr/apparmor/current", "/proc/self/attr/current")
_MOUNTS = "/proc/self/mounts"
_AA_PARSERS = ("apparmor_parser", "/usr/sbin/apparmor_parser", "/sbin/apparmor_parser")

_READ_CAP = 4 * 1024 * 1024           # docker config.json can be large (inline registry auths)
_SYS_LANDLOCK_CREATE_RULESET = 444   # unified syscall number (x86_64, aarch64, ...)
_LANDLOCK_CREATE_RULESET_VERSION = 1


class HostReader(Protocol):
    """The read-only slice of :class:`blastbox.host.preflight.HostView` this module needs."""

    def read(self, path: str) -> str | None: ...
    def exists(self, path: str) -> bool: ...
    def which(self, name: str) -> str | None: ...
    def realpath(self, path: str) -> str: ...
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None: ...


class ConfinementUnavailable(RuntimeError):
    """``require`` mode and a sandbox kind this host runs has no usable LSM."""


def landlock_abi() -> int:
    """Landlock ABI via ``landlock_create_ruleset(NULL, 0, VERSION)`` (a query; creates
    nothing). 0 when unavailable: ENOSYS (not built), EOPNOTSUPP (disabled at boot), or a
    seccomp filter refusing it. Linux only: 444 is another syscall elsewhere (macOS:
    change_fdguard_np)."""
    if not sys.platform.startswith("linux"):
        return 0
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        rc = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                          ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION))
    except (OSError, AttributeError):
        return 0
    return int(rc) if rc > 0 else 0


def parse_mode(raw: str | None) -> str:
    mode = (raw or "").strip().lower() or "auto"
    if mode not in MODES:
        raise ValueError(f"{ENV_MODE}={raw!r}: expected one of {', '.join(MODES)}")
    return mode


def mode_from_env(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return parse_mode(env.get(ENV_MODE))


def kinds_for_tiers(tiers: Iterable[str]) -> list[str]:
    """Sandbox kinds behind dispatcher/preflight tier names. The cold docker tier runs runsc
    (gVisor, launched by dockerd); remote tiers run nothing on this host."""
    t = set(tiers)
    kinds = set()
    if t & {"cold", "docker"}:
        kinds.add("cold")
    if "gvisor" in t:
        kinds.add("gvisor")
    if "firecracker" in t:
        kinds.add("firecracker")
    return [k for k in KINDS if k in kinds]


@dataclass(frozen=True)
class HostLsm:
    """What the host offers. Tool fields are None when not probed (the dispatcher's receipt
    probe reads /sys only and never spawns)."""

    lsms: tuple[str, ...] | None        # /sys/kernel/security/lsm; None = securityfs unreadable
    apparmor: bool
    selinux: str                        # "enforcing" | "permissive" | "absent" | "unknown"
    landlock_abi: int                   # 0 = unavailable
    # Why an ON LSM still cannot be used from here (None = no known blocker): no securityfs to
    # load policy through, a caller already confined (docker-default has no change_profile), a
    # read-only selinuxfs (container engines bind it ro).
    apparmor_blocker: str | None = None
    selinux_blocker: str | None = None
    # Cold runsc is started by the daemon the docker CLI talks to; when that is not this host's
    # (DOCKER_HOST / DOCKER_CONTEXT elsewhere), this host's LSM view says nothing about it.
    cold_blocker: str | None = None
    apparmor_parser: str | None = None  # "4.0.1"; None = not found / not probed
    runsc: str | None = None            # "release-20261012.0"
    runsc_split_sentry: bool | None = None
    firecracker: str | None = None      # resolved path
    jailer: str | None = None           # resolved path

    def would_use(self, kind: str, mode: str = "auto") -> str:
        """The LSM ``kind``'s host processes would be confined with: selinux | apparmor |
        landlock | none. Pure."""
        if kind not in KINDS:
            raise ValueError(f"unknown sandbox kind {kind!r}")
        if parse_mode(mode) == "off":
            return "none"
        # The caller-context blockers describe what the DISPATCHER can enter. Cold runsc is
        # exec'd by dockerd on the host (a docker runtime wrapper enters the domain there), so
        # only the host-level state counts for it.
        own = kind != "cold"
        if not own and self.cold_blocker:
            return "none"
        if self.selinux == "enforcing" and not (own and self.selinux_blocker):
            return "selinux"
        if self.apparmor and not (own and self.apparmor_blocker):
            return "apparmor"
        if kind == "firecracker" and self.landlock_abi > 0:
            return "landlock"
        return "none"

    @property
    def flags(self) -> list[str]:
        """Known-bad conditions on this host, as stable identifiers."""
        out = []
        if self.apparmor and self.apparmor_parser and _version(self.apparmor_parser) == \
                AA_PARSER_MOUNT_BUG:
            out.append("apparmor-parser-4.0.1-audit-deny-umount-allows-mount")
        return out

    def as_dict(self) -> dict[str, object]:
        return {
            "lsms": None if self.lsms is None else list(self.lsms),
            "apparmor": self.apparmor,
            "selinux": self.selinux,
            "landlock_abi": self.landlock_abi,
            "apparmor_blocker": self.apparmor_blocker,
            "selinux_blocker": self.selinux_blocker,
            "cold_blocker": self.cold_blocker,
            "apparmor_parser": self.apparmor_parser,
            "runsc": self.runsc,
            "runsc_split_sentry": self.runsc_split_sentry,
            "firecracker": self.firecracker,
            "jailer": self.jailer,
            "flags": self.flags,
        }


def _version(text: str | None) -> tuple[int, int, int] | None:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return None if m is None else (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _first_line(text: str | None) -> str:
    return next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")


def _probe_lsm(host: HostReader, landlock: int | None) -> HostLsm:
    raw = host.read(_LSM)
    lsms = None if raw is None else tuple(x for x in raw.strip().split(",") if x)
    aa_raw = host.read(_AA_ENABLED)
    apparmor = aa_raw is not None and aa_raw.strip().upper().startswith("Y") and (
        lsms is None or "apparmor" in lsms)
    enforce = host.read(_SE_ENFORCE)
    if lsms is not None and "selinux" not in lsms:
        selinux = "absent"
    elif enforce is None:
        # Listed (or stack unreadable) but no selinuxfs here, e.g. a container: not visible,
        # so "unknown" rather than "absent" -- and not usable from here either way.
        selinux = "unknown"
    else:
        selinux = "enforcing" if enforce.strip() == "1" else "permissive"
    # A listed-but-absent landlock is authoritative; an unreadable list still asks the kernel.
    abi = 0 if (lsms is not None and "landlock" not in lsms) else max(0, int(landlock or 0))
    return HostLsm(lsms=lsms, apparmor=apparmor, selinux=selinux, landlock_abi=abi,
                   apparmor_blocker=_aa_blocker(host, lsms) if apparmor else None,
                   selinux_blocker=_se_blocker(host) if selinux in ("enforcing", "permissive") else None)


def _aa_blocker(host: HostReader, lsms: tuple[str, ...] | None) -> str | None:
    if lsms is None:
        # /sys/module shows the HOST's flag; without securityfs no policy can be loaded here.
        return ("securityfs not readable (not mounted in a container, or denied by the "
                "caller's profile): no AppArmor policy can be loaded from here")
    label = host.read(_AA_SELF[0])
    if label is None:
        # attr/current is the stacked LSMs' slot; only read it as AppArmor's when it looks so.
        raw = host.read(_AA_SELF[1])
        label = raw if raw is not None and (raw.strip() == "unconfined" or raw.rstrip().endswith(
            ")")) else None
    label = (label or "").strip().rstrip("\x00").strip()
    if not label:
        # Unknown is not "unconfined": count it as a blocker rather than fail open.
        return "own AppArmor label not readable (/proc/self/attr): cannot tell if a profile " \
               "change is possible from here"
    # The MODE decides, not the name: a flags=(unconfined) or complain-mode profile changes
    # profile like "unconfined" does (preflight._is_unconfined reads labels the same way).
    name, _, mode = label.partition(" (")
    if not (name == "unconfined" or mode.rstrip(")").strip() in ("unconfined", "complain")):
        return (f"caller already confined by {label!r}: entering a blastbox profile needs a "
                "change_profile rule there")
    return None


def _se_blocker(host: HostReader) -> str | None:
    for line in (host.read(_MOUNTS) or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == "/sys/fs/selinux" and parts[2] == "selinuxfs" and \
                "ro" in parts[3].split(","):
            return "selinuxfs mounted read-only (container?): no type transition from here"
    return None


def _cold_blocker(env: Mapping[str, str], host: HostReader) -> str | None:
    """Why the daemon the docker CLI will talk to is not known to be THIS host's, resolved the
    way the CLI resolves it: DOCKER_HOST, else DOCKER_CONTEXT, else config.json currentContext;
    a named context's endpoint from its meta.json. Only a unix:// endpoint is local (not
    Docker Desktop's, which fronts a VM). Anything
    that cannot be resolved is a blocker (fail closed), never an exception."""
    try:
        return _resolve_cold_blocker(env, host)
    except Exception as exc:  # noqa: BLE001 -- never raise on host state
        return f"docker endpoint not resolvable ({type(exc).__name__}): cold runsc host unknown"


def _docker_config_dir(env: Mapping[str, str]) -> str:
    cfg = env.get("DOCKER_CONFIG", "").strip()
    if cfg:
        return cfg
    home = env.get("HOME", "").strip()
    if not home:
        # As the docker CLI: an empty or unset HOME falls back to the passwd entry.
        import pwd  # noqa: PLC0415

        home = pwd.getpwuid(os.getuid()).pw_dir
    return os.path.join(home, ".docker")


_GO_WS = " \t\n\r"   # the only whitespace Go's JSON decoder skips (no BOM, no NBSP)


def _first_json(text: str) -> object:
    """The first JSON value, as Go's json.Decoder reads it: trailing data ignored, every key
    pair kept in order (objects become lists of pairs, so duplicate keys are not collapsed)."""
    return json.JSONDecoder(object_pairs_hook=list).raw_decode(text.lstrip(_GO_WS))[0]


def _go_field(obj: object, name: str) -> object:
    """A struct field as Go's decoder fills it: keys matched case-insensitively, in document
    order, the last one winning; JSON null leaves it unset (None)."""
    if obj is None:
        return None
    if not isinstance(obj, list):
        raise ValueError(f"expected an object around {name!r}")
    found: object = None
    for key, value in obj:
        if key.lower() == name.lower() and value is not None:
            found = value
    return found


def _local_endpoint(endpoint: str) -> bool:
    """A unix socket on this host -- except Docker Desktop's, whose daemon runs in a VM."""
    return endpoint.startswith("unix://") and "/.docker/desktop/" not in endpoint


def _resolve_cold_blocker(env: Mapping[str, str], host: HostReader) -> str | None:
    docker_host = env.get("DOCKER_HOST", "").strip()
    if docker_host:
        if _local_endpoint(docker_host):
            return None
        return f"DOCKER_HOST={docker_host!r}: cold runsc runs on that daemon's host, not this one"
    cfg = _docker_config_dir(env)
    context = env.get("DOCKER_CONTEXT", "").strip()
    source = "DOCKER_CONTEXT"
    if not context:
        source = "docker config currentContext"
        raw = host.read(os.path.join(cfg, "config.json"))
        if raw is not None and raw.strip(_GO_WS):   # an empty file is the CLI's default config
            value = _go_field(_first_json(raw), "currentContext")
            if value is not None and not isinstance(value, str):
                raise ValueError("currentContext is not a string")
            context = (value or "").strip()
    if not context or context == "default":
        return None
    meta = os.path.join(cfg, "contexts", "meta",
                        hashlib.sha256(context.encode()).hexdigest(), "meta.json")
    try:
        endpoint = _go_field(_go_field(_go_field(_first_json(host.read(meta) or ""),
                                                 "Endpoints"), "docker"), "Host")
        if not isinstance(endpoint, str) or not endpoint:
            raise ValueError("no docker endpoint")
    except (ValueError, KeyError, TypeError):
        return f"{source} {context!r}: endpoint unknown, cold runsc may run on another host"
    if _local_endpoint(endpoint):
        return None
    return f"{source} {context!r} -> {endpoint!r}: cold runsc runs on that daemon's host"


def _parser_version(host: HostReader) -> str | None:
    for name in _AA_PARSERS:
        path = host.which(name)
        if path is None:
            continue
        proc = host.run([path, "--version"])
        ver = _version(proc.stdout + proc.stderr) if proc is not None else None
        return None if ver is None else ".".join(map(str, ver))
    return None


def _runsc(host: HostReader, env: Mapping[str, str]) -> tuple[str | None, bool | None]:
    # Exactly as the runtime reads it: set-but-empty is NOT "runsc".
    name = env.get("BLASTBOX_GVISOR_RUNSC", "runsc")
    path = host.which(name) if name and name == name.strip() else None
    if path is None:
        return None, None
    proc = host.run([path, "--version"])
    text = (proc.stdout + proc.stderr) if proc is not None else ""
    m = re.search(r"\brelease-(\d{8})(?:\.\d+)?", text)
    shown = m.group(0) if m else (_first_line(text) or "present (--version failed)")
    sibling = os.path.join(os.path.dirname(host.realpath(path)), "gvisor-bin", "gvisor_sentry")
    if host.exists(sibling):
        return shown, True
    if m is None:
        return shown, None
    return shown, int(m.group(1)) >= SPLIT_SENTRY_RELEASE


def _firecracker(host: HostReader, env: Mapping[str, str]) -> tuple[str | None, str | None]:
    fc = host.which(env.get("BLASTBOX_FC_BIN", "").strip() or "firecracker")
    jailer = host.which("jailer")
    if jailer is None and fc is not None:
        jailer = host.which(os.path.join(os.path.dirname(fc), "jailer"))
    return fc, jailer


def probe(host: HostReader, *, env: Mapping[str, str] | None = None,
          kinds: Collection[str] = (), landlock: int | None = None) -> HostLsm:
    """Read the host. Tool versions are probed only for ``kinds`` (runsc for gvisor;
    firecracker/jailer presence for firecracker) and the parser only when AppArmor is on, so an
    empty ``kinds`` never spawns anything. ``landlock`` is the ABI (None = 0)."""
    env = os.environ if env is None else env
    state = _probe_lsm(host, landlock)
    extra: dict[str, object] = {"cold_blocker": _cold_blocker(env, host)}
    if kinds and state.apparmor:
        extra["apparmor_parser"] = _parser_version(host)
    if "gvisor" in kinds:     # the warm tier's binary; cold runsc is dockerd's registered runtime
        extra["runsc"], extra["runsc_split_sentry"] = _runsc(host, env)
    if "firecracker" in kinds:
        extra["firecracker"], extra["jailer"] = _firecracker(host, env)
    return replace(state, **extra)  # type: ignore[arg-type]


def unmet(state: HostLsm, mode: str, kinds: Iterable[str]) -> list[str]:
    """Kinds ``require`` cannot satisfy on this host (empty outside require)."""
    if parse_mode(mode) != "require":
        return []
    return [k for k in kinds if state.would_use(k, mode) == "none"]


def check_required(state: HostLsm, mode: str, kinds: Iterable[str]) -> None:
    missing = unmet(state, mode, kinds)
    if missing:
        raise ConfinementUnavailable(
            f"{ENV_MODE}=require but no usable LSM for {', '.join(missing)} (selinux="
            f"{state.selinux}, apparmor={'on' if state.apparmor else 'off'}, landlock_abi="
            f"{state.landlock_abi}; Landlock covers firecracker only, permissive SELinux "
            "does not count"
            + "".join(f"; {b}" for b in (state.selinux_blocker, state.apparmor_blocker,
                                         state.cold_blocker) if b)
            + ")")


@dataclass(frozen=True)
class Detection:
    """The mode plus the host state, fixed when the dispatcher starts."""

    mode: str
    state: HostLsm

    def receipt(self, kind: str) -> dict[str, object] | None:
        """The signed-receipt record for a run of ``kind``. Strings only (the canonicaliser
        rejects floats). ``applied`` is "none" until the tier enforces: this release only
        detects. None under ``off``: the receipt keeps its old shape, the opt-out for
        verifiers that predate the field."""
        if self.mode == "off":
            return None
        return {"mode": self.mode, "available": self.state.would_use(kind, self.mode),
                "applied": "none"}


class _SysReader:
    def read(self, path: str) -> str | None:
        # Chunked: /proc/sys handlers refuse ONE large read() with ENOMEM.
        parts: list[str] = []
        total = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                while total < _READ_CAP:
                    chunk = fh.read(min(64 * 1024, _READ_CAP - total))
                    if not chunk:
                        break
                    parts.append(chunk)
                    total += len(chunk)
        except OSError:
            return None
        return "".join(parts)

    def exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def which(self, name: str) -> str | None:
        return None

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        return None


def detect(env: Mapping[str, str] | None = None, *, host: HostReader | None = None,
           landlock: int | None = None) -> Detection:
    """The dispatcher's startup detection: /sys reads and the Landlock query, no spawns.
    Raises ValueError on an invalid mode."""
    env = os.environ if env is None else env
    mode = mode_from_env(env)
    reader = _SysReader() if host is None else host
    state = _probe_lsm(reader, landlock_abi() if landlock is None else landlock)
    return Detection(mode=mode, state=replace(state, cold_blocker=_cold_blocker(env, reader)))
