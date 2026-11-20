"""Host LSM detection for the confinement tier -- DETECTION AND REPORTING ONLY.

The confinement tier (later PRs) will put the HOST-side sandbox processes -- runsc's CLI, gofer
and sentry; firecracker -- into blastbox's own LSM policy, because runsc ignores the OCI
``apparmorProfile``/``selinuxLabel`` and firecracker has no LSM hook. Nothing here enters a
domain, loads a policy or changes the host: it answers "what does this host offer, and which LSM
WOULD each sandbox kind be confined with", for ``blastbox preflight`` and the dispatcher's log.

Selection, per sandbox kind ("cold" | "gvisor" | "firecracker"; cold is runsc started by dockerd,
judged on host state only and only with the default docker endpoint):

    SELinux (enforcing)  >  AppArmor (enabled)  >  Landlock (firecracker only)  >  none

SELinux in permissive mode only logs, so it is never selected (AL2023 ships permissive).
Landlock is not offered for gVisor: runsc mounts, which a Landlock domain forbids.

``BLASTBOX_CONFINEMENT``: ``auto`` (default; best available, else none), ``require`` (fail
closed when a kind this host runs has no usable LSM), ``off``. Anything else is an error, never
"off": a typo must not be what disables confinement.

Firecracker is JAILED by default (``BLASTBOX_FC_JAILER``, runtime/fc_jail.py): the dispatcher
never execs it; the root jail helper on the HOST does, under a per-jail AppArmor profile when its
``hello`` says so. A jailed VMM's confinement is therefore the HELPER's answer -- the dispatcher's
own label, securityfs view and Landlock say nothing about it -- and it is reported whatever
``BLASTBOX_CONFINEMENT`` says: it is the truth about the host, and ``off`` only means "do
not gate on it".
An unreachable helper is UNKNOWN (counted as none, so ``require`` fails closed); with jailing off
the dispatcher launches firecracker itself and its own context decides, as above.

Degrades cleanly: a container without securityfs (``/sys/kernel/security`` unmounted) falls
back to ``/sys/module/apparmor`` and ``/sys/fs/selinux``; a kernel without Landlock answers
ENOSYS/EOPNOTSUPP (ABI 0); a missing tool is reported absent, never raised.
"""
from __future__ import annotations

import ctypes
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


#: ``HostLsm.fc_jail``: how a firecracker VMM is launched, as far as confinement goes.
#:   off          BLASTBOX_FC_JAILER=off: the dispatcher execs firecracker itself
#:   apparmor     jailed; the helper answered and loads a per-jail AppArmor profile
#:   no-apparmor  jailed; the helper answered and loads none (AppArmor off there, --apparmor off)
#:   unknown      jailed; the helper could not be asked (down, restarting, not this uid's to ask)
#:   unusable     jailed; the helper refused for good (protocol skew), or a BLASTBOX_FC_JAILER typo
FC_JAIL_STATES = ("off", "apparmor", "no-apparmor", "unknown", "unusable")


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
    """What the host offers. Tool fields are None when not probed (the dispatcher's startup
    probe only reads files -- /sys, /proc/self/attr, /proc/self/mounts and the docker
    config.json, for currentContext only -- and never spawns)."""

    lsms: tuple[str, ...] | None        # /sys/kernel/security/lsm; None = securityfs unreadable
    apparmor: bool
    selinux: str                        # "enforcing" | "permissive" | "absent" | "unknown"
    landlock_abi: int                   # 0 = unavailable
    # Why an ON LSM still cannot be used from here (None = no known blocker): no securityfs to
    # load policy through, a caller already confined (docker-default has no change_profile), a
    # read-only selinuxfs (container engines bind it ro).
    apparmor_blocker: str | None = None
    selinux_blocker: str | None = None
    # Cold runsc is started by the daemon the docker CLI talks to; with any non-default
    # endpoint configuration this host's LSM view is not taken to describe it.
    cold_blocker: str | None = None
    apparmor_parser: str | None = None  # "4.0.1"; None = not found / not probed
    runsc: str | None = None            # "release-20261012.0"
    runsc_split_sentry: bool | None = None
    firecracker: str | None = None      # resolved path (unjailed only: the helper runs its own)
    jailer: str | None = None           # resolved path (unjailed only)
    fc_jail: str | None = None          # FC_JAIL_STATES; None = not probed (dispatcher's own view)
    fc_jail_detail: str | None = None   # the helper's socket and, when not answered, why

    def would_use(self, kind: str, mode: str = "auto") -> str:
        """The LSM ``kind``'s host processes would be confined with: selinux | apparmor |
        landlock | none. Pure."""
        if kind not in KINDS:
            raise ValueError(f"unknown sandbox kind {kind!r}")
        if kind == "firecracker" and self.fc_jail not in (None, "off"):
            # The jail helper, not this process, launches the VMM: only its answer counts.
            return "apparmor" if self.fc_jail == "apparmor" else "none"
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

    def jail_blocker(self) -> str | None:
        """Why a JAILED firecracker has no LSM (None when it has one, or is not jailed)."""
        where = f" ({self.fc_jail_detail})" if self.fc_jail_detail else ""
        return {
            "no-apparmor": "jail helper runs without per-jail AppArmor profiles (AppArmor off "
                           "where it runs, or --apparmor off)" + where,
            "unknown": "jail helper unreachable: a jailed firecracker's confinement is unknown "
                       "until it answers" + where,
            "unusable": "jail helper not usable: the firecracker tier does not run" + where,
        }.get(self.fc_jail or "")

    def blockers_for(self, kind: str) -> list[str]:
        """Why ``kind`` gets no LSM: cold has its own daemon-view blocker; a jailed firecracker
        the helper's; the kinds the dispatcher launches itself its caller-context blockers."""
        if kind == "cold":
            return [self.cold_blocker] if self.cold_blocker else []
        if kind == "firecracker" and self.fc_jail not in (None, "off"):
            jb = self.jail_blocker()
            return [jb] if jb else []
        return [b for b in (self.selinux_blocker, self.apparmor_blocker) if b]

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
            "fc_jail": self.fc_jail,
            "fc_jail_detail": self.fc_jail_detail,
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
    """Why the daemon the docker CLI talks to is not known to be THIS host's default one.
    Deliberately conservative: ANY non-default endpoint configuration -- DOCKER_HOST,
    DOCKER_TLS(_VERIFY), a non-default DOCKER_CONTEXT or config.json currentContext, or a
    config that cannot be read -- counts, without resolving where it points."""
    try:
        return _resolve_cold_blocker(env, host)
    except Exception as exc:  # noqa: BLE001 -- never raise on host state
        return f"docker endpoint config not readable ({type(exc).__name__})"


def _docker_config_dir(env: Mapping[str, str]) -> str:
    cfg = env.get("DOCKER_CONFIG", "")      # verbatim when set, as the CLI uses it
    if cfg:
        return cfg
    home = env.get("HOME", "")
    if not home:
        # As the docker CLI: an empty or unset HOME falls back to the passwd entry.
        import pwd  # noqa: PLC0415

        home = pwd.getpwuid(os.getuid()).pw_dir
    return os.path.join(home, ".docker")


def _stat_absent(path: str) -> bool:
    """True only when stat() -- which follows links as open() does -- says ENOENT."""
    try:
        os.stat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _absent(host: HostReader, path: str) -> bool:
    probe = getattr(host, "absent", None)
    if callable(probe):
        return bool(probe(path))
    return not host.exists(host.realpath(path))


class _Pairs(list):  # type: ignore[type-arg]
    """A decoded JSON object as its (key, value) pairs, duplicates kept."""


def _resolve_cold_blocker(env: Mapping[str, str], host: HostReader) -> str | None:
    if env.get("DOCKER_HOST", "").strip():
        return "DOCKER_HOST is set: cold runsc may run on another daemon's host"
    for var in ("DOCKER_TLS_VERIFY", "DOCKER_TLS"):
        if env.get(var, ""):
            return f"{var} is set: the docker CLI dials tcp://localhost:2376, not the socket"
    context = env.get("DOCKER_CONTEXT", "")
    if context.strip():
        if context == "default":
            return None
        return f"DOCKER_CONTEXT={context!r}: cold runsc may run on another daemon's host"
    path = os.path.join(_docker_config_dir(env), "config.json")
    raw = host.read(path)
    # Only ENOENT is "no config" to the CLI (silently); EACCES, ENOTDIR, ELOOP ... it warns on,
    # so they are unknown -- whether or not config.json is a symlink.
    if raw is None and not _absent(host, path):
        return f"docker config {path!r} could not be read (and is not simply absent): current " \
               "context unknown"
    if raw is not None and len(raw) >= _READ_CAP:
        return "docker config.json too large to read whole: current context unknown"
    if raw is None or not raw.strip():
        return None                      # no config, or an empty one: the default context
    try:
        doc = json.loads(raw, object_pairs_hook=_Pairs)
    except ValueError:
        return "docker config.json is not valid JSON: current context unknown"
    if doc is None:
        return None
    if not isinstance(doc, _Pairs):
        return "docker config.json is not an object: current context unknown"
    for key, value in doc:
        # Any spelling the CLI might take for currentContext (it folds case), any occurrence.
        if key.lower() == "currentcontext" and value not in (
                None, "", "default"):
            return f"docker config currentContext {value!r}: cold runsc may run elsewhere"
    return None


def _parser_version(host: HostReader) -> str | None:
    for name in _AA_PARSERS:
        path = host.which(name)
        if path is None:
            continue
        proc = host.run([path, "--version"])
        ver = _version(proc.stdout + proc.stderr) if proc is not None else None
        return "present (--version failed)" if ver is None else ".".join(map(str, ver))
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


def _fc_jail(host: HostReader, env: Mapping[str, str]) -> tuple[str, str | None]:
    """``(state, detail)`` for HostLsm.fc_jail. Asks the helper (one ``hello`` over its socket;
    nothing is spawned) only when jailing is on."""
    from blastbox.host.runtime.fc_jail import JailSettings  # noqa: PLC0415

    try:
        settings = JailSettings.from_env(dict(env))
    except ValueError as exc:
        return "unusable", str(exc)
    if not settings.enabled:
        return "off", None
    ask = getattr(host, "jail_hello", None)
    if not callable(ask):
        return "unknown", f"{settings.socket_path}: not asked from here"
    try:
        info, code, detail = ask(settings.socket_path)
    except Exception as exc:  # noqa: BLE001 -- never raise on host state
        info, code, detail = None, "error", f"{type(exc).__name__}: {exc}"
    if info is not None:
        return ("apparmor" if info.get("apparmor") else "no-apparmor"), settings.socket_path
    why = f"{settings.socket_path}: {code}" + (f": {detail}" if detail else "")
    # A protocol/READY-port skew is DECIDED (the runtime drops the tier); everything else --
    # down, timing out, busy, or a uid it does not answer (root preflight) -- is not known.
    return ("unusable" if code == "protocol" else "unknown"), why


def probe(host: HostReader, *, env: Mapping[str, str] | None = None,
          kinds: Collection[str] = (), landlock: int | None = None) -> HostLsm:
    """Read the host. Tool versions are probed only for ``kinds`` (runsc for gvisor; for
    firecracker the jail helper's ``hello`` when jailing is on, else firecracker/jailer
    presence) and the parser only when AppArmor is on, so an empty ``kinds`` never spawns or
    connects anything. ``landlock`` is the ABI (None = 0)."""
    env = os.environ if env is None else env
    state = _probe_lsm(host, landlock)
    extra: dict[str, object] = {"cold_blocker": _cold_blocker(env, host)}
    if kinds and state.apparmor:
        extra["apparmor_parser"] = _parser_version(host)
    if "gvisor" in kinds:     # the warm tier's binary; cold runsc is dockerd's registered runtime
        extra["runsc"], extra["runsc_split_sentry"] = _runsc(host, env)
    if "firecracker" in kinds:
        extra["fc_jail"], extra["fc_jail_detail"] = _fc_jail(host, env)
        if extra["fc_jail"] == "off":
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
            + "".join(f"; {b}" for b in _blockers(state, missing))
            + ")")


def _blockers(state: HostLsm, kinds: Iterable[str]) -> list[str]:
    """The blockers that apply to ``kinds`` (HostLsm.blockers_for), each once, in kind order."""
    out: list[str] = []
    for kind in [k for k in KINDS if k in set(kinds)]:
        out += [b for b in state.blockers_for(kind) if b not in out]
    return out


@dataclass(frozen=True)
class Detection:
    """The mode plus the host state, fixed when the dispatcher starts."""

    mode: str
    state: HostLsm

    def summary(self, kinds: Iterable[str]) -> str:
        """One log line: the mode and, per kind, the LSM it would be confined with (and why
        not, for a kind left with none)."""
        st = self.state
        parts = [f"mode={self.mode}"]
        for kind in kinds:
            use = st.would_use(kind, self.mode)
            jailed = kind == "firecracker" and st.fc_jail not in (None, "off")
            if use != "none":
                why = ["jail helper"] if jailed else []
            else:
                why = [] if self.mode == "off" and not jailed else st.blockers_for(kind)
            parts.append(f"{kind}={use}" + (f" ({'; '.join(why)})" if why else ""))
        return ", ".join(parts)


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

    def absent(self, path: str) -> bool:
        return _stat_absent(path)

    def which(self, name: str) -> str | None:
        return None

    def realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str] | None:
        return None

    def jail_hello(self, socket_path: str) -> tuple[dict[str, object] | None, str, str]:
        """The jail helper's ``hello`` -- one connection, nothing spawned, bounded."""
        from blastbox.host.runtime.fc_jail import JailClient, JailError  # noqa: PLC0415

        try:
            return JailClient(socket_path, timeout_s=_JAIL_HELLO_S).hello(), "", ""
        except JailError as exc:
            return None, exc.code, exc.detail
        except Exception as exc:  # noqa: BLE001 -- never raise on host state
            return None, "error", str(exc)


#: Bound on the startup ``hello`` to the jail helper: a stalled helper costs seconds, not 60.
_JAIL_HELLO_S = 5.0


def detect(env: Mapping[str, str] | None = None, *, host: HostReader | None = None,
           landlock: int | None = None, kinds: Collection[str] = ()) -> Detection:
    """The dispatcher's startup detection: file reads, the Landlock query and -- only when
    ``kinds`` holds firecracker and jailing is on -- one ``hello`` to the jail helper; never a
    spawn. Raises ValueError on an invalid mode."""
    env = os.environ if env is None else env
    mode = mode_from_env(env)
    reader = _SysReader() if host is None else host
    state = _probe_lsm(reader, landlock_abi() if landlock is None else landlock)
    extra: dict[str, object] = {"cold_blocker": _cold_blocker(env, reader)}
    if "firecracker" in kinds:
        extra["fc_jail"], extra["fc_jail_detail"] = _fc_jail(reader, env)
    return Detection(mode=mode, state=replace(state, **extra))  # type: ignore[arg-type]
