"""Sandbox backend auto-selection for the blastbox worker SDK.

Selection order (auto mode):

1. ``nsjail`` — strongest isolation on a bare-metal host; KAFEL seccomp
   policy + namespace isolation + strict rlimits.
2. ``bwrap`` — bubblewrap user-namespace sandbox; good isolation without
   nsjail.
3. ``nono`` — Landlock capability sandbox; filesystem + network containment
   WITHOUT user namespaces (runs where bwrap/nsjail can't). ``secure == False``
   (no seccomp / namespaces), so auto-mode only reaches it under
   ``BLASTBOX_WARN_ON_INSECURE``; otherwise an explicit ``BLASTBOX_SANDBOX=nono``.
4. ``container`` — runs subprocesses directly, trusting the enclosing OCI
   container for isolation.  Always selected inside a Docker/OCI container.

Override with ``BLASTBOX_SANDBOX={nsjail,bwrap,nono,container}``.

In auto mode an insecure backend (``secure == False``) is refused unless
``BLASTBOX_WARN_ON_INSECURE=1``.  In forced mode the same rule applies
unless the env var is set.

Inside a container (detected by checking ``/.dockerenv`` or cgroup membership)
the ``container`` backend is always preferred; nesting bwrap/nsjail adds
friction and no additional isolation.
"""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from blastbox.errors import SandboxUnavailable
from blastbox.worker.sandbox.base import Sandbox, SandboxRequest
from blastbox.worker.sandbox.container import ContainerSandbox


_log = logging.getLogger("blastbox.worker.sandbox")

# All known backend names in preferred order for auto selection on a bare-metal host.
# `nono` (Landlock, no user namespaces) sits after bwrap/nsjail as the fallback for
# hosts where namespace sandboxes can't run; it is `secure=False` (no seccomp/ns) so
# auto-mode only reaches it under BLASTBOX_WARN_ON_INSECURE — otherwise an explicit
# opt-in via BLASTBOX_SANDBOX=nono.
_ALL_BACKENDS = ("nsjail", "bwrap", "nono", "container")

# Backends preferred inside a container (skip namespace-based backends).
_CONTAINER_BACKENDS = ("container",)


def _env_truthy(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw not in ("", "0", "false", "no")


def _in_container() -> bool:
    """Heuristic: are we running inside a Docker/OCI container?"""
    if Path("/.dockerenv").exists():
        return True
    # cgroup v2: container runtimes typically set a cgroup path that does not
    # begin with /1 (init) but contains something like /docker/ or /kubepods/.
    try:
        cg = Path("/proc/self/cgroup").read_text(errors="replace")
        if "docker" in cg or "kubepods" in cg or "containerd" in cg:
            return True
    except OSError:
        pass
    return False


def _make_backend(
    name: str,
    *,
    warn_on_insecure: bool,
    status_path: Path,
) -> Sandbox:
    """Instantiate a backend by name.

    Raises :exc:`SandboxUnavailable` if the backend cannot be constructed
    (e.g. binary not found).
    """
    if name == "container":
        return ContainerSandbox(
            warn_on_insecure=warn_on_insecure,
            status_path=status_path,
        )
    if name == "bwrap":
        from blastbox.worker.sandbox.bwrap import BubblewrapSandbox
        return BubblewrapSandbox()
    if name == "nsjail":
        from blastbox.worker.sandbox.nsjail import NsjailSandbox
        return NsjailSandbox()
    if name == "nono":
        from blastbox.worker.sandbox.nono import NonoSandbox
        return NonoSandbox()
    raise SandboxUnavailable(f"unknown backend: {name!r}")


class _ProfileDeniesProbe(SandboxUnavailable):
    """The backend works; the child profile refuses the probe binary.

    A distinct type because the SELECTION consequence is different. An ordinary smoketest
    failure means "this backend does not work here, try the next one". This one means the
    operator's own MAC policy is misconfigured -- and falling through to the next backend
    walks straight past bwrap (same profile, same denial) to `container`, which on bare metal
    is a plain subprocess on the host with no namespace, no seccomp and no MAC at all
    (claude-security lens, #177). Demoting a malware detonation from nsjail to fork/exec
    because a profile is too narrow is not a fallback, it is the worst possible reading of
    the operator's intent. Selection stops instead.
    """


def _probe(sb: Sandbox, argv: list[str]) -> Exception | None:
    """Run ``argv`` through ``sb``; None on success, else why not."""
    try:
        result = sb.run(SandboxRequest(argv=argv))
    except Exception as exc:  # noqa: BLE001
        return exc
    if result.exit_code != 0 or result.killed:
        return SandboxUnavailable(
            f"{sb.name} smoketest exit={result.exit_code} killed={result.killed}"
        )
    return None


def _looks_like_a_timeout(err: Exception | None) -> bool:
    """A probe killed on the clock is a slow host, never an AppArmor denial.

    `_probe` reports `killed` the same way it reports a non-zero exit, and the profile-denial
    conclusion is the one that aborts selection with no fallback -- so the two must not be
    confused.
    """
    return err is not None and "killed=True" in str(err)


def _smoketest(sb: Sandbox) -> tuple[bool, Exception | None]:
    """Run ``/usr/bin/true`` through the backend's REAL argv; ``(True, None)`` on success.

    The probe deliberately carries everything a job carries, AppArmor prefix included -- a
    probe that skips the confinement is not testing what will run. The cost is that a child
    profile narrow enough for one parser can deny the probe binary, and then a working
    backend with a working profile is rejected with nothing but "smoketest failed" to go on
    (codex, #177). So on failure, when a profile was attached, probe once more with it
    suspended: if THAT succeeds, the profile is the cause and the message says so. The
    rejection stands either way -- a profile that cannot run ``/usr/bin/true`` is a profile
    to fix, not one to quietly bypass -- but "fix your profile" and "this backend does not
    work here" are different afternoons.
    """
    # Prefer /usr/bin/true which works on merged-usr systems.
    true_path = "/usr/bin/true" if Path("/usr/bin/true").exists() else "/bin/true"
    err = _probe(sb, [true_path])
    if err is None:
        return True, None

    suspend = getattr(sb, "apparmor_suspended", None)
    if suspend is not None and getattr(sb, "apparmor_active", False):
        # CONFIRM the confined failure before blaming the profile for it. This conclusion
        # aborts selection outright -- no bwrap, no container -- so a single flaky probe
        # (memory pressure, a slow host, a transient mount error) would stop a worker from
        # starting and send the operator to edit a profile that is correct. Two failures with
        # the profile and a success without it is a much narrower claim than one of each
        # (claude-code-review lens, round 2 of #177).
        confirm_err = _probe(sb, [true_path])
        with suspend():
            unconfined_err = _probe(sb, [true_path])
        if (
            confirm_err is not None
            and unconfined_err is None
            and not _looks_like_a_timeout(err)
            and not _looks_like_a_timeout(confirm_err)
        ):
            profile = getattr(sb, "_apparmor_profile", "the child profile")
            _log.warning(
                "sandbox smoketest fails only WITH the AppArmor profile",
                extra={"backend": sb.name, "profile": profile, "probe": true_path},
            )
            return False, _ProfileDeniesProbe(
                f"{sb.name} smoketest fails with AppArmor profile {profile!r} but passes "
                f"without it: the profile denies the probe {true_path}. Permit it in the "
                f"profile (it is also what a worker's own preflight runs), or unload the "
                f"profile and accept the loss of confinement"
            )
    return False, err


def _security_state(sb: Sandbox) -> tuple[bool, list[str]]:
    secure = bool(getattr(sb, "secure", False))
    reasons = list(getattr(sb, "insecurity_reasons", []))
    return secure, reasons


def select_sandbox(
    *,
    backend: str | None = None,
    _status_path: Path = Path("/proc/self/status"),
) -> Sandbox:
    """Return a ready sandbox backend, or raise :exc:`SandboxUnavailable`.

    Selection logic
    ---------------
    1. If ``backend`` is given (or ``BLASTBOX_SANDBOX`` env var is set),
       force that backend — no silent fallback.
    2. If inside a container (heuristic), try only ``container``.
    3. Otherwise try ``nsjail``, ``bwrap``, ``nono``, ``container`` in order;
       accept the first that constructs, passes ``/usr/bin/true`` smoketest, and
       is not insecure (unless ``BLASTBOX_WARN_ON_INSECURE=1``). ``nono`` is
       ``secure=False`` (no seccomp/namespaces), so auto-mode only reaches it under
       that env var; it is otherwise an explicit ``BLASTBOX_SANDBOX=nono`` choice.

    Parameters
    ----------
    backend:
        Explicit backend name (``"nsjail"``, ``"bwrap"``, ``"nono"``,
        ``"container"``). Overrides ``BLASTBOX_SANDBOX`` env var.
    _status_path:
        Injected ``/proc/self/status`` stand-in for unit tests.
    """
    warn_on_insecure = _env_truthy("BLASTBOX_WARN_ON_INSECURE")

    # Determine the effective backend name from arg or env.
    forced_name: str | None = backend
    if forced_name is None:
        env_val = os.environ.get("BLASTBOX_SANDBOX", "").strip().lower()
        if env_val:
            forced_name = env_val

    if forced_name is not None:
        return _select_forced(
            forced_name,
            warn_on_insecure=warn_on_insecure,
            status_path=_status_path,
        )

    # Auto-select: prefer container if we're already inside one.
    candidates = _CONTAINER_BACKENDS if _in_container() else _ALL_BACKENDS

    # EVERY rejection, not just the last one. When no backend survives, the reason the
    # operator needs is usually the FIRST candidate's (nsjail's) -- "last error" reported
    # whatever `container` said, which is a different subsystem and a misleading place to
    # start. One `apparmor_missing` across nsjail and bwrap is a one-command fix; reading it
    # off the container backend's complaint is an afternoon.
    rejections: list[str] = []
    # Set only by a REJECTION whose structured reasons contain apparmor_missing -- never by
    # matching text. The smoketest's own diagnosis ends with "...accept apparmor_missing", so
    # a substring test fired on a host whose profile is loaded AND enforcing and then told the
    # operator to load it, offering BLASTBOX_WARN_ON_INSECURE=1 as the alternative -- which
    # cannot help, because the smoketest gate runs before the security gate and ignores that
    # variable entirely (claude-code-review lens, #177).
    apparmor_gap = False
    for name in candidates:
        try:
            sb = _make_backend(name, warn_on_insecure=warn_on_insecure, status_path=_status_path)
        except SandboxUnavailable as exc:
            rejections.append(f"{name}: unavailable ({exc})")
            _log.debug("backend unavailable: %s — %s", name, exc)
            continue

        smoke_ok, smoke_err = _smoketest(sb)
        if not smoke_ok:
            if isinstance(smoke_err, _ProfileDeniesProbe):
                # NOT a fallback condition. Every remaining candidate is either weaker than
                # this one or carries the same profile, so continuing can only end at a less
                # confined backend chosen because confinement was misconfigured.
                _log.error(
                    "sandbox selection aborted: the child AppArmor profile denies the probe",
                    extra={"backend": name, "detail": str(smoke_err)},
                )
                raise smoke_err
            rejections.append(f"{name}: smoketest failed ({smoke_err})")
            _log.debug("backend smoketest failed: %s — %s", name, smoke_err)
            continue

        secure, reasons = _security_state(sb)
        if not secure:
            detail = ", ".join(reasons) or "unspecified"
            if not warn_on_insecure:
                blocked = getattr(sb, "apparmor_blocked_reason", None)
                if blocked and "apparmor_missing" in reasons:
                    # The backend knows a cause the generic remedy cannot guess (an nsjail
                    # build with no --proc_rw). Carry it instead of letting the hint send the
                    # operator to load a profile that is already loaded.
                    rejections.append(f"{name}: insecure ({detail}: {blocked})")
                else:
                    rejections.append(f"{name}: insecure ({detail})")
                    if "apparmor_missing" in reasons:
                        apparmor_gap = True
                _log.warning(
                    "sandbox backend rejected as insecure",
                    extra={"backend": name, "reasons": reasons},
                )
                continue
            _log.warning(
                "sandbox backend selected in insecure mode",
                extra={"backend": name, "reasons": reasons},
            )

        # ADMISSION HAPPENS HERE, not in the constructor. The regression guard compares
        # against the confinement the selector accepted, and capturing that in __init__ made it
        # inert for a profile that became enforcing between construction and this point
        # (codex, #177).
        note = getattr(sb, "note_admitted", None)
        if note is not None:
            note()
        _log.info("sandbox backend selected", extra={"backend": name})
        return sb

    hint = _apparmor_remedy() if apparmor_gap else ""
    raise SandboxUnavailable(
        "no sandbox backend available: " + "; ".join(rejections) + hint
    )


def _apparmor_remedy() -> str:
    """The way out of `apparmor_missing`, naming the half that is actually missing.

    Two independent causes -- no `aa-exec` helper, or no enforcing profile -- and telling an
    operator whose apparmor-utils package is absent to go load a profile sends them to fix
    the half that is already fine (claude-code-review lens, #177). The helper is probed here
    rather than remembered from a backend, because by the time this is needed every backend
    that could have said has already been rejected.

    Shared by the auto and FORCED paths. It was written for auto only, so an operator who
    pinned `BLASTBOX_SANDBOX=bwrap` -- which the pre-#160 deployment recipe told them to do --
    got `forced backend 'bwrap' is insecure: apparmor_missing` and none of the remedies,
    while the operator who left it on auto got all of them (claude-blast-radius lens, #177).
    """
    remedy = (
        "installing the aa-exec helper (the apparmor / apparmor-utils package)"
        if shutil.which("aa-exec") is None
        else "loading the child profile named by BLASTBOX_APPARMOR_PROFILE "
             "(default blastbox-sandbox; this repo ships one in deploy/apparmor/) "
             "in enforce or kill mode"
    )
    return (
        f"; apparmor_missing is satisfied by {remedy} — see deploy/apparmor/README.md — "
        "or accepted knowingly with BLASTBOX_WARN_ON_INSECURE=1"
    )


def _select_forced(
    name: str,
    *,
    warn_on_insecure: bool,
    status_path: Path,
) -> Sandbox:
    """Construct and smoketest a forced backend; raise on any failure."""
    valid_names = _ALL_BACKENDS
    if name not in valid_names:
        raise SandboxUnavailable(
            f"BLASTBOX_SANDBOX={name!r} is not a valid backend; "
            f"valid values are: {sorted(valid_names)}"
        )

    try:
        sb = _make_backend(name, warn_on_insecure=warn_on_insecure, status_path=status_path)
    except SandboxUnavailable:
        raise

    smoke_ok, smoke_err = _smoketest(sb)
    if not smoke_ok:
        raise SandboxUnavailable(
            f"forced backend {name!r} failed smoketest: {smoke_err}"
        )

    secure, reasons = _security_state(sb)
    if not secure:
        detail = ", ".join(reasons) or "unspecified"
        if not warn_on_insecure:
            raise SandboxUnavailable(
                f"forced backend {name!r} is insecure: {detail}"
                + (_apparmor_remedy() if "apparmor_missing" in reasons else "")
            )
        _log.warning(
            "sandbox backend selected in insecure mode (forced)",
            extra={"backend": name, "reasons": reasons},
        )

    note = getattr(sb, "note_admitted", None)
    if note is not None:
        note()
    _log.info("sandbox backend selected (forced)", extra={"backend": name})
    return sb
