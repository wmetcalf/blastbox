"""Container-native sandbox backend for the blastbox worker SDK.

In the container deployment mode the worker already runs inside a hardened
OCI container (``--cap-drop=ALL --no-new-privileges --read-only
--network=none`` + seccomp, launched by the dispatcher).  Nesting a second
sandbox layer (bwrap, nsjail) inside an existing container adds friction and
no additional isolation, so ``ContainerSandbox`` runs subprocesses directly.

Before any engine code runs the sandbox **self-checks** that the outer
container's hardening is actually effective by parsing ``/proc/self/status``
(injectable for unit tests via ``status_path``).  Any detected shortcoming is
recorded in :attr:`insecurity_reasons`.

Security guarantees on every :meth:`run` call:

* ``shell=True`` is NEVER used; ``argv`` is always passed as a list.
* The ambient ``os.environ`` is NEVER inherited — the subprocess receives only
  a minimal env (``PATH``, ``HOME=/tmp``) plus ``request.env`` overlay.
* ``resource.setrlimit`` is applied in a ``preexec_fn`` so RLIMIT_AS /
  RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CPU are enforced in the child before
  it exec()s the target binary.
* A child that exceeds ``request.limits.timeout_s`` is killed with SIGKILL;
  ``SandboxResult.killed`` is set to ``True``.
"""
from __future__ import annotations

import logging
import os
import resource
import signal
import subprocess
from pathlib import Path
from typing import Callable

from blastbox.errors import SandboxError
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult, kill_sandbox_group


_log = logging.getLogger("blastbox.worker.sandbox.container")

# Minimal safe environment passed to every child process.
# HOST os.environ is NEVER inherited — this dict (plus request.env) is all
# the child sees.
_MINIMAL_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
}


def _env_truthy(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    return raw not in ("", "0", "false", "no")


def _parse_status(status_path: Path) -> dict[str, str]:
    """Parse ``/proc/self/status`` (or a fake stand-in) into a key→value map.

    Robust to missing files, partial content, and gVisor-virtualized values.
    Returns an empty dict if the file cannot be read.
    """
    if not status_path.exists():
        return {}
    out: dict[str, str] = {}
    try:
        text = status_path.read_text(errors="replace")
    except OSError:
        return {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


def _runtime_hardening_reasons(
    status_path: Path,
    *,
    warn_on_insecure: bool,
) -> list[str]:
    """Collect reasons the container is NOT provably hardened.

    Parses ``status_path`` (normally ``/proc/self/status``) for three flags:

    * ``NoNewPrivs`` != ``"1"``  → ``"no_new_privs_off"``
    * ``Seccomp`` == ``"0"`` (or missing) → ``"seccomp_off"``
    * ``CapEff`` != ``"0000000000000000"`` (or missing) → ``"cap_not_dropped"``

    Under gVisor (``runsc``) ``/proc/self/status`` is virtualized — the values
    may not reflect the host-applied flags.  When ``warn_on_insecure=True``
    (set by the dispatcher under runsc via ``BLASTBOX_WARN_ON_INSECURE=1``)
    these three per-flag checks are **advisory**: the reasons are recorded but
    the sandbox remains usable.  When ``warn_on_insecure=False`` (strict /
    runc) the reasons make ``secure == False``.

    A structural ``"network_egress_not_verified"`` reason is **always**
    appended — the container backend cannot prove ``--network=none`` from
    inside the container, so ``secure`` is permanently ``False`` regardless
    of warn_on_insecure.  This is the conservative safe default.
    """
    status = _parse_status(status_path)
    per_flag_reasons: list[str] = []

    if status.get("NoNewPrivs") != "1":
        per_flag_reasons.append("no_new_privs_off")
    if status.get("Seccomp") in (None, "0"):
        per_flag_reasons.append("seccomp_off")
    # Treat a missing CapEff as insecure (unknown = unverified).
    # An all-zero value means all capabilities are dropped (safe).
    cap_eff = status.get("CapEff")
    if cap_eff is None or cap_eff.lower() not in ("0000000000000000",):
        per_flag_reasons.append("cap_not_dropped")

    if per_flag_reasons:
        if warn_on_insecure:
            _log.warning(
                "container hardening flags unverified (advisory, warn_on_insecure=True): %s",
                ", ".join(per_flag_reasons),
            )
        else:
            _log.warning(
                "container hardening flags missing or unverified: %s",
                ", ".join(per_flag_reasons),
            )

    # Always append the structural network-egress reason.  The container
    # backend cannot prove --network=none from inside; callers that need
    # security guarantees must treat this conservatively.
    all_reasons = per_flag_reasons + ["network_egress_not_verified"]
    return all_reasons


def _make_apply_rlimits(limits: Limits) -> Callable[[], None]:
    """Return a ``preexec_fn`` that applies rlimits inside the child process.

    Called after ``fork()`` but before ``exec()`` in the child.  Any failure
    to set a limit is silently swallowed (best-effort) so a missing/too-high
    ceiling on a particular platform doesn't prevent the child from starting.
    """
    timeout_s = limits.timeout_s
    memory_bytes = limits.memory_bytes
    tmpfs_bytes = limits.tmpfs_bytes

    def _set() -> None:
        # Virtual address space — primary memory guard.
        try:
            resource.setrlimit(
                resource.RLIMIT_AS, (memory_bytes, memory_bytes)
            )
        except (ValueError, OSError):
            pass

        # File size — prevent runaway writes.
        try:
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (tmpfs_bytes, tmpfs_bytes)
            )
        except (ValueError, OSError):
            pass

        # Open file descriptors — 4096 is generous for real workloads while
        # still capping fd leaks.
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
        except (ValueError, OSError):
            pass

        # CPU time hard limit (timeout_s + 30 s headroom).  The wall-clock
        # timeout in communicate() is the primary kill mechanism; RLIMIT_CPU
        # is a belt-and-suspenders backstop for CPU-bound infinite loops.
        cpu_hard = timeout_s + 30
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_hard, cpu_hard))
        except (ValueError, OSError):
            pass

        # Suppress core dumps.
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass

    return _set


class ContainerSandbox:
    """Run commands directly, trusting the enclosing container for isolation.

    Construction performs the hardening self-check and records any deficiencies
    in :attr:`insecurity_reasons`.  No exception is raised even when checks
    fail — callers inspect :attr:`secure` and :attr:`insecurity_reasons` to
    decide whether to proceed.

    Parameters
    ----------
    warn_on_insecure:
        ``True`` makes the per-flag checks advisory (gVisor mode).
        ``False`` (default) treats any per-flag failure as a hard insecurity
        reason.  ``None`` reads ``BLASTBOX_WARN_ON_INSECURE`` from env.
    status_path:
        Path to ``/proc/self/status`` equivalent.  Injectable for unit tests.
    """

    name = "container"

    def __init__(
        self,
        *,
        warn_on_insecure: bool | None = None,
        status_path: Path = Path("/proc/self/status"),
    ) -> None:
        if warn_on_insecure is None:
            warn_on_insecure = _env_truthy("BLASTBOX_WARN_ON_INSECURE")
        self._warn_on_insecure = warn_on_insecure
        self._status_path = status_path
        self._insecurity_reasons: list[str] = _runtime_hardening_reasons(
            status_path, warn_on_insecure=warn_on_insecure
        )
        _log.info(
            "ContainerSandbox initialised",
            extra={
                "warn_on_insecure": warn_on_insecure,
                "insecurity_reasons": self._insecurity_reasons,
            },
        )

    @property
    def secure(self) -> bool:
        """``False`` if any insecurity reason is present (always False for
        ContainerSandbox due to the structural ``network_egress_not_verified``
        reason)."""
        return not bool(self._insecurity_reasons)

    @property
    def insecurity_reasons(self) -> list[str]:
        """Copy of the list of insecurity reason strings."""
        return list(self._insecurity_reasons)

    def run(self, request: SandboxRequest) -> SandboxResult:
        """Run ``request.argv`` as a subprocess with a stripped env and rlimits.

        Security invariants:
        - ``shell=True`` is NEVER used.
        - The subprocess environment is built from scratch; ``os.environ`` is
          NOT inherited.  The child only sees ``_MINIMAL_ENV`` + ``request.env``.
        - ``_make_apply_rlimits`` is called as ``preexec_fn`` so RLIMIT_AS /
          RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CPU are set in the child
          process space before exec.
        - A child exceeding ``request.limits.timeout_s`` is SIGKILL-ed and
          ``SandboxResult.killed = True`` is returned.
        - ``argv`` is validated to be a non-empty list (never a string).
        """
        argv = request.argv
        if not isinstance(argv, list) or not argv:
            raise SandboxError("argv must be a non-empty list of strings")

        # Build the subprocess environment from scratch — never inherit from
        # os.environ.  _MINIMAL_ENV provides PATH + HOME=/tmp; request.env
        # overlays any engine-specific variables.
        child_env: dict[str, str] = {**_MINIMAL_ENV, **request.env}

        limits = request.limits
        preexec = _make_apply_rlimits(limits)

        killed = False
        try:
            proc = subprocess.Popen(
                argv,                    # list, never shell=True
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=child_env,           # stripped — no os.environ inheritance
                preexec_fn=preexec,      # rlimits applied in child before exec
                start_new_session=True,  # new process group for reliable cleanup
            )
        except FileNotFoundError as exc:
            raise SandboxError(f"failed to start {argv[0]!r}: {exc}") from exc

        try:
            stdout, stderr = proc.communicate(timeout=limits.timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            killed = True
            # Kill the entire process group to reap any children.
            kill_sandbox_group(proc)
            # Drain any partial output; accept another short timeout.
            try:
                stdout, stderr = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
            exit_code = -int(signal.SIGKILL)

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout or b"",
            stderr=stderr or b"",
            killed=killed,
        )
