"""Landlock capability sandbox (``nono``) backend for the blastbox worker SDK.

`nono <https://nono.sh>`_ applies a kernel-enforced **Landlock** ruleset
(filesystem capabilities) plus an optional network block, then execs the target
— "nono disappears". Its niche among the worker sandboxes is **containment
without user namespaces**: it runs where ``bwrap``/``nsjail`` cannot (hosts with
unprivileged userns disabled, no ``CAP_SYS_ADMIN``, or inside a container where
nesting namespaces is undesirable).

Trade-offs vs ``bwrap``/``nsjail`` (recorded in :attr:`insecurity_reasons`, so
``secure`` is ``False`` and auto-selection only reaches it as an explicit
fallback): Landlock mediates the **filesystem only** — there is no PID/mount
namespace (the child sees the host ``/proc`` and ``/sys``), and nono applies no
seccomp syscall filter. So it is strictly weaker than ``bwrap`` + seccomp; treat
it as an **explicit opt-in** (``BLASTBOX_SANDBOX=nono``) for the no-userns niche.
Measured overhead on nono ≥ 0.61 is +1–4 % per job (kernel Landlock enforcement
is ~free).

Security invariants shared with the other backends:
- ``shell=True`` is NEVER used; ``argv`` is always a list.
- The child env is built from scratch via ``env -i`` — ``os.environ`` is not
  inherited; the child sees only ``_MINIMAL_ENV`` + ``request.env``. nono's own
  state root is relocated (via ``HOME``) **off** the granted paths so the child
  cannot reach it.
- rlimits are applied in a ``preexec_fn``; a child exceeding the wall-clock
  timeout is SIGKILL-ed (``SandboxResult.killed=True``).
- Outbound network is blocked (``--block-net``).
"""
from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
from pathlib import Path
from typing import Callable

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.base import SandboxRequest, SandboxResult

_MINIMAL_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/tmp",
}

# Read-only system dirs every command needs (mirrors the bwrap base rootfs).
_RO_SYSTEM_DIRS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc")
# Read access children commonly need. No PID/mount namespace, so these are the
# HOST procfs/sysfs (an info-exposure flagged in insecurity_reasons).
_RO_RUNTIME_DIRS = ("/proc", "/sys")
# Writable surfaces the child needs: a writable HOME (/tmp) + device nodes
# (/dev/null, /dev/urandom, and /dev/shm for multiprocessing rasterizers).
_RW_BASE_DIRS = ("/tmp", "/dev")

# nono process env that reduces state writes + prompts (this is a one-shot wrap).
_NONO_QUIET_ENV: dict[str, str] = {
    "NONO_NO_UPDATE_CHECK": "1",
    "NONO_NO_SAVE_PROMPT": "1",
}

_DEFAULT_STATE_DIR = "/var/lib/blastbox/nono-state"


def _resolve_nono_bin() -> str | None:
    explicit = os.environ.get("BLASTBOX_NONO_BIN", "").strip()
    if explicit:
        return explicit if Path(explicit).exists() else None
    found = shutil.which("nono")
    return found


def _make_apply_rlimits(limits: Limits) -> Callable[[], None]:
    """Return a ``preexec_fn`` that applies rlimits in the child (best-effort)."""
    memory_bytes = limits.memory_bytes
    tmpfs_bytes = limits.tmpfs_bytes
    timeout_s = limits.timeout_s

    def _set() -> None:
        for res, val in (
            (resource.RLIMIT_AS, (memory_bytes, memory_bytes)),
            (resource.RLIMIT_FSIZE, (tmpfs_bytes, tmpfs_bytes)),
            (resource.RLIMIT_NOFILE, (4096, 4096)),
            (resource.RLIMIT_CPU, (timeout_s + 30, timeout_s + 30)),
            (resource.RLIMIT_CORE, (0, 0)),
        ):
            try:
                resource.setrlimit(res, val)
            except (ValueError, OSError):
                pass

    return _set


class NonoSandbox:
    """:class:`~blastbox.worker.sandbox.base.Sandbox` backed by nono (Landlock)."""

    name = "nono"

    def __init__(
        self,
        *,
        nono_bin: str | None = None,
        state_dir: str | os.PathLike[str] | None = None,
        popen: Callable[..., "subprocess.Popen[bytes]"] = subprocess.Popen,
    ) -> None:
        self._nono = nono_bin if nono_bin is not None else _resolve_nono_bin()
        self._state_dir = Path(
            state_dir
            if state_dir is not None
            else os.environ.get("BLASTBOX_NONO_STATE_DIR", _DEFAULT_STATE_DIR)
        )
        self._popen = popen
        self._binary_present = self._nono is not None and Path(self._nono).exists()

        reasons: list[str] = []
        if not self._binary_present:
            reasons.append("binary_missing")
        # nono provides Landlock fs containment + a network block, but NOT a
        # seccomp filter and NOT pid/mount-namespace isolation. Record honestly so
        # `secure` is False and nono is an explicit opt-in, not an auto-default.
        reasons.append("no_seccomp")
        reasons.append("no_pid_namespace")
        self._insecurity_reasons = reasons

    @property
    def secure(self) -> bool:
        """``False`` — nono is fs+net containment only (no seccomp / namespaces)."""
        return not bool(self._insecurity_reasons)

    @property
    def insecurity_reasons(self) -> list[str]:
        return list(self._insecurity_reasons)

    # ------------------------------------------------------------------
    def run(self, request: SandboxRequest) -> SandboxResult:
        if not isinstance(request.argv, list) or not request.argv:
            raise SandboxError("argv must be a non-empty list of strings")
        if not self._binary_present:
            raise SandboxUnavailable(
                "nono not found (install nono or set BLASTBOX_NONO_BIN)"
            )

        # nono writes a little config/cache to $HOME; relocate it OFF the granted
        # paths so the sandboxed child can't reach nono's own state. This dir must
        # NOT be under any granted mount (it isn't — grants never include it).
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SandboxUnavailable(
                f"nono state dir {self._state_dir} not writable "
                f"(set BLASTBOX_NONO_STATE_DIR to a writable dir off the grants): {exc}"
            ) from exc

        argv = self._build_argv(request)
        nono_env = {
            "PATH": _MINIMAL_ENV["PATH"],
            "HOME": str(self._state_dir),
            **_NONO_QUIET_ENV,
        }

        killed = False
        try:
            proc = self._popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                env=nono_env,
                preexec_fn=_make_apply_rlimits(request.limits),
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise SandboxError(f"failed to start nono: {exc}") from exc

        try:
            stdout, stderr = proc.communicate(timeout=request.limits.timeout_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            killed = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
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

    # ------------------------------------------------------------------
    def _build_argv(self, req: SandboxRequest) -> list[str]:
        """Build the ``nono wrap`` argv. All mount sources are value arguments
        after their flag token, so no caller value can inject a nono flag."""
        assert self._nono is not None  # guarded by _binary_present in run()
        grants: list[str] = []
        for d in (*_RO_SYSTEM_DIRS, *_RO_RUNTIME_DIRS):
            if Path(d).exists():
                grants += ["-r", d]
        for d in _RW_BASE_DIRS:
            if Path(d).exists():
                grants += ["-a", d]
        # nono's -r/-a grant DIRECTORIES; single files need --read-file/--allow-file.
        for m in req.ro_mounts:
            src = Path(m.source)
            grants += ["--read-file", str(src)] if src.is_file() else ["-r", str(src)]
        for m in req.rw_mounts:
            src = Path(m.source)
            grants += ["--allow-file", str(src)] if src.is_file() else ["-a", str(src)]

        # Child clean env via `env -i`: nono passes its own env through to the
        # child, so reset it explicitly (the child must NOT see nono's HOME=state).
        child_env = {**_MINIMAL_ENV, **req.env}
        env_prefix = ["/usr/bin/env", "-i"] + [f"{k}={v}" for k, v in child_env.items()]

        return [self._nono, "wrap", *grants, "--block-net", "--", *env_prefix, *req.argv]
