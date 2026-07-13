"""Shared source of truth for the worker syscall denylist + a libseccomp BPF builder.

The **nsjail** backend applies this denylist as a KAFEL policy
(``deploy/seccomp/blastbox.seccomp.policy``); the **bwrap** backend has no KAFEL, so it
builds an equivalent BPF program here (via ``python3-libseccomp``) and feeds it to
``bwrap --seccomp <fd>``. A parity test asserts this list equals the KAFEL ``ERRNO(1)`` block
so the two backends can't drift.

**Policy:** ``DEFAULT ALLOW`` + ``ERRNO(1)`` (EPERM) on the names below, ``ERRNO(38)`` (ENOSYS)
on ``clone3`` (its flags live in a struct seccomp can't inspect → glibc falls back to the
arg-filtered ``clone``), and ``ERRNO(1)`` on ``clone`` when **any** new-namespace flag is set
(mask ``0x7E020000``). **x86_64-only**, matching the nsjail policy. ``python3-libseccomp`` is a
*distro* package (not on PyPI); where it's absent the builder returns ``None`` and the bwrap
backend keeps marking itself insecure on the seccomp axis (fail-safe).
"""
from __future__ import annotations

import logging
import os
import platform

_log = logging.getLogger("blastbox.worker.sandbox.seccomp")

# EXACTLY the plain names in the KAFEL blastbox_deny ERRNO(1) block (clone/clone3 handled below).
# A parity test guards this equality so the bwrap BPF and the nsjail KAFEL policy can't drift.
DENY_ERRNO1: tuple[str, ...] = (
    "init_module", "finit_module", "delete_module",
    "add_key", "keyctl", "request_key",
    # libseccomp needs the REAL x86_64 syscall `umount2` (`umount` resolves to a pseudo that never
    # matches); the nsjail KAFEL policy names the same syscall `umount` (KAFEL can't lex `umount2` —
    # see the .policy header). Same intent, backend-appropriate name — the parity test normalizes it.
    "mount", "umount2", "pivot_root",
    "kexec_load", "kexec_file_load", "reboot",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "bpf", "perf_event_open",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "userfaultfd",
    "clock_settime", "clock_adjtime", "settimeofday", "adjtimex",
    "sethostname", "setdomainname",
    "unshare", "setns",
    "quotactl", "vhangup", "nfsservctl",
    "name_to_handle_at", "open_by_handle_at", "swapon", "swapoff",
    "kcmp", "uselib", "sysfs",
    "iopl", "ioperm", "modify_ldt",
    "fanotify_init", "fanotify_mark",
)

# clone(flags,...): deny when ANY new-namespace bit is set (blocks the child creating nested
# namespaces). Mask 0x7E020000 = CLONE_NEWNS|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET|NEWCGROUP.
# libseccomp can't express "(arg & mask) != 0" in one rule, so emit one MASKED_EQ rule per bit
# (rules for the same syscall OR together → any bit set ⇒ deny).
CLONE_NS_BITS: tuple[int, ...] = (
    0x00020000,  # CLONE_NEWNS
    0x04000000,  # CLONE_NEWUTS
    0x08000000,  # CLONE_NEWIPC
    0x10000000,  # CLONE_NEWUSER
    0x20000000,  # CLONE_NEWPID
    0x40000000,  # CLONE_NEWNET
    0x02000000,  # CLONE_NEWCGROUP
)
CLONE_NS_MASK = 0x7E020000  # == sum(CLONE_NS_BITS); the KAFEL clone_flags mask


def build_bpf_bytes() -> bytes | None:
    """Build the ``DEFAULT ALLOW`` denylist BPF via libseccomp and return its raw bytes (to feed
    ``bwrap --seccomp <fd>``).

    Returns ``None`` — so the caller keeps bwrap marked insecure — when the arch isn't x86_64,
    libseccomp is unavailable, OR **any** deny rule (a name, ``clone3``, or a ``clone`` bit) can't
    be added. That last case is deliberately **fail-CLOSED**: a partial denylist (e.g. an older
    libseccomp that doesn't know ``clone3``) would still report ``seccomp_active=True`` while
    silently allowing a denied syscall, breaking the parity guarantee — attach the FULL filter or
    none at all.
    """
    if platform.machine() not in ("x86_64", "amd64"):
        # The denylist (and the nsjail KAFEL policy it mirrors) is x86_64-only.
        _log.warning("seccomp: denylist is x86_64-only; not building on %s", platform.machine())
        return None
    try:
        import seccomp  # type: ignore[import-not-found]
    except Exception:
        return None
    try:
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
        for name in DENY_ERRNO1:
            try:
                f.add_rule(seccomp.ERRNO(1), name)
            except Exception as e:  # noqa: BLE001
                _log.warning("seccomp: cannot add deny rule for %r (%s) — failing closed", name, e)
                return None
        # clone3 → ENOSYS(38) so glibc falls back to the arg-filtered clone().
        try:
            f.add_rule(seccomp.ERRNO(38), "clone3")
        except Exception as e:  # noqa: BLE001
            _log.warning("seccomp: cannot add clone3 rule (%s) — failing closed", e)
            return None
        # clone() with any new-namespace bit → EPERM (one MASKED_EQ rule per bit).
        for bit in CLONE_NS_BITS:
            try:
                f.add_rule(seccomp.ERRNO(1), "clone", seccomp.Arg(0, seccomp.MASKED_EQ, bit, bit))
            except Exception as e:  # noqa: BLE001
                _log.warning("seccomp: cannot add clone ns-bit 0x%x rule (%s) — failing closed", bit, e)
                return None
        # Export to a memfd (unconditionally deadlock-safe vs a pipe). closefd=False → outer os.close owns it.
        fd = os.memfd_create("blastbox_seccomp_build", 0)
        try:
            with os.fdopen(fd, "wb", closefd=False) as bf:
                f.export_bpf(bf)   # flushed + closed by the with (fd stays open)
            os.lseek(fd, 0, os.SEEK_SET)
            return b"".join(iter(lambda: os.read(fd, 1 << 16), b""))
        finally:
            os.close(fd)
    except Exception as e:  # noqa: BLE001
        _log.warning("seccomp: BPF build failed, bwrap will run without a syscall filter: %s", e)
        return None
