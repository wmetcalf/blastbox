"""The worker seccomp denylist covers the new mount API, not just mount(2).

`mount`, `umount2` and `pivot_root` were denied, but Linux 5.2+ can build and attach a mount
without ever calling mount(2): `fsopen` -> `fsconfig` -> `fsmount` -> `move_mount`, plus
`open_tree` / `open_tree_attr` (clone a subtree), `fspick` (reconfigure an existing mount) and
`mount_setattr` (flip a mount's flags, e.g. drop `ro`/`nosuid`). A denylist that names only
the old calls lets a child that ever gains CAP_SYS_ADMIN in its namespace remount around the
`ro` binds the backends rely on. `chroot` rides along: the docker JSON profile already denies
it (allowlist), the namespace backends did not.

Three layers, cheapest first:

1. the shared name list and the nsjail KAFEL policy name every one of them;
2. the BPF bytes bwrap is handed return EPERM for each syscall NUMBER (evaluated here by a
   tiny cBPF interpreter, so no privilege is needed and the numbers are an independent oracle);
3. inside the real bwrap / nsjail sandbox, each call comes back EPERM. Several of these calls
   need no privilege at all with benign arguments (`open_tree(AT_FDCWD, "/", 0)` returns an
   O_PATH fd; `fsconfig(-1, ...)` is EBADF), so without the filter they visibly do NOT return
   EPERM -- which is what makes this layer fail on a denylist that misses them.
"""
from __future__ import annotations

import errno
import json
import platform
import re
import shutil
import struct
from pathlib import Path

import pytest

from blastbox.worker.sandbox.base import SandboxRequest

# Linux syscall numbers. The new-mount-API calls are in the unified asm-generic range, so they
# are the SAME on x86_64 and aarch64; chroot is not. Written out here, not taken from
# libseccomp, so a wrong number in the product cannot also be the oracle.
MOUNT_API_NR: dict[str, int] = {
    "open_tree": 428,
    "move_mount": 429,
    "fsopen": 430,
    "fsconfig": 431,
    "fsmount": 432,
    "fspick": 433,
    "mount_setattr": 442,
    "open_tree_attr": 467,
}
CHROOT_NR = {"x86_64": 161, "aarch64": 51}
NEW_DENIES = (*MOUNT_API_NR, "chroot")

AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000

_POLICY = Path(__file__).resolve().parents[3] / "deploy" / "seccomp" / "blastbox.seccomp.policy"


def _kafel_errno1_names() -> set[str]:
    text = _POLICY.read_text()
    block = text[text.index("ERRNO(1) {"):text.index("USE ")]
    names: set[str] = set()
    for line in block.splitlines():
        code, _, comment = line.partition("//")
        code = code.strip()
        if "{" in code or "}" in code:
            continue
        for tok in (t.strip() for t in code.split(",")):
            m = re.fullmatch(r"SYSCALL\[(\d+)\]", tok)
            if m:
                # A numbered entry must carry its name in the comment AND the right number.
                name = comment.strip()
                assert MOUNT_API_NR.get(name) == int(m.group(1)), (tok, name)
                names.add(name)
            elif tok.isidentifier():
                names.add(tok)
    return names


# --- layer 1: the lists -------------------------------------------------------------------


def test_the_shared_denylist_names_the_new_mount_api() -> None:
    from blastbox.worker.sandbox.seccomp_denylist import DENY_ERRNO1

    missing = [n for n in NEW_DENIES if n not in DENY_ERRNO1]
    assert not missing, f"bwrap BPF denylist misses {missing}"


def test_the_nsjail_kafel_policy_names_the_new_mount_api() -> None:
    missing = [n for n in NEW_DENIES if n not in _kafel_errno1_names()]
    assert not missing, f"nsjail KAFEL policy misses {missing}"


def test_the_docker_profile_does_not_allow_the_new_mount_api() -> None:
    """The docker JSON is an allowlist (default ERRNO), so these are denied by omission. Guard
    that nobody 'fixes' a crashing engine by allowing one of them."""
    prof = json.loads((_POLICY.parent / "blastbox.seccomp.json").read_text())
    assert prof["defaultAction"] == "SCMP_ACT_ERRNO"
    allowed = {n for s in prof["syscalls"] if s["action"] == "SCMP_ACT_ALLOW" for n in s["names"]}
    assert not (allowed & set(NEW_DENIES)), allowed & set(NEW_DENIES)


def test_a_libseccomp_that_predates_a_name_gets_its_number_not_a_dropped_filter() -> None:
    """Ubuntu 24.04's libseccomp 2.5.5 cannot resolve open_tree_attr (Linux 6.15). The builder is
    fail-closed, so an unresolvable name would drop the WHOLE filter on that host; the known
    number is used instead. An unknown name with no number still goes through as a name, so
    add_rule raises and the build fails closed."""
    from blastbox.worker.sandbox.seccomp_denylist import _syscall_ref

    class _Old:
        class Arch:
            NATIVE = 0

        @staticmethod
        def resolve_syscall(_arch: int, name: str) -> int:
            return -1 if name in ("open_tree_attr", "no_such_call") else 1

    for arch in ("x86_64", "aarch64"):
        assert _syscall_ref(_Old, "open_tree_attr", arch) == 467
        assert _syscall_ref(_Old, "mount", arch) == "mount"
        assert _syscall_ref(_Old, "no_such_call", arch) == "no_such_call"


# --- layer 2: the BPF bytes ---------------------------------------------------------------


def _run_cbpf(prog: bytes, nr: int, arch: int, args: tuple[int, ...] = (0,) * 6) -> int:
    """Evaluate a classic-BPF seccomp program against one seccomp_data. Supports the opcode
    subset libseccomp emits (LD/LDX/ST/STX, ALU, JMP, RET, TAX/TXA)."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, *args)
    insns = [struct.unpack_from("<HBBI", prog, i) for i in range(0, len(prog), 8)]
    a = x = 0
    mem = [0] * 16
    pc = 0
    m32 = 0xFFFFFFFF
    for _ in range(100_000):
        code, jt, jf, k = insns[pc]
        cls = code & 0x07
        if cls in (0, 1):                                         # LD / LDX
            mode = code & 0xE0
            if mode == 0x20:                                      # ABS (W only in seccomp)
                val = struct.unpack_from("<I", data, k)[0]
            elif mode == 0x00:                                    # IMM
                val = k
            elif mode == 0x60:                                    # MEM
                val = mem[k]
            elif mode == 0x80:                                    # LEN
                val = len(data)
            else:
                raise AssertionError(f"unsupported ld mode {code:#x}")
            if cls == 0:
                a = val
            else:
                x = val
        elif cls == 2:
            mem[k] = a
        elif cls == 3:
            mem[k] = x
        elif cls == 4:                                            # ALU
            src = x if code & 0x08 else k
            op = code & 0xF0
            a = {
                0x00: lambda: a + src, 0x10: lambda: a - src, 0x20: lambda: a * src,
                0x30: lambda: a // src, 0x40: lambda: a | src, 0x50: lambda: a & src,
                0x60: lambda: a << src, 0x70: lambda: a >> src, 0x80: lambda: -a,
                0xA0: lambda: a ^ src,
            }[op]() & m32
        elif cls == 5:                                            # JMP
            op = code & 0xF0
            src = x if code & 0x08 else k
            if op == 0x00:
                pc += 1 + k
                continue
            hit = {0x10: a == src, 0x20: a > src, 0x30: a >= src, 0x40: bool(a & src)}[op]
            pc += 1 + (jt if hit else jf)
            continue
        elif cls == 6:                                            # RET
            return {0x00: k, 0x08: x, 0x10: a}[code & 0x18]
        elif cls == 7:                                            # TAX / TXA
            if code & 0xF8 == 0x00:
                x = a
            else:
                a = x
        pc += 1
    raise AssertionError("BPF program did not terminate")


@pytest.fixture(scope="module")
def bpf() -> bytes:
    pytest.importorskip("seccomp")
    if platform.machine() not in ("x86_64", "amd64"):
        pytest.skip("the bwrap denylist BPF is x86_64-only")
    from blastbox.worker.sandbox.seccomp_denylist import build_bpf_bytes

    prog = build_bpf_bytes()
    assert prog is not None, "libseccomp is present but the denylist failed to build"
    return prog


def test_the_interpreter_agrees_with_known_rules(bpf: bytes) -> None:
    """Self-check of the oracle before trusting it: read(0) is allowed, mount(165) is EPERM,
    clone with CLONE_NEWUSER is EPERM, plain clone is allowed."""
    assert _run_cbpf(bpf, 0, AUDIT_ARCH_X86_64) == SECCOMP_RET_ALLOW
    assert _run_cbpf(bpf, 165, AUDIT_ARCH_X86_64) == SECCOMP_RET_ERRNO | errno.EPERM
    assert _run_cbpf(bpf, 56, AUDIT_ARCH_X86_64, (0x10000000, 0, 0, 0, 0, 0)) == (
        SECCOMP_RET_ERRNO | errno.EPERM)
    assert _run_cbpf(bpf, 56, AUDIT_ARCH_X86_64, (0x11, 0, 0, 0, 0, 0)) == SECCOMP_RET_ALLOW


@pytest.mark.parametrize("name", NEW_DENIES)
def test_the_bpf_returns_eperm_for_each_new_mount_syscall(bpf: bytes, name: str) -> None:
    nr = CHROOT_NR["x86_64"] if name == "chroot" else MOUNT_API_NR[name]
    got = _run_cbpf(bpf, nr, AUDIT_ARCH_X86_64)
    assert got == SECCOMP_RET_ERRNO | errno.EPERM, f"{name}({nr}) -> {got:#x}"


# --- layer 3: inside the real sandboxes ---------------------------------------------------

# Run inside the sandbox. Arguments are chosen so an UNFILTERED unprivileged call returns
# something other than EPERM wherever the kernel allows it (open_tree/open_tree_attr: an fd;
# fsconfig/mount_setattr: EBADF/EINVAL), so an EPERM there is the filter's. fsopen, fsmount,
# fspick, move_mount and chroot are EPERM unprivileged regardless; layer 2 is their proof.
_PROBE = r"""
import ctypes, json, os, platform
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
AT_FDCWD = -100
chroot_nr = {"x86_64": 161, "aarch64": 51}[platform.machine()]
calls = {
    "open_tree": (428, AT_FDCWD, b"/", 0),
    "open_tree_attr": (467, AT_FDCWD, b"/", 0, None, 0),
    "move_mount": (429, -1, b"", -1, b"", 0),
    "fsopen": (430, b"tmpfs", 0),
    "fsconfig": (431, -1, 0, None, None, 0),
    "fsmount": (432, -1, 0, 0),
    "fspick": (433, AT_FDCWD, b"/", 0),
    "mount_setattr": (442, -1, b"", 0, None, 0),
    "chroot": (chroot_nr, b"/"),
}
out = {}
for name, (nr, *args) in calls.items():
    r = libc.syscall(nr, *args)
    out[name] = "ok" if r >= 0 else ctypes.get_errno()
print(json.dumps(out))
"""


def _python3() -> str:
    p = "/usr/bin/python3"
    if not Path(p).exists():
        pytest.skip("no /usr/bin/python3 to run inside the sandbox")
    return p


def _assert_all_eperm(res) -> None:  # noqa: ANN001
    assert res.exit_code == 0, (res.exit_code, res.stderr[-400:])
    got = json.loads(res.stdout.decode().strip().splitlines()[-1])
    leaked = {k: v for k, v in got.items() if v != errno.EPERM}
    assert not leaked, (
        f"inside the sandbox these did not return EPERM (\"ok\" = it succeeded): {leaked}"
    )


_INSTALL = r"""
import ctypes, sys
bpf = sys.stdin.buffer.read()
libc = ctypes.CDLL(None, use_errno=True)
class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_char_p)]
prog = SockFprog(len(bpf) // 8, bpf)
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
assert libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
assert libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) == 0, ctypes.get_errno()
"""


def test_under_the_real_kernel_filter_the_new_mount_api_is_eperm(bpf: bytes) -> None:
    """No namespace needed: install the exact BPF bwrap is handed into a child with prctl and
    run the probe. Runs on hosts whose userns policy skips the sandbox tests below."""
    import subprocess
    import sys

    res = subprocess.run([sys.executable, "-I", "-c", _INSTALL + _PROBE], input=bpf,
                         capture_output=True, timeout=60)

    class _R:
        exit_code, stdout, stderr = res.returncode, res.stdout, res.stderr

    _assert_all_eperm(_R)


def test_inside_bwrap_the_new_mount_api_is_eperm() -> None:
    from .conftest import bwrap_usable

    why = bwrap_usable()
    if why:
        pytest.skip(f"bwrap not usable here: {why}")
    pytest.importorskip("seccomp")
    from blastbox.worker.sandbox.bwrap import BubblewrapSandbox

    sb = BubblewrapSandbox(bwrap_path=shutil.which("bwrap") or "/usr/bin/bwrap")
    assert sb.seccomp_active, sb.insecurity_reasons
    _assert_all_eperm(sb.run(SandboxRequest(argv=[_python3(), "-c", _PROBE])))


def test_inside_nsjail_the_new_mount_api_is_eperm() -> None:
    from .conftest import nsjail_usable

    why = nsjail_usable()
    if why:
        pytest.skip(f"nsjail not usable here: {why}")
    from blastbox.worker.sandbox.nsjail import NsjailSandbox

    sb = NsjailSandbox(seccomp_policy=_POLICY)
    _assert_all_eperm(sb.run(SandboxRequest(argv=[_python3(), "-c", _PROBE])))
