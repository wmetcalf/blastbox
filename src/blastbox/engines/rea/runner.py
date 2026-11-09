"""Bounded REA / Ghidra CLI runner seam.

Every subprocess runs with :func:`rea_env` (work-dir scoped TMPDIR/HOME, a small
env allowlist, no proxy variables). Output is capped *while reading*, and a
timeout or overflow kills the whole process group (Ghidra forks a JVM).
The only caller-influenced argv element is the sample path.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import threading
import time
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

MAX_STDOUT = 4 * 1024 * 1024
MAX_MEMBERS = 256
MAX_MEMBER_BYTES = 64 * 1024 * 1024

# Exact allowlist: no REA_* prefix rule (REA_OPENAI_API_KEY etc. must never pass).
_ENV_ALLOW = (
    "PATH",
    "JAVA_HOME",
    "GHIDRA_INSTALL_DIR",
    "REA_BIN",
    "LANG",
    "REA_ANALYSIS_PROVIDER",
)

INSPECT_MAP: dict[str, tuple[str, ...]] = {
    "pe": (
        "inspect-pe-imports",
        "inspect-pe-certificates",
        "inspect-pe-load-config",
        "inspect-pe-resources",
        "inspect-native-exports",
        "inspect-byte-entropy",
        "inspect-go-binary",
        "inspect-rust-binary",
        "inspect-artifact",
    ),
    "elf": (
        "inspect-elf-notes",
        "inspect-native-exports",
        "inspect-byte-entropy",
        "inspect-go-binary",
        "inspect-rust-binary",
        "inspect-artifact",
    ),
    "macho": (
        "inspect-macho",
        "inspect-go-binary",
        "inspect-rust-binary",
        "inspect-artifact",
    ),
    "dotnet": (
        "inspect-managed-artifact",
        "inspect-pe-certificates",
        "inspect-pe-resources",
        "inspect-byte-entropy",
    ),
    "apk": ("inspect-apk-signature", "inspect-artifact"),
    "asar": ("inspect-artifact",),
    "archive": ("inspect-artifact",),
    "firmware": ("inspect-firmware-regions", "inspect-artifact"),
    "other": ("inspect-artifact",),
}
_ALLOWED_INSPECT = frozenset(c for cmds in INSPECT_MAP.values() for c in cmds)


# ---------------------------------------------------------------- environment


def rea_env(work_dir: Path, base: Mapping[str, str]) -> dict[str, str]:
    """Environment for every REA/Ghidra subprocess, scoped under ``work_dir``."""
    tmp = work_dir / "tmp"
    home = work_dir / "home"
    cache = home / ".cache"
    config = home / ".config"
    for d in (tmp, home, cache, config):
        d.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in base.items() if k in _ENV_ALLOW}
    env.update(
        TMPDIR=str(tmp),
        HOME=str(home),
        XDG_CACHE_HOME=str(cache),
        XDG_CONFIG_HOME=str(config),
        JAVA_TOOL_OPTIONS=f"-Djava.io.tmpdir={tmp} -Duser.home={home} -XX:-UsePerfData",
    )
    return env


# ------------------------------------------------------------------ execution


@dataclass(frozen=True)
class RunOutcome:
    rc: int | None
    stdout: bytes = b""
    capped: bool = False
    timed_out: bool = False


RunFn = Callable[..., RunOutcome]
"""``run_fn(argv, *, env, cwd, timeout_s, max_stdout) -> RunOutcome``."""


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def bounded_run(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None,
    timeout_s: float,
    max_stdout: int,
) -> RunOutcome:
    """Run ``argv`` in its own process group, capping stdout while reading.

    ``max_stdout == 0`` discards stdout. stderr is always discarded.
    """
    keep = max_stdout > 0
    proc = subprocess.Popen(
        argv,
        env=dict(env),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if keep else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    buf = bytearray()
    capped = threading.Event()

    def reader() -> None:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                return
            room = max_stdout - len(buf)
            if len(chunk) > room:
                buf.extend(chunk[:room])
                capped.set()
                _kill_group(proc)
                return
            buf.extend(chunk)

    t = threading.Thread(target=reader, daemon=True)
    if keep:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # Reap stragglers (JVM children) whatever happened.
        _kill_group(proc)
        proc.wait()
        if keep:
            t.join(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()
    if capped.is_set():
        return RunOutcome(proc.returncode, bytes(buf), capped=True)
    return RunOutcome(None if timed_out else proc.returncode, bytes(buf), timed_out=timed_out)


# ------------------------------------------------------------------- classify

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
}
_FIRMWARE_MAGICS = (b"\x27\x05\x19\x56", b"hsqs", b"sqsh", b"ANDROID!")
_ARCHIVE_MAGICS = (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
_HEAD = 65536


def _pe_kind(head: bytes) -> str:
    if len(head) < 0x40:
        return "other"
    (lfanew,) = struct.unpack_from("<I", head, 0x3C)
    if lfanew > len(head) - 24 or head[lfanew : lfanew + 4] != b"PE\0\0":
        return "other"
    opt = lfanew + 24
    if opt + 2 > len(head):
        return "pe"
    (magic,) = struct.unpack_from("<H", head, opt)
    if magic == 0x10B:
        nrva_off, dirs = opt + 92, opt + 96
    elif magic == 0x20B:
        nrva_off, dirs = opt + 108, opt + 112
    else:
        return "pe"
    clr = dirs + 14 * 8
    if clr + 8 > len(head):
        return "pe"
    (nrva,) = struct.unpack_from("<I", head, nrva_off)
    rva, size = struct.unpack_from("<II", head, clr)
    return "dotnet" if nrva > 14 and rva and size else "pe"


def classify(sample: Path) -> str:
    """Classify by magic bytes: pe|elf|macho|dotnet|apk|asar|archive|firmware|other."""
    try:
        with sample.open("rb") as f:
            head = f.read(_HEAD)
    except OSError:
        return "other"
    if head[:2] == b"MZ":
        return _pe_kind(head)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # Fat Mach-O has a small arch count; Java classes carry version >= 45 there.
        (n,) = struct.unpack_from(">I", head, 4)
        if 0 < n < 20:
            return "macho"
    if head[:4] == b"\x04\x00\x00\x00" and head[16:24] == b'{"files"':
        return "asar"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        try:
            with zipfile.ZipFile(sample) as z:
                if "AndroidManifest.xml" in z.namelist():
                    return "apk"
        except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
            pass
        return "archive"
    if any(head.startswith(m) for m in _ARCHIVE_MAGICS):
        return "archive"
    if any(head.startswith(m) for m in _FIRMWARE_MAGICS):
        return "firmware"
    return "other"


# --------------------------------------------------------------------- runner


@dataclass
class ExtractResult:
    files: list[Path] = field(default_factory=list)
    dropped: list[tuple[str, str]] = field(default_factory=list)  # (relative_path, reason)
    error: str | None = None


def _normalized_extraction(data: Any) -> dict[str, Any] | None:
    """``normalized_result`` of the Evidence envelope, if it has the extraction shape."""
    if not isinstance(data, dict):
        return None
    norm = data.get("normalized_result")
    if (
        isinstance(norm, dict)
        and isinstance(norm.get("output_root"), str)
        and isinstance(norm.get("artifacts"), list)
    ):
        return norm
    return None


def _error_code(node: Any) -> str | None:
    if isinstance(node, dict):
        code = node.get("code")
        if isinstance(code, str):
            return code
        err = node.get("error")
        if isinstance(err, dict) and isinstance(err.get("code"), str):
            return str(err["code"])
    return None


def _is_within(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
    except ValueError:
        return False
    return True


def _copy_capped(src: Any, dst: Any) -> int:
    copied = 0
    while chunk := src.read(1 << 20):
        copied += len(chunk)
        if copied > MAX_MEMBER_BYTES:
            break
        dst.write(chunk)
    return copied


class ReaRunner:
    def __init__(
        self,
        rea_bin: str,
        env: Mapping[str, str],
        workdir: Path,
        run_fn: RunFn = bounded_run,
    ) -> None:
        self.rea_bin = rea_bin
        self.workdir = workdir
        self.env = rea_env(workdir, env)
        self.run_fn = run_fn

    def _run_json(
        self, argv: list[str], timeout_s: float
    ) -> tuple[Any, str | None, int | None]:
        out = self.run_fn(
            argv,
            env=self.env,
            cwd=self.workdir,
            timeout_s=timeout_s,
            max_stdout=MAX_STDOUT,
        )
        if out.timed_out:
            return None, "timeout", None
        if out.capped or len(out.stdout) > MAX_STDOUT:
            return None, "output_capped", out.rc
        try:
            return json.loads(out.stdout), None, out.rc
        except (ValueError, RecursionError):
            return None, "invalid_json", out.rc

    def inspect(self, cmd: str, sample: Path, timeout_s: float) -> dict[str, Any]:
        if cmd not in _ALLOWED_INSPECT:
            raise ValueError(f"unsupported inspect command: {cmd!r}")
        argv = [self.rea_bin, cmd, str(sample.resolve()), "--json"]
        data, err, rc = self._run_json(argv, timeout_s)
        if err is not None:
            return {"ok": False, "error": err}
        if rc != 0:
            return {"ok": False, "error": _error_code(data) or f"rea_failed:rc={rc}"}
        return {"ok": True, "result": data}

    def extract(self, sample: Path, outdir: Path, timeout_s: float) -> ExtractResult:
        try:
            return self._extract(sample, outdir, timeout_s)
        finally:
            # REA picks its own extraction dir; never leave one behind, even on early exit.
            for d in (self.workdir / "tmp").glob("rea-extracted-*"):
                shutil.rmtree(d, ignore_errors=True)

    def _extract(self, sample: Path, outdir: Path, timeout_s: float) -> ExtractResult:
        argv = [self.rea_bin, "extract-artifact", str(sample.resolve()), "--json"]
        data, err, _rc = self._run_json(argv, timeout_s)
        if err is not None:
            return ExtractResult(error=err)
        if _error_code(data) == "unsupported_target":
            return ExtractResult()
        ext = _normalized_extraction(data)
        if ext is None:
            return ExtractResult(error=_error_code(data) or "unrecognized_result")

        tmp_root = (self.workdir / "tmp").resolve()
        root = Path(ext["output_root"])
        res = ExtractResult()
        # REA's extraction dir must live under our TMPDIR; never trust it elsewhere.
        if not root.is_absolute() or not _is_within(root.resolve(), tmp_root) or root.resolve() == tmp_root:
            res.error = "output_root_outside_tmp"
            return res
        real_root = root.resolve()
        try:
            outdir.mkdir(parents=True, exist_ok=True)
            n = 0
            for item in ext["artifacts"]:
                rel = item.get("relative_path") if isinstance(item, dict) else None
                if not isinstance(rel, str) or not rel:
                    continue
                if n >= MAX_MEMBERS:
                    res.dropped.append((rel, "member_cap"))
                    continue
                cand = root / rel
                try:
                    st = os.lstat(cand)
                except OSError:
                    res.dropped.append((rel, "missing"))
                    continue
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
                    res.dropped.append((rel, "not_regular"))
                    continue
                if not _is_within(cand.resolve(), real_root):
                    res.dropped.append((rel, "escapes_root"))
                    continue
                if st.st_size > MAX_MEMBER_BYTES:
                    res.dropped.append((rel, "too_large"))
                    continue
                dest = outdir / f"member-{n}"
                try:
                    fd = os.open(cand, os.O_RDONLY | os.O_NOFOLLOW)
                except OSError:
                    res.dropped.append((rel, "not_regular"))
                    continue
                with os.fdopen(fd, "rb") as src:
                    fst = os.fstat(src.fileno())
                    if not stat.S_ISREG(fst.st_mode) or fst.st_nlink > 1:
                        res.dropped.append((rel, "not_regular"))
                        continue
                    if fst.st_size > MAX_MEMBER_BYTES:
                        res.dropped.append((rel, "too_large"))
                        continue
                    with dest.open("wb") as dst:
                        copied = _copy_capped(src, dst)
                if copied > MAX_MEMBER_BYTES:
                    dest.unlink(missing_ok=True)
                    res.dropped.append((rel, "too_large"))
                    continue
                res.files.append(dest)
                n += 1
        finally:
            shutil.rmtree(real_root, ignore_errors=True)
        return res


_SCRIPT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\.(?:java|py)")

# Auto-analysis runs one native decompiler process per analysis thread, and on a .NET
# assembly each one grew past 1 GiB until the 6 GiB slot was OOM-killed (no output at all).
# Two threads keep the JVM's 2 GiB heap plus the decompilers inside the slot; the image's
# decompile wrapper caps each process's address space so one runaway function fails alone.
GHIDRA_MAX_CPU = 2


def run_ghidra_analysis(
    sample: Path,
    project_dir: Path,
    timeout_s: float,
    *,
    env: Mapping[str, str],
    run_fn: RunFn = bounded_run,
    post_script: tuple[Path, str, Path] | None = None,
) -> Literal["ok", "timeout", "failed"]:
    """Import ``sample`` into a fresh Ghidra project named ``sample`` under ``project_dir``.

    ``env`` should come from :func:`rea_env` (must carry GHIDRA_INSTALL_DIR).
    ``post_script`` is ``(script_dir, script_name, output_path)``: appends
    ``-scriptPath <dir> -postScript <name> <output_path>`` (paths resolved absolute).
    """
    if post_script is not None and not _SCRIPT_NAME.fullmatch(post_script[1]):
        raise ValueError(f"bad Ghidra script name: {post_script[1]!r}")
    install = env.get("GHIDRA_INSTALL_DIR")
    if not install:
        return "failed"
    sample = sample.resolve()
    project_dir = project_dir.resolve()
    project_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        f"{install}/support/analyzeHeadless",
        str(project_dir),
        "sample",
        "-import",
        str(sample),
        "-overwrite",
        "-max-cpu",
        str(GHIDRA_MAX_CPU),
    ]
    if post_script is not None:
        script_dir, script_name, output_path = post_script
        argv += [
            "-scriptPath",
            str(script_dir.resolve()),
            "-postScript",
            script_name,
            str(output_path.resolve()),
        ]
    out = run_fn(argv, env=env, cwd=project_dir, timeout_s=timeout_s, max_stdout=0)
    if out.timed_out:
        return "timeout"
    if out.rc == 0 and (project_dir / "sample.gpr").exists():
        return "ok"
    return "failed"


def upx_unpack(
    sample: Path,
    dest: Path,
    timeout_s: float,
    *,
    env: Mapping[str, str],
    max_bytes: int,
    run_fn: RunFn = bounded_run,
) -> Literal["ok", "timeout", "failed"]:
    """``upx -d`` ``sample`` into ``dest`` (a static decompressor: the sample never runs).

    The output is attacker-sized, so ``ulimit -f`` stops the write at ``max_bytes`` (upx dies
    with SIGXFSZ) and an over-size or missing ``dest`` is a failure. A scrambled UPX header,
    the common anti-unpack trick, makes upx exit non-zero: also a failure.
    """
    sample, dest = sample.resolve(), dest.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    blocks = max(1, max_bytes // 512)  # sh's ulimit -f counts 512-byte blocks
    argv = ["sh", "-c", 'ulimit -f "$1" && exec upx -d -q -o "$2" "$3"', "sh", str(blocks), str(dest), str(sample)]
    out = run_fn(argv, env=env, cwd=dest.parent, timeout_s=timeout_s, max_stdout=0)
    if out.timed_out:
        dest.unlink(missing_ok=True)
        return "timeout"
    try:
        ok = out.rc == 0 and dest.is_file() and not dest.is_symlink() and 0 < dest.stat().st_size <= max_bytes
    except OSError:
        ok = False
    if not ok:
        dest.unlink(missing_ok=True)
        return "failed"
    return "ok"


WatchStatus = Literal["ok", "failed", "timeout", "too_large"]
WatchFn = Callable[..., WatchStatus]
"""``watch_fn(argv, *, env, cwd, timeout_s, watch, max_bytes, max_files) -> WatchStatus``."""


def _tree_usage(root: Path, max_files: int) -> tuple[int, int]:
    """``(bytes, entries)`` under ``root`` by lstat (links are never followed); stops past ``max_files``."""
    total = n = 0
    stack = [root]
    while stack and n <= max_files:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    n += 1
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(Path(e.path))
                    else:
                        total += st.st_size
        except OSError:
            continue
    return total, n


def watched_run(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path | None,
    timeout_s: float,
    watch: Path,
    max_bytes: int,
    max_files: int,
    poll_s: float = 0.1,
) -> WatchStatus:
    """Run an extractor in its own process group while watching what it writes under ``watch``.

    An archive's sizes are attacker-chosen and a solid NSIS block lists none, so the bound is
    enforced on the output itself: the whole group is killed (``too_large``) as soon as the bytes
    or entries under ``watch`` pass ``max_bytes`` / ``max_files``, and on ``timeout``. Output
    written between two polls is also bounded by the caller's ``ulimit -f``. stdout and stderr
    are discarded. A non-zero exit is ``failed`` (the caller decides what a partial tree is worth).
    """
    proc = subprocess.Popen(argv, env=dict(env), cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout_s
    status: WatchStatus = "failed"
    try:
        while True:
            try:
                rc = proc.wait(timeout=poll_s)
            except subprocess.TimeoutExpired:
                rc = None
            used, entries = _tree_usage(watch, max_files)
            if used > max_bytes or entries > max_files:
                status = "too_large"
                break
            if rc is not None:
                status = "ok" if rc == 0 else "failed"
                break
            if time.monotonic() >= deadline:
                status = "timeout"
                break
    finally:
        _kill_group(proc)
        proc.wait()
    return status


DotnetStatus = Literal["ok", "timeout", "failed", "too_large"]


def run_dotnet_resources(
    sample: Path,
    outdir: Path,
    timeout_s: float,
    *,
    env: Mapping[str, str],
    python: str,
    max_kb: int,
    max_stdout: int,
    max_write_bytes: int,
    run_fn: RunFn = bounded_run,
) -> tuple[DotnetStatus, bytes]:
    """``dotnet_resources.py`` over ``sample`` under ``python`` (the capa venv's, which has dnfile).

    dnfile parses hostile metadata, so it runs out of process: ``ulimit -v`` caps memory,
    ``ulimit -f`` each file it writes into ``outdir``, ``max_stdout`` its JSON, ``timeout_s`` its
    time. ``-I`` keeps the script's own directory and the environment out of ``sys.path``.
    """
    from blastbox.engines.rea import dotnet_resources

    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    blocks = max(1, max_write_bytes // 512)
    argv = ["sh", "-c", 'ulimit -v "$1" || exit 1; ulimit -f "$2" || exit 1; exec "$3" -I "$4" "$5" "$6"',
            "sh", str(max_kb), str(blocks), python, str(Path(dotnet_resources.__file__).resolve()),
            str(sample.resolve()), str(outdir)]
    out = run_fn(argv, env=env, cwd=outdir, timeout_s=timeout_s, max_stdout=max_stdout)
    if out.timed_out:
        return "timeout", b""
    if out.capped:
        return "too_large", b""
    if out.rc != 0 or not out.stdout:
        return "failed", b""
    return "ok", out.stdout


EmulateStatus = Literal["ok", "timeout", "failed", "too_large", "unavailable"]


def run_emulation(
    sample: Path,
    outdir: Path,
    timeout_s: float,
    *,
    env: Mapping[str, str],
    python: str,
    budget_s: float,
    max_api: int,
    max_insn: int,
    max_kb: int,
    max_stdout: int,
    max_write_bytes: int,
    run_fn: RunFn = bounded_run,
) -> tuple[EmulateStatus, bytes]:
    """``emulate_runner.py`` over ``sample`` under ``python`` (the Speakeasy venv's).

    The sample's code is interpreted by unicorn inside that process, so it is bounded like any
    hostile parser and more: ``ulimit -v`` caps memory, ``ulimit -f`` each region file it writes
    into ``outdir``, ``ulimit -t`` its CPU seconds, ``max_stdout`` its JSON and ``timeout_s`` its
    wall clock (Speakeasy's own ``budget_s`` stops emulation first, so the dumps still happen).
    ``-I`` keeps the script's own directory and the environment out of ``sys.path``. A missing
    interpreter (no Speakeasy in this image) is ``unavailable``.
    """
    from blastbox.engines.rea import emulate_runner

    if not Path(python).is_file():
        return "unavailable", b""
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    blocks = max(1, max_write_bytes // 512)
    cpu = max(1, int(timeout_s) + 1)
    argv = ["sh", "-c",
            'ulimit -v "$1" || exit 1; ulimit -f "$2" || exit 1; ulimit -t "$3" || exit 1; '
            'exec "$4" -I "$5" "$6" "$7" "$8" "$9" "${10}"',
            "sh", str(max_kb), str(blocks), str(cpu), python, str(Path(emulate_runner.__file__).resolve()),
            str(sample.resolve()), str(outdir), f"{budget_s:g}", str(max_api), str(max_insn)]
    out = run_fn(argv, env=env, cwd=outdir, timeout_s=timeout_s, max_stdout=max_stdout)
    if out.timed_out:
        return "timeout", b""
    if out.capped:
        return "too_large", b""
    if out.rc != 0 or not out.stdout:
        return "failed", b""
    return "ok", out.stdout


CAPA_BACKENDS = {"pe": ("pe", "vivisect"), "elf": ("elf", "vivisect"), "dotnet": ("dotnet", "dotnet")}
# capa's exit codes for a file it does not handle (main.py E_INVALID_FILE_TYPE/_ARCH/_OS).
_CAPA_UNSUPPORTED = frozenset({16, 17, 18})
CapaStatus = Literal["ok", "timeout", "failed", "unsupported", "too_large", "skipped"]


def run_capa(
    sample: Path,
    kind: str,
    timeout_s: float,
    *,
    env: Mapping[str, str],
    capa_bin: str,
    rules: Path,
    signatures: Path,
    max_kb: int,
    max_stdout: int,
    run_fn: RunFn = bounded_run,
) -> tuple[CapaStatus, bytes]:
    """``capa -j`` over ``sample`` (static: vivisect or dnfile extract features, nothing runs).

    The format and backend are fixed per ``kind`` (``CAPA_BACKENDS``), never auto-detected, and
    the rule and signature sets are the pinned ones. ``ulimit -v`` caps the address space
    (vivisect's workspace grows with the image), ``max_stdout`` the JSON document.
    """
    fmt, backend = CAPA_BACKENDS[kind]
    argv = ["sh", "-c",
            'ulimit -v "$1" || exit 1; exec "$2" -j -q -f "$3" -b "$4" -r "$5" -s "$6" -- "$7"',
            "sh", str(max_kb), capa_bin, fmt, backend, str(rules), str(signatures), str(sample.resolve())]
    out = run_fn(argv, env={**env, "CAPA_SAVE_WORKSPACE": "0"}, cwd=None, timeout_s=timeout_s,
                 max_stdout=max_stdout)
    if out.timed_out:
        return "timeout", b""
    if out.capped:
        return "too_large", b""
    if out.rc in _CAPA_UNSUPPORTED:
        return "unsupported", b""
    if out.rc != 0 or not out.stdout:
        return "failed", b""
    return "ok", out.stdout
