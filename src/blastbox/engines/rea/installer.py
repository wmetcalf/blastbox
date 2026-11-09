"""Static unwrapping for the sweep: installers whose stub hides the program (nothing runs).

An installer's stub is generic NSIS/Inno code; what the sample does lives in the files it
installs. The sweep (step 0b) asks :func:`detect` which :data:`UNWRAPPERS` entry claims the sample,
extracts it with that entry's decompressor (:func:`extract`: 7-Zip for NSIS, innoextract for Inno
Setup), copies every member out as a ``members`` artifact (:func:`collect`) and analyses the PE
the entry's ``choose`` picks in place of the stub. The payload is offered to :func:`detect` again,
up to ``MAX_DEPTH_UNWRAP`` layers (an installer inside an installer), and the sweep's UPX step
then applies to the innermost payload.

ADDING A FORMAT is one :class:`Unwrapper` entry here: a ``detect(path)`` (bounded reads, never
raises), a fixed ``sh -c`` extraction script (``$1`` = ``ulimit -f`` blocks, ``$2`` = output dir,
``$3`` = absolute sample path; the tool must be pinned in the worker image) and a
``choose(members, sample)`` returning ``(member, reason, extra evidence)`` or None. Candidates on
the same 7-Zip base: MSI (CAB streams + the CustomAction table), 7z/RAR/ZIP SFX (the SFX config's
``RunProgram``/``Setup=``), ISO/IMG; AutoIt and PyInstaller need their own extractors.

Which PE an NSIS installer runs: the decompressors write files, not the install script (7-Zip
stopped emitting ``[NSIS].nsi`` after 15.05, innoextract never decoded ``[Run]``). This module
decodes the NSIS script's *string table* itself (:func:`nsis_strings`): the header block is the
first item of the (LZMA/deflate) data stream, and its strings are the operands of every script
instruction: ``Exec``/``ExecWait`` command lines, ``WriteRegStr`` keys and values, output paths,
plugin calls. Instruction opcodes are not decoded (their numbering moves between NSIS builds), so
a member counts as executed when a string names it under a directory (``$INSTDIR\\x.exe``,
``"..\\x.exe" /arg``), which ``File`` operands (bare names) never do. Otherwise, and always for
Inno Setup, the payload is the largest PE member outside ``$PLUGINSDIR`` (NSIS plugin DLLs).

All names come from the sample and are attacker-controlled. :func:`collect` never follows a link,
drops anything that is not a regular single-link file, and caps member count and size; the
payload's on-disk name is sanitized by the sweep. The string decoder caps the header size, the
input it reads, the number of strings and their length. The extractor's output is bounded by
``ulimit -f`` per file and by ``runner.watched_run`` for the whole tree.
"""

from __future__ import annotations

import lzma
import mmap
import os
import re
import stat
import struct
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from blastbox.engines.rea.runner import WatchFn, classify, watched_run
from blastbox.engines.rea.triage import inno_marked, nsis_marked

__all__ = ["MAX_DEPTH_UNWRAP", "UNWRAPPERS", "Member", "Unwrapper", "choose_payload", "collect", "detect",
           "extract", "nsis_strings", "script_excerpt"]

MAX_DEPTH_UNWRAP = 3  # unwrapped layers per sample (installer inside installer...)

MAX_SCAN = 256 * 1024 * 1024  # where the NSIS first header may sit
MAX_HEADER_BYTES = 8 * 1024 * 1024  # decompressed script header
MAX_HEADER_INPUT = 64 * 1024 * 1024  # compressed bytes read to get it
MAX_DECODED_STRINGS = 20_000
MAX_STRING_CHARS = 512
MAX_SCRIPT_STRINGS = 256  # the excerpt that goes to State.sweep (the agent and report read it)
MAX_SCRIPT_CHARS = 16 * 1024
MAX_DEPTH = 32
_CHUNK = 1 << 20

_NSIS_SIG = b"\xef\xbe\xad\xdeNullsoftInst"
_FIRST_HEADER = struct.Struct("<II12sII")  # flags, siginfo, magic, header length, data length
_BLOCKS = 8
_NB_STRINGS, _NB_LANGTABLES = 3, 4

# NSIS built-in variables by index ($0-$9, $R0-$R9, then the named ones).
_VARS = {20: "$CMDLINE", 21: "$INSTDIR", 22: "$OUTDIR", 23: "$EXEDIR", 24: "$LANGUAGE", 25: "$TEMP",
         26: "$PLUGINSDIR", 27: "$EXEPATH", 28: "$EXEFILE", 29: "$HWNDPARENT", 30: "$_CLICK",
         31: "$_OUTDIR"}
# Shell folder constants by CSIDL.
_CSIDL = {0x00: "$DESKTOP", 0x02: "$SMPROGRAMS", 0x05: "$DOCUMENTS", 0x07: "$SMSTARTUP",
          0x0B: "$STARTMENU", 0x10: "$DESKTOP", 0x14: "$FONTS", 0x15: "$TEMPLATES", 0x18: "$SMSTARTUP",
          0x1A: "$APPDATA", 0x1C: "$LOCALAPPDATA", 0x20: "$INTERNET_CACHE", 0x21: "$COOKIES",
          0x22: "$HISTORY", 0x23: "$APPDATA", 0x24: "$WINDIR", 0x25: "$SYSDIR", 0x26: "$PROGRAMFILES",
          0x28: "$PROFILE", 0x2B: "$COMMONFILES"}
_REG_FOLDERS = {"ProgramFilesDir": "$PROGRAMFILES", "CommonFilesDir": "$COMMONFILES"}
# Code -> meaning, for NSIS 3 (1..4, both encodings) and NSIS 2 ANSI (252..255).
_LANG, _SHELL, _VAR, _SKIP = "lang", "shell", "var", "skip"
_CODES = {1: _LANG, 2: _SHELL, 3: _VAR, 4: _SKIP, 255: _LANG, 254: _SHELL, 253: _VAR, 252: _SKIP}

_BEHAVIOUR = re.compile(r"[\\/$]|://|^HK|\.(?:exe|dll|bat|cmd|ps1|vbs|js|lnk|sys|msi|scr|com)\b", re.I)


# ----------------------------------------------------------------- the header


def _lzma_props(head: bytes) -> dict[str, int] | None:
    if len(head) < 5 or head[0] >= 9 * 5 * 5:
        return None
    p = head[0]
    lc, p = p % 9, p // 9
    lp, pb = p % 5, p // 5
    (dict_size,) = struct.unpack_from("<I", head, 1)
    if not 4096 <= dict_size <= 1 << 30:
        return None
    return {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}


def _inflate(f: BinaryIO, start: int, need: int, method: str) -> bytes:
    """The first ``need`` decompressed bytes of the stream at ``start`` ("" when it does not decode)."""
    f.seek(start)
    out = bytearray()
    read = 0
    try:
        if method.startswith("lzma"):
            head = f.read(5)
            props = _lzma_props(head)
            if props is None:
                return b""
            read += 5
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
            while len(out) < need and not dec.eof:
                chunk = b""
                if dec.needs_input:
                    if read >= MAX_HEADER_INPUT:
                        break
                    chunk = f.read(_CHUNK)
                    if not chunk:
                        break
                    read += len(chunk)
                out += dec.decompress(chunk, max_length=need - len(out))
        else:
            z = zlib.decompressobj(-15)
            while len(out) < need and not z.eof:
                data = z.unconsumed_tail
                if not data:
                    if read >= MAX_HEADER_INPUT:
                        break
                    data = f.read(_CHUNK)
                    if not data:
                        break
                    read += len(data)
                out += z.decompress(data, need - len(out))
    except (lzma.LZMAError, zlib.error, EOFError, MemoryError):
        return bytes(out)
    return bytes(out)


def _find_first_header(fd: int, size: int) -> int:
    with mmap.mmap(fd, min(size, MAX_SCAN), access=mmap.ACCESS_READ) as m:
        pos = m.find(_NSIS_SIG)
        # exehead looks at 512-byte boundaries; prefer an aligned copy over a stray string.
        while pos >= 0 and (pos - 4) % 512 != 0:
            nxt = m.find(_NSIS_SIG, pos + 1)
            if nxt < 0:
                break
            pos = nxt
    return pos - 4 if pos >= 4 else -1


def nsis_header(path: Path) -> bytes | None:
    """The decompressed NSIS script header, or None (not NSIS, bzip2, damaged, over the caps)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            size = os.fstat(fd).st_size
            if size == 0:
                return None
            fh = _find_first_header(fd, size)
            if fh < 0:
                return None
            f.seek(fh)
            raw = f.read(_FIRST_HEADER.size)
            if len(raw) < _FIRST_HEADER.size:
                return None
            _flags, _sig, _magic, hlen, _dlen = _FIRST_HEADER.unpack(raw)
            if not 4 + 8 * _BLOCKS < hlen <= MAX_HEADER_BYTES:
                return None
            body = fh + _FIRST_HEADER.size
            # Solid archive: one stream holding [u32 size][header][u32 size][file]...; a 0/1 byte
            # in front of LZMA props marks NSIS's x86 filter.
            for start, method in ((body, "lzma"), (body + 1, "lzma"), (body, "deflate")):
                out = _inflate(f, start, 4 + hlen, method)
                if len(out) == 4 + hlen and struct.unpack_from("<I", out)[0] == hlen:
                    return out[4:]
            # Non-solid: [u32 compressed size | 0x80000000][stream], or the header stored as is.
            f.seek(body)
            lead = f.read(4)
            if len(lead) < 4:
                return None
            (n,) = struct.unpack("<I", lead)
            if n & 0x80000000:
                for start, method in ((body + 4, "lzma"), (body + 5, "lzma"), (body + 4, "deflate")):
                    out = _inflate(f, start, hlen, method)
                    if len(out) == hlen:
                        return out
            elif n == hlen:
                out = f.read(hlen)
                if len(out) == hlen:
                    return out
        except (OSError, ValueError, OverflowError):
            return None
    return None


# ---------------------------------------------------------------- the strings


def _var(n: int) -> str:
    if n < 10:
        return f"${n}"
    if n < 20:
        return f"$R{n - 10}"
    return _VARS.get(n, f"$_{n}")


def _clean(ch: int) -> str:
    if 0xD800 <= ch <= 0xDFFF:
        return "�"
    if ch < 0x20 and ch not in (9, 10, 13):
        return ""
    return chr(ch)


def _decode(block: bytes, unicode: bool) -> list[str]:
    if unicode:
        units = memoryview(block[: len(block) // 2 * 2]).cast("H").tolist()
    else:
        units = list(block)
    starts: dict[int, str] = {}

    def at(off: int) -> str:
        return starts.get(off, "")

    out: list[str] = []
    cur: list[str] = []
    begin = 0
    i = 0
    pending_reg: list[tuple[int, int]] = []  # (index in out, char offset of the registry value name)
    while i < len(units) and len(out) < MAX_DECODED_STRINGS:
        c = units[i]
        i += 1
        if c == 0:
            s = "".join(cur)[:MAX_STRING_CHARS]
            starts[begin] = s
            out.append(s)
            cur, begin = [], i
            continue
        code = _CODES.get(c)
        if code is None:
            cur.append(_clean(c) if unicode else _clean(c) if c < 0x80 else bytes([c]).decode("cp1252", "replace"))
            continue
        if unicode:
            if i >= len(units):
                break
            v = units[i]
            i += 1
            lo, hi = v & 0xFF, v >> 8
        else:
            if i + 1 >= len(units):
                break
            lo, hi = units[i], units[i + 1]
            i += 2
        if code == _SKIP:
            cur.append(_clean(lo | hi << 8) if unicode else _clean(lo))
        elif code == _VAR:
            cur.append(_var((lo & 0x7F) | (hi & 0x7F) << 7))
        elif code == _LANG:
            cur.append(f"$(LangString{(lo & 0x7F) | (hi & 0x7F) << 7})")
        elif lo & 0x80:
            # $PROGRAMFILES-style: read from the registry value whose name is a string in this table.
            pending_reg.append((len(out), lo & 0x3F))
            cur.append(f"\x00REG{lo & 0x3F}\x00")
        else:
            cur.append(_CSIDL.get(lo, f"$SHELL[{lo:#x}]"))
    # Resolve registry-folder placeholders now that every string's offset is known.
    for idx, off in pending_reg:
        if idx < len(out):
            name = _REG_FOLDERS.get(at(off), "$SHELL")
            out[idx] = out[idx].replace(f"\x00REG{off}\x00", name)
    return [s for s in out if s]


def nsis_strings(path: Path) -> list[str]:
    """The NSIS script's string table, variables rendered (``$INSTDIR``...); [] when undecodable."""
    header = nsis_header(path)
    if header is None:
        return []
    try:
        blocks = [struct.unpack_from("<II", header, 4 + 8 * i) for i in range(_BLOCKS)]
    except struct.error:
        return []
    lo = blocks[_NB_STRINGS][0]
    hi = blocks[_NB_LANGTABLES][0]
    if not 0 < hi <= len(header):
        hi = len(header)
    if not 0 < lo < hi:
        return []
    block = header[lo:hi]
    return _decode(block, unicode=block[:2] == b"\x00\x00")


def script_excerpt(strings: list[str]) -> list[str]:
    """A bounded excerpt for the agent: strings that name paths, keys, URLs or programs first."""
    seen: set[str] = set()
    first: list[str] = []
    rest: list[str] = []
    for s in strings:
        s = s[:MAX_STRING_CHARS]
        if len(s) < 3 or s in seen:
            continue
        seen.add(s)
        (first if _BEHAVIOUR.search(s) else rest).append(s)
    out: list[str] = []
    used = 0
    for s in first + rest:
        if len(out) >= MAX_SCRIPT_STRINGS or used + len(s) > MAX_SCRIPT_CHARS:
            break
        out.append(s)
        used += len(s)
    return out


# ---------------------------------------------------------------- the members


@dataclass(frozen=True)
class Member:
    rel: str  # path inside the installer (attacker-controlled; for evidence only)
    path: Path  # the copy under the members dir (member-<n>)
    size: int


def _rel_text(rel: str) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in rel)[:255]


def copy_member(src_path: str, dest: Path, cap: int) -> str | None:
    """Copy one file without following links; the drop reason, or None when copied."""
    try:
        fd = os.open(src_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return "not_regular"
    with os.fdopen(fd, "rb") as src:
        st = os.fstat(src.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            return "not_regular"
        if st.st_size > cap:
            return "too_large"
        copied = 0
        with dest.open("wb") as dst:
            while chunk := src.read(_CHUNK):
                copied += len(chunk)
                if copied > cap:
                    break
                dst.write(chunk)
    if copied > cap:
        dest.unlink(missing_ok=True)
        return "too_large"
    return None


def collect(root: Path, dest: Path, *, max_members: int, max_member_bytes: int,
            start: int = 0) -> tuple[list[Member], list[tuple[str, str]]]:
    """Copy the regular files under ``root`` to ``dest/member-<start + n>`` (sorted walk, links
    never followed); ``(members, [(relative path, drop reason)])``."""
    dest.mkdir(parents=True, exist_ok=True)
    members: list[Member] = []
    dropped: list[tuple[str, str]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        subdirs: list[Path] = []
        for e in entries:
            rel = _rel_text(Path(e.path).relative_to(root).as_posix())
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                dropped.append((rel, "missing"))
                continue
            if stat.S_ISDIR(st.st_mode):
                if depth + 1 > MAX_DEPTH:
                    dropped.append((rel, "too_deep"))
                else:
                    subdirs.append(Path(e.path))
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
                dropped.append((rel, "not_regular"))
                continue
            if st.st_size > max_member_bytes:
                dropped.append((rel, "too_large"))
                continue
            if len(members) >= max_members:
                dropped.append((rel, "member_cap"))
                continue
            target = dest / f"member-{start + len(members)}"
            why = copy_member(e.path, target, max_member_bytes)
            if why is not None:
                dropped.append((rel, why))
                continue
            members.append(Member(rel, target, target.stat().st_size))
        stack.extend((p, depth + 1) for p in reversed(subdirs))
    return members, dropped


def _is_plugin(rel: str) -> bool:
    return rel.lower().startswith("$pluginsdir/")


def choose_payload(members: list[Member], strings: list[str]) -> tuple[Member, str] | None:
    """``(member, "script_reference" | "largest_pe")``: the PE the script runs, else the largest."""
    pes = [m for m in members if classify(m.path) in ("pe", "dotnet")]
    if not pes:
        return None
    own = [m for m in pes if not _is_plugin(m.rel)] or pes
    lowered = [s.lower() for s in strings]
    best: tuple[int, int, Member] | None = None
    for m in own:
        base = m.rel.rsplit("/", 1)[-1].lower()
        ref = re.compile(r"[\\/]" + re.escape(base) + r"(\"|\s|$)")
        score = 0
        for s in lowered:
            hit = ref.search(s)
            if hit is None:
                continue
            # A command line (quoted path, or arguments after the program) beats a bare path.
            score = max(score, 2 if s.startswith('"') or s[hit.end():].strip(' "') else 1)
        if score and (best is None or (score, m.size) > best[:2]):
            best = (score, m.size, m)
    if best is not None:
        return best[2], "script_reference"
    return max(own, key=lambda m: m.size), "largest_pe"


# ---------------------------------------------------------------- the registry

Choice = tuple[Member, str, dict[str, Any]]


@dataclass(frozen=True)
class Unwrapper:
    name: str  # the evidence/summary ``packer`` value
    detect: Callable[[Path], bool]
    script: str  # fixed ``sh -c`` body: $1 ulimit -f blocks, $2 output dir, $3 sample
    choose: Callable[[list[Member], Path], Choice | None]


def _choose_nsis(members: list[Member], sample: Path) -> Choice | None:
    strings = nsis_strings(sample)
    picked = choose_payload(members, strings)
    if picked is None:
        return None
    excerpt = script_excerpt(strings)
    return picked[0], picked[1], ({"script_strings": excerpt} if excerpt else {})


def _choose_largest(members: list[Member], sample: Path) -> Choice | None:
    picked = choose_payload(members, [])
    return None if picked is None else (picked[0], picked[1], {})


UNWRAPPERS: tuple[Unwrapper, ...] = (
    Unwrapper("nsis", nsis_marked,
              'ulimit -f "$1" && exec 7z x -tNsis -y -bd -bso0 -bse0 -bsp0 -o"$2" -- "$3"', _choose_nsis),
    # innoextract takes no "--"; $3 is absolute, so it is never read as an option.
    Unwrapper("inno", inno_marked,
              'ulimit -f "$1" && exec innoextract -s -p 0 -c 0 -d "$2" "$3"', _choose_largest),
)
_BY_NAME = {u.name: u for u in UNWRAPPERS}


def detect(path: Path) -> str | None:
    """The name of the first unwrapper that claims a PE ``path``, else None."""
    if classify(path) != "pe":
        return None
    return next((u.name for u in UNWRAPPERS if u.detect(path)), None)


def choose(packer: str, members: list[Member], sample: Path) -> Choice | None:
    return _BY_NAME[packer].choose(members, sample)


ExtractStatus = Literal["ok", "partial", "failed", "timeout", "too_large"]


def extract(
    sample: Path,
    dest: Path,
    timeout_s: float,
    *,
    packer: str,
    env: Mapping[str, str],
    max_bytes: int,
    max_files: int,
    watch_fn: WatchFn = watched_run,
) -> ExtractStatus:
    """Run ``packer``'s fixed extraction script over ``sample`` into ``dest``.

    The only caller-influenced argv element is the sample path (absolute). ``ulimit -f`` caps
    each written file at ``max_bytes`` and ``watch_fn`` the whole tree. Both tools strip absolute
    and ``..`` member paths; :func:`collect` still walks ``dest`` without following links. A
    non-zero exit that left files behind (an encrypted or unsupported member) is ``partial``.
    """
    u = _BY_NAME.get(packer)
    if u is None:
        raise ValueError(f"unsupported unwrapper: {packer!r}")
    sample, dest = sample.resolve(), dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    argv = ["sh", "-c", u.script, "sh", str(max(1, max_bytes // 512)), str(dest), str(sample)]
    status = watch_fn(argv, env=env, cwd=dest, timeout_s=timeout_s, watch=dest, max_bytes=max_bytes,
                      max_files=max_files)
    if status == "failed":
        try:
            if any(dest.iterdir()):
                return "partial"
        except OSError:
            pass
    return status
