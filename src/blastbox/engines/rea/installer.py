"""Static unwrapping for the sweep: installers whose stub hides the program (nothing runs).

An installer's stub is generic NSIS/Inno code; what the sample does lives in the files it
installs. The sweep (step 0b) asks :func:`detect` which :data:`UNWRAPPERS` entry claims the sample,
extracts it with that entry's decompressor (:func:`extract`: 7-Zip for NSIS, with the in-process
:func:`nsis_carve` when 7-Zip lists nothing; ``inno_unwrap`` on Binary Refinery's parser for Inno
Setup), copies every member out as a ``members`` artifact (:func:`collect`) and analyses the PE
the entry's ``choose`` picks in place of the stub. The payload is offered to :func:`detect` again,
up to ``MAX_DEPTH_UNWRAP`` layers (an installer inside an installer), and the sweep's UPX step
then applies to the innermost payload.

ADDING A FORMAT is one :class:`Unwrapper` entry here: a ``detect(path)`` (bounded reads, never
raises), a fixed ``sh -c`` extraction script (``$1`` = ``ulimit -f`` blocks, ``$2`` = output dir,
``$3`` = absolute sample path, ``$4``... = the entry's fixed ``args``; the tool must be pinned in
the worker image) and a ``choose(members, sample)`` returning an :class:`Unwrapped`. Candidates on
the same 7-Zip base: MSI (CAB streams + the CustomAction table), 7z/RAR/ZIP SFX (the SFX config's
``RunProgram``/``Setup=``), ISO/IMG; AutoIt and PyInstaller need their own extractors.

Which PE an NSIS installer runs: the decompressors write files, not the install script (7-Zip
stopped emitting ``[NSIS].nsi`` after 15.05). This module
decodes the NSIS script's *string table* itself (:func:`nsis_strings`): the header block is the
first item of the (LZMA/deflate) data stream, and its strings are the operands of every script
instruction: ``Exec``/``ExecWait`` command lines, ``WriteRegStr`` keys and values, output paths,
plugin calls. Instruction opcodes are not decoded (their numbering moves between NSIS builds), so
a member counts as executed when a string names it under a directory (``$INSTDIR\\x.exe``,
``"..\\x.exe" /arg``), which ``File`` operands (bare names) never do. Otherwise the payload is
the largest program (EXE before DLL) outside ``$PLUGINSDIR``. For Inno Setup the same choice runs
over the ``data/`` members, and :func:`inno_script` reads the header's ``[Run]``/``[Registry]``
entries and the ``[Code]`` script's literals and external imports.

Three shapes the largest-program rule gets wrong, each seen in live malware:

- DLL side-loading: the largest program is a legitimate *signed* EXE and the malware is the
  unsigned DLL beside it that it imports. ``choose`` hops to that DLL (reason
  ``unsigned_import``) and records the EXE as ``loader_member``.
- An altered archive signature: the ``NullsoftInst`` magic is overwritten so 7-Zip and every
  signature scanner find no archive, while the stub still unpacks it. :func:`_layout` finds the
  first header by structure, :func:`nsis_carve` writes the members by position
  (``carved/item-<n>.bin``, no names) and the evidence carries ``signature: "altered"``.
- No program at all: only stock plugins (``System.dll``) and data files, the script-driven
  shellcode loader. There is no payload; :func:`stub_profile` describes what is there and the
  sweep analyses the stub with that as ``installer_stub`` evidence.

All names come from the sample and are attacker-controlled. :func:`collect` never follows a link,
drops anything that is not a regular single-link file, and caps member count and size; the
payload's on-disk name is sanitized by the sweep. The string decoder caps the header size, the
input it reads, the number of strings and their length. The extractor's output is bounded by
``ulimit -f`` per file and by ``runner.watched_run`` for the whole tree.
"""

from __future__ import annotations

import ast
import json
import lzma
import math
import mmap
import os
import re
import stat
import struct
import time
import zlib
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from blastbox.engines.rea.runner import WatchFn, classify, watched_run
from blastbox.engines.rea.triage import inno_marked, nsis_marked

__all__ = ["MAX_DEPTH_UNWRAP", "UNWRAPPERS", "Member", "Unwrapped", "Unwrapper", "choose_payload", "collect",
           "detect", "extract", "inno_script", "nsis_carve", "nsis_strings", "script_excerpt", "stub_profile"]

MAX_DEPTH_UNWRAP = 3  # unwrapped layers per sample (installer inside installer...)

MAX_SCAN = 256 * 1024 * 1024  # where the NSIS first header may sit
MAX_HEADER_BYTES = 8 * 1024 * 1024  # decompressed script header
MAX_HEADER_INPUT = 64 * 1024 * 1024  # compressed bytes read to get it
MAX_HEADER_CANDIDATES = 64  # structural first-header candidates tried when the signature is gone
MAX_DECODED_STRINGS = 20_000
MAX_STRING_CHARS = 512
MAX_SCRIPT_STRINGS = 256  # the excerpt that goes to State.sweep (the agent and report read it)
MAX_SCRIPT_CHARS = 16 * 1024
MAX_DEPTH = 32
MAX_PROFILE_MEMBERS = 12  # plugins / data members listed for an installer with no payload
MAX_INNO_TEXT = 16 * 1024 * 1024  # setup.json / script.ps bytes read
MAX_SCRIPT_IMPORTS = 160
DEFAULT_REFINERY_PYTHON = "/opt/refinery/bin/python"  # the hash-locked Binary Refinery venv
INNO_MAX_KB = 4 * 1024 * 1024  # ulimit -v for the Inno parser
MAX_IMPORT_DLLS = 256  # import descriptors read per PE member
CARVED = "carved"  # nsis_carve's directory: members named by position, not by the script
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


def _stream(f: BinaryIO, start: int, method: str, in_limit: int) -> Iterator[bytes]:
    """Decompressed chunks (at most ``_CHUNK`` each) of the stream at ``start``, reading at most
    ``in_limit`` compressed bytes; ends quietly where the stream ends or stops decoding."""
    f.seek(start)
    read = 0

    def more() -> bytes:
        nonlocal read
        chunk = f.read(min(_CHUNK, in_limit - read)) if read < in_limit else b""
        read += len(chunk)
        return chunk

    try:
        if method == "lzma":
            props = _lzma_props(more()[:5] if in_limit >= 5 else b"")
            if props is None:
                return
            f.seek(start + 5)
            read = 5
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[props])
            while not dec.eof:
                chunk = b""
                if dec.needs_input:
                    chunk = more()
                    if not chunk:
                        return
                out = dec.decompress(chunk, max_length=_CHUNK)
                if out:
                    yield out
        else:
            z = zlib.decompressobj(-15)
            while not z.eof:
                data = z.unconsumed_tail or more()
                if not data:
                    return
                out = z.decompress(data, _CHUNK)
                if out:
                    yield out
    except (lzma.LZMAError, zlib.error, EOFError, MemoryError):
        return


def _inflate(f: BinaryIO, start: int, need: int, method: str) -> bytes:
    """The first ``need`` decompressed bytes of the stream at ``start`` ("" when it does not decode)."""
    out = bytearray()
    for chunk in _stream(f, start, method, MAX_HEADER_INPUT):
        out += chunk
        if len(out) >= need:
            break
    return bytes(out[:need])


@dataclass(frozen=True)
class _Layout:
    """Where an NSIS archive's data sits: ``solid`` is one stream of ``[u32 size][item]...`` (the
    header is item 0); otherwise ``start`` is the header's ``[u32 size | flag][block]`` and the
    file blocks follow it. ``altered``: the first header's signature bytes are not NSIS's."""

    first: int
    hlen: int
    end: int
    solid: bool
    method: str  # "lzma" | "deflate" | "stored"
    start: int
    altered: bool


def _open_header(f: BinaryIO, first: int, hlen: int, end: int, altered: bool) -> tuple[_Layout, bytes] | None:
    body = first + _FIRST_HEADER.size
    # Solid archive: one stream holding [u32 size][header][u32 size][file]...; a 0/1 byte
    # in front of LZMA props marks NSIS's x86 filter.
    for start, method in ((body, "lzma"), (body + 1, "lzma"), (body, "deflate")):
        out = _inflate(f, start, 4 + hlen, method)
        if len(out) == 4 + hlen and struct.unpack_from("<I", out)[0] == hlen:
            return _Layout(first, hlen, end, True, method, start, altered), out[4:]
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
                return _Layout(first, hlen, end, False, method, body, altered), out
    elif n == hlen:
        out = f.read(hlen)
        if len(out) == hlen:
            return _Layout(first, hlen, end, False, "stored", body, altered), out
    return None


def _plausible(raw: bytes, off: int, size: int) -> tuple[int, int] | None:
    """``(header length, archive end)`` when ``raw`` reads as a first header at ``off``."""
    if len(raw) < _FIRST_HEADER.size:
        return None
    flags, _sig, _magic, hlen, dlen = _FIRST_HEADER.unpack(raw)
    if flags >= 16 or not 4 + 8 * _BLOCKS < hlen <= MAX_HEADER_BYTES:
        return None
    if not hlen < dlen <= size - off:
        return None
    return hlen, off + dlen


def _layout(f: BinaryIO, fd: int, size: int) -> tuple[_Layout, bytes] | None:
    """The archive layout and its decompressed script header.

    exehead finds the first header by its signature at a 512-byte boundary. A stub patched to look
    for other bytes (seen live: a ValleyRAT dropper whose 16 signature bytes were replaced, which
    7-Zip then refuses to open) is found by structure instead: flags, lengths that fit the file,
    and a data stream that really opens with a header block of the stated length.
    """
    with mmap.mmap(fd, min(size, MAX_SCAN), access=mmap.ACCESS_READ) as m:
        pos = m.find(_NSIS_SIG)
        # exehead looks at 512-byte boundaries; prefer an aligned copy over a stray string.
        while pos >= 0 and (pos - 4) % 512 != 0:
            nxt = m.find(_NSIS_SIG, pos + 1)
            if nxt < 0:
                break
            pos = nxt
        if pos >= 4:
            first = pos - 4
            raw = m[first: first + _FIRST_HEADER.size]
            if len(raw) < _FIRST_HEADER.size:
                return None
            _flags, _sig, _magic, hlen, dlen = _FIRST_HEADER.unpack(raw)
            if not 4 + 8 * _BLOCKS < hlen <= MAX_HEADER_BYTES:
                return None
            end = first + dlen if hlen < dlen <= size - first else size
            return _open_header(f, first, hlen, end, False)
        candidates = []
        for off in range(512, len(m) - _FIRST_HEADER.size, 512):
            fit = _plausible(m[off: off + _FIRST_HEADER.size], off, size)
            if fit is not None:
                candidates.append((off, *fit))
                if len(candidates) >= MAX_HEADER_CANDIDATES:
                    break
    for off, hlen, end in candidates:
        found = _open_header(f, off, hlen, end, True)
        if found is not None:
            return found
    return None


def _read_layout(path: Path) -> tuple[_Layout, bytes] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        try:
            size = os.fstat(fd).st_size
            return _layout(f, fd, size) if size else None
        except (OSError, ValueError, OverflowError, struct.error):
            return None


def nsis_header(path: Path) -> bytes | None:
    """The decompressed NSIS script header, or None (not NSIS, bzip2, damaged, over the caps)."""
    found = _read_layout(path)
    return None if found is None else found[1]


def nsis_signature_altered(path: Path) -> bool:
    """True when the archive was found by structure because its signature bytes were replaced."""
    found = _read_layout(path)
    return found is not None and found[0].altered


# ----------------------------------------------------------------- the carver


def nsis_carve(sample: Path, dest: Path, *, deadline: float, max_bytes: int, max_files: int) -> int:
    """Write the archive's data items to ``dest/carved/item-<n>.bin`` without the install script;
    the number written.

    7-Zip names files from the script's instructions, so a build whose opcodes were renumbered
    lists nothing (and one with an altered signature does not open at all). The data is still a
    plain sequence: solid, one stream of ``[u32 size][item]``; otherwise one
    ``[u32 size | 0x80000000 when compressed][block]`` per item. Names are lost, so members are
    ``item-<n>.bin`` in archive order. Stops at ``deadline`` (``time.monotonic``), ``max_bytes``
    or ``max_files``; whatever was complete by then stays.
    """
    found = _read_layout(sample)
    if found is None:
        return 0
    lay = found[0]
    out_dir = dest / CARVED
    out_dir.mkdir(parents=True, exist_ok=True)
    written = count = 0
    with sample.open("rb") as f:
        if lay.solid:
            buf = bytearray()
            need = -1  # bytes left in the current item (-1: reading its size)
            index = 0  # item 0 is the script header
            sink: BinaryIO | None = None
            try:
                for chunk in _stream(f, lay.start, lay.method, max(0, lay.end - lay.start)):
                    if time.monotonic() >= deadline:
                        break
                    buf += chunk
                    done = False
                    while not done:
                        if need < 0:
                            if len(buf) < 4:
                                break
                            (need,) = struct.unpack_from("<I", buf)
                            del buf[:4]
                            if index and (need > max_bytes - written or count >= max_files):
                                done = True
                                break
                            if index and need:
                                sink = (out_dir / f"item-{index}.bin").open("wb")
                        take = min(need, len(buf))
                        if sink is not None:
                            sink.write(buf[:take])
                            written += take
                        del buf[:take]
                        need -= take
                        if need:
                            break
                        if sink is not None:
                            sink.close()
                            sink = None
                            count += 1
                        need = -1
                        index += 1
                    if done:
                        break
            finally:
                if sink is not None:  # cut off mid-item: not a whole file
                    sink.close()
                    (out_dir / f"item-{index}.bin").unlink(missing_ok=True)
            return count
        pos = lay.start
        index = 0
        while pos + 4 <= lay.end and count < max_files and time.monotonic() < deadline:
            f.seek(pos)
            lead = f.read(4)
            if len(lead) < 4:
                break
            (n,) = struct.unpack("<I", lead)
            size = n & 0x7FFFFFFF
            if pos + 4 + size > lay.end:
                break
            if index and size:
                target = out_dir / f"item-{index}.bin"
                ok = True
                with target.open("wb") as sink:
                    if n & 0x80000000:
                        got = 0
                        for chunk in _stream(f, pos + 4, lay.method, size):
                            got += len(chunk)
                            if got > max_bytes - written or time.monotonic() >= deadline:
                                ok = False
                                break
                            sink.write(chunk)
                        ok = ok and got > 0
                    else:
                        got = size
                        if got > max_bytes - written:
                            ok = False
                        else:
                            f.seek(pos + 4)
                            left = size
                            while left and (data := f.read(min(_CHUNK, left))):
                                sink.write(data)
                                left -= len(data)
                if not ok:
                    target.unlink(missing_ok=True)
                    if got > max_bytes - written:
                        break
                else:
                    written += got
                    count += 1
            pos += 4 + size
            index += 1
    return count


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


def _strings(header: bytes) -> list[str]:
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


def nsis_strings(path: Path) -> list[str]:
    """The NSIS script's string table, variables rendered (``$INSTDIR``...); [] when undecodable."""
    header = nsis_header(path)
    return [] if header is None else _strings(header)


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
    return rel.lower().startswith("$pluginsdir/") and rel.lower().endswith(".dll")


# NSIS's own plugin DLLs (and the common third-party ones): installer machinery, never the payload.
_STOCK_PLUGINS = frozenset(
    "system nsdialogs nsexec banner bgimage dialer installoptions langdll math nsisdl splash startmenu "
    "userinfo vpatch advsplash nsis7z inetc nsprocess accesscontrol nsjson uac stdutils nsisunz ziparchive "
    "modern-wizard nsresize nswindows killproc findprocdll registry locate textreplace md5dll".split())
_PLUGIN_REF = re.compile(r"\$PLUGINSDIR\\([^\\\"/:*?<>|]{1,64}\.dll)", re.I)


@dataclass(frozen=True)
class _PeFacts:
    dll: bool
    signed: bool  # carries an Authenticode certificate table (present; nothing verifies it here)
    export_name: str  # the DLL name in the export directory, "" without one
    imports: frozenset[str]  # imported DLL names, lowercased


def _pe_facts(path: Path) -> _PeFacts | None:
    """Header facts of a PE member (bounded reads; None when the headers do not parse)."""
    try:
        with path.open("rb") as f:
            head = f.read(8192)
            pe = struct.unpack_from("<I", head, 0x3C)[0]
            if head[pe:pe + 4] != b"PE\x00\x00":
                return None
            nsec, opt, chars = (struct.unpack_from("<H", head, pe + o)[0] for o in (6, 20, 22))
            dirs = pe + 24 + (112 if struct.unpack_from("<H", head, pe + 24)[0] == 0x20B else 96)
            ndirs = struct.unpack_from("<I", head, dirs - 4)[0]
            sections: list[tuple[int, int, int]] = []
            for i in range(min(nsec, 96)):
                try:
                    _vsize, va, raw_size, raw = struct.unpack_from("<IIII", head, pe + 24 + opt + 40 * i + 8)
                except struct.error:
                    break
                sections.append((va, raw_size, raw))

            def directory(i: int) -> tuple[int, int]:
                rva, size = struct.unpack_from("<II", head, dirs + 8 * i) if i < ndirs else (0, 0)
                return rva, size

            def read_at(rva: int, n: int) -> bytes:
                for va, raw_size, raw in sections:
                    if va <= rva < va + raw_size:
                        f.seek(rva - va + raw)
                        return f.read(n)
                return b""

            def name_at(rva: int) -> str:
                raw = read_at(rva, 64).split(b"\x00", 1)[0]
                return raw.decode("ascii") if raw.isascii() else ""

            export = ""
            rva = directory(0)[0]
            ptr = read_at(rva + 12, 4) if rva else b""
            if len(ptr) == 4:
                export = name_at(struct.unpack("<I", ptr)[0])
            imports: set[str] = set()
            rva = directory(1)[0]
            table = read_at(rva, 20 * MAX_IMPORT_DLLS) if rva else b""
            for i in range(0, len(table) - 19, 20):
                if not any(table[i:i + 20]):
                    break
                name = name_at(struct.unpack_from("<I", table, i + 12)[0])
                if name:
                    imports.add(name.lower())
            return _PeFacts(bool(chars & 0x2000), directory(4)[1] > 0, export, frozenset(imports))
    except (OSError, struct.error):
        return None


def _plugin_kind(m: Member, facts: _PeFacts | None, referenced: frozenset[str]) -> str:
    """``own`` (a program the installer carries), ``plugin`` (a DLL the script calls through
    ``$PLUGINSDIR``) or ``stock`` (one of NSIS's own). A carved member has no name, so its
    export-directory name stands in for it."""
    name = m.rel.rsplit("/", 1)[-1].lower()
    if m.rel.startswith(CARVED + "/"):
        name = facts.export_name.lower() if facts is not None else ""
        if not name.endswith(".dll") or not (name in referenced or name[:-4] in _STOCK_PLUGINS):
            return "own"
    elif not _is_plugin(m.rel):
        return "own"
    return "stock" if name[:-4] in _STOCK_PLUGINS else "plugin"


def _unsigned_import(program: Member, own: list[Member], facts: dict[str, _PeFacts | None],
                     strings: list[str]) -> Member | None:
    """The unsigned DLL a signed ``program`` imports from its own directory, when the installer
    ships one: the DLL side-loading layout, where the signed program is only the loader. A carved
    tree has no names, so there the program must import a DLL the script names that no signed
    member accounts for."""
    pf = facts[program.rel]
    if pf is None or pf.dll or not pf.signed or not pf.imports:
        return None
    folder = program.rel.rpartition("/")[0]
    dlls = [m for m in own if m is not program and m.rel.rpartition("/")[0] == folder
            and (f := facts[m.rel]) is not None and f.dll and not f.signed]
    if program.rel.startswith(CARVED + "/"):
        named = {re.split(r"[\\/]", s)[-1].lower() for s in strings if s.lower().endswith(".dll")}
        known = {f.export_name.lower() for m in own if (f := facts[m.rel]) is not None and f.signed}
        hits = dlls if (pf.imports & named) - known else []
    else:
        hits = [m for m in dlls if m.rel.rsplit("/", 1)[-1].lower() in pf.imports]
    return max(hits, key=lambda m: m.size) if hits else None


def _pick(members: list[Member], strings: list[str]) -> tuple[Member, str, Member | None] | None:
    """``(payload, reason, loader)``; ``loader`` is the signed program that imports the payload
    when the reason is ``unsigned_import``."""
    pes = [m for m in members if classify(m.path) in ("pe", "dotnet")]
    facts = {m.rel: _pe_facts(m.path) for m in pes}
    referenced = frozenset(n.lower() for s in strings for n in _PLUGIN_REF.findall(s))
    kinds = {m.rel: _plugin_kind(m, facts[m.rel], referenced) for m in pes}
    own = [m for m in pes if kinds[m.rel] == "own"]
    if not own:
        custom = [m for m in pes if kinds[m.rel] == "plugin"]
        return (max(custom, key=lambda m: m.size), "plugin_dll", None) if custom else None
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
        program, reason = best[2], "script_reference"
    else:  # a program before a library: the largest EXE, else the largest PE
        exes = [m for m in own if (f := facts[m.rel]) is None or not f.dll]
        program, reason = max(exes or own, key=lambda m: m.size), "largest_pe"
    side = _unsigned_import(program, own, facts, strings)
    return (side, "unsigned_import", program) if side is not None else (program, reason, None)


def choose_payload(members: list[Member], strings: list[str]) -> tuple[Member, str] | None:
    """``(member, reason)``: the PE the script runs (``script_reference``), else the largest
    program (``largest_pe``); when that program is signed and imports an unsigned DLL shipped
    beside it, that DLL instead (``unsigned_import``: the side-loading layout). With no program,
    the largest DLL the script calls as a plugin (``plugin_dll``). NSIS's own plugins are never
    the payload: an installer carrying nothing else has none (a script-driven loader)."""
    picked = _pick(members, strings)
    return None if picked is None else picked[:2]


def _entropy(path: Path) -> float:
    try:
        with path.open("rb") as f:
            data = f.read(_CHUNK)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 2)


def stub_profile(members: list[Member], strings: list[str]) -> dict[str, Any]:
    """What an installer with no program of its own carries: its plugin DLLs and its largest
    non-executable members (name, size, entropy of the first MiB)."""
    pes = [m for m in members if classify(m.path) in ("pe", "dotnet")]
    seen = {m.rel for m in pes}
    referenced = frozenset(n.lower() for s in strings for n in _PLUGIN_REF.findall(s))
    plugins: set[str] = set()
    for m in pes:
        facts = _pe_facts(m.path)
        if _plugin_kind(m, facts, referenced) != "own":
            carved = facts.export_name if facts is not None and m.rel.startswith(CARVED + "/") else ""
            plugins.add((carved or m.rel).rsplit("/", 1)[-1])
    data = sorted((m for m in members if m.rel not in seen), key=lambda m: -m.size)[:MAX_PROFILE_MEMBERS]
    out: dict[str, Any] = {"member_count": len(members)}
    if plugins:
        out["plugins"] = [_rel_text(p)[:64] for p in sorted(plugins)[:MAX_PROFILE_MEMBERS]]
    if data:
        out["data_members"] = [{"name": m.rel[-128:], "size": m.size, "entropy": _entropy(m.path)} for m in data]
    return out


# ------------------------------------------------------------ the Inno script

_PS_LITERAL = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""")
_PS_EXTERNAL = re.compile(r"^external (?:function|procedure) ([A-Za-z_!][\w.:@!]{0,80})", re.M)
_JSON_SECTIONS = (("RunEntries", "[Run]"), ("UninstallRunEntries", "[UninstallRun]"),
                  ("RegistryEntries", "[Registry]"), ("IconEntries", "[Icons]"), ("Icons", "[Icons]"),
                  ("IniEntries", "[INI]"), ("DeleteEntries", "[InstallDelete]"))


def _read_text(path: Path, cap: int) -> str:
    try:
        with path.open("rb") as f:
            return f.read(cap).decode("utf-8", "replace")
    except OSError:
        return ""


def inno_script(members: list[Member]) -> tuple[list[str], list[str]]:
    """``(strings, imports)`` of an Inno Setup installer unwrapped by ``inno_unwrap``: the entries
    of the setup header's ``[Run]``/``[Registry]``/``[Icons]`` sections and the string literals of
    the compiled ``[Code]`` script, then the support functions that script imports (``Exec``,
    ``DownloadTemporaryFile``, ``CreateOleObject``, DLL imports)."""
    by_rel = {m.rel: m for m in members}
    strings: list[str] = []
    setup = by_rel.get("meta/setup.json")
    if setup is not None and setup.size <= MAX_INNO_TEXT:
        try:
            doc = json.loads(_read_text(setup.path, MAX_INNO_TEXT))
        except (ValueError, RecursionError):
            doc = None
        for key, label in _JSON_SECTIONS if isinstance(doc, dict) else ():
            entries = doc.get(key)
            for entry in entries[:MAX_DECODED_STRINGS] if isinstance(entries, list) else []:
                if isinstance(entry, dict):
                    text = " ".join(v for v in entry.values() if isinstance(v, str) and v)
                    if text:
                        strings.append(f"{label} {text}"[:MAX_STRING_CHARS])
    imports: list[str] = []
    script = by_rel.get("embedded/script.ps")
    if script is not None:
        text = _read_text(script.path, MAX_INNO_TEXT)
        for name in _PS_EXTERNAL.findall(text):
            if name not in imports and len(imports) < MAX_SCRIPT_IMPORTS and not name.startswith("!"):
                imports.append(name)
        for hit in _PS_LITERAL.finditer(text):
            if len(strings) >= MAX_DECODED_STRINGS:
                break
            raw = hit.group()
            try:
                value = ast.literal_eval(raw)
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                value = raw[1:-1]
            if isinstance(value, str):
                value = "".join(_clean(ord(ch)) for ch in value[:MAX_STRING_CHARS])
                if value:
                    strings.append(value)
    return strings, imports


# ---------------------------------------------------------------- the registry


@dataclass(frozen=True)
class Unwrapped:
    """What an unwrapper made of the extracted members: the ``payload`` to analyse instead of the
    stub (None: the installer carries no program of its own), how it was chosen, and evidence
    about the installer itself (script strings, altered signature, the stub's profile)."""

    payload: Member | None
    reason: str
    extra: dict[str, Any]


@dataclass(frozen=True)
class Unwrapper:
    name: str  # the evidence/summary ``packer`` value
    detect: Callable[[Path], bool]
    script: str  # fixed ``sh -c`` body: $1 ulimit -f blocks, $2 output dir, $3 sample, $4.. ``args``
    choose: Callable[[list[Member], Path], Unwrapped]
    args: Callable[[int], list[str]] = lambda max_bytes: []  # extra fixed argv (never from the sample)
    fallback: Callable[..., int] | None = None  # in-process carver for when the tool lists nothing


def _choose_nsis(members: list[Member], sample: Path) -> Unwrapped:
    found = _read_layout(sample)
    strings = [] if found is None else _strings(found[1])
    extra: dict[str, Any] = {}
    if found is not None and found[0].altered:
        extra["signature"] = "altered"
    excerpt = script_excerpt(strings)
    if excerpt:
        extra["script_strings"] = excerpt
    return _unwrapped(members, strings, extra)


def _unwrapped(members: list[Member], strings: list[str], extra: dict[str, Any]) -> Unwrapped:
    picked = _pick(members, strings)
    if picked is None:
        return Unwrapped(None, "", {**extra, **stub_profile(members, strings)})
    payload, reason, loader = picked
    return Unwrapped(payload, reason, {**extra, **({"loader_member": loader.rel} if loader else {})})


def _choose_inno(members: list[Member], sample: Path) -> Unwrapped:
    strings, imports = inno_script(members)
    extra: dict[str, Any] = {}
    excerpt = script_excerpt(strings)
    if excerpt:
        extra["script_strings"] = excerpt
    if imports:
        extra["script_imports"] = imports
    # Refinery's tree keeps installed files under data/; a tree from another extractor has no such
    # split, and then every PE is a candidate.
    files = [m for m in members if m.rel.startswith("data/")] or [m for m in members
                                                                 if not m.rel.startswith(("embedded/", "meta/"))]
    return _unwrapped(files, [], extra)


def _inno_args(max_bytes: int) -> list[str]:
    from blastbox.engines.rea import inno_unwrap

    return [DEFAULT_REFINERY_PYTHON, str(Path(inno_unwrap.__file__).resolve()), str(max_bytes), str(INNO_MAX_KB)]


UNWRAPPERS: tuple[Unwrapper, ...] = (
    Unwrapper("nsis", nsis_marked,
              'ulimit -f "$1" && exec 7z x -tNsis -y -bd -bso0 -bse0 -bsp0 -o"$2" -- "$3"', _choose_nsis,
              fallback=nsis_carve),
    # inno_unwrap.py under the Refinery venv; -I keeps its directory and the environment off sys.path.
    Unwrapper("inno", inno_marked,
              'ulimit -f "$1" && ulimit -v "$7" && exec "$4" -I "$5" "$3" "$2" "$6"', _choose_inno,
              args=_inno_args),
)
_BY_NAME = {u.name: u for u in UNWRAPPERS}


def detect(path: Path) -> str | None:
    """The name of the first unwrapper that claims a PE ``path``, else None."""
    if classify(path) != "pe":
        return None
    return next((u.name for u in UNWRAPPERS if u.detect(path)), None)


def choose(packer: str, members: list[Member], sample: Path) -> Unwrapped:
    return _BY_NAME[packer].choose(members, sample)


ExtractStatus = Literal["ok", "partial", "failed", "timeout", "too_large"]


def _has_files(dest: Path) -> bool:
    try:
        return any(files for _dir, _subdirs, files in os.walk(dest))
    except OSError:
        return False


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
    each written file at ``max_bytes`` and ``watch_fn`` the whole tree. 7-Zip strips absolute and
    ``..`` member paths and ``inno_unwrap`` rebuilds every path from sanitised components;
    :func:`collect` still walks ``dest`` without following links. A non-zero exit that left files
    behind (an encrypted or unsupported member) is ``partial``. When the tool wrote no file and
    the unwrapper has a ``fallback`` (NSIS: :func:`nsis_carve`), the archive's items are carved
    in-process under the same caps and the result is ``partial``: members without names.
    """
    u = _BY_NAME.get(packer)
    if u is None:
        raise ValueError(f"unsupported unwrapper: {packer!r}")
    sample, dest = sample.resolve(), dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    argv = ["sh", "-c", u.script, "sh", str(max(1, max_bytes // 512)), str(dest), str(sample), *u.args(max_bytes)]
    status = watch_fn(argv, env=env, cwd=dest, timeout_s=timeout_s, watch=dest, max_bytes=max_bytes,
                      max_files=max_files)
    if status in ("timeout", "too_large"):
        return status
    if _has_files(dest):
        return "partial" if status == "failed" else status
    if u.fallback is not None:
        try:
            carved = u.fallback(sample, dest, deadline=started + timeout_s, max_bytes=max_bytes,
                                max_files=max_files)
        except OSError:
            carved = 0
        if carved:
            return "partial"
    return "failed"
