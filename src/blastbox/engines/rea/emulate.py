"""Emulated unpacking of native Windows loaders (the sweep's step 4a, after UPX, before Ghidra).

Live, obfuscated native loaders (custom-packed stubs, TLS-callback decoders, PEB-walking API
hashing, XOR/RC4-decrypted stages, reflective loaders) were analysed as the stub only: their real
stage exists only at run time. The sweep emulates such a stub in Mandiant Speakeasy
(``emulate_runner.py``, run out of process under the Speakeasy venv's python by
``runner.run_emulation``; unicorn interprets the code, nothing runs natively) and

- captures the next stage: PE images the stub wrote into its own allocations (file or memory
  layout), its own image when it rewrote its code in place, and executable allocations
  (shellcode). PEs are carved to a file Ghidra can load (:func:`carve`), deduplicated by sha256;
  copies of the input and of Speakeasy's decoy system DLLs are dropped. Every capture becomes a
  member; the most plausible PE (:func:`choose`) replaces the stub for every later step;
- records what the stub did: a capped per-API summary with argument samples for file, registry,
  process, network, crypto, memory, sync and loader APIs, the strings seen in API arguments (they
  also go to the IOC extractor as ``emulation:<api>``), the concealment it showed
  (:data:`CONCEALMENT`) and why emulation stopped.

:func:`triggers` decides from cheap static signals whether a stub is worth emulating; it errs on
the side of running, since the wall-clock budget bounds the cost.

``State.sweep["emulation"]`` / report ``emulation``::

    {"status": "ok" | "budget" | "failed", "triggers": [...], "arch"?, "dll"?,
     "stop"?: "exit" | "budget" | "api_limit" | "unsupported_api" | "exception", "stop_detail"?,
     "entry_points": [{"type", "stop"[, "detail"]}], "apis_total", "apis_distinct",
     "apis": [{"api", "category", "count"[, "args": [[display, ...], ...]]}],
     "strings": [{"api", "value"}], "events": [{"event", ...}], "dynamic_code": [{"tag", "base", "size"}],
     "concealment": [...], "unimported_apis"?: [...], "truncated"?: true,
     "captures": [{"member"?, "sha256", "size", "kind": "pe" | "shellcode",
       "layout"?: "file" | "memory", "dll"?, "source", "region": {"base", "size", "protect"},
       "executed", "exec_requested"}],
     "captures_dropped": {"same_as_input"?, "decoy_module"?, "duplicate"?, "too_small"?, "capped"?},
     "payload_sha256"?}

Bases are ``0x``-hex strings, sizes ints. ``protect`` is the protection the stub asked for
(``PAGE_*``) or else the emulator's page permissions (``rwx`` letters). ``concealment`` codes
(:data:`CONCEALMENT`): ``exec_alloc`` (the stub asked for executable memory), ``dynamic_code``
(code ran outside its image), ``pe_in_memory`` (a PE capture), ``self_modified`` (it rewrote its
own code or empty sections), ``injection_apis`` (WriteProcessMemory, CreateRemoteThread, ...),
``manual_api_resolution`` (it called APIs it neither imports nor looked up by name:
``unimported_apis``). A failed run has only ``status``, ``triggers`` and maybe ``stop_detail``. An emulator is not Windows: a stage may never appear
(anti-emulation checks, an unsupported API), and behaviour seen here is behaviour of the stub
under Speakeasy, which the agent and report prompts say.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blastbox.engines.rea import triage

DEFAULT_TIMEOUT_S = 120.0  # Speakeasy's own budget (REA_EMULATE_TIMEOUT_S)
OVERHEAD_S = 30.0  # interpreter start, decoy-module setup and region dumps, on top of the budget
DEFAULT_MAX_API = 20_000  # API calls per run (REA_EMULATE_MAX_API)
# Instructions per run (REA_EMULATE_MAX_INSTRUCTIONS). -1 = no cap: Speakeasy counts instructions
# in a Python hook (measured ~2.7M/s against ~600M/s without it), so the wall clock is the guard.
DEFAULT_MAX_INSN = -1
DEFAULT_PYTHON = "/opt/speakeasy/bin/python"
MAX_KB = 3 * 1024 * 1024  # unicorn reserves a 1 GiB translation buffer up front
MAX_JSON = 32 * 1024 * 1024
MAX_WRITE = 320 * 1024 * 1024

MAX_INPUT_BYTES = 64 * 1024 * 1024  # larger stubs are not emulated
PAYLOAD_MIN_BYTES = 4096
SHELLCODE_MIN_BYTES = 16
MAX_CAPTURES = 16
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_PE_PER_REGION = 4
MAX_IMAGE = 256 * 1024 * 1024
STATE_APIS = 64
ARG_SAMPLES = 3
STATE_STRINGS = 64
STATE_EVENTS = 32
STATE_ENTRY_POINTS = 16
STATE_DYNAMIC = 16
MAX_TEXT = 256
ARG_TEXT = 128
MAX_ARGS = 8
# The evidence goes into every agent pass's context and the report call: past this size, argument
# samples go first, then the tails of the API, string and event lists.
MAX_EVIDENCE_BYTES = 48 * 1024

FEW_IMPORTS = 10
HIGH_ENTROPY = triage.HIGH_ENTROPY
MIN_ENTROPY_BYTES = triage.MIN_ENTROPY_BYTES
_MACHINES = {0x14C: "x86", 0x8664: "amd64"}
_LOADER_IMPORTS = frozenset({
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress", "getmodulehandlea",
    "getmodulehandlew", "getmodulehandleexa", "getmodulehandleexw", "virtualalloc", "virtualprotect", "virtualfree",
    "exitprocess", "ldrloaddll", "ldrgetprocedureaddress", "ldrgetdllhandle",
})
CONCEALMENT = ("exec_alloc", "dynamic_code", "pe_in_memory", "self_modified", "injection_apis", "manual_api_resolution")
_RESOLVERS = frozenset({"getprocaddress", "ldrgetprocedureaddress", "ldrgetprocedureaddressforcaller"})
_INJECTION = frozenset({"writeprocessmemory", "createremotethread", "createremotethreadex", "ntcreatethreadex",
                        "queueuserapc", "ntqueueapcthread", "setthreadcontext", "ntsetcontextthread",
                        "ntunmapviewofsection", "zwunmapviewofsection", "ntwritevirtualmemory"})
_STOPS = {None: "exit", "timeout": "budget", "max_total_time": "budget", "max_instructions": "budget",
          "max_api_count": "api_limit", "unsupported_api": "unsupported_api"}
_STOP_ORDER = ("budget", "api_limit", "unsupported_api", "exception", "exit")
_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("network", re.compile(r"^(?:wininet|winhttp|ws2_32|wsock32|urlmon|dnsapi|iphlpapi|mswsock)\.|"
                           r"\.(?:Internet|WinHttp|URLDownload|DnsQuery|gethostbyname|getaddrinfo|connect|send|recv|"
                           r"WSAConnect|WSASend|WSARecv|HttpSendRequest|HttpOpenRequest)", re.I)),
    ("registry", re.compile(r"\.(?:Reg[A-Z]|Nt(?:Open|Create|SetValue|QueryValue|Delete)(?:Key|ValueKey)|"
                            r"Zw(?:Open|Create|SetValue|QueryValue)(?:Key|ValueKey))", re.I)),
    ("process", re.compile(r"\.(?:CreateProcess|WinExec|ShellExecute|OpenProcess|CreateRemoteThread|CreateThread|"
                           r"WriteProcessMemory|ReadProcessMemory|NtUnmapViewOfSection|ZwUnmapViewOfSection|"
                           r"ResumeThread|SuspendThread|SetThreadContext|GetThreadContext|QueueUserAPC|NtQueueApcThread|"
                           r"CreateToolhelp32Snapshot|Process32|TerminateProcess|NtCreateThreadEx|NtWriteVirtualMemory|"
                           r"NtSetContextThread)", re.I)),
    ("file", re.compile(r"\.(?:CreateFile|WriteFile|ReadFile|DeleteFile|CopyFile|MoveFile|FindFirstFile|FindNextFile|"
                        r"GetTempPath|GetTempFileName|CreateDirectory|SetFileAttributes|NtCreateFile|NtWriteFile|"
                        r"NtReadFile|ZwCreateFile|GetModuleFileName|_wfopen|fopen)", re.I)),
    ("crypto", re.compile(r"^(?:advapi32\.Crypt|bcrypt\.|ncrypt\.|crypt32\.)|\.(?:Crypt[A-Z]|BCrypt|NCrypt|"
                          r"RtlDecompressBuffer|RtlCompressBuffer)", re.I)),
    ("memory", re.compile(r"\.(?:VirtualAlloc|VirtualProtect|VirtualFree|NtAllocateVirtualMemory|ZwAllocateVirtualMemory|"
                          r"NtProtectVirtualMemory|ZwProtectVirtualMemory|HeapCreate|MapViewOfFile|NtMapViewOfSection|"
                          r"CreateFileMapping|NtCreateSection|RtlMoveMemory)", re.I)),
    ("sync", re.compile(r"\.(?:CreateMutex|OpenMutex|CreateEvent|OpenEvent|CreateSemaphore)", re.I)),
    ("loader", re.compile(r"\.(?:LoadLibrary|GetProcAddress|GetModuleHandle|LdrLoadDll|LdrGetProcedureAddress|"
                          r"LdrGetDllHandle)", re.I)),
)
_ARG_CATEGORIES = frozenset(c for c, _ in _CATEGORIES)
_HEX = re.compile(r"0x[0-9a-fA-F]{1,16}")
_REGION_FILE = re.compile(r"region-[0-9]{1,3}\.bin")
_FLAGS = re.compile(r"[A-Z][A-Z0-9_]*(?:\|[A-Z][A-Z0-9_]*)*")  # an enum/flags rendering, not a string


def env_number(name: str, default: float, *, integer: bool = False, allow_negative_one: bool = False) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if not math.isfinite(value):
        return default
    if allow_negative_one and value == -1:
        return -1
    if value <= 0 or (integer and value != int(value)):
        return default
    return value


def _short(text: Any, n: int = MAX_TEXT) -> str:
    s = text if isinstance(text, str) else str(text)
    return s if len(s) <= n else s[: n - 3] + "..."


def category(api: str) -> str:
    for name, pattern in _CATEGORIES:
        if pattern.search(api):
            return name
    return "other"


# ------------------------------------------------------------------- trigger

def _read_head(path: Path, n: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return b""
    with os.fdopen(fd, "rb") as f:
        return f.read(n)


def emulatable(path: Path) -> str | None:
    """The Speakeasy arch (``x86`` / ``amd64``) of a native x86/x64 PE it can load, or None
    (not a PE, another machine, a .NET assembly, or over ``MAX_INPUT_BYTES``)."""
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return None
    except OSError:
        return None
    head = _read_head(path, triage.HEAD_BYTES)
    if not triage._pe_sections(head) or triage._has_clr_header(head):
        return None
    try:
        (lfanew,) = struct.unpack_from("<I", head, 0x3C)
        (machine,) = struct.unpack_from("<H", head, lfanew + 4)
    except struct.error:
        return None
    return _MACHINES.get(machine)


def imports(path: Path) -> list[str] | None:
    """The PE's imported function names (lower case; ``#<dll>`` for an import by ordinal), or None
    when the table does not parse."""
    return _imports_and_tls(path)[0]


def _imports_and_tls(path: Path) -> tuple[list[str] | None, int]:
    """``(imported function names (lower case) or None if unparsable, TLS callbacks)``."""
    import pefile  # type: ignore[import-untyped]

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:  # pefile raises many types on hostile input
        return None, 0
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                               pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        names = [imp.name.decode("latin-1").lower() if imp.name
                 else "#" + (entry.dll or b"").decode("latin-1").lower().removesuffix(".dll")
                 for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:256]
                 for imp in entry.imports[:4096]]
        callbacks = 0
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls is not None and tls.struct.AddressOfCallBacks:
            rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            width = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
            for i in range(16):
                data = pe.get_data(rva + i * width, width)
                if len(data) < width or not int.from_bytes(data, "little"):
                    break
                callbacks += 1
        return names, callbacks
    except Exception:
        return None, 0
    finally:
        pe.close()


def triggers(path: Path, *, api_hashes: int = 0, upx_failed: bool = False) -> list[str]:
    """Why the PE at ``path`` looks like it hides its real stage until run time ([] = it does not).

    Signals (cheap and static, deliberately loose: the emulation budget bounds a false hit):

    ```text
    high_entropy_section  a section of >= MIN_ENTROPY_BYTES with entropy >= HIGH_ENTROPY
    few_imports           <= FEW_IMPORTS imported functions (none, or an unparsable table)
    loader_imports_only   every import is a loader/allocator API (LoadLibrary, GetProcAddress, ...)
    tls_callbacks         a TLS callback runs before the entry point (mingw's CRT has them too)
    wx_section            a section that is both writable and executable
    entry_outside_code    the entry point is not in an executable section with file bytes
    api_hashes            apihash found hashed API names in the code
    upx_unpack_failed     UPX-marked but upx -d refused it (a tampered header)
    ```
    """
    head = _read_head(path, triage.HEAD_BYTES)
    sections = triage._pe_sections(head)
    if not sections:
        return []
    out: list[str] = []
    if triage._high_entropy(path, [(off, size) for _n, _c, off, size in sections]):
        out.append("high_entropy_section")
    names, callbacks = _imports_and_tls(path)
    if names is None or len(names) <= FEW_IMPORTS:
        out.append("few_imports")
    if names and all(n in _LOADER_IMPORTS for n in names):
        out.append("loader_imports_only")
    if callbacks:
        out.append("tls_callbacks")
    if any(chars & 0x20000000 and chars & 0x80000000 for _n, chars, _o, _s in sections):
        out.append("wx_section")
    try:
        (lfanew,) = struct.unpack_from("<I", head, 0x3C)
        (entry,) = struct.unpack_from("<I", head, lfanew + 24 + 16)
        (opt,) = struct.unpack_from("<H", head, lfanew + 20)
        table = lfanew + 24 + opt
        inside = False
        for i in range(min(len(sections), triage.MAX_SECTIONS)):
            vsize, va = struct.unpack_from("<II", head, table + 40 * i + 8)
            _name, chars, _off, raw = sections[i]
            if va <= entry < va + max(vsize, raw) and chars & 0x20000000 and raw:
                inside = True
        if entry and not inside:
            out.append("entry_outside_code")
    except struct.error:
        pass
    if api_hashes:
        out.append("api_hashes")
    if upx_failed:
        out.append("upx_unpack_failed")
    return out


# ------------------------------------------------------------------- carving

@dataclass(frozen=True)
class Carved:
    data: bytes
    layout: str  # "file" | "memory"
    machine: int
    dll: bool
    identity: tuple[int, int, int, int]  # machine, timestamp, entry RVA, SizeOfImage


def _headers(blob: bytes, off: int) -> tuple[int, int, int, int, int, int, int, int, list[tuple[int, int, int, int]]] | None:
    """``(lfanew, machine, chars, timestamp, magic, entry, size_of_image, size_of_headers,
    [(vsize, va, raw_size, raw_ptr)])`` of the PE at ``off`` in ``blob``, or None."""
    try:
        if blob[off:off + 2] != b"MZ":
            return None
        (lfanew,) = struct.unpack_from("<I", blob, off + 0x3C)
        p = off + lfanew
        if not 0x40 <= lfanew <= 0x1000 or blob[p:p + 4] != b"PE\x00\x00":
            return None
        machine, nsec, timestamp = struct.unpack_from("<HHI", blob, p + 4)
        opt_size, chars = struct.unpack_from("<HH", blob, p + 20)
        (magic,) = struct.unpack_from("<H", blob, p + 24)
        if magic not in (0x10B, 0x20B) or not 1 <= nsec <= triage.MAX_SECTIONS:
            return None
        (entry,) = struct.unpack_from("<I", blob, p + 24 + 16)
        size_of_image, size_of_headers = struct.unpack_from("<II", blob, p + 24 + 56)
        if not 0 < size_of_headers <= size_of_image <= MAX_IMAGE:
            return None
        table = p + 24 + opt_size
        secs = []
        for i in range(nsec):
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, table + 40 * i + 8)
            secs.append((vsize, va, raw_size, raw_ptr))
        return lfanew, machine, chars, timestamp, magic, entry, size_of_image, size_of_headers, secs
    except struct.error:
        return None


def _memory_layout(blob: bytes, off: int, secs: list[tuple[int, int, int, int]]) -> bool:
    """Whether the image at ``off`` is mapped (sections at their RVAs) rather than a file copy.

    A loader copies only SizeOfHeaders bytes of header, so in a mapped image the bytes from the
    first section's file offset up to its RVA are zero, while in a file copy that section's data
    starts there. Where every section's file offset equals its RVA the layouts coincide (file)."""
    with_raw = [(va, ptr) for _vs, va, raw, ptr in secs if raw and ptr]
    if not with_raw or all(va == ptr for va, ptr in with_raw):
        return False
    va0 = min(va for va, _p in with_raw)
    ptr0 = min(ptr for _v, ptr in with_raw)
    if ptr0 >= va0:
        return False
    window = blob[off + ptr0: off + min(ptr0 + 0x200, va0)]
    return not any(window)


def carve(blob: bytes, off: int, base: int, alloc_size: int | None = None) -> Carved | None:
    """The PE whose MZ header sits at ``off`` of a region mapped at ``base``, as a loadable file.

    A file-layout copy is cut at the end of its last section's file data (plus its certificate
    table and any non-zero overlay up to the region's end). A mapped (memory-layout) image is
    realigned: the image is kept as mapped, every section's file offset and size are rewritten
    to its RVA and virtual size, and ImageBase to where it was mapped, so Ghidra loads it at the
    addresses it ran at. ``alloc_size`` (the size the stub asked VirtualAlloc for) bounds a
    file copy at the start of its allocation exactly, trailing zeros included. None when the
    headers do not parse or the region holds only part of the file."""
    hdr = _headers(blob, off)
    if hdr is None:
        return None
    lfanew, machine, chars, timestamp, magic, entry, size_of_image, size_of_headers, secs = hdr
    identity = (machine, timestamp, entry, size_of_image)
    dll = bool(chars & 0x2000)
    if _memory_layout(blob, off, secs):
        img = bytearray(blob[off:off + size_of_image].ljust(size_of_image, b"\x00"))
        p = lfanew
        opt_size = struct.unpack_from("<H", img, p + 20)[0]
        (file_align,) = struct.unpack_from("<I", img, p + 24 + 36)
        align = file_align if file_align and not file_align & (file_align - 1) and file_align <= 0x10000 else 1
        table = p + 24 + opt_size
        for i, (vsize, va, raw, _ptr) in enumerate(secs):
            want = (vsize or raw) + align - 1 & ~(align - 1)
            span = max(0, min(want, size_of_image - va)) if va < size_of_image else 0
            struct.pack_into("<II", img, table + 40 * i + 16, span, va if span else 0)
        if magic == 0x20B:
            struct.pack_into("<Q", img, p + 24 + 24, base + off)
        elif base + off < 1 << 32:
            struct.pack_into("<I", img, p + 24 + 28, base + off)
        return Carved(bytes(img), "memory", machine, dll, identity)
    end = max([size_of_headers] + [ptr + raw for _vs, _va, raw, ptr in secs if raw])
    try:
        dirs = off + lfanew + 24 + (112 if magic == 0x20B else 96)
        cert_off, cert_size = struct.unpack_from("<II", blob, dirs + 4 * 8)  # the security directory
        if cert_off and cert_size and cert_off + cert_size <= len(blob) - off:
            end = max(end, cert_off + cert_size)
    except struct.error:
        pass
    if off == 0 and alloc_size is not None and end <= alloc_size <= len(blob):
        data = blob[:alloc_size]
    else:
        tail = blob[off + end:].rstrip(b"\x00")
        data = blob[off:off + end + len(tail)]
    if len(data) < end:
        return None  # the region holds only part of the file
    return Carved(data, "file", machine, dll, identity)


def pe_offsets(blob: bytes, page: int = 0x1000) -> list[int]:
    out = []
    for off in range(0, len(blob), page):
        if blob[off:off + 2] == b"MZ" and _headers(blob, off) is not None:
            out.append(off)
            if len(out) >= MAX_PE_PER_REGION:
                break
    return out


# ----------------------------------------------------------- evidence shaping

@dataclass
class Capture:
    path: Path
    sha256: str
    size: int
    kind: str  # "pe" | "shellcode"
    source: str
    region: dict[str, Any]
    executed: bool
    exec_requested: bool
    layout: str | None = None
    dll: bool | None = None
    machine: int | None = None
    identity: tuple[int, int, int, int] | None = None
    member: str | None = None

    def row(self) -> dict[str, Any]:
        r: dict[str, Any] = {"sha256": self.sha256, "size": self.size, "kind": self.kind, "source": self.source,
                             "region": dict(self.region), "executed": self.executed,
                             "exec_requested": self.exec_requested}
        if self.layout is not None:
            r["layout"] = self.layout
        if self.dll is not None:
            r["dll"] = self.dll
        if self.member is not None:
            r["member"] = self.member
        return r


@dataclass
class Emulation:
    evidence: dict[str, Any]
    captures: list[Capture] = field(default_factory=list)
    strings: list[tuple[str, str]] = field(default_factory=list)  # (source, value) for the IOC extractor


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and _HEX.fullmatch(v):
        return int(v, 16)
    return None


def _source(tag: str) -> str:
    """``VirtualAlloc`` from ``api.VirtualAlloc.0x50000``; ``module`` for the stub's own image."""
    if tag == "module":
        return "module"
    parts = tag.split(".")
    return _short(".".join(p for p in parts[1:] if not _HEX.fullmatch(p)) or tag, 64)


def _stop(error: Any) -> str:
    if error is None or isinstance(error, str) and error in _STOPS:
        return _STOPS.get(error, "exit")
    return "exception"


def _api_rows(apis: list[Any]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, str]], int]:
    """``(per-API summary rows, every distinct API, (api, string arg) pairs, injection API calls)``;
    both lists keep first-call order."""
    order: list[str] = []
    counts: Counter[str] = Counter()
    samples: dict[str, list[list[str]]] = {}
    strings: list[tuple[str, str]] = []
    seen_strings: set[tuple[str, str]] = set()
    injection = 0
    for ev in apis:
        if not isinstance(ev, dict) or not isinstance(ev.get("n"), str):
            continue
        name = _short(ev["n"], 96)
        if name not in counts:
            order.append(name)
        counts[name] += 1
        if name.rsplit(".", 1)[-1].lower() in _INJECTION:
            injection += 1
        raw_args = ev.get("a")
        args = [a for a in raw_args if isinstance(a, list) and len(a) == 2 and all(isinstance(x, str) for x in a)] \
            if isinstance(raw_args, list) else []
        found = [d for t, d in args if len(d) >= 4 and (t == "str" or t == "text" and not _FLAGS.fullmatch(d))]
        hive = next((d for t, d in args if t != "str" and d.startswith("HKEY_") and _FLAGS.fullmatch(d)), None)
        if hive is not None and category(name) == "registry":
            found = [f"{hive}\\{d.lstrip(chr(92))}" if not d.upper().startswith("HK") else d for d in found]
        for display in found:
            if (name, display) not in seen_strings and len(seen_strings) < 4096:
                seen_strings.add((name, display))
                strings.append((name, display))
        if category(name) in _ARG_CATEGORIES:
            sample = [_short(d, ARG_TEXT) for _t, d in args[:MAX_ARGS]]
            bucket = samples.setdefault(name, [])
            if sample not in bucket and len(bucket) < ARG_SAMPLES:
                bucket.append(sample)
    rows = []
    for name in order[:STATE_APIS]:
        row: dict[str, Any] = {"api": name, "category": category(name), "count": counts[name]}
        if name in samples:
            row["args"] = samples[name]
        rows.append(row)
    return rows, order, strings, injection


def manual_resolution(called: Iterable[str], imported: list[str] | None,
                      resolved: Iterable[str]) -> list[str]:
    """APIs the stub called that it neither imports nor looked up by name (GetProcAddress /
    LdrGetProcedureAddress string arguments): resolved by hand, e.g. a PEB walk with name hashes.
    Empty when the import table did not parse (nothing to compare against)."""
    if imported is None:
        return []
    known = set(imported) | {r.lower() for r in resolved}
    by_ordinal = {n[1:] for n in imported if n.startswith("#")}  # any function of such a DLL may be one
    out = []
    for api in called:
        dll, _, fn = api.lower().rpartition(".")
        if fn and fn not in known and dll not in by_ordinal and fn not in out:
            out.append(fn)
    return out


def shape(doc: dict[str, Any], scan_dir: Path, work: Path, *, input_sha256: str,
          triggers: list[str], imported: list[str] | None = None) -> Emulation:
    """The evidence and captures from the runner's JSON ``doc`` and the region files it wrote
    under ``scan_dir``. Carved files go under ``work``. Everything the runner wrote is treated
    as hostile: types are checked, names validated, sizes capped."""
    ev: dict[str, Any] = {"status": "ok", "triggers": list(triggers)}
    if isinstance(doc.get("arch"), str):
        ev["arch"] = _short(doc["arch"], 16)
    if isinstance(doc.get("dll"), bool):
        ev["dll"] = doc["dll"]
    eps = []
    raw_eps = doc.get("entry_points")
    for ep in raw_eps if isinstance(raw_eps, list) else []:
        if not isinstance(ep, dict):
            continue
        err = ep.get("error")
        row = {"type": _short(ep.get("type") if isinstance(ep.get("type"), str) else "?", 96),
               "stop": _stop(err if isinstance(err, str) or err is None else "?")}
        if row["stop"] == "exception" and isinstance(err, str):
            row["detail"] = _short(err, 64)
        elif row["stop"] == "unsupported_api" and isinstance(ep.get("api"), str):
            row["detail"] = _short(ep["api"], 96)
        eps.append(row)
    ev["entry_points"] = eps[:STATE_ENTRY_POINTS]
    stops = [e["stop"] for e in eps]
    stop = next((s for s in _STOP_ORDER if s in stops), None)
    if isinstance(doc.get("error"), str):
        stop = "exception"
        ev["stop_detail"] = _short(doc["error"], 200)
    elif stop is not None and stop != "exit":
        detail = next((e.get("detail") for e in eps if e["stop"] == stop and e.get("detail")), None)
        if detail:
            ev["stop_detail"] = detail
    if stop is not None:
        ev["stop"] = stop

    raw_apis = doc.get("apis")
    rows, called, strings, injection = _api_rows(raw_apis if isinstance(raw_apis, list) else [])
    total = doc.get("apis_total")
    ev["apis_total"] = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else 0
    ev["apis_distinct"] = len(called)
    ev["apis"] = rows

    events = []
    raw_events = doc.get("events")
    for e in raw_events if isinstance(raw_events, list) else []:
        if not isinstance(e, dict) or not isinstance(e.get("event"), str):
            continue
        if e["event"].startswith("mem_") or e["event"] == "module_load":
            continue
        row = {_short(k, 32): _short(v, MAX_TEXT) for k, v in list(e.items())[:8]
               if isinstance(k, str) and isinstance(v, str)}
        events.append(row)
        for k in ("server", "query", "path", "cmdline", "url"):
            v = e.get(k)
            if isinstance(v, str) and len(v) >= 4 and (e["event"], v) not in strings:
                strings.append((e["event"], v))
    ev["events"] = events[:STATE_EVENTS]
    ev["strings"] = [{"api": a, "value": _short(v)} for a, v in strings
                     if (category(a) in _ARG_CATEGORIES or "." not in a)][:STATE_STRINGS]

    dynamic = []
    raw_dyn = doc.get("dynamic_code")
    for d in raw_dyn if isinstance(raw_dyn, list) else []:
        if isinstance(d, dict) and _as_int(d.get("base")) is not None and _as_int(d.get("size")) is not None:
            dynamic.append({"tag": _short(d.get("tag") if isinstance(d.get("tag"), str) else "", 96),
                            "base": f"{_as_int(d['base']):#x}", "size": _as_int(d["size"])})
    ev["dynamic_code"] = dynamic[:STATE_DYNAMIC]

    decoys = set()
    raw_decoys = doc.get("decoys")
    for d in raw_decoys if isinstance(raw_decoys, list) else []:
        if isinstance(d, dict) and isinstance(d.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", d["sha256"]):
            decoys.add(d["sha256"])

    captures, dropped = _captures(doc.get("regions"), scan_dir, work, input_sha256, decoys)
    ev["captures"] = []  # filled by the caller once members are numbered (Capture.row)
    if dropped:
        ev["captures_dropped"] = dropped

    concealment = []
    if any(c.exec_requested and c.source != "module" for c in captures) or _asked_exec(doc.get("regions")):
        concealment.append("exec_alloc")
    if dynamic:
        concealment.append("dynamic_code")
    if any(c.kind == "pe" for c in captures):
        concealment.append("pe_in_memory")
    module = doc.get("module")
    changed = module.get("changed") if isinstance(module, dict) else None
    if isinstance(changed, int) and not isinstance(changed, bool) and changed >= 512:
        concealment.append("self_modified")
    if injection:
        concealment.append("injection_apis")
    by_name = [a for a, _v in strings if a.rsplit(".", 1)[-1].lower() in _RESOLVERS]
    looked_up = [v for a, v in strings if a in by_name]
    manual = manual_resolution(called, imported, looked_up)
    if manual:
        concealment.append("manual_api_resolution")
        ev["unimported_apis"] = manual[:32]
    ev["concealment"] = concealment
    fit(ev)
    ioc_strings = [(f"emulation:{a}", v) for a, v in strings]
    return Emulation(ev, captures, ioc_strings)


def fit(ev: dict[str, Any], limit: int = MAX_EVIDENCE_BYTES) -> None:
    """Shrink ``ev`` in place to at most ``limit`` bytes of JSON (see ``MAX_EVIDENCE_BYTES``)."""
    def size() -> int:
        return len(json.dumps(ev))

    if size() <= limit:
        return
    for row in ev.get("apis", []):
        if len(row.get("args", [])) > 1:
            row["args"] = row["args"][:1]
    while size() > limit and any(len(ev.get(k, [])) > 1 for k in ("apis", "strings", "events")):
        for k in ("apis", "strings", "events"):
            if len(ev.get(k, [])) > 1:
                ev[k] = ev[k][: len(ev[k]) // 2]
    ev["truncated"] = True


def _asked_exec(regions: Any) -> bool:
    return any(isinstance(r, dict) and r.get("exec_requested") is True and r.get("source") == "alloc"
               for r in (regions if isinstance(regions, list) else []))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_region(scan_dir: Path, name: str) -> bytes | None:
    try:
        fd = os.open(scan_dir / name, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        return f.read(MAX_CAPTURE_BYTES)


def _captures(regions: Any, scan_dir: Path, work: Path, input_sha256: str,
              decoys: set[str]) -> tuple[list[Capture], dict[str, int]]:
    out: list[Capture] = []
    seen: set[str] = set()
    dropped: Counter[str] = Counter()

    def keep(data: bytes, cap: Capture) -> None:
        if len(out) >= MAX_CAPTURES:
            dropped["capped"] += 1
            return
        if cap.sha256 == input_sha256:
            dropped["same_as_input"] += 1
            return
        if cap.sha256 in seen:
            dropped["duplicate"] += 1
            return
        seen.add(cap.sha256)
        work.mkdir(parents=True, exist_ok=True)
        cap.path = work / f"capture-{len(out)}.bin"
        fd = os.open(cap.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        out.append(cap)

    for r in regions if isinstance(regions, list) else []:
        if not isinstance(r, dict) or not isinstance(r.get("file"), str) or not _REGION_FILE.fullmatch(r["file"]):
            continue
        base, size = _as_int(r.get("base")), _as_int(r.get("size"))
        if base is None or size is None or base < 0 or size <= 0:
            continue
        blob = _read_region(scan_dir, r["file"])
        if not blob:
            continue
        tag = r["tag"] if isinstance(r.get("tag"), str) else ""
        src = _source(tag)
        executed, asked = r.get("executed") is True, r.get("exec_requested") is True
        alloc = _as_int(r.get("alloc_size"))
        region = {"base": f"{base:#x}", "size": size,
                  "protect": _short(r.get("prot") if isinstance(r.get("prot"), str) else "", 64)}
        offs = pe_offsets(blob)
        for off in offs:
            c = carve(blob, off, base, alloc)
            if c is None:
                continue
            img = blob[off:off + c.identity[3]]
            if c.layout == "memory" and _sha(img) in decoys:
                dropped["decoy_module"] += 1
                continue
            data = c.data[:MAX_CAPTURE_BYTES]
            keep(data, Capture(Path(), _sha(data), len(data), "pe", src,
                               {**region, "base": f"{base + off:#x}"} if off else region, executed, asked,
                               c.layout, c.dll, c.machine, c.identity))
        if not offs and (executed or asked) and src != "module":
            code = blob.rstrip(b"\x00")
            if len(code) - code.count(0) < SHELLCODE_MIN_BYTES:
                dropped["too_small"] += 1
                continue
            keep(code, Capture(Path(), _sha(code), len(code), "shellcode", src, region, executed, asked))
    return out, dict(dropped)


def choose(captures: Iterable[Capture]) -> tuple[Capture, str] | None:
    """The captured PE most plausibly the next stage, and why: ``(capture, reason)`` or None.

    Candidates are PEs of at least ``PAYLOAD_MIN_BYTES`` for x86/x64. Copies of one image (same
    machine, timestamp, entry point and SizeOfImage) form a group whose signal is the strongest
    of its copies: ``executed_region`` (code ran in it) > ``executable_region`` (the stub asked
    for executable memory there) > ``self_modified_image`` (the stub rewrote its own image) >
    ``written_region``. The best group wins (then the larger image); within it the file-layout
    copy (the stage's original bytes) is preferred over a realigned mapped image."""
    rank = {"executed_region": 4, "executable_region": 3, "self_modified_image": 2, "written_region": 1}
    groups: dict[Any, list[Capture]] = {}
    for c in captures:
        if c.kind != "pe" or c.size < PAYLOAD_MIN_BYTES or c.machine not in _MACHINES:
            continue
        groups.setdefault(c.identity, []).append(c)

    def signal(c: Capture) -> str:
        if c.executed:
            return "executed_region"
        if c.exec_requested:
            return "executable_region"
        return "self_modified_image" if c.source == "module" else "written_region"

    best: tuple[int, int, Capture, str] | None = None
    for copies in groups.values():
        reason = max((signal(c) for c in copies), key=lambda s: rank[s])
        pick = sorted(copies, key=lambda c: (c.layout != "file", -c.size))[0]
        key = (rank[reason], pick.size)
        if best is None or key > best[:2]:
            best = (key[0], key[1], pick, reason)
    return (best[2], best[3]) if best is not None else None


def parse(out: bytes) -> dict[str, Any] | None:
    try:
        doc = json.loads(out)
    except (ValueError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None
