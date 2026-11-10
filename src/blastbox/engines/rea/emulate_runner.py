"""Speakeasy emulation of one native Windows PE, for the sweep's emulated unpacking.

THIS FILE RUNS AS A STANDALONE SCRIPT under the Speakeasy venv's python (``/opt/speakeasy``, a
hash-locked wheel venv of its own), as a bounded subprocess (``runner.run_emulation``:
``ulimit -v``/``-f``/``-t``, a wall-clock timeout, a stdout cap). It imports only the standard
library and ``speakeasy``:

    python -I emulate_runner.py <sample> <outdir> <budget_s> <max_api> <max_insn>

The sample's code is only ever interpreted by unicorn (Speakeasy's CPU emulator) inside this
process: it never runs natively. Its Windows API calls go to Speakeasy's handlers, so files,
registry, processes and the network are emulated (DNS and HTTP answer with decoys; nothing leaves
the process, and the worker slot has no network anyway). Everything it writes goes under
``outdir``.

An EXE runs from its entry point (TLS callbacks first, as Speakeasy does). A DLL runs DllMain and
then each export (``all_entrypoints``). ``budget_s`` is Speakeasy's total execution time across
those runs (``max_total_time``), ``max_api`` its API-call cap per run and ``max_insn`` its
instruction cap per run (``-1`` = none: Speakeasy counts instructions in a Python hook, which
runs about 100x slower than unicorn alone, so time is the default guard).

Speakeasy is helped along in these places, all in this file and all bounded (``_Assist``; one
that cannot be installed is named in ``notes`` and the run goes on without it):

- an API Speakeasy has neither a handler nor a usable declaration for would end the run
  (``unsupported_api``); it is stubbed instead: the C runtime is cdecl, a declared function keeps
  its declared convention and argument count, anything else gets no stack cleanup (popping a
  guessed argument count corrupts an x86 stack), and the return value is "nothing there" for
  the few calls where success would be a lie (``_access``) and success otherwise
  (:func:`stub_return`); a C runtime ``__p_<global>`` accessor returns storage
  (:func:`stub_global`). Every stubbed name goes to ``stubbed``. Speakeasy's own
  ``functions_always_exist`` is left off: it pops four stdcall arguments whatever the function;
- ``_initterm`` / ``_initterm_e`` call the initializer table they are given (Speakeasy returns
  without calling it, so a CRT-DLL stub never fetched argv); an EXE's command line is its own
  name, not Speakeasy's ``svchost.exe myarg1 myarg2``;
- allocations stay out of the first 64 KiB (a "pointer" below it reads as an ordinal or an atom),
  and the search for free address space is a bisect over the mapped ranges instead of Speakeasy's
  set arithmetic over every mapped page (measured 37 of 50 s on a loader that allocates in a
  loop);
- ``Nt``/``ZwProtectVirtualMemory`` change the protection (Speakeasy answers success and changes
  nothing) and executable requests through them and ``Nt``/``ZwAllocateVirtualMemory`` count;
- ``Sleep`` advances the emulated tick and performance counters by the time asked for,
  ``GetCursorPos`` reports a moving pointer and ``GetProcessId`` agrees with
  ``GetCurrentProcessId``: the cheapest checks a stub waits on;
- exceptions: every one Speakeasy dispatches is recorded (``faults``; with no handler it runs the
  stub's unhandled-exception filter and reports a clean exit), and the stub's vectored handlers
  are called first, as on Windows (Speakeasy keeps the list and never calls it; x64 has no
  handler dispatch at all), including for an access to a page the stub protected on purpose;
- ``Nt``/``ZwRaiseHardError`` keep the message a refusing protector shows (``hard_error`` events);
- unicorn's own timer burns a core next to the emulation, which pushed long runs over
  ``ulimit -t`` (the process died with nothing on stdout). The deadline is kept by a watchdog
  thread instead;
- Speakeasy leaves its per-instruction Python hook installed after the first API call; it is
  removed while it has nothing to do (measured 8x on a real loader, API sequence identical).

The emulation runs in a forked child; the parent only relays the child's document, and when the
child dies without one (a signal, the CPU limit, its wall clock) it prints
``{"error": <reason>, "fatal": <kind>}`` so the reason is never lost. ``GRACE_S`` is how long past
the budget the parent waits (less than the engine's own kill margin).

Output: one JSON document on stdout,

``{"arch", "dll", "entry_points": [{"type", "error", "calls"[, "api"][, "pc"][, "addr"][, "code"]}],
"apis": [{"n", "a": [[type, display], ...]}], "apis_total", "events": [{"event", ...string
fields}], "dynamic_code": [{"tag", "base", "size"}], "regions": [{"file", "tag", "base", "size",
"prot", "exec_requested", "executed", "source", "alloc_size"[, "copies"]}],
"regions_skipped": {"duplicate", "capped"}, "decoys": [{"name", "sha256"}],
"module": {"base", "size", "changed"},
"stubbed": [{"n": "<dll>.<function>", "c": <calls>, "how": "stub" | "signature"}],
"sleep_ms", "initializers", "faults": [{"code", "pc"[, "addr"], "handled"[, "by"]}],
"faults_total", "vectored", "notes": [...][, "error"[, "fatal"]]}``

(entry point ``calls``: its API calls, ``pc``/``addr``: where it stopped and the address it could
not access, ``error`` ``unhandled_exception`` with its ``code``: the run ended in the stub's
unhandled-exception filter, which Speakeasy reports as a clean exit; ``how``: ``signature`` = Speakeasy emulated the call from its declaration, ``stub`` =
this file did; ``sleep_ms``: emulated time slept; ``initializers``: C runtime initializers run;
``faults``: the first exceptions dispatched to the stub (ints), ``by``: ``vectored`` | ``seh`` |
``filter`` (the unhandled-exception filter, after which the run ends); ``vectored``: exceptions
handed to vectored handlers; an event ``{"event": "hard_error", "api", "status"[, "text"]}`` per
hard error raised; ``fatal``: ``wall_clock`` | ``cpu_limit`` | ``signal`` | ``exit`` | ``output``)

and one ``region-<n>.bin`` per captured region: the sample's own allocations (Speakeasy tags them
``api.<function>.<base>``) that hold an MZ/PE header, that the sample asked to make executable
(``PAGE_EXECUTE*`` in an allocate/protect call) or that ran code (a dynamic-code segment, or
where a thread started or a run stopped), plus the sample's own image when emulation rewrote at
least ``MODULE_MIN_CHANGED`` bytes of its code or empty sections (an in-place unpacker). Regions
with the same bytes are written once (``copies``), PE-bearing and executed ones first.
Speakeasy's own decoy system modules are never written; their image hashes go to ``decoys`` so
the engine can drop a sample's copy of one. Every count and size is capped.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import select
import signal
import struct
import sys
import threading
import time
from typing import Any

MAX_API_EVENTS = 20_000
MAX_ARGS = 12
MAX_TEXT = 512
MAX_EVENTS = 2_000
MAX_DYNAMIC = 64
MAX_REGIONS = 32
MAX_REGION_BYTES = 64 * 1024 * 1024
MAX_WRITE_BYTES = 256 * 1024 * 1024
MAX_DECOYS = 256
MAX_STUBBED = 256
MAX_NOTES = 16
MAX_FAULTS = 16
MAX_INITIALIZERS = 256  # entries of one _initterm table
MAX_EXEC_REQUESTS = 4096
MAX_PROTECT_BYTES = 1 << 30  # one Nt/ZwProtectVirtualMemory call
MAX_VECTORED = 64  # exceptions handed to the stub's vectored handlers in one run
VECTORED_REPEAT = 4  # ... of them at one instruction and address
MAX_MESSAGES = 8  # hard-error message boxes kept
MAX_RANGE_TRIES = 9999  # Speakeasy's own bound on one search for free address space
MAX_DOC_BYTES = 32 * 1024 * 1024  # what the parent relays (the engine caps stdout at the same size)
MAX_SLEEP_MS = 3_600_000  # one emulated Sleep advances the clocks by at most an hour
MODULE_MIN_CHANGED = 512
GRACE_S = 25.0  # wall seconds past the budget (start-up, report, dumps) before the parent kills the child
CPU_RESERVE_S = 20.0  # CPU seconds of ``ulimit -t`` kept back from the emulation for the same work
WATCHDOG_TICK_S = 0.1
_UC_EXEC = 4  # unicorn UC_PROT_EXEC
_UC_READ, _UC_WRITE = 1, 2
_EVENT_SKIP = frozenset({"api", "mem_read", "mem_write"})


def _text(v: Any) -> str:
    s = v if isinstance(v, str) else str(v)
    return s[:MAX_TEXT]


def pe_image_size(data: bytes, off: int = 0) -> int | None:
    """SizeOfImage of the PE whose MZ header sits at ``off``, or None."""
    try:
        if data[off:off + 2] != b"MZ":
            return None
        (lfanew,) = struct.unpack_from("<I", data, off + 0x3C)
        if lfanew > 0x1000 or data[off + lfanew:off + lfanew + 4] != b"PE\x00\x00":
            return None
        (size,) = struct.unpack_from("<I", data, off + lfanew + 24 + 56)
        return int(size)
    except struct.error:
        return None


def has_pe(data: bytes, page: int = 0x1000) -> bool:
    """An MZ/PE header at the start of ``data`` or of any page in it."""
    for off in range(0, len(data), page):
        if data[off:off + 2] == b"MZ" and pe_image_size(data, off) is not None:
            return True
    return False


def code_spans(data: bytes) -> list[tuple[int, int]]:
    """``(rva, size)`` of the image's executable sections and of sections with no file bytes
    (where an in-place unpacker writes the real code), from a PE's headers; [] if none parse."""
    try:
        (lfanew,) = struct.unpack_from("<I", data, 0x3C)
        nsec, opt = struct.unpack_from("<H", data, lfanew + 6)[0], struct.unpack_from("<H", data, lfanew + 20)[0]
        table = lfanew + 24 + opt
        out = []
        for i in range(min(nsec, 96)):
            vsize, va, raw = struct.unpack_from("<III", data, table + 40 * i + 8)
            (chars,) = struct.unpack_from("<I", data, table + 40 * i + 36)
            if chars & 0x20000000 or raw == 0:
                out.append((va, vsize))
        return out
    except struct.error:
        return []


def changed_bytes(before: bytes, after: bytes, spans: list[tuple[int, int]]) -> int:
    n = 0
    for va, size in spans:
        a, b = before[va:va + size], after[va:va + size]
        n += sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    return n


def prot_text(perms: int) -> str:
    return ("r" if perms & _UC_READ else "-") + ("w" if perms & _UC_WRITE else "-") + ("x" if perms & _UC_EXEC else "-")


def _perms_at(regions: list[tuple[int, int, int]], base: int, size: int) -> int:
    """OR of unicorn permissions over the pages of ``[base, base + size)``."""
    out = 0
    for begin, end, perms in regions:
        if begin < base + size and end >= base:
            out |= perms
    return out


class _Writer:
    def __init__(self, outdir: str) -> None:
        self.outdir = outdir
        self.used = 0
        self.n = 0

    def write(self, data: bytes) -> str | None:
        data = data[:MAX_REGION_BYTES]
        if self.n >= MAX_REGIONS or self.used + len(data) > MAX_WRITE_BYTES:
            return None
        name = f"region-{self.n}.bin"
        fd = os.open(os.path.join(self.outdir, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.n += 1
        self.used += len(data)
        return name


_ALLOC = ("VirtualAlloc", "VirtualAllocEx")
_PROTECT = {"VirtualProtect": 0, "VirtualProtectEx": 1}


def _int(text: Any) -> int | None:
    try:
        return int(str(text), 16) if str(text).lower().startswith("0x") else int(str(text))
    except ValueError:
        return None


def exec_request(name: str, args: list[dict[str, Any]], ret: Any) -> tuple[int, str] | None:
    """``(address, protection)`` when this call asked for executable memory, else None:
    VirtualAlloc(Ex) returns the address, VirtualProtect(Ex) takes it as an argument."""
    fn = name.rsplit(".", 1)[-1]
    prot = next((str(a.get("display", "")) for a in args if "PAGE_EXECUTE" in str(a.get("display", ""))), None)
    if prot is None:
        return None
    if fn in _ALLOC:
        addr = _int(ret) if ret is not None else None
    elif fn in _PROTECT and len(args) > _PROTECT[fn]:
        addr = _int(args[_PROTECT[fn]].get("display", ""))
    else:
        return None
    return (addr, prot[:64]) if addr else None


def _api_events(report: dict[str, Any]) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]], list[tuple[int, str]]]:
    apis: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    execs: list[tuple[int, str]] = []
    total = 0
    for ep in report.get("entry_points") or []:
        for ev in ep.get("events") or []:
            kind = ev.get("event")
            if kind == "api":
                total += 1
                req = exec_request(str(ev.get("api_name", "")), ev.get("args") or [], ev.get("ret_val"))
                if req is not None and len(execs) < MAX_API_EVENTS:
                    execs.append(req)
                if len(apis) < MAX_API_EVENTS:
                    args = [[_text(a.get("type", "")), _text(a.get("display", ""))] for a in (ev.get("args") or [])[:MAX_ARGS]]
                    apis.append({"n": _text(ev.get("api_name", "")), "a": args})
            elif kind not in _EVENT_SKIP and len(events) < MAX_EVENTS:
                row = {k: _text(v) for k, v in ev.items() if k not in ("pos", "pid", "tid") and isinstance(v, (str, int))
                       and not isinstance(v, bool)}
                events.append(row)
    return apis, total, events, execs


# ------------------------------------------------------------------ assists

_CRT_PREFIXES = ("msvcrt", "msvcr", "msvcp", "ucrtbase", "vcruntime", "api-ms-win-crt-", "crtdll")
# Calls where "it worked" would be a lie the stub then acts on: the file is not there.
_RETURNS = {"_access": -1, "_waccess": -1, "_access_s": 2, "_waccess_s": 2}  # -1 / ENOENT
_RETURNS_ARG0 = frozenset({"_onexit", "__dllonexit", "_onexit_m"})  # return the registered function
# The C runtime's ``__p_<global>()`` accessors return the address of a global. These globals hold a
# pointer (to a string or to a NULL-terminated array of strings); the others hold a number.
_POINTER_GLOBALS = frozenset({"environ", "wenviron", "pgmptr", "wpgmptr", "acmdln", "wcmdln", "_argv", "_wargv",
                              "_initenv", "_winitenv", "tzname"})
NULL_PARTITION = 0x10000  # Windows never maps the first 64 KiB: a "pointer" below it is an ordinal or an atom


# Windows PAGE_* protection (low byte) -> unicorn permissions. x86 has no execute-only and no
# write-only pages: PAGE_EXECUTE is readable.
_PAGE_PERMS = {0x01: 0, 0x02: _UC_READ, 0x04: _UC_READ | _UC_WRITE, 0x08: _UC_READ | _UC_WRITE,
               0x10: _UC_READ | _UC_EXEC, 0x20: _UC_READ | _UC_EXEC, 0x40: _UC_READ | _UC_WRITE | _UC_EXEC,
               0x80: _UC_READ | _UC_WRITE | _UC_EXEC}
_PAGE_NAMES = {0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ", 0x40: "PAGE_EXECUTE_READWRITE",
               0x80: "PAGE_EXECUTE_WRITECOPY"}


def page_perms(protect: int) -> int | None:
    """unicorn permissions for a Windows ``PAGE_*`` protection (modifier bits such as PAGE_GUARD
    are ignored), or None for a value that names no protection."""
    return _PAGE_PERMS.get(protect & 0xFF)


def page_protect(perms: int) -> int:
    """The Windows ``PAGE_*`` protection for unicorn permissions (what a protect call reports as
    the old protection)."""
    if perms & _UC_EXEC:
        return 0x40 if perms & _UC_WRITE else 0x20
    if perms & _UC_WRITE:
        return 0x04
    return 0x02 if perms & _UC_READ else 0x01


def free_range(spans: list[tuple[int, int]], size: int, addr: int, page: int = 0x1000) -> tuple[int, int]:
    """(base, length) of the first free page-aligned range Speakeasy's allocator would pick for
    ``size`` bytes at or after ``addr``, given the occupied ``[start, end)`` spans."""
    total = max(page, -(-size // page) * page)
    base = addr - addr % page
    spans = sorted(spans)
    starts = [s for s, _ in spans]
    reach: list[int] = []  # the furthest end among the spans up to each one
    for _, end in spans:
        reach.append(max(end, reach[-1]) if reach else end)
    for attempt in range(MAX_RANGE_TRIES, 0, -1):
        i = bisect.bisect_left(starts, base + total)
        if i == 0 or reach[i - 1] <= base:
            return base, total
        base += page * 1000 if not attempt % 10 else total
    raise MemoryError("no free address range")


def exception_record(code: int, pc: int, width: int, info: tuple[int, ...] = ()) -> bytes:
    """An ``EXCEPTION_RECORD`` (Speakeasy's own has 32-bit information slots on x64)."""
    info = tuple(info[:15])
    slots = info + (0,) * (15 - len(info))
    mask = (1 << 8 * width) - 1
    if width == 8:
        return struct.pack("<IIQQI4x15Q", code & 0xFFFFFFFF, 0, 0, pc & mask, len(info), *(v & mask for v in slots))
    return struct.pack("<IIIII15I", code & 0xFFFFFFFF, 0, 0, pc & mask, len(info), *(v & mask for v in slots))


def is_crt(dll: str) -> bool:
    """A C runtime DLL: its functions are cdecl (the caller pops the arguments on x86)."""
    return dll.lower().startswith(_CRT_PREFIXES)


def stub_global(dll: str, name: str) -> str | None:
    """For a C runtime accessor ``__p_<global>``: ``"pointer"`` when the global holds a pointer
    (the stub then answers with storage whose value points at an empty, NULL-terminated table
    rather than NULL, which the CRT start-up code dereferences), ``"number"`` when it holds a
    number (zeroed storage). None for every other function."""
    if not is_crt(dll) or not name.startswith("__p_"):
        return None
    return "pointer" if name[4:].lstrip("_") in {g.lstrip("_") for g in _POINTER_GLOBALS} else "number"


def stub_return(dll: str, name: str, argv: list[int], declared: int | None = None) -> int | None:
    """What a stubbed API returns: a per-function answer where one is known, else the value its
    declaration implies (``declared``), else 0 for the C runtime and Nt*/Zw* (success) and 1
    (TRUE) for everything else."""
    fn = name.lower()
    if fn in _RETURNS:
        return _RETURNS[fn] & 0xFFFFFFFF
    if fn in _RETURNS_ARG0:
        return argv[0] if argv else 0
    if declared is not None:
        return declared
    if is_crt(dll) or name[:2] in ("Nt", "Zw") or name[:3] == "Rtl":
        return 0
    return 1


class _Assist:
    """The changes made to one loaded Speakeasy emulator (see the module docstring). Each
    ``install_*`` is independent; one that fails is named in ``notes`` and the run goes on
    without it."""

    def __init__(self, se: Any) -> None:
        self.se = se
        self.emu = se.emu
        self.eng = self.emu.emu_eng
        self.stubbed: dict[str, list[Any]] = {}  # "<dll>.<fn>" -> [calls, how], first-call order
        self.sleep_ms = 0
        self.initializers = 0
        self.faults: list[dict[str, Any]] = []
        self.faults_total = 0
        self.execs: list[tuple[int, str]] = []  # (address, PAGE_EXECUTE*) asked for through Nt* calls
        self.vectored = 0  # exceptions handed to the stub's vectored handlers
        self.messages: list[dict[str, str]] = []  # hard errors the stub raised (a message box)
        # (run type, start address) -> the exception that ended it in the unhandled-exception filter
        self.unhandled: dict[tuple[str, int], dict[str, int]] = {}
        self._veh: dict[str, Any] | None = None  # the one being handled
        self._veh_last: tuple[Any, int] = (None, 0)
        self.notes: list[str] = []
        self._deadline: float | None = None
        self._resolving = 0
        self._cursor = 0

    def install(self) -> None:
        for name, fn in (("low_memory", self.install_low_memory), ("stubs", self.install_stubs),
                         ("waits", self.install_waits), ("protect", self.install_protect),
                         ("hard_error", self.install_hard_error),
                         ("initializers", self.install_initializers), ("faults", self.install_faults),
                         ("timer", self.install_timer), ("code_hook", self.install_code_hook)):
            try:
                fn()
            except Exception as exc:
                if len(self.notes) < MAX_NOTES:
                    self.notes.append(f"{name}: {type(exc).__name__}")

    def note(self, text: str) -> None:
        if len(self.notes) < MAX_NOTES and text not in self.notes:
            self.notes.append(text)

    def _count(self, api: str, how: str) -> None:
        row = self.stubbed.get(api)
        if row is not None:
            row[0] += 1
        elif len(self.stubbed) < MAX_STUBBED:
            self.stubbed[api] = [1, how]

    # -- the null partition

    def install_low_memory(self) -> None:
        """Keep new allocations out of the first 64 KiB. Speakeasy hands out heap chunks from
        0x1000 up, and Windows APIs read a "pointer" below 0x10000 as an integer: GetProcAddress
        took a heap-allocated name for an ordinal, returned NULL, and the stub called it."""
        emu = self.emu
        page = int(emu.page_size)

        def get_valid_ranges(size: int, addr: Any = None) -> tuple[int, int]:
            # Speakeasy's search, with its steps and its bound, over intervals: its own builds a
            # list of every mapped page and walks it once per step, which on a stub that allocates
            # in a loop took four fifths of the whole time budget.
            spans = [(int(b), int(e) + 1) for b, e, _ in emu.get_mem_regions()]
            spans += [(int(r.base), int(r.base) + int(r.size)) for r in emu.mem_reserves]
            base, total = free_range(spans, int(size), NULL_PARTITION if addr is None else int(addr), page)
            return base, total

        emu.get_valid_ranges = get_valid_ranges
        if 0 < int(emu.block_base) < NULL_PARTITION:
            emu.block_base = 0  # the next small allocation starts a new block above the partition

    # -- unsupported APIs

    def _has_handler(self, dll: str, name: str) -> bool:
        emu = self.emu
        if emu.api.get_export_func_handler(dll, name)[1]:
            return True
        return bool(emu.normalize_import_miss(dll, name)[1])

    def _stub_hook(self, dll: str, name: str) -> Any:
        """An ApiHook that stands in for ``dll.name``. Speakeasy takes the convention and the
        argument count of an API it has no handler for from the hook."""
        from speakeasy import common  # type: ignore[import-not-found]
        from speakeasy.winenv import arch  # type: ignore[import-not-found]

        emu, api = self.emu, f"{dll}.{name}"
        conv, argc, declared = None, 4, None
        try:
            decl = emu._lookup_api_declaration(dll, name)
        except Exception:
            decl = None
        if decl is not None:
            try:
                n = int(decl.slot_count(emu.get_ptr_size()))
                if decl.conv in ("cdecl", "stdcall") and 0 <= n <= 32:
                    conv = arch.CALL_CONV_CDECL if decl.conv == "cdecl" else arch.CALL_CONV_STDCALL
                    argc = n
                declared = emu._default_return_for_signature(decl)
            except Exception:
                conv, argc, declared = None, 4, None
        if conv is None:
            # No usable declaration: the argument count is unknown, so nothing is popped (right
            # for the C runtime and for x64, and the lesser error for an x86 stdcall function).
            conv = arch.CALL_CONV_CDECL

        kind, storage = stub_global(dll, name), [0]

        def cb(_emu: Any, _api: str, _orig: Any, argv: list[int]) -> int | None:
            self._count(api, "stub")
            if kind is not None:
                if not storage[0]:
                    width = int(emu.get_ptr_size())
                    storage[0] = int(emu.mem_map(8 * width, tag=f"emu.stub.{name[:64]}"))
                    cell = storage[0] + width if kind == "pointer" else 0
                    emu.mem_write(storage[0], cell.to_bytes(width, "little") + bytes(7 * width))
                return storage[0]
            return stub_return(dll, name, argv, declared)

        return common.ApiHook(emu, self.eng, cb, dll.lower(), name.lower(), argc, conv)

    def install_stubs(self) -> None:
        emu = self.emu
        hooks_of, resolve, from_sig = emu.get_api_hooks, emu.resolve_export, emu.emulate_api_from_signature
        cache: dict[tuple[str, str], list[Any]] = {}

        def resolve_export(*args: Any, **kw: Any) -> Any:
            # GetProcAddress asks for hooks to decide whether a name exists: a stub must not make
            # an export exist that Windows does not have (a probe for wine_get_version).
            self._resolving += 1
            try:
                return resolve(*args, **kw)
            finally:
                self._resolving -= 1

        def get_api_hooks(mod_name: str, func_name: str) -> list[Any]:
            hooks = hooks_of(mod_name, func_name)
            if hooks or self._resolving:
                return list(hooks)
            key = (str(mod_name).lower(), str(func_name))
            made = cache.get(key)
            if made is None:
                made = []
                try:
                    if not self._has_handler(mod_name, func_name) and emu.lookup_api_signature(
                            mod_name, func_name) is None:
                        made = [self._stub_hook(mod_name, func_name)]
                except Exception:
                    made = []
                if len(cache) < 65536:
                    cache[key] = made
            return made

        def emulate_api_from_signature(dll: str, name: str, *args: Any, **kw: Any) -> Any:
            self._count(f"{dll}.{name}", "signature")
            return from_sig(dll, name, *args, **kw)

        emu.resolve_export = resolve_export
        emu.get_api_hooks = get_api_hooks
        emu.emulate_api_from_signature = emulate_api_from_signature

    # -- waits a stub commonly sits in

    def install_waits(self) -> None:
        emu, se = self.emu, self.se
        k32 = emu.api.get_export_func_handler("kernel32", "Sleep")[0]
        current = (1 << 8 * int(emu.get_ptr_size())) - 1  # GetCurrentProcess()

        def sleep(_emu: Any, _api: str, orig: Any, argv: list[int]) -> Any:
            rv = orig(argv) if orig is not None else None
            ms = (argv[0] if argv else 0) & 0xFFFFFFFF
            ms = min(1000 if ms == 0xFFFFFFFF else ms, MAX_SLEEP_MS)
            self.sleep_ms = min(self.sleep_ms + ms, 1 << 62)
            if k32 is not None:  # the clocks GetTickCount(64) and QueryPerformanceCounter read
                k32.tick_counter = (int(k32.tick_counter) + ms) & 0xFFFFFFFFFFFFFFFF
                k32.perf_counter = (int(k32.perf_counter) + ms * 10_000) & 0x7FFFFFFFFFFFFFFF
            return rv

        def cursor(_emu: Any, _api: str, orig: Any, argv: list[int]) -> int:
            if orig is not None:
                orig(argv)
            self._cursor += 1
            x, y = 400 + self._cursor * 37 % 500, 300 + self._cursor * 23 % 300
            try:
                emu.mem_write(argv[0], struct.pack("<ii", x, y))
            except Exception:
                return 0
            return 1

        def process_id(_emu: Any, _api: str, _orig: Any, argv: list[int]) -> int:
            # No Speakeasy handler: its signature stub answered 0 for the stub's own process while
            # GetCurrentProcessId answered the id, and a loader that compares the two saw the lie.
            handle = argv[0] if argv else 0
            if handle & current == current:
                return int(emu.get_current_process().id)
            try:
                return int(emu.get_object_from_handle(handle).id)
            except Exception:
                return 0

        se.add_api_hook(process_id, "kernel32", "GetProcessId", argc=1)
        se.add_api_hook(sleep, "kernel32", "Sleep", argc=1)
        se.add_api_hook(sleep, "kernel32", "SleepEx", argc=2)
        se.add_api_hook(cursor, "user32", "GetCursorPos", argc=1)

    # -- Nt/ZwProtectVirtualMemory and Nt/ZwAllocateVirtualMemory

    def install_protect(self) -> None:
        """Speakeasy's ``ZwProtectVirtualMemory`` answers success and changes nothing: a packer
        that makes its own sections writable that way faulted on its first write to them. Apply
        the protection (this process only), and note executable requests made through the Nt
        calls, whose addresses are behind pointers the API log does not show."""
        emu, se, uc = self.emu, self.se, self.eng.emu
        width = int(emu.get_ptr_size())
        current = (1 << 8 * width) - 1  # NtCurrentProcess()

        def read(addr: int) -> int:
            return int.from_bytes(emu.mem_read(addr, width), "little")

        def asked(addr: int, protect: int) -> None:
            name = _PAGE_NAMES.get(protect & 0xF0)
            if name is not None and addr and len(self.execs) < MAX_EXEC_REQUESTS:
                self.execs.append((addr, name))

        def protect(_emu: Any, _api: str, orig: Any, argv: list[int]) -> Any:
            rv = orig(argv) if orig is not None else 0
            handle, p_base, p_size, new, p_old = (list(argv) + [0] * 5)[:5]
            perms = page_perms(new)
            if handle & current != current or not p_base or not p_size or perms is None:
                return rv
            try:
                base, size = read(p_base), read(p_size)
                start, end = base & ~0xFFF, (base + size + 0xFFF) & ~0xFFF
                if not 0 < end - start <= MAX_PROTECT_BYTES:
                    return rv
                old = _perms_at([(int(b), int(e), int(p)) for b, e, p in emu.get_mem_regions()], start, 1)
                uc.mem_protect(start, end - start, perms)
                if p_old:
                    emu.mem_write(p_old, page_protect(old).to_bytes(4, "little"))
                asked(base, new)
            except Exception:
                pass  # an unmapped range: the call stays the no-op Speakeasy made it
            return rv

        def allocate(_emu: Any, _api: str, orig: Any, argv: list[int]) -> Any:
            rv = orig(argv) if orig is not None else 0
            if len(argv) >= 6 and argv[1] and not rv:
                try:
                    asked(read(argv[1]), argv[5])
                except Exception:
                    pass
            return rv

        for prefix in ("Nt", "Zw"):
            se.add_api_hook(protect, "*", f"{prefix}ProtectVirtualMemory", argc=5)
            se.add_api_hook(allocate, "*", f"{prefix}AllocateVirtualMemory", argc=6)

    # -- Nt/ZwRaiseHardError

    def install_hard_error(self) -> None:
        """A protector that refuses to run says why in a hard-error message box
        (``NtRaiseHardError``) and exits. Speakeasy has no handler, so the text was lost behind
        pointers. Keep the strings (``hard_error`` events) and answer "OK"."""
        emu, se = self.emu, self.se
        width = int(emu.get_ptr_size())

        def text(p_string: int) -> str:
            head = bytes(emu.mem_read(p_string, 2 * width))  # UNICODE_STRING {Length, MaximumLength, Buffer}
            length = min(int.from_bytes(head[:2], "little"), 2 * MAX_TEXT)
            buffer = int.from_bytes(head[width:2 * width], "little")
            return bytes(emu.mem_read(buffer, length)).decode("utf-16-le", "replace") if buffer and length else ""

        def hard_error(_emu: Any, api: str, _orig: Any, argv: list[int]) -> int:
            status, count, mask, params, _options, p_response = (list(argv) + [0] * 6)[:6]
            row = {"event": "hard_error", "api": _text(api), "status": f"{status & 0xFFFFFFFF:#x}"}
            texts = []
            for i in range(min(count, 4)):
                if not params or not mask >> i & 1:
                    continue
                try:
                    found = text(int.from_bytes(emu.mem_read(params + i * width, width), "little"))
                except Exception:
                    continue
                if found.strip():
                    texts.append(" ".join(found.split())[:MAX_TEXT])
            if texts:
                row["text"] = " | ".join(texts)[:MAX_TEXT]
            if len(self.messages) < MAX_MESSAGES:
                self.messages.append(row)
            try:
                if p_response:
                    emu.mem_write(p_response, (6).to_bytes(4, "little"))  # ResponseOk
            except Exception:
                pass
            return 0

        for prefix in ("Nt", "Zw"):
            se.add_api_hook(hard_error, "ntdll", f"{prefix}RaiseHardError", argc=6)

    # -- the C runtime's initializer tables

    def install_initializers(self) -> None:
        """Speakeasy's ``_initterm`` / ``_initterm_e`` return without calling the table's
        functions, so a stub linked against a CRT DLL never ran its C/C++ initializers (mingw
        fetches argc/argv in one: ``main`` then got a NULL ``argv`` and faulted). Call them, in
        table order, as guest callbacks of the API call."""
        from speakeasy.winenv import arch  # type: ignore[import-not-found]

        emu, se = self.emu, self.se
        width = int(emu.get_ptr_size())

        def initterm(_emu: Any, api: str, orig: Any, argv: list[int]) -> Any:
            rv = orig(argv) if orig is not None else 0
            first, last = (argv + [0, 0])[:2]
            n = (last - first) // width
            if not 0 < n <= MAX_INITIALIZERS:
                return rv
            dll, _, fn = api.rpartition(".")
            handler = emu.api.get_export_func_handler(dll, fn)[0] or emu.normalize_import_miss(dll, fn)[0]
            if handler is None:
                return rv
            try:
                table = bytes(emu.mem_read(first, n * width))
            except Exception:
                return rv
            for i in range(n):
                target = int.from_bytes(table[i * width:(i + 1) * width], "little")
                if target and emu.is_address_valid(target):
                    handler.setup_callback(target, ())
                    self.initializers += 1
            return rv

        for name in ("_initterm", "_initterm_e"):
            se.add_api_hook(initterm, "*", name, argc=2, call_conv=arch.CALL_CONV_CDECL)

    # -- faults: a run that "exits" after one did not finish

    def install_faults(self) -> None:
        """Record every exception Speakeasy dispatches to the stub's handlers. With no handler it
        calls the stub's unhandled-exception filter and ends the run when that returns, which the
        report shows as a clean exit.

        And call the stub's vectored handlers first, as Windows does. Speakeasy keeps the list
        ``AddVectoredExceptionHandler`` builds and never calls an entry, and a read of a page the
        stub made PAGE_NOACCESS is no fault it handles: a loader that does its work in a vectored
        handler it triggers on purpose stopped at the trigger. EXCEPTION_CONTINUE_EXECUTION
        resumes with the context the handler left; EXCEPTION_CONTINUE_SEARCH tries the next
        handler and then what Speakeasy did before."""
        from speakeasy import common
        from speakeasy.winenv import arch

        emu, eng = self.emu, self.eng
        dispatch = emu.dispatch_seh
        unmapped = emu._hook_mem_unmapped
        width = int(emu.get_ptr_size())
        violation = 0xC0000005
        kinds = {common.INVALID_MEM_READ: 0, common.INVAL_PERM_MEM_READ: 0, common.INVALID_MEM_WRITE: 1,
                 common.INVAL_PERM_MEM_WRITE: 1, common.INVALID_MEM_EXEC: 8, common.INVAL_PERM_MEM_EXEC: 8}
        access: list[int] = [0]  # the kind of the access being handled
        landing: list[int] = []  # where a vectored handler returns to: one hooked instruction

        def call(state: dict[str, Any]) -> None:
            if not landing:
                landing.append(int(emu.mem_map(emu.page_size, tag="emu.struct.VECTORED_RETURN")))
                emu.mem_write(landing[0], b"\x0f\x0b")  # ud2, should the hook not take over
                emu.add_code_hook(landed, begin=landing[0], end=landing[0])
            handler = state["rest"].pop(0)
            sp = (state["sp"] - 0x400) & ~0xF  # below the interrupted frame and its red tape
            emu.set_func_args(sp, landing[0], state["pointers"], conv=arch.CALL_CONV_STDCALL)
            emu.set_pc(handler)

        def begin(code: int, address: Any) -> bool:
            handlers = [int(h) for h in emu.veh_handlers if h]
            if not handlers or self._veh is not None or self.vectored >= MAX_VECTORED:
                return False
            pc = int(emu.get_pc())
            key = (pc, address)
            seen = self._veh_last[1] + 1 if self._veh_last[0] == key else 1
            self._veh_last = (key, seen)
            if seen > VECTORED_REPEAT:  # no handler took it, or the one that did changed nothing
                return False
            info = (access[0], address) if code == violation and isinstance(address, int) else ()
            record = exception_record(code, pc, width, info)
            ctx = emu.get_thread_context()
            raw = ctx.get_bytes()
            base = int(emu.mem_map(2 * width + len(record) + len(raw), tag="emu.struct.VECTORED_EXCEPTION"))
            p_record, p_ctx = base + 2 * width, base + 2 * width + len(record)
            emu.mem_write(base, p_record.to_bytes(width, "little") + p_ctx.to_bytes(width, "little"))
            emu.mem_write(p_record, record)
            emu.mem_write(p_ctx, raw)
            state = {"rest": handlers, "pointers": base, "ctx": p_ctx, "saved": raw, "code": code,
                     "address": address, "sp": int(emu.get_stack_ptr())}
            call(state)
            self._veh = state
            self.vectored += 1
            return True

        def resume(state: dict[str, Any], raw: bytes) -> None:
            ctx = emu.get_thread_context()
            ctx.cast(raw)
            emu.load_thread_context(ctx)

        def landed(_se: Any, _addr: int, _size: int) -> bool:
            state, self._veh = self._veh, None
            if state is None:
                return True
            try:
                if int(emu.get_return_val()) & 0xFFFFFFFF == 0xFFFFFFFF:  # EXCEPTION_CONTINUE_EXECUTION
                    resume(state, bytes(emu.mem_read(state["ctx"], len(state["saved"]))))
                elif state["rest"]:  # EXCEPTION_CONTINUE_SEARCH
                    call(state)
                    self._veh = state
                else:  # nobody took it: the instruction faults again, and Speakeasy answers this time
                    self._veh_last = (self._veh_last[0], VECTORED_REPEAT)
                    resume(state, state["saved"])
            except Exception as exc:
                self.note(f"vectored: {type(exc).__name__}")
            return True

        def dispatch_seh(except_code: int, faulting_address: Any = None) -> Any:
            self.faults_total += 1
            row: dict[str, Any] | None = None
            pc = int(emu.get_pc())  # before a handler is entered
            if len(self.faults) < MAX_FAULTS:
                row = {"code": int(except_code) & 0xFFFFFFFF, "pc": pc}
                if isinstance(faulting_address, int):
                    row["addr"] = faulting_address
                self.faults.append(row)
            handled: Any = False
            by = "vectored"
            try:
                handled = begin(int(except_code), faulting_address)
            except Exception as exc:
                self._veh = None
                self.note(f"vectored: {type(exc).__name__}")
            if handled:
                if isinstance(faulting_address, int) and not protected[0]:
                    emu._map_faulting_page_for_exception(faulting_address)
            else:
                last_resort = emu.unhandled_exception_filter
                handled = dispatch(except_code, faulting_address)
                by = "filter" if last_resort and not emu.unhandled_exception_filter else "seh"
            if row is not None:
                row["handled"] = bool(handled)
                if handled:
                    row["by"] = by
            if handled and by == "filter" and len(self.unhandled) < MAX_FAULTS:
                run = getattr(emu, "curr_run", None)
                lost = {"code": int(except_code) & 0xFFFFFFFF, "pc": pc}
                if isinstance(faulting_address, int):
                    lost["addr"] = faulting_address
                self.unhandled[(str(getattr(run, "type", "")), int(getattr(run, "start_addr", 0) or 0))] = lost
            return handled

        protected: list[bool] = [False]  # the access being handled hit a mapped, protected page

        def hook_mem_unmapped(se: Any, kind: int, address: int, size: int, value: int) -> Any:
            what = eng.mem_access.get(kind)
            access[0] = kinds.get(what, 0)
            if what in (common.INVAL_PERM_MEM_READ, common.INVAL_PERM_MEM_WRITE) and emu.veh_handlers:
                # Speakeasy ends the run on a protected write and has no answer to a protected read.
                protected[0] = True
                try:
                    emu.prev_pc = emu.get_pc()
                    if dispatch_seh(violation, address):
                        return True
                finally:
                    protected[0] = False
            return unmapped(se, kind, address, size, value)

        emu.dispatch_seh = dispatch_seh
        emu._hook_mem_unmapped = hook_mem_unmapped

    # -- the time budget, without unicorn's busy timer thread

    def install_timer(self) -> None:
        eng = self.eng
        start = eng.start

        def run(addr: int, timeout: float = 0, count: int = 0) -> Any:
            self._deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
            try:
                return start(addr, timeout=0, count=count)
            finally:
                self._deadline = None

        def watchdog() -> None:
            while True:
                time.sleep(WATCHDOG_TICK_S)
                deadline = self._deadline
                # Repeated every tick: a stop that lands between two bursts is forgotten by unicorn.
                if deadline is not None and time.monotonic() >= deadline:
                    try:
                        eng.stop()
                    except Exception:
                        pass

        threading.Thread(target=watchdog, daemon=True).start()
        eng.start = run

    # -- Speakeasy's transient per-instruction hook

    def install_code_hook(self) -> None:
        from speakeasy import common

        emu, eng = self.emu, self.eng
        flush = eng.emu.ctl_flush_tb  # translated blocks keep (or lack) the hook call: retranslate
        callbacks = eng._callbacks
        keep: list[Any] = []  # the ctypes thunks of removed hooks, while unicorn may still call them

        def enable_code_hook() -> None:
            hook = emu.tmp_code_hook
            if not hook:
                emu.tmp_code_hook = hook = emu.add_code_hook(cb=emu._hook_code_core)
                flush()
            elif not hook.handle:
                hook.handle = eng.hook_add(htype=common.HOOK_CODE, cb=hook._wrap_code_cb, begin=hook.begin,
                                           end=hook.end)
                flush()
            hook.enabled = True

        def disable_code_hook() -> None:
            hook = emu.tmp_code_hook
            if not hook:
                return
            hook.enabled = False
            if hook.handle:
                keep.append(callbacks.get(hook.handle))
                del keep[:-8]
                eng.hook_remove(hook.handle)
                hook.handle = 0

        emu.enable_code_hook = enable_code_hook
        emu.disable_code_hook = disable_code_hook


def cpu_budget(budget_s: float, cpu_limit: float | None, cpu_used: float) -> float:
    """``budget_s`` cut to what ``ulimit -t`` leaves once ``CPU_RESERVE_S`` is kept for the work
    around the emulation (never under a second): the run then ends on its own budget, with a
    document, rather than on SIGKILL."""
    if cpu_limit is None:
        return budget_s
    return max(1.0, min(budget_s, cpu_limit - cpu_used - CPU_RESERVE_S))


def _cpu_limit() -> float | None:
    try:
        import resource

        soft = resource.getrlimit(resource.RLIMIT_CPU)[0]
    except (ImportError, OSError, ValueError):
        return None
    return None if soft == resource.RLIM_INFINITY or soft < 0 else float(soft)


def emulate(sample: str, outdir: str, budget_s: float, max_api: int, max_insn: int) -> dict[str, Any]:
    import speakeasy  # type: ignore[import-not-found]  # the Speakeasy venv only
    from speakeasy.config import get_default_config_dict  # type: ignore[import-not-found]

    budget_s = cpu_budget(budget_s, _cpu_limit(), time.process_time())
    cfg = get_default_config_dict()
    cfg["timeout"] = budget_s
    cfg["max_total_time"] = budget_s
    cfg["max_api_count"] = max_api
    cfg["max_instructions"] = max_insn
    cfg["keep_memory_on_free"] = True  # a stage freed after use is still captured
    cfg["analysis"] = {"memory_tracing": False, "strings": False, "coverage": False}

    with open(sample, "rb") as f:
        data = f.read()
    is_dll = False
    try:
        (lfanew,) = struct.unpack_from("<I", data, 0x3C)
        (chars,) = struct.unpack_from("<H", data, lfanew + 22)
        is_dll = bool(chars & 0x2000)
    except struct.error:
        pass

    if not is_dll:
        # Speakeasy's default is "svchost.exe myarg1 myarg2": a stub that reads its arguments
        # would act on two it was never given. An EXE runs as itself, without arguments.
        cfg["command_line"] = "sample.exe"

    out: dict[str, Any] = {"arch": None, "dll": is_dll, "entry_points": [], "apis": [], "apis_total": 0, "events": [],
                           "dynamic_code": [], "regions": [], "regions_skipped": {"duplicate": 0, "capped": 0},
                           "decoys": [], "module": None, "stubbed": [], "sleep_ms": 0, "initializers": 0,
                           "faults": [], "faults_total": 0, "vectored": 0, "notes": []}
    se = speakeasy.Speakeasy(config=cfg)
    # Bytes, not a path: Speakeasy auto-mounts a target's directory into the emulated file system.
    module = se.load_module(data=data, filename="sample.dll" if is_dll else "sample.exe")
    mod_base, mod_size = int(module.base), int(module.image_size)
    before = se.mem_read(mod_base, mod_size)
    assist = _Assist(se)
    assist.install()
    try:
        se.run_module(module, all_entrypoints=is_dll)
    except Exception as exc:  # partial results still go out
        out["error"] = f"{type(exc).__name__}: {_text(exc)[:200]}"
    out["stubbed"] = [{"n": _text(n), "c": c, "how": how} for n, (c, how) in assist.stubbed.items()]
    out["sleep_ms"] = assist.sleep_ms
    out["initializers"] = assist.initializers
    out["faults"], out["faults_total"] = assist.faults, assist.faults_total
    out["vectored"] = assist.vectored
    out["notes"] = assist.notes
    try:
        report = json.loads(se.get_report().model_dump_json())
    except Exception as exc:
        out["error"] = out.get("error") or f"report: {type(exc).__name__}"
        report = {}
    out["arch"] = report.get("arch")
    for ep in report.get("entry_points") or []:
        err = ep.get("error") or {}
        row = {"type": _text(ep.get("ep_type", "")), "error": _text(err["type"]) if err.get("type") else None,
               "calls": sum(1 for ev in ep.get("events") or [] if ev.get("event") == "api")}
        if err.get("api_name"):
            row["api"] = _text(err["api_name"])
        for key, short in (("pc", "pc"), ("address", "addr")):
            at = _int(err.get(key)) if err.get(key) is not None else None
            if at is not None:
                row[short] = at
        lost = assist.unhandled.get((str(ep.get("ep_type", "")), _int(ep.get("start_addr")) or 0))
        if row["error"] is None and lost is not None:
            # Speakeasy ran the stub's unhandled-exception filter and reported a clean exit.
            row.update(lost, error="unhandled_exception")
        out["entry_points"].append(row)
        for seg in ep.get("dynamic_code_segments") or []:
            if len(out["dynamic_code"]) < MAX_DYNAMIC:
                out["dynamic_code"].append({"tag": _text(seg.get("tag", "")), "base": _text(seg.get("base", "")),
                                            "size": _text(seg.get("size", ""))})
    out["apis"], out["apis_total"], out["events"], execs = _api_events(report)
    out["events"].extend(assist.messages)
    execs.extend(assist.execs)

    executed = []
    for seg in out["dynamic_code"]:
        try:
            executed.append((int(seg["base"], 16), int(seg["size"], 16)))
        except ValueError:
            continue
    # Where a run started or stopped: a stage mapped as a section and started as a thread is in
    # no dynamic-code segment (Speakeasy follows VirtualAlloc/VirtualProtect memory only).
    started: list[tuple[int, int]] = []
    for ep in report.get("entry_points") or []:
        err = ep.get("error") if isinstance(ep.get("error"), dict) else {}
        for at in (_int(ep.get("start_addr")), _int(err.get("pc"))):
            if at:
                started.append((at, 1))
    try:
        uc_regions = [(int(b), int(e), int(p)) for b, e, p in se.emu.get_mem_regions()]
    except Exception:
        uc_regions = []
    allocs: dict[int, int] = {}  # base -> the size the sample asked for (mem_alloc events)
    for ev in out["events"]:
        if ev.get("event") == "mem_alloc":
            b, n = _int(ev.get("base", "")), _int(ev.get("size", ""))
            if b and n:
                allocs.setdefault(b, n)
    writer = _Writer(outdir)
    self_tag = f"emu.module.{getattr(module, 'name', '')}."
    # One candidate per distinct content: a stub that fills a buffer hundreds of times must not
    # use up the region cap with copies. [rank, order, base, size, tag, asked, ran, copies]
    found: dict[bytes, list[Any]] = {}
    for mm in se.get_mem_maps():
        tag = str(mm.tag or "")
        base, size = int(mm.base), int(mm.size)
        if tag.startswith("emu.module.") and not tag.startswith(self_tag) and base != mod_base:
            if len(out["decoys"]) < MAX_DECOYS:
                try:
                    img = se.mem_read(base, size)
                except Exception:
                    continue
                n = pe_image_size(img)
                out["decoys"].append({"name": _text(tag.split(".")[2] if tag.count(".") >= 2 else tag),
                                      "sha256": hashlib.sha256(img[:n] if n else img).hexdigest()})
            continue
        if not tag.startswith("api."):
            continue
        try:
            blob = se.mem_read(base, min(size, MAX_REGION_BYTES))
        except Exception:
            continue
        # Speakeasy maps most of its own buffers RWX, so "executable" means the sample asked for it.
        asked = [p for a, p in execs if base <= a < base + size]
        ran = any(b < base + size and b + s > base for b, s in executed + started)
        pe = has_pe(blob)
        if not (asked or ran or pe):
            continue
        digest = hashlib.sha256(blob).digest()
        cand = found.get(digest)
        if cand is None:
            cand = found[digest] = [0, len(found), base, size, tag, asked, ran, 1]
        else:
            cand[5], cand[6], cand[7] = cand[5] or asked, cand[6] or ran, cand[7] + 1
            out["regions_skipped"]["duplicate"] += 1
        cand[0] = -(4 * pe + 2 * bool(cand[6]) + bool(cand[5]))
    for _rank, _order, base, size, tag, asked, ran, copies in sorted(found.values(), key=lambda r: (r[0], r[1])):
        try:
            name = writer.write(se.mem_read(base, min(size, MAX_REGION_BYTES)))
        except Exception:
            name = None
        if name is None:
            out["regions_skipped"]["capped"] += 1
            continue
        region = {"file": name, "tag": _text(tag), "base": base, "size": size,
                  "prot": asked[-1] if asked else prot_text(_perms_at(uc_regions, base, size)),
                  "exec_requested": bool(asked), "executed": ran, "source": "alloc",
                  "alloc_size": allocs.get(base)}
        if copies > 1:
            region["copies"] = copies
        out["regions"].append(region)
    try:
        after = se.mem_read(mod_base, mod_size)
    except Exception:
        after = before
    changed = changed_bytes(before, after, code_spans(before))
    out["module"] = {"base": mod_base, "size": mod_size, "changed": changed}
    if changed >= MODULE_MIN_CHANGED:
        name = writer.write(after)
        if name is not None:
            ran = any(b < mod_base + mod_size and b + s > mod_base for b, s in executed)
            out["regions"].append({"file": name, "tag": "module", "base": mod_base, "size": mod_size,
                                   "prot": prot_text(_perms_at(uc_regions, mod_base, mod_size)),
                                   "exec_requested": False, "executed": ran, "source": "module"})
    return out


# ---------------------------------------------------------------- supervisor

def _run(sample: str, outdir: str, budget_s: float, max_api: int, max_insn: int) -> dict[str, Any]:
    try:
        return emulate(sample, outdir, budget_s, max_api, max_insn)
    except BaseException as exc:  # MemoryError and SystemExit included: one document, always
        return {"error": f"{type(exc).__name__}: {_text(exc)[:200]}"}


def death_reason(status: int, *, cpu_s: float, cpu_limit: float | None, wall_killed: bool,
                 wall_s: float, rss_kb: int, got_bytes: int) -> tuple[str, str]:
    """``(kind, one bounded sentence)`` for a child that left no usable document; ``status`` is
    its wait status. Kinds: ``wall_clock``, ``cpu_limit``, ``signal``, ``exit``, ``output``."""
    used = f"cpu {cpu_s:.0f} s, peak rss {rss_kb // 1024} MiB"
    if wall_killed:
        return "wall_clock", f"emulator process passed its {wall_s:.0f} s wall clock and was killed ({used})"
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"signal {sig}"
        if sig in (signal.SIGKILL, signal.SIGXCPU) and cpu_limit is not None and cpu_s >= cpu_limit - 2:
            return "cpu_limit", f"emulator process killed at its {cpu_limit:.0f} s CPU limit ({name}, {used})"
        return "signal", f"emulator process killed by {name} ({used})"
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    if got_bytes > MAX_DOC_BYTES:
        return "output", f"emulator output over {MAX_DOC_BYTES // (1024 * 1024)} MiB"
    if code:
        return "exit", f"emulator process exited {code} without a result ({used})"
    return "output", f"emulator process left no readable result ({got_bytes} bytes, {used})"


def supervise(sample: str, outdir: str, budget_s: float, max_api: int, max_insn: int) -> dict[str, Any]:
    """Run :func:`emulate` in a forked child and return its document, or a failure document
    naming why there is none. Without ``fork`` the emulation runs in this process."""
    try:
        rfd, wfd = os.pipe()
    except OSError:
        return _run(sample, outdir, budget_s, max_api, max_insn)
    try:
        pid = os.fork()
    except OSError:
        os.close(rfd)
        os.close(wfd)
        return _run(sample, outdir, budget_s, max_api, max_insn)
    if pid == 0:
        code = 1
        try:
            os.close(rfd)
            try:  # die with the parent (PR_SET_PDEATHSIG, SIGKILL)
                import ctypes

                ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGKILL), 0, 0, 0)
            except Exception:
                pass
            payload = json.dumps(_run(sample, outdir, budget_s, max_api, max_insn)).encode()
            with os.fdopen(wfd, "wb") as f:
                f.write(payload)
            code = 0
        finally:
            os._exit(code)
    os.close(wfd)
    wall_s = budget_s + GRACE_S
    deadline = time.monotonic() + wall_s
    chunks: list[bytes] = []
    got = 0
    wall_killed = False
    with os.fdopen(rfd, "rb", buffering=0) as f:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                wall_killed = True
                break
            ready, _, _ = select.select([f], [], [], min(left, 1.0))
            if not ready:
                continue
            chunk = f.read(1 << 16)
            if not chunk:
                break
            got += len(chunk)
            if got > MAX_DOC_BYTES:
                break
            chunks.append(chunk)
        if wall_killed or got > MAX_DOC_BYTES:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    _pid, status, usage = os.wait4(pid, 0)
    if not wall_killed and got <= MAX_DOC_BYTES and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        try:
            doc = json.loads(b"".join(chunks))
            if isinstance(doc, dict):
                return doc
        except (ValueError, RecursionError):
            pass
    kind, text = death_reason(status, cpu_s=usage.ru_utime + usage.ru_stime, cpu_limit=_cpu_limit(),
                              wall_killed=wall_killed, wall_s=wall_s, rss_kb=int(usage.ru_maxrss), got_bytes=got)
    return {"error": text, "fatal": kind}


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print("usage: emulate_runner.py <sample> <outdir> <budget_s> <max_api> <max_insn>", file=sys.stderr)
        return 2
    import logging

    logging.disable(logging.CRITICAL)  # Speakeasy logs every API call at INFO
    try:
        doc = supervise(argv[1], argv[2], float(argv[3]), int(argv[4]), int(argv[5]))
    except Exception as exc:
        doc = {"error": f"{type(exc).__name__}: {_text(exc)[:200]}"}
    sys.stdout.write(json.dumps(doc))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
