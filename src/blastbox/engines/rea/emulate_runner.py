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

Output: one JSON document on stdout,

``{"arch", "dll", "entry_points": [{"type", "error"[, "api"]}], "apis": [{"n", "a": [[type,
display], ...]}], "apis_total", "events": [{"event", ...string fields}], "dynamic_code": [{"tag",
"base", "size"}], "regions": [{"file", "tag", "base", "size", "prot", "exec_requested", "executed", "source",
"alloc_size"}],
"decoys": [{"name", "sha256"}], "module": {"base", "size", "changed"}[, "error"]}``

and one ``region-<n>.bin`` per captured region: the sample's own allocations (Speakeasy tags them
``api.<function>.<base>``) that hold an MZ/PE header, that the sample asked to make executable
(``PAGE_EXECUTE*`` in a VirtualAlloc/VirtualProtect call) or that ran code, plus the sample's own
image when emulation rewrote at least ``MODULE_MIN_CHANGED`` bytes of its code or empty sections
(an in-place unpacker). Speakeasy's own decoy system modules are never written; their image hashes
go to ``decoys`` so the engine can drop a sample's copy of one. Every count and size is capped.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
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
MODULE_MIN_CHANGED = 512
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


def emulate(sample: str, outdir: str, budget_s: float, max_api: int, max_insn: int) -> dict[str, Any]:
    import speakeasy  # type: ignore[import-not-found]  # the Speakeasy venv only
    from speakeasy.config import get_default_config_dict  # type: ignore[import-not-found]

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

    out: dict[str, Any] = {"arch": None, "dll": is_dll, "entry_points": [], "apis": [], "apis_total": 0, "events": [],
                           "dynamic_code": [], "regions": [], "decoys": [], "module": None}
    se = speakeasy.Speakeasy(config=cfg)
    # Bytes, not a path: Speakeasy auto-mounts a target's directory into the emulated file system.
    module = se.load_module(data=data, filename="sample.dll" if is_dll else "sample.exe")
    mod_base, mod_size = int(module.base), int(module.image_size)
    before = se.mem_read(mod_base, mod_size)
    try:
        se.run_module(module, all_entrypoints=is_dll)
    except Exception as exc:  # partial results still go out
        out["error"] = f"{type(exc).__name__}: {_text(exc)[:200]}"
    try:
        report = json.loads(se.get_report().model_dump_json())
    except Exception as exc:
        out["error"] = out.get("error") or f"report: {type(exc).__name__}"
        report = {}
    out["arch"] = report.get("arch")
    for ep in report.get("entry_points") or []:
        err = ep.get("error") or {}
        row = {"type": _text(ep.get("ep_type", "")), "error": _text(err["type"]) if err.get("type") else None}
        if err.get("api_name"):
            row["api"] = _text(err["api_name"])
        out["entry_points"].append(row)
        for seg in ep.get("dynamic_code_segments") or []:
            if len(out["dynamic_code"]) < MAX_DYNAMIC:
                out["dynamic_code"].append({"tag": _text(seg.get("tag", "")), "base": _text(seg.get("base", "")),
                                            "size": _text(seg.get("size", ""))})
    out["apis"], out["apis_total"], out["events"], execs = _api_events(report)

    executed = []
    for seg in out["dynamic_code"]:
        try:
            executed.append((int(seg["base"], 16), int(seg["size"], 16)))
        except ValueError:
            continue
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
        ran = any(b < base + size and b + s > base for b, s in executed)
        if not (asked or ran or has_pe(blob)):
            continue
        name = writer.write(blob)
        if name is None:
            continue
        out["regions"].append({"file": name, "tag": _text(tag), "base": base, "size": size,
                               "prot": asked[-1] if asked else prot_text(_perms_at(uc_regions, base, size)),
                               "exec_requested": bool(asked), "executed": ran, "source": "alloc",
                               "alloc_size": allocs.get(base)})
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


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print("usage: emulate_runner.py <sample> <outdir> <budget_s> <max_api> <max_insn>", file=sys.stderr)
        return 2
    import logging

    logging.disable(logging.CRITICAL)  # Speakeasy logs every API call at INFO
    sample, outdir = argv[1], argv[2]
    try:
        doc = emulate(sample, outdir, float(argv[3]), int(argv[4]), int(argv[5]))
    except Exception as exc:
        doc = {"error": f"{type(exc).__name__}: {_text(exc)[:200]}"}
    sys.stdout.write(json.dumps(doc))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
