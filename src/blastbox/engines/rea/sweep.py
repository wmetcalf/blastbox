"""``rea`` — the deterministic pass-0 sweep (no model, no network).

One job, in order, everything under a fresh per-job dir in ``BLASTBOX_WORK_DIR``:

1. classify the sample by magic bytes; a PE goes through ``dumpfix`` (headers only): a
   VirtualSize past SizeOfImage (seen in CAPE's rebuilt dumps) is rewritten and every later
   step reads the repaired copy (``pe_header_repaired``); code/data sections the dump never
   captured are a ``pe_sections_missing`` warning. Both go to ``State.sweep["dump_headers"]``;
1b. an installer PE (``installer.UNWRAPPERS``: NSIS via ``7z x -tNsis``, else an in-process carve
   of its archive when 7-Zip lists nothing; Inno Setup via Binary Refinery's parser,
   ``inno_unwrap.py``; static decompressors, the installer never runs) is unwrapped: every
   extracted file becomes a ``member-<n>`` and the PE the install script runs (NSIS: named under a
   directory in the script's string table) or else the largest PE member replaces the sample for
   every later step, inspect included, with ``kind`` re-classified (a .NET payload is ``dotnet``).
   NSIS's own plugin DLLs are never the payload. The payload is offered to the registry again, up
   to ``installer.MAX_DEPTH_UNWRAP`` layers. Evidence: ``State.sweep["unpacked"] = {"packer",
   "packed_sha256", "payload_member", "payload_sha256", "payload_reason"[, "script_strings"]
   [, "script_imports"][, "signature": "altered"][, "inner": [layer, ...]]}``. A failed extraction
   (``installer_unpack_failed``) is a warning and the stub is analysed as before. So is one that
   carries no program of its own (``installer_no_payload``: a script-driven loader), and then
   ``State.sweep["installer_stub"] = {"packer", "member_count"[, "plugins"][, "data_members":
   [{"name", "size", "entropy"}]][, "script_strings"][, "script_imports"][, "signature"]}`` says
   what it does carry;
2. run the fixed ``INSPECT_MAP[kind]`` REA inspect commands (no caller arguments);
3. ``extract-artifact`` for containers (archive/apk/asar/firmware) -> ``member-<n>``;
4. icons -> ``icon-<n>``;
4a. a UPX-marked PE/ELF is ``upx -d``-ed (a static decompressor; the sample never runs) and
   every later step analyses the unpacked image instead (``unpacked: "upx"``); a failed unpack
   is a warning and the packed original goes on, to stop at ``chain_stop: packed``;
4a'. a native x86/x64 PE (not .NET) whose static signals say it hides its next stage
   (``emulate.triggers``: high-entropy section, few or loader-only imports, TLS callbacks, W+X
   section, entry outside code, hashed API names, a UPX header upx refused) is emulated in Speakeasy
   (``emulate_runner.py`` under the Speakeasy venv's python, out of process, wall-clock / API /
   memory / file-size capped; unicorn interprets the code, nothing runs natively). PEs it wrote
   into memory and executable allocations become ``member-<n>``; the most plausible PE
   (``emulate.choose``) replaces the stub for every later step (layer ``{"packer": "emulated",
   "packed_sha256", "payload_sha256", "payload_reason", "region": {"base", "size", "protect"}}``,
   summary ``unpacked: "emulated"`` when outermost) and may be ``upx -d``-ed in turn. What the stub
   did goes to ``State.sweep["emulation"]`` and the report (``emulate.py`` documents the shape); the
   strings in its API arguments go to the IOC extractor as ``emulation:<api>``. Summary
   ``emulation`` (``ok`` | ``budget`` | ``failed``) and ``emulation_captures``. A crash or missing
   emulator is ``emulation_failed``, a budget stop ``emulation_budget``; the stub is analysed as before;
4b. a .NET assembly's ManifestResources (``dotnet_resources.py``, run under the capa venv's python
   as a bounded subprocess): name/size/entropy per resource and ``.resources`` entry, the loader APIs
   the code references, and hidden payloads (large + high-entropy, decoding to a PE, or a PNG/BMP
   whose pixels decode to one or are noise), which become members and ``hidden_payload`` warnings.
   A recovered .NET PE is described (``stage``) and its own resources scanned, named
   ``<module>!<resource>``. Evidence ``State.sweep["dotnet_resources"] =
   {"resources_total", "resources", "loader_refs", "hidden_payloads": [{"resource"[, "entry"], "size",
   "entropy"[, "image"[, "noise"]][, "member"][, "decoded"[, "decoded_member", "decoded_sha256"]
   [, "stage": {"dotnet"[, "module", "types", "methods", "loader_refs"]}]]}]}``; a failed scan is a
   ``dotnet_resources_failed`` warning;
5. native code (pe/elf/macho/dotnet): ``analyzeHeadless`` import + auto-analysis with the
   bundled ``ListStrings.java`` post-script dumping defined strings and the image base;
5a. after it, ``capa`` (pe/elf/dotnet; ``capa.py``): rule matches with ATT&CK/MBC
   ids and the functions they hit, moved into Ghidra's image base. They go to the payload
   (``capa_status``, ``capabilities_total``, ``capabilities`` columns), the report and
   ``State.sweep["capabilities"]``, where the agent seeds its todo with those functions. A capa
   failure or timeout is a warning; ``unsupported`` (capa's architecture/format refusal) is not;
   Go binaries and images over ``CAPA_MAX_INPUT_BYTES`` are ``skipped`` (``capa_skipped``);
5b. for a PE, hashed API imports (``apihash.py``, at most ``API_HASH_S``): the hashing algorithm
   and the APIs whose hashes sit in the code or data, with their sites. They go to the report
   (``api_hashes``) and ``State.sweep["api_hashes"]``, never to the payload;
6. deterministic IOCs over the inspect JSON string leaves, the Ghidra strings and, for native
   code, UTF-16LE URL strings in the sample bytes (a .NET ``#US`` heap has no Ghidra string)
   and, for Go binaries, the exact string literals named by Go string headers
   (``gostrings.py``, source ``gostring:0x<va>``); an IOC read across a Go literal's end is
   clipped to that literal's own IOC;
7. a continuation archive (sample + Ghidra project + ``State``, whose ``sweep`` holds the kind and
   the first ``STATE_IOCS`` IOCs for the agent's analysis report), only when a model pass can
   follow. Otherwise the payload names why in ``chain_stop`` (Ruling AL, superseding "a Ghidra
   timeout still continues"), seals ``more_pending=false`` and packs no continuation;
8. a ``rea.report/1`` Record payload plus a full JSON ``report`` artifact.

``rea.report/1`` payload fields: ``schema``, ``kind``, ``inspect`` (``{cmd: {ok[, error]}}``),
``ghidra_status`` (ok | timeout | failed | skipped), ``members``, ``icons``, ``more_pending``,
``iocs_total``, ``iocs`` (parallel columns ``type``/``value``/``source``), the optional
``unpacked`` (``"upx"``, ``"nsis"``, ``"inno"`` or ``"emulated"``: the outermost layer, with ``unpacked_sha256``
of the image finally analysed), the optional ``hidden_payloads`` (int, .NET only: how many hidden payloads the resource scan
flagged), the optional ``emulation`` / ``emulation_captures`` (step 4a'), the optional ``capa_status`` /
``capabilities_total`` / ``capabilities`` (parallel columns ``rule``/``namespace``/``attack``) and
the optional ``chain_stop``.
``chain_stop`` is absent while the chain can continue; otherwise it is exactly one of, checked
in this order:

```text
not_native        not pe/elf/macho/dotnet (archives, APKs and every other kind)
ghidra_failed     Ghidra import/analysis failed (any status other than ok or timeout)
ghidra_timeout    Ghidra exceeded its sweep budget (the agent would only time out again)
unsupported_arch  REA's Ghidra lane rejects the architecture (32-bit MIPS I-V)
packed            UPX sections / UPX! magic, or <= 16 procedures plus a high-entropy code section
                  (the entropy rule never applies to .NET)
```

``more_pending=false`` without ``chain_stop`` means the continuation itself could not be packed
or exceeded the artifact limits (a warning says which).

Nothing here is fatal on its own: a failing inspect command, extraction, Ghidra run or pack
becomes a Warning and the job still seals ``ok``. Every attacker-influenced quantity is
capped (members, artifact bytes/count from ``Limits``, strings dump bytes, IOC count,
payload and report size).
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import mmap
import os
import shutil
import tempfile
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.engines.rea import apihash, capa, dotnet_resources, dumpfix, emulate, installer
from blastbox.engines.rea.continuation import GhidraStatus, State, pack
from blastbox.engines.rea.gostrings import clip_overruns, exact_iocs, go_strings
from blastbox.engines.rea.icons import extract_icons
from blastbox.engines.rea.iocs import Ioc, extract_iocs, utf16le_urls
from blastbox.engines.rea.triage import packed, unsupported_arch, upx_marked
from blastbox.engines.rea.runner import (
    INSPECT_MAP,
    ReaRunner,
    classify,
    CAPA_BACKENDS,
    CapaStatus,
    MAX_MEMBER_BYTES,
    MAX_MEMBERS,
    rea_env,
    run_capa,
    run_dotnet_resources,
    run_emulation,
    run_ghidra_analysis,
    upx_unpack,
)
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

_log = logging.getLogger("blastbox.engines.rea.sweep")
_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]{1,16}")

SCHEMA = "rea.report/1"
CHAIN_STOPS = ("ghidra_timeout", "ghidra_failed", "packed", "unsupported_arch", "not_native")
NATIVE_KINDS = frozenset({"pe", "elf", "macho", "dotnet"})
EXTRACT_KINDS = frozenset({"archive", "apk", "asar", "firmware"})

DEFAULT_GHIDRA_SWEEP_S = 420.0
DEFAULT_INSPECT_TIMEOUT_S = 60.0
EXTRACT_TIMEOUT_S = 120.0
UNPACK_TIMEOUT_S = 60.0
INSTALLER_TIMEOUT_S = 120.0
DOTNET_RESOURCES_S = 90.0
DEFAULT_DOTNET_PYTHON = "/opt/capa/bin/python"  # the capa venv carries the hash-locked dnfile
DOTNET_MAX_KB = 2 * 1024 * 1024
MAX_DOTNET_JSON = 4 * 1024 * 1024
MAX_DOTNET_WRITE = 256 * 1024 * 1024
STATE_RESOURCES = 32  # resources (and entries per container) carried in the continuation
_SCAN_FILE = re.compile(r"(?:hidden|decoded)-[0-9]{1,4}\.bin")
_DECODED = re.compile(r"(?:image:(?:col|row)-(?:rgb|bgr|rgba|bgra|argb)(?:\+len)?/)?"
                      r"(?:plain|gzip|zlib|deflate|base64|xor:0x(?:[0-9a-f]{2}){1,30})")
_IMAGE = re.compile(r"(?:png|bmp) [0-9]{1,5}x[0-9]{1,5}")
# The installer's whole extracted tree (bytes, entries), before the members caps apply.
MAX_INSTALLER_BYTES = 512 * 1024 * 1024
MAX_INSTALLER_FILES = 4096
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
DEFAULT_CAPA_S = 300.0
# Address-space cap on capa (KiB). vivisect on an 876 KB PE64 peaked at 2.8 GB RSS (MemoryError
# under a 2 GiB cap). capa runs after Ghidra, never beside it: the two together outgrow a 6 GiB slot.
CAPA_MAX_KB = 4 * 1024 * 1024
# vivisect's memory grows with the image: a 4 MB Go PE ran out under 4 GiB after 306 s. Larger
# images, and Go binaries (a statically linked runtime in every one), skip capa: "skipped".
CAPA_MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_CAPA_JSON = 64 * 1024 * 1024
STATE_CAPABILITIES = 64  # capa rules carried in the continuation for the agent
DEFAULT_CAPA_BIN = "/opt/capa/bin/capa"
DEFAULT_CAPA_DATA = "/opt/capa"
GHIDRA_SCRIPT = "ListStrings.java"
DEFAULT_SCRIPTS_DIR = "/opt/rea/ghidra_scripts"

MAX_STRINGS_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 50_000
MAX_STRING_CHARS = 4096
MAX_IOCS = 2048
MAX_UTF16_SCAN_BYTES = 256 * 1024 * 1024
MAX_UTF16_URLS = 1024
STATE_IOCS = 64  # sweep IOCs carried in the continuation for the agent's analysis report
GO_SCAN_S = 30.0  # wall-clock cap on the Go string-header scan
API_HASH_S = 30.0  # wall-clock cap on the hashed-import scan (apihash.py)
MAX_ICONS = 8
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_LEAVES = 200_000
MAX_DROP_WARNINGS = 32

_MIME = {
    "pe": "application/x-dosexec",
    "dotnet": "application/x-dosexec",
    "elf": "application/x-executable",
    "macho": "application/x-mach-binary",
    "apk": "application/vnd.android.package-archive",
}

GhidraFn = Callable[..., str]
UnpackFn = Callable[..., str]
InstallerFn = Callable[..., str]
DotnetFn = Callable[..., tuple[str, bytes]]
EmulateFn = Callable[..., tuple[str, bytes]]
CapaFn = Callable[..., tuple[CapaStatus, bytes]]
RunnerFactory = Callable[..., Any]


def _env_seconds(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value <= 0:
        _log.warning("%s=%r is not a positive number of seconds; using %s", name, raw, default)
        return default
    return value


def _short(text: str, n: int = 128) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _utf16_urls(path: Path) -> list[tuple[str, str]]:
    """UTF-16LE URL strings in the first ``MAX_UTF16_SCAN_BYTES`` of the sample (mmap, no copy)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return []
    with os.fdopen(fd, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            return []
        with mmap.mmap(f.fileno(), min(size, MAX_UTF16_SCAN_BYTES), access=mmap.ACCESS_READ) as m:
            return utf16le_urls(m, limit=MAX_UTF16_URLS)


def _string_leaves(obj: Any) -> Iterator[str]:
    """String values in a parsed JSON tree, iteratively and capped at MAX_LEAVES."""
    stack = [obj]
    n = 0
    while stack and n < MAX_LEAVES:
        cur = stack.pop()
        if isinstance(cur, str):
            n += 1
            yield cur
        elif isinstance(cur, dict):
            stack.extend(reversed(list(cur.values())))
        elif isinstance(cur, list):
            stack.extend(reversed(cur))


@dataclass
class GhidraStrings:
    strings: list[tuple[str, str]] = field(default_factory=list)  # (address, value)
    truncated: bool = False
    malformed: int = 0
    function_count: int | None = None
    image_base: int | None = None


def _read_ghidra_strings(path: Path) -> GhidraStrings:
    """ListStrings' JSONL: strings, truncation, malformed lines, function count, image base.

    The first line may be ``{"function_count": N[, "image_base": "0x.."]}``; every other line
    is ``{"address", "value"}``.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return GhidraStrings()
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_STRINGS_BYTES + 1)
    truncated = len(data) > MAX_STRINGS_BYTES
    if truncated:
        data = data[:MAX_STRINGS_BYTES]
        data = data[: data.rfind(b"\n") + 1]
    out: list[tuple[str, str]] = []
    bad = 0
    function_count: int | None = None
    image_base: int | None = None
    for n, line in enumerate(data.splitlines()):
        if len(out) >= MAX_STRINGS:
            truncated = True
            break
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except (ValueError, RecursionError):
            bad += 1
            continue
        if n == 0 and isinstance(d, dict) and "function_count" in d and set(d) <= {"function_count",
                                                                                   "image_base"}:
            fc, ib = d["function_count"], d.get("image_base")
            if isinstance(fc, int) and not isinstance(fc, bool) and fc >= 0:
                function_count = fc
                if isinstance(ib, str) and _HEX_ADDR.fullmatch(ib):
                    image_base = int(ib, 16)
                continue
        addr = d.get("address") if isinstance(d, dict) else None
        val = d.get("value") if isinstance(d, dict) else None
        if not isinstance(addr, str) or not isinstance(val, str) or not 0 < len(addr) <= 64:
            bad += 1
            continue
        out.append((addr, val[:MAX_STRING_CHARS]))
    return GhidraStrings(out, truncated, bad, function_count, image_base)


class ReaSweepEngine:
    """Pass 0 of the REA chain: deterministic inspection, extraction and Ghidra import."""

    name = "rea"
    formats = frozenset({"*"})
    jobs_per_recycle = 1

    def __init__(
        self,
        runner_factory: RunnerFactory = ReaRunner,
        ghidra_fn: GhidraFn = run_ghidra_analysis,
        unpack_fn: UnpackFn = upx_unpack,
        capa_fn: CapaFn = run_capa,
        installer_fn: InstallerFn = installer.extract,
        dotnet_fn: DotnetFn = run_dotnet_resources,
        emulate_fn: EmulateFn = run_emulation,
    ) -> None:
        self._runner_factory = runner_factory
        self._ghidra_fn = ghidra_fn
        self._unpack_fn = unpack_fn
        self._capa_fn = capa_fn
        self._installer_fn = installer_fn
        self._dotnet_fn = dotnet_fn
        self._emulate_fn = emulate_fn

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        base = Path(os.environ.get("BLASTBOX_WORK_DIR") or "/work")
        base.mkdir(parents=True, exist_ok=True)
        job = Path(tempfile.mkdtemp(prefix="rea-sweep-", dir=base))
        try:
            return self._sweep(input, outdir, limits, job)
        finally:
            shutil.rmtree(job, ignore_errors=True)

    # ----------------------------------------------------------------- the sweep
    def _sweep(self, input: Path, outdir: Path, limits: Limits, job: Path) -> DetonationResult:
        start = time.monotonic()
        deadline = start + limits.timeout_s
        margin = max(5.0, min(60.0, 0.1 * limits.timeout_s))

        def remaining() -> float:
            return deadline - time.monotonic() - margin

        warnings: list[Warning] = []
        kind = classify(input)
        dump, input = self._dumpfix(input, kind, job, warnings)

        # 0b. an installer (installer.UNWRAPPERS: NSIS, Inno Setup): everything from here on
        # (inspect included) analyses the PE it installs and runs, up to MAX_DEPTH_UNWRAP layers,
        # and every extracted file goes out as a member.
        analysed = input
        members: list[Path] = []
        # Every unwrapped layer, outermost first: installers, upx -d, the emulated stage.
        layers: list[dict[str, Any]] = []
        installer_stub: dict[str, Any] | None = None
        for depth in range(installer.MAX_DEPTH_UNWRAP):
            packer = installer.detect(analysed) if kind == "pe" else None
            if packer is None:
                break
            inner, layer, found = self._installer(analysed, packer, job / f"installer-{depth}",
                                                    outdir / "members", len(members),
                                                    min(INSTALLER_TIMEOUT_S, remaining()), warnings)
            members += found
            if inner is None:
                installer_stub = layer  # unwrapped, but it carries no program: the stub is analysed
                break
            if layer is None:
                break
            layers.append(layer)
            analysed = inner
            kind = classify(inner)
        runner = self._runner_factory(os.environ.get("REA_BIN") or "rea", os.environ, job / "rea")

        # 1. inspect
        inspect_timeout = _env_seconds("REA_INSPECT_TIMEOUT_S", DEFAULT_INSPECT_TIMEOUT_S)
        inspect: dict[str, dict[str, Any]] = {}
        for cmd in INSPECT_MAP[kind]:
            budget = min(inspect_timeout, remaining())
            if budget < 1:
                inspect[cmd] = {"ok": False, "error": "budget_exhausted"}
            else:
                try:
                    inspect[cmd] = runner.inspect(cmd, analysed, budget)
                except Exception as exc:  # an inspect failure never fails the job
                    inspect[cmd] = {"ok": False, "error": f"exception:{type(exc).__name__}"}
            if not inspect[cmd].get("ok"):
                err = str(inspect[cmd].get("error", "unknown"))
                inspect[cmd] = {"ok": False, "error": _short(err)}
                warnings.append(Warning(code="inspect_failed", message=f"{cmd}: {_short(err, 1000)}",
                                        context=cmd))

        # 2. extraction (containers only)
        if kind in EXTRACT_KINDS:
            members = self._extract(runner, input, outdir / "members", min(EXTRACT_TIMEOUT_S, remaining()),
                                    warnings)

        # 3. icons
        icons_dir = outdir / "icons"
        icons_dir.mkdir(parents=True, exist_ok=True)
        icons = extract_icons(input, icons_dir, max_icons=MAX_ICONS)

        # 4a. UPX: everything from here on analyses the unpacked image when there is one.
        if kind in ("pe", "elf") and upx_marked(analysed):
            analysed = self._upx_layer(analysed, job / "upx-0", remaining(), layers, warnings)

        # 4a'. emulated unpacking (emulate.py): a native PE that conceals its next stage runs under
        # Speakeasy (interpreted by unicorn, out of process); a captured stage replaces it for every
        # later step, and may itself be upx -d-ed.
        emulation: dict[str, Any] | None = None
        emulation_strings: list[tuple[str, str]] = []
        api_hashes: apihash.ApiHashes | None = None
        hashed: Path | None = None  # the image api_hashes describes
        if kind == "pe" and len(layers) < installer.MAX_DEPTH_UNWRAP and emulate.emulatable(analysed):
            api_hashes, hashed = self._api_hashes(analysed, remaining(), warnings), analysed
            reasons = emulate.triggers(analysed, api_hashes=len(api_hashes.hits) if api_hashes else 0,
                                       upx_failed=upx_marked(analysed))
            if reasons:
                emulation, emulation_strings, stage, layer, found = self._emulate(
                    analysed, job, outdir / "members", len(members), remaining(), reasons, warnings)
                members += found
                if stage is not None and layer is not None:
                    layers.append(layer)
                    analysed = stage
                    kind = classify(stage)
                    if kind in ("pe", "elf") and upx_marked(analysed) and len(layers) <= installer.MAX_DEPTH_UNWRAP:
                        analysed = self._upx_layer(analysed, job / "upx-1", remaining(), layers, warnings)

        # 4b. .NET: embedded resources (hidden payloads behind a decoy UI), out of process.
        resources: dict[str, Any] | None = None
        if kind == "dotnet":
            resources, found = self._dotnet(analysed, job, outdir / "members", len(members),
                                            min(DOTNET_RESOURCES_S, remaining()), warnings)
            members += found

        # 4. Ghidra
        ghidra_status: GhidraStatus = "skipped"
        project = job / "proj"
        strings_path = job / "strings.jsonl"
        if kind in NATIVE_KINDS:
            ghidra_status = self._ghidra(analysed, project, strings_path, job, remaining(), warnings)

        # 5. IOCs
        gstrings: list[tuple[str, str]] = []
        function_count: int | None = None
        image_base: int | None = None
        if ghidra_status == "ok":
            gs = _read_ghidra_strings(strings_path)
            gstrings, truncated, bad = gs.strings, gs.truncated, gs.malformed
            function_count, image_base = gs.function_count, gs.image_base
            if truncated:
                warnings.append(Warning(code="ghidra_strings_truncated",
                                        message=f"Ghidra strings dump capped at {MAX_STRINGS_BYTES} "
                                                f"bytes / {MAX_STRINGS} entries"))
            if bad:
                warnings.append(Warning(code="ghidra_strings_malformed",
                                        message=f"{bad} malformed line(s) in the Ghidra strings dump"))

        wide_urls: list[tuple[str, str]] = []
        if kind in NATIVE_KINDS:
            try:
                wide_urls = _utf16_urls(analysed)
            except (OSError, ValueError) as exc:
                warnings.append(Warning(code="utf16_scan_failed", message=f"exception:{type(exc).__name__}"))

        # Go packs string literals with no terminator: their exact bounds come from the string
        # headers (gostrings.py), and IOCs read across a literal's end are clipped to it.
        go_lits: list[tuple[int, str]] = []
        if kind in NATIVE_KINDS:
            try:
                go_lits = go_strings(analysed, deadline=time.monotonic() + max(0.0, min(GO_SCAN_S, remaining())))
            except (OSError, ValueError) as exc:
                warnings.append(Warning(code="go_strings_failed", message=f"exception:{type(exc).__name__}"))

        def sources() -> Iterator[tuple[str, str]]:
            for va, value in go_lits:
                yield f"gostring:{va:#x}", value
            for cmd, res in inspect.items():
                if res.get("ok"):
                    for leaf in _string_leaves(res.get("result")):
                        yield f"inspect:{cmd}", leaf
            for addr, value in gstrings:
                yield f"ghidra:{addr}", value
            yield from wide_urls
            yield from emulation_strings

        # 4b. capa, after Ghidra (see CAPA_MAX_KB), moved into Ghidra's image base.
        capa_status: CapaStatus | None = None
        capabilities: list[dict[str, Any]] = []
        if kind in CAPA_BACKENDS:
            skip = ("go binary" if go_lits else
                    "image over the size limit" if analysed.stat().st_size > CAPA_MAX_INPUT_BYTES else None)
            if skip is not None:
                capa_status = "skipped"
                warnings.append(Warning(code="capa_skipped", message=f"capa skipped: {skip}"))
            else:
                capa_status, capabilities = self._capa(analysed, kind, job, image_base, remaining(), warnings)

        # 4c. hashed API imports (PE only; .NET resolves by metadata, not by hash). Already computed
        # for the emulation trigger when the image did not change since.
        if kind != "pe":
            api_hashes = None
        elif hashed != analysed:
            api_hashes = self._api_hashes(analysed, remaining(), warnings)

        iocs = extract_iocs(sources(), limit=MAX_IOCS)
        if go_lits:
            iocs = clip_overruns(iocs, exact_iocs(go_lits), key=lambda i: (i.type, i.value),
                                 replace=lambda i, v: Ioc(i.type, v, i.source))
        if len(iocs) >= MAX_IOCS:
            warnings.append(Warning(code="iocs_capped", message=f"IOC extraction stopped at {MAX_IOCS}"))

        # 6. continuation: only when a model pass can follow it (Ruling AL). A failed or timed-out
        # Ghidra run would only repeat in the agent; non-native inputs, architectures REA's lane
        # rejects and packed stubs give the model nothing to analyse.
        chain_stop = self._chain_stop(analysed, kind, ghidra_status, function_count)
        chainable = chain_stop is None
        sweep_evidence: dict[str, Any] = {"kind": kind, "iocs": [{"type": i.type, "value": i.value, "source": i.source}
                                                 for i in iocs[:STATE_IOCS]]}
        if layers:
            # An inner upx layer is recorded as {"packer": "upx"} (the outer layer names the input).
            nested = [{"packer": "upx"} if layer["packer"] == "upx" else layer for layer in layers[1:]]
            sweep_evidence["unpacked"] = {**layers[0], **({"inner": nested} if nested else {})}
        if installer_stub is not None:
            sweep_evidence["installer_stub"] = installer_stub
        if emulation is not None:
            sweep_evidence["emulation"] = emulation
        if dump is not None:
            sweep_evidence["dump_headers"] = dump
        if resources is not None:
            sweep_evidence["dotnet_resources"] = resources
        if capabilities:
            sweep_evidence["capabilities"] = capabilities[:STATE_CAPABILITIES]
        if api_hashes is not None:
            sweep_evidence["api_hashes"] = {"algorithm": api_hashes.algorithm, "hits": api_hashes.hits}
        cont = (self._continuation(analysed, outdir, project, ghidra_status, limits, warnings, sweep_evidence)
                if chainable else None)

        # 7. artifact budget (report + continuation reserved first)
        report_cap = min(MAX_REPORT_BYTES, limits.max_artifact_bytes)
        icons, members = self._budget(icons, members, cont, report_cap, limits, warnings)

        more_pending = chainable and cont is not None

        summary: dict[str, Any] = {
            "schema": SCHEMA,
            "kind": kind,
            "inspect": {c: ({"ok": True} if r.get("ok") else {"ok": False, "error": r["error"]})
                        for c, r in inspect.items()},
            "ghidra_status": ghidra_status,
            "members": len(members),
            "icons": len(icons),
            "more_pending": more_pending,
            "iocs_total": len(iocs),
        }
        if layers:
            summary["unpacked"] = layers[0]["packer"]
            summary["unpacked_sha256"] = _sha256(analysed)
        if emulation is not None:
            summary["emulation"] = emulation["status"]
            summary["emulation_captures"] = len(emulation.get("captures", []))
        if resources is not None:
            summary["hidden_payloads"] = len(resources["hidden_payloads"])
        if capa_status is not None:
            summary["capa_status"] = capa_status
            summary["capabilities_total"] = len(capabilities)
        if chain_stop is not None:
            summary["chain_stop"] = chain_stop

        # 8. report artifact, then the payload
        report_path = outdir / "report.json"
        self._write_report(report_path, summary, iocs, inspect, report_cap, warnings, capabilities, api_hashes,
                           resources, emulation)
        payload = self._payload(summary, iocs, limits, warnings, capabilities)

        artifacts = [DeclaredArtifact(id=f"member-{i}", path=p.relative_to(outdir).as_posix(), kind="extracted")
                     for i, p in enumerate(members)]
        artifacts += [DeclaredArtifact(id=f"icon-{i}", path=p.relative_to(outdir).as_posix(), kind="icon")
                      for i, p in enumerate(icons)]
        if cont is not None:
            artifacts.append(DeclaredArtifact(id="continuation", path=cont.relative_to(outdir).as_posix(),
                                              kind="rea_continuation"))
        artifacts.append(DeclaredArtifact(id="report", path="report.json", kind="report"))

        return DetonationResult(
            payload=payload,
            artifacts=artifacts,
            # Magic-byte classification, not a calibrated score: 0.0 = "no confidence value".
            detected=Detection(label=kind, mime=_MIME.get(kind, "application/octet-stream"),
                               confidence=0.0, source=self.name),
            warnings=warnings,
            status="ok",
        )

    # ------------------------------------------------------------------ steps
    @staticmethod
    def _chain_stop(sample: Path, kind: str, ghidra_status: GhidraStatus,
                    function_count: int | None) -> str | None:
        """Why no model pass should follow this sweep, or None (see the module docstring)."""
        if kind not in NATIVE_KINDS:
            return "not_native"
        if ghidra_status == "timeout":
            return "ghidra_timeout"
        if ghidra_status != "ok":
            return "ghidra_failed"
        if unsupported_arch(sample):
            return "unsupported_arch"
        if packed(sample, function_count=function_count, dotnet=kind == "dotnet"):
            return "packed"
        return None

    def _capa(self, sample: Path, kind: str, job: Path, image_base: int | None, remaining_s: float,
              warnings: list[Warning]) -> tuple[CapaStatus, list[dict[str, Any]]]:
        """capa's status and its summarized capabilities, rebased into Ghidra's image."""
        budget = min(_env_seconds("REA_CAPA_TIMEOUT_S", DEFAULT_CAPA_S), remaining_s)
        if budget < 1:
            warnings.append(Warning(code="capa_timeout", message="no time left for capa"))
            return "timeout", []
        data = Path(DEFAULT_CAPA_DATA)
        try:
            status, out = self._capa_fn(sample, kind, budget, env=rea_env(job / "capa", os.environ),
                                        capa_bin=DEFAULT_CAPA_BIN, rules=data / "rules",
                                        signatures=data / "sigs", max_kb=CAPA_MAX_KB, max_stdout=MAX_CAPA_JSON)
        except Exception as exc:
            warnings.append(Warning(code="capa_failed", message=f"exception:{type(exc).__name__}"))
            return "failed", []
        if status != "ok":
            if status != "unsupported":
                warnings.append(Warning(code=f"capa_{status}", message=f"capa: {status}"))
            return status, []
        try:
            doc = json.loads(out)
        except (ValueError, RecursionError):
            warnings.append(Warning(code="capa_failed", message="capa output is not JSON"))
            return "failed", []
        capa_base = capa.base_address(doc)
        rebase: Callable[[int], int] | None = None
        if capa_base is not None and image_base is not None and capa_base != image_base:
            delta = image_base - capa_base
            rebase = lambda va: va + delta  # noqa: E731
        return "ok", capa.summarize(doc, rebase=rebase)

    @staticmethod
    def _dumpfix(sample: Path, kind: str, job: Path,
                 warnings: list[Warning]) -> tuple[dict[str, Any] | None, Path]:
        """``(State.sweep["dump_headers"] or None, the image every later step reads)``: a PE whose
        rebuilt headers ``dumpfix`` repaired is analysed as the repaired copy (same file name)."""
        if kind not in ("pe", "dotnet"):
            return None, sample
        dest = job / "repaired" / sample.name
        try:
            fix = dumpfix.repair(sample, dest)
        except (OSError, ValueError) as exc:
            warnings.append(Warning(code="dumpfix_failed", message=f"exception:{type(exc).__name__}"))
            return None, sample
        if fix is None:
            return None, sample
        evidence: dict[str, Any] = {}
        if fix.missing:
            evidence["missing_sections"] = fix.missing
            warnings.append(Warning(code="pe_sections_missing",
                                    message=_short("sections with no bytes in the file (a dump that never "
                                                   "captured them): " + ", ".join(fix.missing), 1000)))
        if fix.repaired:
            evidence["repaired_sections"] = fix.repaired
            evidence["original_sha256"] = _sha256(sample)
            warnings.append(Warning(code="pe_header_repaired",
                                    message=_short("VirtualSize past SizeOfImage rewritten to the section "
                                                   "span: " + ", ".join(fix.repaired), 1000)))
            return evidence, dest
        return evidence, sample

    def _installer(self, sample: Path, packer: str, job: Path, members_dir: Path, have: int, timeout_s: float,
                   warnings: list[Warning]) -> tuple[Path | None, dict[str, Any] | None, list[Path]]:
        """Unwrap one installer layer: ``(payload copy or None, evidence or None, member
        artifacts)``; ``have`` members already exist. Every failure is a warning and the wrapper
        itself is analysed as before. An installer that unwrapped but carries no program of its
        own returns no payload and its ``installer_stub`` evidence (what it does carry)."""
        if timeout_s < 1:
            warnings.append(Warning(code="installer_unpack_failed", message=f"{packer}: no time left"))
            return None, None, []
        tree = job / "tree"
        try:
            status = self._installer_fn(sample, tree, timeout_s, packer=packer, env=rea_env(job / "env", os.environ),
                                        max_bytes=MAX_INSTALLER_BYTES, max_files=MAX_INSTALLER_FILES)
        except Exception as exc:
            warnings.append(Warning(code="installer_unpack_failed",
                                    message=f"{packer}: exception:{type(exc).__name__}"))
            return None, None, []
        if status not in ("ok", "partial"):
            warnings.append(Warning(code="installer_unpack_failed",
                                    message=f"{packer}: {_short(str(status), 64)}; analysing the installer stub"))
            shutil.rmtree(tree, ignore_errors=True)
            return None, None, []
        if status == "partial":
            warnings.append(Warning(code="installer_partial",
                                    message=f"{packer}: the extractor reported errors; some members may be missing"))
        try:
            found, dropped = installer.collect(tree, members_dir, max_members=max(0, MAX_MEMBERS - have),
                                               max_member_bytes=MAX_MEMBER_BYTES, start=have)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        capped = sum(1 for _rel, why in dropped if why == "member_cap")
        if capped:
            warnings.append(Warning(code="members_capped",
                                    message=f"{capped} member(s) beyond the {MAX_MEMBERS}-member cap dropped"))
        others = [(rel, why) for rel, why in dropped if why != "member_cap"]
        for rel, why in others[:MAX_DROP_WARNINGS]:
            warnings.append(Warning(code="member_dropped", message=f"member dropped: {_short(why, 64)}",
                                    context=_short(rel, 255)))
        paths = [m.path for m in found]
        choice = installer.choose(packer, found, sample)
        member = choice.payload
        if member is None:
            warnings.append(Warning(code="installer_no_payload",
                                    message=f"{packer}: no program among {len(found)} extracted member(s); "
                                            "analysing the installer stub"))
            return None, {"packer": packer, **choice.extra}, paths
        name = _SAFE_NAME.sub("_", member.rel.rsplit("/", 1)[-1])[-64:].lstrip(".-") or "payload.exe"
        dest = job / "payload" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(member.path, dest)
        evidence: dict[str, Any] = {"packer": packer, "packed_sha256": _sha256(sample), "payload_member": member.rel,
                                    "payload_sha256": _sha256(dest), "payload_reason": choice.reason,
                                    **choice.extra}
        return dest, evidence, paths

    def _dotnet(self, sample: Path, job: Path, members_dir: Path, have: int, timeout_s: float,
                warnings: list[Warning]) -> tuple[dict[str, Any] | None, list[Path]]:
        """``(State.sweep["dotnet_resources"] or None, member artifacts)`` from the resource scan
        (``dotnet_resources.py``). Hidden payloads, and the PEs they decode to, become members and
        ``hidden_payload`` warnings; a failed scan is a ``dotnet_resources_failed`` warning."""
        if timeout_s < 1:
            warnings.append(Warning(code="dotnet_resources_failed", message="no time left for the resource scan"))
            return None, []
        scan_dir = job / "dotnet-res"
        python = DEFAULT_DOTNET_PYTHON
        try:
            status, out = self._dotnet_fn(sample, scan_dir, timeout_s, env=rea_env(job / "dotnet", os.environ),
                                          python=python, max_kb=DOTNET_MAX_KB, max_stdout=MAX_DOTNET_JSON,
                                          max_write_bytes=MAX_DOTNET_WRITE)
        except Exception as exc:
            warnings.append(Warning(code="dotnet_resources_failed", message=f"exception:{type(exc).__name__}"))
            return None, []
        try:
            doc = json.loads(out) if status == "ok" else None
        except (ValueError, RecursionError):
            doc = None
        doc_rows = doc.get("resources") if isinstance(doc, dict) else None
        doc_hidden = doc.get("hidden") if isinstance(doc, dict) else None
        if not isinstance(doc, dict) or not isinstance(doc_rows, list) or not isinstance(doc_hidden, list):
            warnings.append(Warning(code="dotnet_resources_failed",
                                    message=f"resource scan: {status if status != 'ok' else 'malformed output'}"))
            return None, []
        if isinstance(doc.get("error"), str):
            warnings.append(Warning(code="dotnet_resources_failed", message=f"resource scan: {_short(doc['error'], 64)}"))
        def num(v: Any, kind: type | tuple[type, ...]) -> Any:
            return v if isinstance(v, (int, float)) and not isinstance(v, bool) and isinstance(v, kind) else 0

        unread = num(doc.get("images_unread"), int)
        if unread:
            warnings.append(Warning(code="dotnet_resources_failed",
                                    message=f"resource scan: {unread} image resource(s) not read (time budget)"))


        def text(v: Any) -> str:
            return _short(v, 200) if isinstance(v, str) else ""

        rows: list[dict[str, Any]] = []
        for r in doc_rows[:STATE_RESOURCES]:
            if not isinstance(r, dict):
                continue
            row: dict[str, Any] = {"name": text(r.get("name")), "size": num(r.get("size"), int),
                                   "entropy": float(num(r.get("entropy"), (int, float))),
                                   "container": r.get("container") is True}
            if isinstance(r.get("format"), str):
                row["format"] = text(r["format"])
            if row["container"]:
                row["entries_total"] = num(r.get("entries_total"), int)
                raw_ents = r.get("entries")
                ents: list[Any] = raw_ents if isinstance(raw_ents, list) else []
                row["entries"] = [{"name": text(e.get("name")), "size": num(e.get("size"), int),
                                   "entropy": float(num(e.get("entropy"), (int, float))), "type": text(e.get("type"))}
                                  for e in ents[:STATE_RESOURCES] if isinstance(e, dict)]
            rows.append(row)
        raw_refs = doc.get("loader_refs")
        refs: list[Any] = raw_refs if isinstance(raw_refs, list) else []
        hidden: list[dict[str, Any]] = []
        paths: list[Path] = []

        def take(name: Any) -> Path | None:
            if not isinstance(name, str) or not _SCAN_FILE.fullmatch(name) or have + len(paths) >= MAX_MEMBERS:
                return None
            dest = members_dir / f"member-{have + len(paths)}"
            if installer.copy_member(str(scan_dir / name), dest, MAX_MEMBER_BYTES) is not None:
                return None
            paths.append(dest)
            return dest

        members_dir.mkdir(parents=True, exist_ok=True)
        for h in doc_hidden[:dotnet_resources.MAX_HIDDEN]:
            if not isinstance(h, dict):
                continue
            item: dict[str, Any] = {"resource": text(h.get("resource")), "size": num(h.get("size"), int),
                                    "entropy": float(num(h.get("entropy"), (int, float)))}
            if isinstance(h.get("entry"), str):
                item["entry"] = text(h["entry"])
            image = h.get("image")
            if isinstance(image, str) and _IMAGE.fullmatch(image):
                item["image"] = image
                if num(h.get("noise"), (int, float)):
                    item["noise"] = float(h["noise"])
            raw = take(h.get("file"))
            if raw is not None:
                item["member"] = raw.name
            decoded = h.get("decoded")
            if isinstance(decoded, str) and _DECODED.fullmatch(decoded):
                item["decoded"] = decoded
                pe = raw if decoded == "plain" else take(h.get("decoded_file"))
                if pe is not None:
                    item["decoded_member"] = pe.name
                    item["decoded_sha256"] = _sha256(pe)
                stage = h.get("stage")
                if isinstance(stage, dict):
                    item["stage"] = {"dotnet": stage.get("dotnet") is True}
                    if item["stage"]["dotnet"]:
                        srefs = stage.get("loader_refs")
                        item["stage"].update(
                            module=text(stage.get("module")), types=num(stage.get("types"), int),
                            methods=num(stage.get("methods"), int),
                            loader_refs=[text(r) for r in (srefs if isinstance(srefs, list) else [])[:32]
                                         if isinstance(r, str)])
            hidden.append(item)
            where = item["resource"] + (f"/{item['entry']}" if "entry" in item else "")
            what = f"{item['image']} image" if "image" in item else "embedded resource"
            how = ""
            if "decoded" in item:
                module = item.get("stage", {}).get("module")
                how = (f", {'its pixels decode' if 'image' in item else 'decodes'} ({item['decoded']}) to a PE"
                       + (f" ({module}, .NET)" if module else ""))
            elif "noise" in item:
                how = f", pixels are noise (entropy {item['noise']:.2f}): an encrypted payload, not a picture"
            warnings.append(Warning(code="hidden_payload",
                                    message=_short(f"{what} {where}: {item['size']} bytes, entropy "
                                                   f"{item['entropy']:.2f}{how}", 1000)))
        shutil.rmtree(scan_dir, ignore_errors=True)
        evidence = {"resources_total": num(doc.get("resources_total"), int), "resources": rows,
                    "loader_refs": [text(r) for r in refs[:32] if isinstance(r, str)], "hidden_payloads": hidden}
        return evidence, paths

    def _upx_layer(self, sample: Path, job: Path, remaining_s: float, layers: list[dict[str, Any]],
                   warnings: list[Warning]) -> Path:
        """``upx -d`` one layer: the unpacked image (a layer is appended) or ``sample``."""
        upx = self._unpack(sample, job, min(UNPACK_TIMEOUT_S, remaining_s), warnings)
        if upx != sample:
            layers.append({"packer": "upx", "packed_sha256": _sha256(sample)})
        return upx

    @staticmethod
    def _api_hashes(sample: Path, remaining_s: float, warnings: list[Warning]) -> apihash.ApiHashes | None:
        try:
            return apihash.resolve(sample, deadline=time.monotonic() + max(0.0, min(API_HASH_S, remaining_s)))
        except (OSError, ValueError) as exc:
            warnings.append(Warning(code="api_hash_failed", message=f"exception:{type(exc).__name__}"))
            return None

    def _emulate(self, sample: Path, job: Path, members_dir: Path, have: int, remaining_s: float,
                 reasons: list[str], warnings: list[Warning]
                 ) -> tuple[dict[str, Any], list[tuple[str, str]], Path | None, dict[str, Any] | None, list[Path]]:
        """Emulate one stub: ``(State.sweep["emulation"], IOC strings, the captured stage to analyse
        instead or None, its unpack layer or None, member artifacts)``; ``have`` members already
        exist. A crash or a missing emulator is ``emulation_failed``, a budget stop
        ``emulation_budget``; both are warnings and the stub is analysed as before."""
        evidence: dict[str, Any] = {"status": "failed", "triggers": list(reasons)}
        budget = min(emulate.env_number("REA_EMULATE_TIMEOUT_S", emulate.DEFAULT_TIMEOUT_S),
                     remaining_s - emulate.OVERHEAD_S)
        if budget < 5:
            warnings.append(Warning(code="emulation_budget", message="no time left to emulate the stub"))
            return {**evidence, "status": "budget"}, [], None, None, []
        scan = job / "emulate"
        try:
            status, out = self._emulate_fn(
                sample, scan, budget + emulate.OVERHEAD_S, env=rea_env(job / "emulate-env", os.environ),
                python=emulate.DEFAULT_PYTHON, budget_s=budget,
                max_api=int(emulate.env_number("REA_EMULATE_MAX_API", emulate.DEFAULT_MAX_API, integer=True)),
                max_insn=int(emulate.env_number("REA_EMULATE_MAX_INSTRUCTIONS", emulate.DEFAULT_MAX_INSN,
                                                integer=True, allow_negative_one=True)),
                max_kb=emulate.MAX_KB, max_stdout=emulate.MAX_JSON, max_write_bytes=emulate.MAX_WRITE)
        except Exception as exc:
            status, out = f"exception:{type(exc).__name__}", b""
        doc = emulate.parse(out) if status == "ok" else None
        if status == "timeout":
            shutil.rmtree(scan, ignore_errors=True)
            warnings.append(Warning(code="emulation_budget",
                                    message=f"emulation exceeded its {budget + emulate.OVERHEAD_S:.0f}s wall clock "
                                            "and was killed; analysing the stub"))
            return {**evidence, "status": "budget"}, [], None, None, []
        if doc is None:
            shutil.rmtree(scan, ignore_errors=True)
            why = "Speakeasy is not installed" if status == "unavailable" else (
                "malformed output" if status == "ok" else _short(str(status), 64))
            warnings.append(Warning(code="emulation_failed", message=f"emulation: {why}; analysing the stub"))
            return {**evidence, "stop_detail": why}, [], None, None, []
        try:
            em = emulate.shape(doc, scan, job / "captures", input_sha256=_sha256(sample), triggers=reasons,
                               imported=emulate.imports(sample))
        finally:
            shutil.rmtree(scan, ignore_errors=True)
        evidence = em.evidence
        if isinstance(doc.get("error"), str):
            warnings.append(Warning(code="emulation_failed",
                                    message=_short(f"Speakeasy raised: {doc['error']}; partial results kept", 1000)))
        if evidence.get("stop") == "budget":
            warnings.append(Warning(code="emulation_budget",
                                    message=f"emulation stopped at its {budget:.0f}s / instruction budget; a "
                                            "stage decrypted later was not reached"))
        members_dir.mkdir(parents=True, exist_ok=True)
        paths: list[Path] = []
        capped = 0
        for cap in em.captures:
            if have + len(paths) >= MAX_MEMBERS:
                capped += 1
                continue
            dest = members_dir / f"member-{have + len(paths)}"
            if installer.copy_member(str(cap.path), dest, MAX_MEMBER_BYTES) is None:
                cap.member = dest.name
                paths.append(dest)
        if capped:
            warnings.append(Warning(code="members_capped",
                                    message=f"{capped} emulation capture(s) beyond the {MAX_MEMBERS}-member cap dropped"))
        evidence["captures"] = [c.row() for c in em.captures]
        choice = emulate.choose(em.captures)
        if choice is None:
            return evidence, em.strings, None, None, paths
        cap, reason = choice
        dest = job / "emulated" / f"stage-{cap.sha256[:12]}.{'dll' if cap.dll else 'exe'}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cap.path, dest)
        evidence["payload_sha256"] = cap.sha256
        layer = {"packer": "emulated", "packed_sha256": _sha256(sample), "payload_sha256": cap.sha256,
                 "payload_reason": reason, "region": dict(cap.region)}
        return evidence, em.strings, dest, layer, paths

    def _unpack(self, sample: Path, job: Path, timeout_s: float, warnings: list[Warning]) -> Path:
        """The ``upx -d`` image of ``sample`` (same file name, so the agent sees the same name), or
        ``sample`` itself with an ``unpack_failed`` warning."""
        if timeout_s < 1:
            warnings.append(Warning(code="unpack_failed", message="no time left for upx -d"))
            return sample
        dest = job / "unpacked" / sample.name
        try:
            status = self._unpack_fn(sample, dest, timeout_s, env=rea_env(job / "upx", os.environ),
                                     max_bytes=MAX_UNPACKED_BYTES)
        except Exception as exc:
            warnings.append(Warning(code="unpack_failed", message=f"upx -d: exception:{type(exc).__name__}"))
            return sample
        if status != "ok":
            warnings.append(Warning(code="unpack_failed", message=f"upx -d: {status} (a modified UPX header "
                                                                  f"defeats it); analysing the packed sample"))
            return sample
        return dest

    @staticmethod
    def _extract(runner: Any, sample: Path, dest: Path, timeout_s: float,
                 warnings: list[Warning]) -> list[Path]:
        if timeout_s < 1:
            warnings.append(Warning(code="extract_failed", message="no time left for extraction"))
            return []
        try:
            res = runner.extract(sample, dest, timeout_s)
        except Exception as exc:
            warnings.append(Warning(code="extract_failed", message=f"exception:{type(exc).__name__}"))
            return []
        if res.error:
            warnings.append(Warning(code="extract_failed", message=_short(str(res.error), 1000)))
        capped = sum(1 for _rel, why in res.dropped if why == "member_cap")
        if capped:
            warnings.append(Warning(code="members_capped",
                                    message=f"{capped} member(s) beyond the {len(res.files)}-member cap dropped"))
        others = [(rel, why) for rel, why in res.dropped if why != "member_cap"]
        for rel, why in others[:MAX_DROP_WARNINGS]:
            warnings.append(Warning(code="member_dropped", message=f"member dropped: {_short(why, 64)}",
                                    context=_short(rel, 255)))
        if len(others) > MAX_DROP_WARNINGS:
            warnings.append(Warning(code="member_dropped",
                                    message=f"{len(others) - MAX_DROP_WARNINGS} further member(s) dropped"))
        return [p for p in res.files if p.is_file() and not p.is_symlink()]

    def _ghidra(self, sample: Path, project: Path, strings_path: Path, job: Path,
                remaining_s: float, warnings: list[Warning]) -> GhidraStatus:
        budget = min(_env_seconds("REA_GHIDRA_SWEEP_S", DEFAULT_GHIDRA_SWEEP_S), remaining_s)
        if budget < 1:
            warnings.append(Warning(code="ghidra_timeout", message="no time left for Ghidra analysis"))
            return "timeout"
        scripts = Path(os.environ.get("REA_GHIDRA_SCRIPTS") or DEFAULT_SCRIPTS_DIR)
        try:
            status = self._ghidra_fn(sample, project, budget, env=rea_env(job / "ghidra", os.environ),
                                     post_script=(scripts, GHIDRA_SCRIPT, strings_path))
        except Exception as exc:
            warnings.append(Warning(code="ghidra_failed", message=f"exception:{type(exc).__name__}"))
            return "failed"
        if status == "timeout":
            warnings.append(Warning(code="ghidra_timeout",
                                    message=f"Ghidra analysis exceeded its {budget:.0f}s sweep budget"))
            return "timeout"
        if status != "ok":
            warnings.append(Warning(code="ghidra_failed", message="Ghidra analysis failed"))
            return "failed"
        return "ok"

    @staticmethod
    def _continuation(sample: Path, outdir: Path, project: Path, ghidra_status: GhidraStatus,
                      limits: Limits, warnings: list[Warning],
                      sweep_evidence: dict[str, Any] | None = None) -> Path | None:
        dest = outdir / "continuation.tar.gz"
        state = State(
            pass_no=0,
            sample_name=sample.name,
            sample_sha256=_sha256(sample),
            program_name=sample.name if ghidra_status == "ok" else None,
            ghidra_status=ghidra_status,
            started_at=time.time(),
            sweep=dict(sweep_evidence or {}),
        )
        try:
            pack(dest, sample=sample, project_dir=project if ghidra_status == "ok" else None, state=state)
        except Exception as exc:
            dest.unlink(missing_ok=True)
            warnings.append(Warning(code="continuation_failed", message=f"exception:{type(exc).__name__}"))
            return None
        size = dest.stat().st_size
        report_cap = min(MAX_REPORT_BYTES, limits.max_artifact_bytes)
        if size > limits.max_artifact_bytes or size + report_cap > limits.max_total_artifact_bytes:
            dest.unlink(missing_ok=True)
            warnings.append(Warning(code="continuation_too_large",
                                    message=f"continuation is {size} bytes, over the artifact limit"))
            return None
        return dest

    @staticmethod
    def _budget(icons: list[Path], members: list[Path], cont: Path | None, report_cap: int,
                limits: Limits, warnings: list[Warning]) -> tuple[list[Path], list[Path]]:
        used = report_cap + (cont.stat().st_size if cont is not None else 0)
        count = 1 + (cont is not None)
        dropped = 0
        kept: dict[str, list[Path]] = {"icons": [], "members": []}
        for group, paths in (("icons", icons), ("members", members)):
            for p in paths:
                size = p.stat().st_size
                if (size > limits.max_artifact_bytes or used + size > limits.max_total_artifact_bytes
                        or count + 1 > limits.max_artifacts):
                    p.unlink(missing_ok=True)
                    dropped += 1
                    continue
                used += size
                count += 1
                kept[group].append(p)
        if dropped:
            warnings.append(Warning(code="artifact_budget",
                                    message=f"{dropped} icon/member file(s) dropped to stay within Limits"))
        return kept["icons"], kept["members"]

    @staticmethod
    def _write_report(path: Path, summary: dict[str, Any], iocs: list[Ioc],
                      inspect: dict[str, dict[str, Any]], cap: int, warnings: list[Warning],
                      capabilities: list[dict[str, Any]] | None = None,
                      api_hashes: apihash.ApiHashes | None = None,
                      resources: dict[str, Any] | None = None,
                      emulation: dict[str, Any] | None = None) -> None:
        results = dict(inspect)
        hashes = ({"algorithm": api_hashes.algorithm, "hits": api_hashes.hits}
                  if api_hashes is not None else None)
        ioc_rows = [{"type": i.type, "value": i.value, "source": i.source} for i in iocs]
        caps = list(capabilities or [])

        def encode() -> bytes:
            return json.dumps({**summary, "iocs": ioc_rows, "capabilities": caps, "api_hashes": hashes,
                               "dotnet_resources": resources, "emulation": emulation,
                               "inspect_results": results}).encode()

        data = encode()
        if len(data) > cap:
            warnings.append(Warning(code="report_truncated",
                                    message=f"report over {cap} bytes; largest inspect results truncated"))
            by_size = sorted(results, key=lambda c: len(json.dumps(results[c])), reverse=True)
            for cmd in by_size:
                results[cmd] = {"ok": bool(results[cmd].get("ok")), "truncated": True}
                data = encode()
                if len(data) <= cap:
                    break
            while len(data) > cap and (ioc_rows or caps):
                ioc_rows = ioc_rows[: len(ioc_rows) // 2]
                caps = caps[: len(caps) // 2]
                data = encode()
            if len(data) > cap:
                data = json.dumps({"schema": SCHEMA, "truncated": True}).encode()
        path.write_bytes(data)

    @staticmethod
    def _payload(summary: dict[str, Any], iocs: list[Ioc], limits: Limits,
                 warnings: list[Warning], capabilities: list[dict[str, Any]] | None = None) -> Record:
        budget = min(1024 * 1024, limits.max_metadata_bytes // 4)
        types: list[str | int | float | bool | None] = []
        values: list[str | int | float | bool | None] = []
        srcs: list[str | int | float | bool | None] = []
        used = 0
        for i in iocs:
            cost = len(json.dumps(i.value)) + len(json.dumps(i.source)) + len(i.type) + 16
            if used + cost > budget:
                warnings.append(Warning(code="iocs_payload_truncated",
                                        message=f"{len(iocs) - len(values)} IOC(s) only in the report artifact"))
                break
            used += cost
            types.append(i.type)
            values.append(i.value)
            srcs.append(i.source)
        inspect = Record(fields={c: Record(fields=dict(r)) for c, r in summary["inspect"].items()})
        fields: dict[str, Any] = {
            **{k: v for k, v in summary.items() if k != "inspect"},
            "inspect": inspect,
            # Record values cannot be lists of objects: IOCs travel as parallel columns.
            "iocs": Record(fields={"type": types, "value": values, "source": srcs}),
        }
        if capabilities:
            # Rule name, namespace and ATT&CK ids; the functions stay in the report artifact.
            caps = capabilities[:STATE_CAPABILITIES]
            fields["capabilities"] = Record(fields={
                "rule": [c["rule"] for c in caps],
                "namespace": [c["namespace"] for c in caps],
                "attack": [",".join(c["attack"]) for c in caps],
            })
        return Record(fields=fields)
