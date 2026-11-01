"""``rea`` — the deterministic pass-0 sweep (no model, no network).

One job, in order, everything under a fresh per-job dir in ``BLASTBOX_WORK_DIR``:

1. classify the sample by magic bytes;
2. run the fixed ``INSPECT_MAP[kind]`` REA inspect commands (no caller arguments);
3. ``extract-artifact`` for containers (archive/apk/asar/firmware) -> ``member-<n>``;
4. icons -> ``icon-<n>``;
5. native code (pe/elf/macho/dotnet): ``analyzeHeadless`` import + auto-analysis with the
   bundled ``ListStrings.java`` post-script dumping defined strings;
6. deterministic IOCs over the inspect JSON string leaves, the Ghidra strings and, for native
   code, UTF-16LE URL strings in the sample bytes (a .NET ``#US`` heap has no Ghidra string);
7. a continuation archive (sample + Ghidra project + ``State``), only when a model pass can
   follow. Otherwise the payload names why in ``chain_stop`` (Ruling AL, superseding "a Ghidra
   timeout still continues"), seals ``more_pending=false`` and packs no continuation;
8. a ``rea.report/1`` Record payload plus a full JSON ``report`` artifact.

``rea.report/1`` payload fields: ``schema``, ``kind``, ``inspect`` (``{cmd: {ok[, error]}}``),
``ghidra_status`` (ok | timeout | failed | skipped), ``members``, ``icons``, ``more_pending``,
``iocs_total``, ``iocs`` (parallel columns ``type``/``value``/``source``) and the optional
``chain_stop``. ``chain_stop`` is absent while the chain can continue; otherwise it is exactly
one of, checked in this order:

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
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.engines.rea.continuation import GhidraStatus, State, pack
from blastbox.engines.rea.icons import extract_icons
from blastbox.engines.rea.iocs import Ioc, extract_iocs, utf16le_urls
from blastbox.engines.rea.triage import packed, unsupported_arch
from blastbox.engines.rea.runner import (
    INSPECT_MAP,
    ReaRunner,
    classify,
    rea_env,
    run_ghidra_analysis,
)
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

_log = logging.getLogger("blastbox.engines.rea.sweep")

SCHEMA = "rea.report/1"
CHAIN_STOPS = ("ghidra_timeout", "ghidra_failed", "packed", "unsupported_arch", "not_native")
NATIVE_KINDS = frozenset({"pe", "elf", "macho", "dotnet"})
EXTRACT_KINDS = frozenset({"archive", "apk", "asar", "firmware"})

DEFAULT_GHIDRA_SWEEP_S = 420.0
DEFAULT_INSPECT_TIMEOUT_S = 60.0
EXTRACT_TIMEOUT_S = 120.0
GHIDRA_SCRIPT = "ListStrings.java"
DEFAULT_SCRIPTS_DIR = "/opt/rea/ghidra_scripts"

MAX_STRINGS_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 50_000
MAX_STRING_CHARS = 4096
MAX_IOCS = 2048
MAX_UTF16_SCAN_BYTES = 256 * 1024 * 1024
MAX_UTF16_URLS = 1024
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


def _read_ghidra_strings(path: Path) -> tuple[list[tuple[str, str]], bool, int, int | None]:
    """(``[(address, value)]``, truncated, malformed_lines, function_count) from ListStrings' JSONL.

    The first line may be ``{"function_count": N}`` (the program's function count); every
    other line is ``{"address", "value"}``.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return [], False, 0, None
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_STRINGS_BYTES + 1)
    truncated = len(data) > MAX_STRINGS_BYTES
    if truncated:
        data = data[:MAX_STRINGS_BYTES]
        data = data[: data.rfind(b"\n") + 1]
    out: list[tuple[str, str]] = []
    bad = 0
    function_count: int | None = None
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
        if n == 0 and isinstance(d, dict) and set(d) == {"function_count"}:
            fc = d["function_count"]
            if isinstance(fc, int) and not isinstance(fc, bool) and fc >= 0:
                function_count = fc
                continue
        addr = d.get("address") if isinstance(d, dict) else None
        val = d.get("value") if isinstance(d, dict) else None
        if not isinstance(addr, str) or not isinstance(val, str) or not 0 < len(addr) <= 64:
            bad += 1
            continue
        out.append((addr, val[:MAX_STRING_CHARS]))
    return out, truncated, bad, function_count


class ReaSweepEngine:
    """Pass 0 of the REA chain: deterministic inspection, extraction and Ghidra import."""

    name = "rea"
    formats = frozenset({"*"})
    jobs_per_recycle = 1

    def __init__(
        self,
        runner_factory: RunnerFactory = ReaRunner,
        ghidra_fn: GhidraFn = run_ghidra_analysis,
    ) -> None:
        self._runner_factory = runner_factory
        self._ghidra_fn = ghidra_fn

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
                    inspect[cmd] = runner.inspect(cmd, input, budget)
                except Exception as exc:  # an inspect failure never fails the job
                    inspect[cmd] = {"ok": False, "error": f"exception:{type(exc).__name__}"}
            if not inspect[cmd].get("ok"):
                err = str(inspect[cmd].get("error", "unknown"))
                inspect[cmd] = {"ok": False, "error": _short(err)}
                warnings.append(Warning(code="inspect_failed", message=f"{cmd}: {_short(err, 1000)}",
                                        context=cmd))

        # 2. extraction (containers only)
        members: list[Path] = []
        if kind in EXTRACT_KINDS:
            members = self._extract(runner, input, outdir / "members", min(EXTRACT_TIMEOUT_S, remaining()),
                                    warnings)

        # 3. icons
        icons_dir = outdir / "icons"
        icons_dir.mkdir(parents=True, exist_ok=True)
        icons = extract_icons(input, icons_dir, max_icons=MAX_ICONS)

        # 4. Ghidra
        ghidra_status: GhidraStatus = "skipped"
        project = job / "proj"
        strings_path = job / "strings.jsonl"
        if kind in NATIVE_KINDS:
            ghidra_status = self._ghidra(input, project, strings_path, job, remaining(), warnings)

        # 5. IOCs
        gstrings: list[tuple[str, str]] = []
        function_count: int | None = None
        if ghidra_status == "ok":
            gstrings, truncated, bad, function_count = _read_ghidra_strings(strings_path)
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
                wide_urls = _utf16_urls(input)
            except (OSError, ValueError) as exc:
                warnings.append(Warning(code="utf16_scan_failed", message=f"exception:{type(exc).__name__}"))

        def sources() -> Iterator[tuple[str, str]]:
            for cmd, res in inspect.items():
                if res.get("ok"):
                    for leaf in _string_leaves(res.get("result")):
                        yield f"inspect:{cmd}", leaf
            for addr, value in gstrings:
                yield f"ghidra:{addr}", value
            yield from wide_urls

        iocs = extract_iocs(sources(), limit=MAX_IOCS)
        if len(iocs) >= MAX_IOCS:
            warnings.append(Warning(code="iocs_capped", message=f"IOC extraction stopped at {MAX_IOCS}"))

        # 6. continuation: only when a model pass can follow it (Ruling AL). A failed or timed-out
        # Ghidra run would only repeat in the agent; non-native inputs, architectures REA's lane
        # rejects and packed stubs give the model nothing to analyse.
        chain_stop = self._chain_stop(input, kind, ghidra_status, function_count)
        chainable = chain_stop is None
        cont = (self._continuation(input, outdir, project, ghidra_status, limits, warnings)
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
        if chain_stop is not None:
            summary["chain_stop"] = chain_stop

        # 8. report artifact, then the payload
        report_path = outdir / "report.json"
        self._write_report(report_path, summary, iocs, inspect, report_cap, warnings)
        payload = self._payload(summary, iocs, limits, warnings)

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
                      limits: Limits, warnings: list[Warning]) -> Path | None:
        dest = outdir / "continuation.tar.gz"
        state = State(
            pass_no=0,
            sample_name=sample.name,
            sample_sha256=_sha256(sample),
            program_name=sample.name if ghidra_status == "ok" else None,
            ghidra_status=ghidra_status,
            started_at=time.time(),
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
                      inspect: dict[str, dict[str, Any]], cap: int, warnings: list[Warning]) -> None:
        results = dict(inspect)
        ioc_rows = [{"type": i.type, "value": i.value, "source": i.source} for i in iocs]

        def encode() -> bytes:
            return json.dumps({**summary, "iocs": ioc_rows, "inspect_results": results}).encode()

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
            while len(data) > cap and ioc_rows:
                ioc_rows = ioc_rows[: len(ioc_rows) // 2]
                data = encode()
            if len(data) > cap:
                data = json.dumps({"schema": SCHEMA, "truncated": True}).encode()
        path.write_bytes(data)

    @staticmethod
    def _payload(summary: dict[str, Any], iocs: list[Ioc], limits: Limits,
                 warnings: list[Warning]) -> Record:
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
        return Record(fields={
            **{k: v for k, v in summary.items() if k != "inspect"},
            "inspect": inspect,
            # Record values cannot be lists of objects: IOCs travel as parallel columns.
            "iocs": Record(fields={"type": types, "value": values, "source": srcs}),
        })
