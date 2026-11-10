"""YARA signatures over the submitted file and every recovered stage: naming the family.

The sweep recovers stages (installer payloads, ``upx -d`` output, emulation captures, .NET payloads
hidden in resources) but nothing in it names the malware. This step matches each of them against
CAPEv2's family rules (``data/yara/CAPE``, compiled once at image build into
:data:`DEFAULT_RULES`) with YARA-X, out of process: :func:`scan` spawns ``signatures_runner.py``
under the yara venv's python (:data:`DEFAULT_PYTHON`, ``-I``) with ``ulimit -d`` (data memory),
``-t`` (CPU seconds) and ``-f 0`` (it writes no files), a wall-clock timeout, a stdout cap and caps
on every count and string. Nothing is executed: YARA matches bytes.

A target is ``(label, path)``; labels name where the bytes came from, e.g. ``"sample"``,
``"unpacked"``, ``"member:<name>"``, ``"hidden:<resource>"``, ``"capture:<n>"``. Targets with the
same content are scanned once (the first label wins, the others are listed in ``also``).

:class:`SigResult` / :func:`evidence` (``State.sweep["signatures"]``)::

    {"status": "ok" | "unavailable" | "timeout" | "failed", "reason"?: str,
     "engine": "yara-x", "rules": "CAPEv2 data/yara/CAPE", "rules_total": int,
     "targets": [{"label", "sha256", "size", "scanned"?: int, "error"?: str, "also"?: [label, ...]}],
     "matches": [{"rule", "family", "target", "sha256", "meta": {key: str | int | float | bool}}],
     "matches_total": int, "families": [str, ...]}

``family`` is the rule's ``family`` / ``malware`` meta, else its ``cape_type`` without a trailing
``Payload`` / ``Loader`` / ``Config`` word ("AgentTesla Payload" -> "AgentTesla"), else "".
``scanned`` is present when only the first :data:`MAX_TARGET_BYTES` of a larger target were
scanned. A ``timeout`` result keeps the targets finished before the kill. A YARA match says the
bytes contain what the rule's author tied to that family; it is evidence to weigh, not a verdict.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blastbox.engines.rea.runner import RunFn, bounded_run

DEFAULT_PYTHON = Path("/opt/yara/bin/python")
DEFAULT_RULES = Path("/opt/yara/cape.yarx")
ENGINE = "yara-x"
RULESET = "CAPEv2 data/yara/CAPE"

MAX_TARGETS = 64
MAX_TARGET_BYTES = 64 * 1024 * 1024  # larger targets: only their first MAX_TARGET_BYTES are scanned
PER_TARGET_S = 30  # YARA-X's own per-target timeout (it stops the scan, the next target goes on)
MAX_DATA_KB = 2 * 1024 * 1024  # ulimit -d: the target buffer, the rules and YARA-X's scan state
MAX_STDOUT = 1024 * 1024
MAX_MATCHES = 64  # (rule, target) pairs kept
MAX_META = 8
MAX_LABEL = 160
MAX_TEXT = 200
MAX_REASON = 200
SUMMARY_NAMES = 32
_META_KEYS = ("cape_type", "family", "malware", "description", "author", "packed", "reference")
_FAMILY_SUFFIX = re.compile(r"\s+(?:payload|loader|config|configuration)\s*$", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class SigTarget:
    label: str
    path: Path


@dataclass
class SigResult:
    status: str  # ok | unavailable | timeout | failed
    reason: str = ""
    rules_total: int = 0
    targets: list[dict[str, Any]] = field(default_factory=list)
    matches: list[dict[str, Any]] = field(default_factory=list)
    matches_total: int = 0


def _short(text: Any, n: int = MAX_TEXT) -> str:
    s = _CONTROL.sub(" ", text if isinstance(text, str) else str(text))
    return s if len(s) <= n else s[: n - 3] + "..."


def family(meta: Mapping[str, Any]) -> str:
    """The family a rule names: ``family`` / ``malware`` meta, else ``cape_type`` minus its kind word."""
    for key in ("family", "malware"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return _short(value.strip(), 64)
    value = meta.get("cape_type")
    if isinstance(value, str) and value.strip():
        return _short(_FAMILY_SUFFIX.sub("", value.strip()) or value.strip(), 64)
    return ""


def _sha256(path: Path) -> tuple[str, int] | None:
    h = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None
            while chunk := fh.read(1 << 20):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest(), st.st_size


def _meta(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key in _META_KEYS:
        value = raw.get(key)
        if isinstance(value, bool) or (isinstance(value, int) and abs(value) < 1 << 53):
            out[key] = value
        elif isinstance(value, str) and value:
            out[key] = _short(value)
        if len(out) >= MAX_META:
            break
    return out


def _parse(stdout: bytes, slots: list[dict[str, Any]], result: SigResult) -> tuple[bool, str, int]:
    """Fill ``result`` from the runner's JSON lines: ``(saw "done", setup error or "", targets finished)``."""
    done, error, finished = False, "", 0
    for line in stdout.splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        if "rules_total" in doc and isinstance(doc["rules_total"], int):
            result.rules_total = max(0, min(doc["rules_total"], 1 << 31))
        elif doc.get("done") is True:
            done = True
        elif isinstance(doc.get("i"), int) and 0 <= doc["i"] < len(slots):
            slot = slots[doc["i"]]
            finished += 1
            if "error" in doc:
                slot["error"] = _short(doc["error"], 32)
                continue
            scanned = doc.get("scanned")
            if isinstance(scanned, int) and scanned < slot["size"]:
                slot["scanned"] = scanned
            matches = doc.get("matches")
            for m in matches if isinstance(matches, list) else []:
                if not isinstance(m, dict) or not isinstance(m.get("rule"), str):
                    continue
                result.matches_total += 1
                if len(result.matches) >= MAX_MATCHES:
                    continue
                meta = _meta(m.get("meta"))
                result.matches.append({"rule": _short(m["rule"], 128), "family": family(meta),
                                       "target": slot["label"], "sha256": slot["sha256"], "meta": meta})
        elif isinstance(doc.get("error"), str):
            error = _short(doc["error"], MAX_REASON)
    return done, error, finished


def scan(
    targets: list[SigTarget],
    *,
    timeout_s: float,
    python: Path = DEFAULT_PYTHON,
    rules: Path = DEFAULT_RULES,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    run: RunFn = bounded_run,
) -> SigResult:
    """Match every target against the compiled rules; never raises for a target or tool problem."""
    from blastbox.engines.rea import signatures_runner

    if not python.is_file():
        return SigResult("unavailable", "no yara interpreter in this image")
    if not rules.is_file():
        return SigResult("unavailable", "no compiled rules in this image")
    slots: list[dict[str, Any]] = []
    paths: list[str] = []
    by_sha: dict[str, dict[str, Any]] = {}
    skipped = 0
    for target in targets:
        label = _short(target.label, MAX_LABEL) or "?"
        digest = _sha256(target.path)
        if digest is None:
            continue
        sha, size = digest
        if sha in by_sha:
            also = by_sha[sha].setdefault("also", [])
            if len(also) < 8:
                also.append(label)
            continue
        if len(slots) >= MAX_TARGETS:
            skipped += 1
            continue
        slot = {"label": label, "sha256": sha, "size": size}
        by_sha[sha] = slot
        slots.append(slot)
        paths.append(str(target.path.resolve()))
    if not slots:
        return SigResult("failed", "no readable target")
    if timeout_s < 1:
        return SigResult("timeout", "no time left to scan", targets=slots)
    cpu = max(1, int(timeout_s) + 1)
    argv = ["sh", "-c",
            'ulimit -d "$1" || exit 1; ulimit -t "$2" || exit 1; ulimit -f 0 || exit 1; shift 2; exec "$@"',
            "sh", str(MAX_DATA_KB), str(cpu), str(python), "-I", str(Path(signatures_runner.__file__).resolve()),
            "scan", str(rules), str(MAX_TARGET_BYTES), str(max(1, min(PER_TARGET_S, int(timeout_s)))), *paths]
    base_env = env if env is not None else {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
    result = SigResult("ok", targets=slots)
    try:
        out = run(argv, env=base_env, cwd=cwd, timeout_s=timeout_s, max_stdout=MAX_STDOUT)
    except OSError as exc:
        return SigResult("failed", _short(f"could not start the scanner: {type(exc).__name__}", MAX_REASON),
                         targets=slots)
    done, error, finished = _parse(out.stdout, slots, result)
    if skipped:
        result.reason = f"{skipped} target(s) over the {MAX_TARGETS}-target cap not scanned"
    if out.timed_out:
        result.status = "timeout"
        result.reason = f"scanner killed at its {timeout_s:.0f}s wall clock after {finished} of {len(slots)} target(s)"
    elif out.capped:
        result.status, result.reason = "failed", "scanner output over its cap"
    elif not done:
        result.status = "failed"
        result.reason = error or f"scanner exited with status {out.rc}"
    return result


def _distinct(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        if v:
            seen.setdefault(v, None)
    return list(seen)


def evidence(result: SigResult) -> dict[str, Any] | None:
    """What the sweep's evidence (and so the agent and the report) gets; None when nothing ran."""
    if result.status == "unavailable" or not result.targets:
        return None
    doc: dict[str, Any] = {"status": result.status, "engine": ENGINE, "rules": RULESET,
                           "rules_total": result.rules_total, "targets": result.targets,
                           "matches": result.matches, "matches_total": result.matches_total,
                           "families": _distinct([m["family"] for m in result.matches])}
    if result.reason:
        doc["reason"] = result.reason
    return doc


def summary_fields(result: SigResult) -> dict[str, Any]:
    """Flat summary fields (strings, ints and a list of strings only)."""
    names = _distinct([m["rule"] for m in result.matches])
    return {"signatures_status": result.status, "signatures_total": len(names),
            "signatures": names[:SUMMARY_NAMES]}
