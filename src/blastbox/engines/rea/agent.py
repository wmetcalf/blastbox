"""``rea-agent`` — one model-driven reverse-engineering pass (pass 1 and later).

Input is a continuation archive (``continuation.unpack``). The pass, all under a fresh per-job
dir in ``BLASTBOX_WORK_DIR``:

1. unpack and check the continuation (sample hash, program name); a corrupt one is ``rejected``;
2. if it carries no Ghidra project (the sweep timed out), run ``run_ghidra_analysis`` first with
   the remaining budget;
3. start REA's MCP server (``[REA_BIN, "--mcp"]``) over the saved project with ``rea_env`` plus
   ``REA_ANALYSIS_PROVIDER/REA_GHIDRA_PROJECT_PATH/REA_GHIDRA_PROGRAM_NAME``; the child gets no
   proxy variables (only ``ModelClient``, in this process, talks to the network);
4. ``open_binary`` on the unpacked sample; when ``State.todo`` and ``State.explored`` are both empty
   (pass 1 after the sweep), seed the todo list with ``procedure_info(entry)`` and
   ``list_procedures(detail=complete)``;
5. the model loop: the model sees only allowlisted tools (``policy.py``); each call is checked by
   ``policy.check_call`` (a refusal never reaches MCP and is returned as a tool error), and each
   result is framed as untrusted evidence by ``prompts.Framer``;
6. the final JSON answer (``response_format`` json_schema, bounded by ``prompts.final_schema``,
   reasoning off unless ``REA_FINAL_THINKING``) is parsed defensively; a cut-off answer keeps its
   complete rows (``salvage_json_prefix``), an unusable one is asked for once more. Function claims
   are kept only for citable addresses (``_Evidence``, Ruling S); a proposed IOC is ``verified``
   only when its value occurs in the sample's own bytes (``verify_iocs_in_sample``, Ruling R);
7. the next continuation (same project, updated ``State``) and a capped JSONL transcript are
   declared, and a ``rea.pass/1`` Record is sealed. The continuation is packed only when another
   pass can follow (``more_pending``); a final pass seals the transcript alone.

Budgets: the pass wall clock is ``min(REA_PASS_WALL_S (540), Limits.timeout_s - reserve)`` where the
reserve keeps time for packing and sealing; REA's 13-20 s session start is inside it. Turns are
capped by ``REA_MAX_STEPS`` (12). Tool-choice turns ask for at most ``REA_TURN_MAX_TOKENS`` (2048)
completion tokens, the final answer for ``REA_MAX_COMPLETION_TOKENS`` (4096). The tail of the wall
(:func:`final_reserve`, sized from the final budget at ``REA_MODEL_TOKENS_PER_S``) is kept for the
final answer: once exploration reaches it, tool turns stop and the final answer is forced with the
evidence gathered so far. Each model request's timeout is the time left for that phase, capped by
``REA_MODEL_TIMEOUT_S`` only when it is set. A request that fails with ``unavailable`` (timeout,
connection, HTTP error) is retried once while the phase still has time. Every tool result shown to
the model is cut to ``TOOL_RESULT_CHARS`` (head + tail around a truncation marker), and
``analyze_function`` always runs at ``detail=summary``.

Model failures never fail the job: ``model_status`` records ``unavailable``/``malformed`` (prior
summary kept, ``more_pending=False``) or ``budget`` (``more_pending=True``). ``skipped`` means the
model was not consulted because no Ghidra project or MCP session could be had.
"""

from __future__ import annotations

import json
import logging
import mmap
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.engines.rea.iocs import extract_iocs
from blastbox.engines.rea.continuation import ContinuationError, GhidraStatus, State, pack, unpack
from blastbox.engines.rea.mcp_client import McpError, McpStdioClient
from blastbox.engines.rea.model import ModelClient, ModelError
from blastbox.engines.rea.policy import ADDRESS_RE, TOOL_ALLOWLIST, CallRefused, check_call, model_tool_specs, safe_name
from blastbox.engines.rea.prompts import IOC_TYPES, Framer, final_response_format
from blastbox.engines.rea.runner import rea_env, run_ghidra_analysis
from blastbox.engines.rea.sweep import _env_seconds, _sha256, _string_leaves
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

__all__ = ["TOOL_ALLOWLIST", "FinalAnswer", "ReaAgentEngine", "TranscriptWriter", "parse_final",
           "salvage_json_prefix"]

_log = logging.getLogger("blastbox.engines.rea.agent")

SCHEMA = "rea.pass/1"
DEFAULT_MODEL_ID = "deepseek-v4-flash"
DEFAULT_PASS_WALL_S = 540.0
DEFAULT_MAX_STEPS = 12  # Ruling O
DEFAULT_MAX_TOKENS = 4096  # the final answer
DEFAULT_TURN_MAX_TOKENS = 2048  # each tool-choice turn
DEFAULT_TOKENS_PER_S = 30.0  # sizes the final-answer reserve (deepseek-v4-flash on vLLM, 1 sequence)
DEFAULT_TOOL_TIMEOUT_S = 120.0
DEFAULT_MAX_UNPACK_BYTES = 2 * 1024 * 1024 * 1024
MCP_START_TIMEOUT_S = 120.0
MIN_TURN_S = 5.0
MIN_MCP_S = 30.0
MAX_STEPS_CEILING = 200

MAX_CALLS_PER_TURN = 8
MAX_ARGS_CHARS = 16 * 1024
TOOL_RESULT_CHARS = 12 * 1024
# Tools whose ``detail=complete`` results are too large to feed back (65-297 KB live, one 3.6 MB):
# the engine always asks for ``summary``.
LIGHT_DETAIL_TOOLS: frozenset[str] = frozenset({"analyze_function"})
CONTEXT_CHARS = 300_000
KEEP_RECENT_TOOL_MSGS = 4
MAX_ADDRESSES = 500_000
MAX_RESULT_IOCS = 20_000

MAX_TRANSCRIPT_BYTES = 4 * 1024 * 1024
TRANSCRIPT_TEXT = 64 * 1024

MAX_SUMMARY = 8000
MAX_FUNCTIONS = 128
MAX_CLAIM = 2000
MAX_NAME = 256
MAX_IOCS = 256
MAX_IOC_VALUE = 2048
MAX_SOURCE = 256
MAX_TODO = 256
MAX_EXPLORED = 4096
SEED_TODO = 32
MAX_FINAL_CHARS = 1024 * 1024
MAX_SALVAGE_CHARS = 256 * 1024
MAX_SALVAGE_DEPTH = 64
MAX_SALVAGE_TRIES = 64
MIN_RETRY_TOKENS = 512  # a final-answer retry shorter than this cannot hold a useful answer

_MAIN_NAMES = ("main", "wmain", "_main", "WinMain", "wWinMain", "DllMain", "DllEntryPoint", "_start",
               "start", "entry")
_NAMED_SOURCES = frozenset({"imported", "user_defined", "user-defined", "user"})
# Ruling S: a citable address is 0x-prefixed hex in a content tool's normalized_result.
_ADDR_TOKEN = re.compile(r"(?<![0-9A-Za-z])0x([0-9a-fA-F]{1,16})(?![0-9A-Za-z])")
# Anything address-like the model typed (with or without 0x), anywhere in its arguments.
_ARG_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?([0-9a-fA-F]{1,16})(?![0-9A-Za-z])")
# Tools whose results describe the program (code, listings, references) rather than echo a query.
# Excluded on purpose: search_* / trace_* (echo the query), get_evidence_bundle (replays earlier
# records), inspect_* file parsers, binary_session, list_unknowns, address_name/comment/inline_comment.
CONTENT_TOOLS: frozenset[str] = frozenset({
    "analyze_function", "batch_decompile", "binary_overview", "find_xrefs_to_name", "get_call_graph",
    "inspect_address_context", "inspect_native_instruction", "list_names", "list_procedures",
    "list_segments", "list_strings", "procedure_address", "procedure_assembly", "procedure_callees",
    "procedure_callers", "procedure_info", "procedure_pseudo_code", "procedure_references",
    "read_function_instructions", "resolve_containing_procedure", "resolve_native_call_targets", "xrefs",
})
MAX_VERIFY_IOCS = 128  # Ruling R: sample-byte searches per pass
VERIFY_BUDGET_S = 60.0  # Ruling W: wall-clock cap on the sample-byte scan (also clamped to the pass)
VERIFY_RESERVE_S = 20.0  # kept out of the final answer's timeout for that scan
VERIFY_CHUNK = 8 * 1024 * 1024
MIN_IOC_CHARS = 4
_CASELESS_IOCS = frozenset({"url", "domain", "email"})
_PROGRAM_NAME = re.compile(r"^[^/\\\x00]{1,255}$")
_RESULT_LEAD = re.compile(r"^Result of call ([st][0-9]+) \(")

McpFactory = Callable[..., Any]
ModelFactory = Callable[..., Any]
GhidraFn = Callable[..., str]
Clock = Callable[[], float]


# ---------------------------------------------------------------- helpers


def final_reserve(wall_s: float, final_tokens: int = DEFAULT_MAX_TOKENS,
                  tokens_per_s: float = DEFAULT_TOKENS_PER_S) -> float:
    """Seconds of the pass kept back for the final-answer request (exploration stops earlier).

    Enough to generate ``final_tokens`` at ``tokens_per_s`` plus 25% for prompt processing, at
    least 60 s / 20% of the wall, never more than half the wall.
    """
    need = 1.25 * final_tokens / max(tokens_per_s, 1e-3)
    return min(wall_s / 2, max(60.0, 0.2 * wall_s, need))


def cap_tool_text(text: str, cap: int = TOOL_RESULT_CHARS) -> tuple[str, int]:
    """(text cut to about ``cap`` chars keeping head and tail, omitted chars); whole if it fits."""
    if len(text) <= cap:
        return text, 0
    tail = cap // 4
    head = cap - tail
    omitted = len(text) - cap
    return (text[:head] + f"\n[... {omitted} chars truncated by the engine; ask for a narrower view ...]\n"
            + text[len(text) - tail:]), omitted


def norm_addr(value: object) -> str | None:
    """``0x``-prefixed lowercase hex without leading zeros, or None if not an address."""
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        return None
    digits = value[2:] if value[:2].lower() == "0x" else value
    return "0x" + (digits.lower().lstrip("0") or "0")


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except ValueError:
        _log.warning("%s=%r is not an integer; using %s", name, raw, default)
        return default
    return max(lo, min(hi, v))


def _cap(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n]


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def render_result(result: dict[str, Any]) -> tuple[str, bool]:
    """(text, is_error) of an MCP ``tools/call`` result."""
    is_error = bool(result.get("isError"))
    content = result.get("content")
    texts = []
    if isinstance(content, list):
        texts = [c["text"] for c in content if isinstance(c, dict) and isinstance(c.get("text"), str)]
    if texts:
        return "\n".join(texts), is_error
    if "structuredContent" in result:
        return json.dumps(result["structuredContent"]), is_error
    return json.dumps(result), is_error


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def compact_for_model(text: str) -> str:
    """Drop REA's evidence boilerplate (profiles, limitations) and keep the result proper."""
    obj = _parse_json(text)
    if isinstance(obj, dict) and "normalized_result" in obj:
        keep = {k: obj[k] for k in ("operation", "parameters", "normalized_result") if k in obj}
        return json.dumps(keep, ensure_ascii=False)
    return text


class TranscriptWriter:
    """JSONL, capped while writing; the last line is a truncation marker once the cap is hit."""

    _MARKER = json.dumps({"event": "truncated", "reason": "transcript cap reached"}) + "\n"

    def __init__(self, path: Path, cap: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.path = path
        self._clock = clock
        self._t0 = clock()
        self.cap = max(len(self._MARKER), cap)
        self.size = 0
        self.truncated = False
        self._f: IO[str] | None = path.open("w", encoding="ascii")

    def write(self, obj: dict[str, Any]) -> bool:
        if self._f is None or self.truncated:
            return False
        stamped = {"t": round(self._clock() - self._t0, 2), **obj}
        line = json.dumps(stamped, ensure_ascii=True, default=str) + "\n"
        if self.size + len(line) + len(self._MARKER) > self.cap:
            self._f.write(self._MARKER)
            self.size += len(self._MARKER)
            self.truncated = True
            return False
        self._f.write(line)
        self.size += len(line)
        return True

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None


@dataclass
class FinalAnswer:
    summary: str = ""
    functions: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    todo: list[str] = field(default_factory=list)
    done: bool = False


def parse_final(text: object) -> FinalAnswer | None:
    """Parse the model's final JSON defensively; None when it is not a usable answer."""
    if not isinstance(text, str) or len(text) > MAX_FINAL_CHARS:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s[:4].lower() == "json":
            s = s[4:]
    start, end = s.find("{"), s.rfind("}")
    if start < 0 or end <= start:
        return None
    obj = _parse_json(s[start:end + 1])
    if not isinstance(obj, dict) or not {"summary", "functions", "iocs", "todo", "done"} & set(obj):
        return None
    ans = FinalAnswer()
    if isinstance(obj.get("summary"), str):
        ans.summary = _cap(obj["summary"].strip(), MAX_SUMMARY)
    raw_functions = obj.get("functions")
    for fn in raw_functions if isinstance(raw_functions, list) else []:
        if len(ans.functions) >= MAX_FUNCTIONS:
            break
        if not isinstance(fn, dict):
            continue
        addr = norm_addr(fn.get("address"))
        if addr is None:
            continue
        ev = fn.get("evidence")
        ans.functions.append({
            "address": addr,
            "name": _cap(fn["name"], MAX_NAME) if isinstance(fn.get("name"), str) else "",
            "claim": _cap(fn["claim"], MAX_CLAIM) if isinstance(fn.get("claim"), str) else "",
            "evidence": [e for e in ev if isinstance(e, str) and len(e) <= 16][:32] if isinstance(ev, list) else [],
        })
    raw_iocs = obj.get("iocs")
    for ioc in raw_iocs if isinstance(raw_iocs, list) else []:
        if len(ans.iocs) >= MAX_IOCS:
            break
        if not isinstance(ioc, dict) or ioc.get("type") not in IOC_TYPES:
            continue
        value = ioc.get("value")
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_IOC_VALUE:
            continue
        value = value.strip()
        if ioc["type"] == "domain":
            value = value.lower()
        src = ioc.get("source")
        ans.iocs.append({"type": ioc["type"], "value": value,
                         "source": _cap(src, MAX_SOURCE) if isinstance(src, str) else ""})
    todo = obj.get("todo")
    if isinstance(todo, list):
        ans.todo = [a for a in (norm_addr(x) for x in todo[:MAX_TODO]) if a is not None]
    ans.done = obj.get("done") is True
    return ans


_CLOSERS = {"{": "}", "[": "]"}


def salvage_json_prefix(text: object) -> str | None:
    """A cut-off JSON object closed right after its last complete value, or None.

    For a final answer that hit the token limit mid-way (live 2026-11-03: cut inside the 22nd
    function). Candidate cut points are the ends of complete strings, arrays and objects, the
    position before each comma and right after each ``[``; from the last one backwards (at most
    ``MAX_SALVAGE_TRIES``) the prefix plus the closers of the open containers is parsed, and the
    first that parses as an object wins. A cut-off value (string, number, row) is dropped whole.
    """
    if not isinstance(text, str) or len(text) > MAX_SALVAGE_CHARS:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = s.lstrip("`")
        if s[:4].lower() == "json":
            s = s[4:]
        s = s.lstrip()
    if not s.startswith("{"):
        return None
    stack: list[str] = []
    cuts: list[tuple[int, str]] = []

    def closers() -> str:
        return "".join(_CLOSERS[c] for c in reversed(stack))

    in_str = esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
                cuts.append((i + 1, closers()))
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
            if len(stack) > MAX_SALVAGE_DEPTH:
                return None
            if ch == "[":
                cuts.append((i + 1, closers()))
        elif ch in "}]":
            if not stack or _CLOSERS[stack[-1]] != ch:
                return None
            stack.pop()
            if not stack:
                return s[:i + 1]
            cuts.append((i + 1, closers()))
        elif ch == ",":
            cuts.append((i, closers()))
    for end, close in reversed(cuts[-MAX_SALVAGE_TRIES:]):
        cand = s[:end] + close
        if isinstance(_parse_json(cand), dict):
            return cand
    return None


# ---------------------------------------------------------------- per-pass evidence


class _Evidence:
    """Which addresses this pass may cite (Ruling S). IOCs are not verified from tool output at all.

    ``citable = engine_addresses | (content_addresses - model_addresses)``:
    - ``content_addresses``: 0x-addresses in the ``normalized_result`` of non-error results of
      ``CONTENT_TOOLS`` called by the model;
    - ``model_addresses``: every address-like value the model supplied in any argument of any
      call this pass (nested dicts/lists, refused calls included), normalised;
    - ``engine_addresses``: the same harvest from calls the engine made with fixed arguments
      (``list_procedures`` each pass, the seed ``procedure_info(entry)``). The model cannot shape
      those arguments, so its echo cannot launder an address into them. Without this term every
      function the model decompiled by address would be uncitable.
    """

    def __init__(self) -> None:
        self.results: dict[str, str] = {}  # every call id (citable as evidence), errors included
        self.content_addresses: set[str] = set()
        self.engine_addresses: set[str] = set()
        self.model_addresses: set[str] = set()

    @property
    def addresses(self) -> set[str]:
        return self.engine_addresses | (self.content_addresses - self.model_addresses)

    def note_model_args(self, value: Any, depth: int = 0) -> None:
        if depth > 32:
            return
        if isinstance(value, str):
            for m in _ARG_HEX.finditer(value):
                a = norm_addr(m.group(1))
                if a is not None:
                    self.model_addresses.add(a)
        elif isinstance(value, dict):
            for k, v in value.items():
                self.note_model_args(k, depth + 1)
                self.note_model_args(v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                self.note_model_args(v, depth + 1)

    def add(self, call_id: str, tool: str, text: str, *, is_error: bool, engine: bool) -> None:
        self.results[call_id] = text
        if is_error or tool not in CONTENT_TOOLS:
            return
        obj = _parse_json(text)
        if not isinstance(obj, dict) or "normalized_result" not in obj:
            return
        dest = self.engine_addresses if engine else self.content_addresses
        for leaf in _string_leaves(obj["normalized_result"]):
            for m in _ADDR_TOKEN.finditer(leaf):
                if len(dest) >= MAX_ADDRESSES:
                    return
                a = norm_addr(m.group(1))
                if a is not None:
                    dest.add(a)


def ioc_shape_ok(typ: str, value: str) -> bool:
    """Ruling V: ``value`` alone must be exactly one IOC of ``typ`` under iocs.py's own rules.

    ``extract_iocs`` on the bare value must report this very ``(type, value)``, so "Rich" is no
    mutex, ".dll" no domain (a dot plus an allowlisted TLD is required), "This" no URL.
    """
    return any(i.type == typ and i.value == value for i in extract_iocs([("shape", value)], limit=16))


def verify_iocs_in_sample(sample: Path, iocs: list[tuple[str, str]], time_left: Callable[[], float], *,
                          chunk_size: int = VERIFY_CHUNK) -> tuple[list[bool], bool]:
    """Ruling R/W: which IOC values occur in the sample's own bytes; (found flags, ran out of time).

    One pass over the mmap in ``chunk_size`` chunks overlapping by (longest needle - 1). Each value
    is searched as UTF-8 and UTF-16LE: exactly for most types, against ``chunk.lower()`` with
    lowered needles for url/domain/email (``bytes.lower`` folds ASCII only, so UTF-16LE's 0x00
    bytes survive). A needle leaves the search set once found. ``time_left()`` is checked per
    chunk; when it reaches 0 the rest stays unverified. Shape/length checks are the caller's.
    """
    found = [False] * len(iocs)
    exact: dict[bytes, set[int]] = {}
    caseless: dict[bytes, set[int]] = {}
    for i, (typ, value) in enumerate(iocs):
        table = caseless if typ in _CASELESS_IOCS else exact
        for enc in ("utf-8", "utf-16-le"):
            needle = value.encode(enc, "surrogatepass")
            if typ in _CASELESS_IOCS:
                needle = needle.lower()
            table.setdefault(needle, set()).add(i)
    if not exact and not caseless:
        return found, False
    try:
        fd = os.open(sample, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return found, False
    with os.fdopen(fd, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):  # empty file
            return found, False
        with mm:
            overlap = max(len(n) for n in (*exact, *caseless)) - 1
            pos, size = 0, len(mm)
            while pos < size and (exact or caseless):
                if time_left() <= 0:
                    return found, True
                chunk = mm[pos:pos + chunk_size + overlap]
                for table, hay in ((exact, chunk), (caseless, chunk.lower() if caseless else b"")):
                    for needle in [n for n in table if hay.find(n) != -1]:
                        for i in table.pop(needle):
                            found[i] = True
                # A needle is done once any of its encodings hit.
                for table in (exact, caseless):
                    for needle in [n for n, ids in table.items() if all(found[i] for i in ids)]:
                        del table[needle]
                pos += chunk_size
    return found, False


# ---------------------------------------------------------------- the engine


@dataclass
class _Pass:
    """Mutable state of one pass, gathered for the payload."""

    pass_no: int
    model_id: str
    model_status: str = "ok"
    steps: int = 0
    refused: int = 0
    tool_calls: int = 0
    summary: str = ""
    functions: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    todo: list[str] = field(default_factory=list)
    explored: list[str] = field(default_factory=list)
    done: bool = False
    final_reserve_s: float = 0.0
    wall_s: float = 0.0
    turn_tokens: int = DEFAULT_TURN_MAX_TOKENS
    tokens_per_s: float = DEFAULT_TOKENS_PER_S
    final_thinking: bool = False  # REA_FINAL_THINKING: keep the model's reasoning on for the final answer
    good_turns: int = 0  # model responses that parsed (with or without tool calls)
    accepted: bool = False  # _accept finished: functions/iocs/summary are one consistent answer
    warnings: list[Warning] = field(default_factory=list)


class ReaAgentEngine:
    """Passes >= 1 of the REA chain: DeepSeek drives read-only Ghidra tools over REA MCP."""

    name = "rea-agent"
    formats = frozenset({"*"})
    jobs_per_recycle = 1

    def __init__(
        self,
        mcp_factory: McpFactory = McpStdioClient,
        model_factory: ModelFactory = ModelClient,
        clock: Clock = time.monotonic,
        ghidra_fn: GhidraFn = run_ghidra_analysis,
    ) -> None:
        self._mcp_factory = mcp_factory
        self._model_factory = model_factory
        self._clock = clock
        self._ghidra_fn = ghidra_fn

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        base = Path(os.environ.get("BLASTBOX_WORK_DIR") or "/work")
        base.mkdir(parents=True, exist_ok=True)
        outdir.mkdir(parents=True, exist_ok=True)
        job = Path(tempfile.mkdtemp(prefix="rea-agent-", dir=base))
        try:
            return self._run(input, outdir, limits, job)
        finally:
            shutil.rmtree(job, ignore_errors=True)

    # ------------------------------------------------------------------ the pass
    def _run(self, input: Path, outdir: Path, limits: Limits, job: Path) -> DetonationResult:
        start = self._clock()
        reserve = max(15.0, min(90.0, 0.1 * limits.timeout_s))
        wall = min(_env_seconds("REA_PASS_WALL_S", DEFAULT_PASS_WALL_S), max(1.0, limits.timeout_s - reserve))
        deadline = start + wall

        def remaining() -> float:
            return deadline - self._clock()

        max_steps = _env_int("REA_MAX_STEPS", DEFAULT_MAX_STEPS, 1, MAX_STEPS_CEILING)
        max_tokens = _env_int("REA_MAX_COMPLETION_TOKENS", DEFAULT_MAX_TOKENS, 256, 131072)
        turn_tokens = min(max_tokens, _env_int("REA_TURN_MAX_TOKENS", DEFAULT_TURN_MAX_TOKENS, 256, 131072))
        tokens_per_s = _env_seconds("REA_MODEL_TOKENS_PER_S", DEFAULT_TOKENS_PER_S)
        model_id = os.environ.get("REA_MODEL_ID") or DEFAULT_MODEL_ID

        # 1. unpack + integrity
        unpack_cap = min(_env_int("REA_MAX_UNPACK_BYTES", DEFAULT_MAX_UNPACK_BYTES, 1 << 20, 1 << 40),
                         max(limits.tmpfs_bytes, 1 << 20))
        try:
            sample, project, state = unpack(input, job / "u", max_bytes=unpack_cap)
        except ContinuationError as exc:
            return self._rejected("bad_continuation", str(exc))
        if sample.name != state.sample_name or _sha256(sample) != state.sample_sha256:
            return self._rejected("bad_continuation", "sample does not match state.json")
        if state.program_name is not None and not _PROGRAM_NAME.fullmatch(state.program_name):
            return self._rejected("bad_continuation", "bad program_name in state.json")

        p = _Pass(pass_no=state.pass_no + 1, model_id=model_id, summary=state.summary,
                  todo=list(state.todo), explored=list(state.explored),
                  final_reserve_s=final_reserve(wall, max_tokens, tokens_per_s), wall_s=wall,
                  turn_tokens=turn_tokens, tokens_per_s=tokens_per_s,
                  final_thinking=os.environ.get("REA_FINAL_THINKING", "").strip().lower()
                  in ("1", "true", "yes", "on"))
        transcript_path = outdir / "transcript.jsonl"
        tw = TranscriptWriter(transcript_path, min(MAX_TRANSCRIPT_BYTES, limits.max_artifact_bytes), self._clock)
        tw.write({"event": "start", "pass_no": p.pass_no, "model": model_id, "wall_budget_s": round(wall, 1),
                  "max_steps": max_steps, "max_tokens": max_tokens, "turn_tokens": turn_tokens,
                  "final_reserve_s": round(p.final_reserve_s, 1)})

        ghidra_status: GhidraStatus = state.ghidra_status
        program_name = state.program_name
        gpr = project / "sample.gpr" if project is not None else None
        try:
            # 2. a project to work on
            if gpr is None or not gpr.is_file() or program_name is None:
                project = job / "u" / "project"
                ghidra_status = self._ghidra(sample, project, job, remaining() - MIN_MCP_S, p)
                if ghidra_status == "ok":
                    program_name = sample.name
                else:
                    project = None
            # 3-6. MCP session + model loop
            if project is not None and program_name is not None:
                if remaining() < MIN_MCP_S:
                    p.model_status = "budget"
                else:
                    self._session(sample, project, program_name, state, p, tw, remaining, job,
                                  max_steps, max_tokens)
            elif p.model_status == "ok":
                p.model_status = "skipped"
        except Exception as exc:  # an engine bug never fails the job or seals a refused shape
            _log.exception("rea-agent pass failed")
            p.warnings.append(Warning(code="agent_failed", message=f"exception:{type(exc).__name__}"))
            if not (p.accepted and p.model_status == "ok"):
                # Loadout accepts findings only with model_status ok. A half-applied answer is
                # dropped whole, so the sealed pass is a consistent "skipped" with no findings.
                p.model_status = "skipped"
                p.functions, p.iocs = [], []
                p.summary, p.done = state.summary, False
            # else: the final answer was fully accepted before the failure (e.g. MCP close):
            # it is sealed as the ok pass it is.

        # 7. continuation, transcript, payload
        next_state = State(
            pass_no=p.pass_no,
            sample_name=state.sample_name,
            sample_sha256=state.sample_sha256,
            program_name=program_name if project is not None else None,
            ghidra_status=ghidra_status,
            explored=p.explored[-MAX_EXPLORED:],
            todo=p.todo[:MAX_TODO],
            summary=p.summary,
            started_at=state.started_at,
        )
        transcript_reserve = min(MAX_TRANSCRIPT_BYTES, limits.max_artifact_bytes)
        if p.model_status == "ok":
            more = (not p.done) and bool(p.todo)
        elif p.model_status == "budget":
            more = True
        else:
            more = False
        # No pass can follow a final one: its continuation would only be retained, never used.
        cont = (self._continuation(outdir, sample, project, next_state, limits, transcript_reserve, p)
                if more else None)
        more_pending = more and cont is not None

        tw.write({"event": "end", "model_status": p.model_status, "steps": p.steps, "refused_calls": p.refused,
                  "tool_calls": p.tool_calls, "more_pending": more_pending,
                  "wall_s": round(self._clock() - start, 1)})
        tw.close()
        if tw.truncated:
            p.warnings.append(Warning(code="transcript_truncated",
                                      message=f"transcript capped at {tw.cap} bytes"))

        artifacts = []
        if cont is not None:
            artifacts.append(DeclaredArtifact(id="continuation", path=cont.relative_to(outdir).as_posix(),
                                              kind="rea_continuation"))
        artifacts.append(DeclaredArtifact(id="transcript", path="transcript.jsonl", kind="report"))
        return DetonationResult(
            payload=self._payload(p, more_pending, limits),
            artifacts=artifacts,
            detected=Detection(label="rea_continuation", mime="application/gzip", confidence=0.0,
                               source=self.name),
            warnings=p.warnings,
            status="ok",
        )

    # ------------------------------------------------------------------ steps
    def _rejected(self, code: str, message: str) -> DetonationResult:
        return DetonationResult(
            payload=Record(fields={"schema": SCHEMA, "error": code}),
            artifacts=[],
            detected=Detection(label="rea_continuation", mime="application/gzip", confidence=0.0,
                               source=self.name),
            warnings=[Warning(code=code, message=message[:2000])],
            status="rejected",
        )

    def _ghidra(self, sample: Path, project: Path, job: Path, budget: float, p: _Pass) -> GhidraStatus:
        if budget < 1:
            p.model_status = "budget"
            p.warnings.append(Warning(code="ghidra_timeout", message="no time left for Ghidra analysis"))
            return "timeout"
        try:
            status = self._ghidra_fn(sample, project, budget, env=rea_env(job / "ghidra", os.environ))
        except Exception as exc:
            status = "failed"
            p.warnings.append(Warning(code="ghidra_failed", message=f"exception:{type(exc).__name__}"))
            p.model_status = "skipped"
            return "failed"
        if status == "ok" and (project / "sample.gpr").is_file():
            return "ok"
        # A second miss would just repeat: stop the chain rather than loop on it.
        p.model_status = "skipped"
        if status == "timeout":
            p.warnings.append(Warning(code="ghidra_timeout",
                                      message=f"Ghidra analysis exceeded its {budget:.0f}s pass budget"))
            return "timeout"
        p.warnings.append(Warning(code="ghidra_failed", message="Ghidra analysis failed"))
        return "failed"

    def _session(self, sample: Path, project: Path, program_name: str, state: State, p: _Pass,
                 tw: TranscriptWriter, remaining: Callable[[], float], job: Path, max_steps: int,
                 max_tokens: int) -> None:
        mcp_dir = job / "mcp"
        env = rea_env(mcp_dir, os.environ)  # allowlisted: no proxy, no API keys
        env.update(
            REA_ANALYSIS_PROVIDER="ghidra",
            REA_GHIDRA_PROJECT_PATH=str((project / "sample.gpr").resolve()),
            REA_GHIDRA_PROGRAM_NAME=program_name,
        )
        rea_bin = os.environ.get("REA_BIN") or "rea"
        mcp: Any = None
        try:
            try:
                mcp = self._mcp_factory([rea_bin, "--mcp"], env, mcp_dir)
                mcp.start(timeout_s=max(1.0, min(MCP_START_TIMEOUT_S, remaining())))
                listed = {t["name"]: str(t.get("description") or "") for t in
                          mcp.list_tools(timeout_s=max(1.0, min(MCP_START_TIMEOUT_S, remaining())))}
                opened = mcp.call("open_binary", {"path": str(sample.resolve())},
                                  timeout_s=max(1.0, min(MCP_START_TIMEOUT_S, remaining())))
                if opened.get("isError"):
                    raise McpError("open_failed", _cap(render_result(opened)[0], 500))
            except (McpError, OSError) as exc:
                code = exc.code if isinstance(exc, McpError) else type(exc).__name__
                p.model_status = "skipped"
                p.warnings.append(Warning(code="mcp_failed", message=f"REA MCP session failed: {code}"[:2000]))
                tw.write({"event": "mcp_failed", "error": str(exc)[:2000]})
                return
            self._loop(mcp, listed, sample, state, p, tw, remaining, max_steps, max_tokens)
        finally:
            if mcp is not None:
                mcp.close()

    def _call_tool(self, mcp: Any, name: str, args: dict[str, Any], call_id: str, ev: _Evidence,
                   tw: TranscriptWriter, remaining: Callable[[], float], *,
                   engine: bool = False) -> tuple[str, bool]:
        tool_timeout = _env_seconds("REA_TOOL_TIMEOUT_S", DEFAULT_TOOL_TIMEOUT_S)
        try:
            res = mcp.call(name, args, timeout_s=max(1.0, min(tool_timeout, remaining())))
            text, is_error = render_result(res)
        except McpError as exc:
            if exc.code == "response_too_large":
                text = ("tool call failed: the result was too large to return. Ask for a narrower view: "
                        "detail=summary, one procedure at a time, or a smaller address range.")
            else:
                text = f"tool call failed: {exc}"
            is_error = True
        ev.add(call_id, name, text, is_error=is_error, engine=engine)
        tw.write({"event": "tool_result", "call_id": call_id, "tool": name, "is_error": is_error,
                  "chars": len(text), "text": text[:TRANSCRIPT_TEXT]})
        return text, is_error

    def _seed(self, mcp: Any, ev: _Evidence, tw: TranscriptWriter,
              remaining: Callable[[], float]) -> list[dict[str, str]]:
        """Todo seed from ``procedure_info(entry)`` + ``list_procedures(detail=complete)``.

        Order: the entry point, well-known main names, functions named by the binary's own
        symbols (exports / symbol table, ``symbol.source == imported``), then the rest by address.
        Externals and thunks are skipped. At most ``SEED_TODO`` entries.
        """
        seeds: list[dict[str, str]] = []
        entry_text, err = self._call_tool(mcp, "procedure_info", {"procedure": "entry"}, "s1", ev, tw, remaining,
                                          engine=True)
        if not err:
            obj = _parse_json(entry_text)
            nr = obj.get("normalized_result", obj) if isinstance(obj, dict) else None
            if isinstance(nr, dict):
                a = norm_addr(nr.get("entrypoint"))
                if a is not None:
                    seeds.append({"address": a, "name": _cap(str(nr.get("name") or "entry"), MAX_NAME)})
        if remaining() < MIN_TURN_S:
            return seeds
        list_text, err = self._call_tool(mcp, "list_procedures", {"detail": "complete"}, "s2", ev, tw, remaining,
                                         engine=True)
        rows: Any = None
        if not err:
            obj = _parse_json(list_text)
            rows = obj.get("normalized_result", obj) if isinstance(obj, dict) else obj
        main, named, rest = [], [], []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            a = norm_addr(row.get("address"))
            proc_raw, sym_raw = row.get("procedure"), row.get("symbol")
            proc: dict[str, Any] = proc_raw if isinstance(proc_raw, dict) else {}
            sym: dict[str, Any] = sym_raw if isinstance(sym_raw, dict) else {}
            if a is None or proc.get("external") or proc.get("thunk") or sym.get("external"):
                continue
            entry = {"address": a, "name": _cap(str(row.get("value") or ""), MAX_NAME)}
            if entry["name"] in _MAIN_NAMES:
                main.append(entry)
            elif sym.get("source") in _NAMED_SOURCES:
                named.append(entry)
            else:
                rest.append(entry)
        main.sort(key=lambda e: _MAIN_NAMES.index(e["name"]))
        rest.sort(key=lambda e: int(e["address"], 16))
        seen = {s["address"] for s in seeds}
        for e in main + named + rest:
            if len(seeds) >= SEED_TODO:
                break
            if e["address"] not in seen:
                seen.add(e["address"])
                seeds.append(e)
        tw.write({"event": "seed", "todo": seeds})
        return seeds

    def _loop(self, mcp: Any, listed: dict[str, str], sample: Path, state: State, p: _Pass,
              tw: TranscriptWriter, remaining: Callable[[], float], max_steps: int, max_tokens: int) -> None:
        explored_now: list[str] = []
        try:
            self._loop_body(mcp, listed, sample, state, p, tw, remaining, max_steps, max_tokens, explored_now)
        finally:
            # Every exit (ok, budget, failure) keeps what this pass explored and prunes the todo.
            p.explored = _dedup(p.explored + explored_now)
            done = set(p.explored)
            p.todo = [a for a in p.todo if a not in done]

    def _loop_body(self, mcp: Any, listed: dict[str, str], sample: Path, state: State, p: _Pass,
                   tw: TranscriptWriter, remaining: Callable[[], float], max_steps: int, max_tokens: int,
                   explored_now: list[str]) -> None:
        ev = _Evidence()
        framer = Framer()

        def explore_left() -> float:
            return remaining() - p.final_reserve_s

        sample_path = str(sample.resolve())
        tools = model_tool_specs(listed)
        tool_names = [t["function"]["name"] for t in tools]

        todo_view = [{"address": a, "name": ""} for a in p.todo[:SEED_TODO * 2]]
        seed_note = ""
        if not p.todo and not p.explored:
            seeds = self._seed(mcp, ev, tw, explore_left)
            p.todo = [s["address"] for s in seeds]
            todo_view = seeds
            seed_note = "The todo list was seeded by the engine from the entry point and the procedure list."
        else:
            # The engine's own procedure list makes real function entries citable (Ruling S).
            self._call_tool(mcp, "list_procedures", {"detail": "complete"}, "s0", ev, tw, explore_left,
                            engine=True)
        messages: list[dict[str, Any]] = [
            framer.system_message(tool_names, max_steps=max_steps),
            framer.initial_user_message(state, p.pass_no, todo=todo_view, explored=p.explored[-200:],
                                        seed_note=seed_note),
        ]
        url = os.environ.get("REA_MODEL_URL")
        if not url:
            p.model_status = "unavailable"
            p.warnings.append(Warning(code="model_unavailable", message="REA_MODEL_URL is not set"))
            return
        try:
            # No fixed per-request ceiling unless REA_MODEL_TIMEOUT_S is set: each request gets the
            # time left in its phase (a full answer at ~30 tok/s outlasts any fixed 240 s).
            model = self._model_factory(url, p.model_id,
                                        _env_seconds("REA_MODEL_TIMEOUT_S", max(1.0, p.wall_s)))
        except ValueError as exc:
            p.model_status = "unavailable"
            p.warnings.append(Warning(code="model_unavailable", message=str(exc)[:2000]))
            return

        counter = 0
        final_text: str | None = None
        while True:
            if p.steps >= max_steps:
                break
            if remaining() < MIN_TURN_S:
                p.model_status = "budget"
                break
            if explore_left() < MIN_TURN_S:
                break  # keep the reserve for the final answer
            try:
                resp = self._chat(model, p, tw, explore_left, messages, tools, p.turn_tokens)
            except ModelError as exc:
                if p.good_turns > 0 or (exc.kind == "unavailable" and remaining() >= 2 * MIN_TURN_S):
                    # Earlier turns worked: one failed turn must not waste them (Ruling O). With
                    # no good turn yet, the final-answer reserve is the last retry of an
                    # unreachable or slow endpoint before the pass seals ``unavailable``.
                    self._turn_failed(p, tw, str(exc))
                    break
                self._model_failed(p, tw, exc.kind, str(exc))
                return
            p.steps += 1
            parsed = _parse_message(resp)
            if remaining() <= 0 and not (parsed is not None and not parsed[1] and parsed[0]):
                # Out of time: only an already-received final answer (no tool calls) is still used.
                p.model_status = "budget"
                break
            if parsed is None:
                if p.good_turns > 0:
                    self._turn_failed(p, tw, "malformed: response has no usable message / tool_calls")
                    break
                self._model_failed(p, tw, "malformed", "response has no usable message / tool_calls")
                return
            p.good_turns += 1
            content, calls = parsed
            tw.write({"event": "model_turn", "step": p.steps, "content": (content or "")[:TRANSCRIPT_TEXT],
                      **_response_info(resp),
                      "tool_calls": [{"id": c["id"], "name": c["name"], "arguments": c["raw"][:2048]}
                                     for c in calls]})
            if not calls:
                final_text = content
                break
            messages.append({"role": "assistant", "content": content,
                             "tool_calls": [{"id": c["id"], "type": "function",
                                             "function": {"name": c["name"], "arguments": c["raw"]}}
                                            for c in calls]})
            out_of_time = False
            for i, c in enumerate(calls):
                counter += 1
                cid = f"t{counter}"
                tool = safe_name(c["name"])
                ev.note_model_args(c["args"] if c["args"] is not None else c["raw"])
                try:
                    if i >= MAX_CALLS_PER_TURN:
                        raise CallRefused(f"at most {MAX_CALLS_PER_TURN} tool calls per turn")
                    if c["args"] is None:
                        raise CallRefused("arguments are not a valid JSON object")
                    args = check_call(c["name"], c["args"], sample_path=sample_path)
                    if c["name"] in LIGHT_DETAIL_TOOLS:
                        args["detail"] = "summary"
                except CallRefused as exc:
                    p.refused += 1
                    tw.write({"event": "tool_call", "call_id": cid, "tool": c["name"][:128],
                              "arguments": c["raw"][:2048], "decision": "refused", "reason": str(exc)})
                    messages.append(framer.refusal(c["id"], cid, tool, str(exc)))
                    continue
                if out_of_time or explore_left() < 1:
                    out_of_time = True
                    messages.append(framer.refusal(c["id"], cid, tool, "the pass ran out of time"))
                    continue
                tw.write({"event": "tool_call", "call_id": cid, "tool": c["name"], "arguments": args,
                          "decision": "ok"})
                p.tool_calls += 1
                text, is_error = self._call_tool(mcp, c["name"], args, cid, ev, tw, explore_left)
                if not is_error:
                    for key in ("address", "procedure"):
                        a = norm_addr(args.get(key))
                        if a is not None:
                            explored_now.append(a)
                shown, omitted = cap_tool_text(compact_for_model(text))
                messages.append(framer.tool_result(c["id"], cid, c["name"], shown,
                                                   is_error=is_error, omitted_chars=omitted))
            if out_of_time:
                break  # straight to the final answer
            _compact_context(messages, framer)

        if p.model_status != "ok":
            return
        answer = parse_final(final_text) if final_text is not None else None
        if answer is None:
            # Keep the sample-byte IOC check's time out of the final answer's timeout, so a slow
            # answer cannot leave verification 0 s (every IOC would seal as "budget").
            verify_reserve = min(VERIFY_RESERVE_S, p.final_reserve_s / 4)

            def final_left() -> float:
                return remaining() - verify_reserve

            if final_left() < MIN_TURN_S:
                p.model_status = "budget"
                return
            messages.append(framer.final_request())
            _compact_context(messages, framer)
            answer = self._final_answer(model, p, tw, final_left, messages, framer, max_tokens)
            if answer is None:
                return
        self._accept(answer, ev, explored_now, p, tw, sample, remaining, self._clock)

    def _final_answer(self, model: Any, p: _Pass, tw: TranscriptWriter, final_left: Callable[[], float],
                      messages: list[dict[str, Any]], framer: Framer, max_tokens: int) -> FinalAnswer | None:
        """The final answer: schema-constrained, reasoning off (unless ``REA_FINAL_THINKING``).

        An answer that does not parse is salvaged (a cut-off object keeps its complete findings,
        ``done`` forced false); one with nothing to salvage is asked for once more, shorter, when
        the time left still holds ``MIN_RETRY_TOKENS`` at ``tokens_per_s``. None = pass sealed.
        """
        kw: dict[str, Any] = {"response_format": final_response_format()}
        if not p.final_thinking:
            kw["chat_template_kwargs"] = {"thinking": False}
        tokens = max_tokens
        for attempt in range(2):
            try:
                resp = self._chat(model, p, tw, final_left, messages, [], tokens, **kw)
            except ModelError as exc:
                self._final_failed(p, tw, exc.kind, str(exc))
                return None
            parsed = _parse_message(resp)
            content = parsed[0] if parsed is not None else None
            info = _response_info(resp)
            tw.write({"event": "final_turn", "attempt": attempt + 1, "content": (content or "")[:TRANSCRIPT_TEXT],
                      **info})
            answer = parse_final(content)
            if answer is not None:
                return answer
            salvaged = parse_final(salvage_json_prefix(content))
            if salvaged is not None and (salvaged.summary or salvaged.functions or salvaged.iocs):
                salvaged.done = False
                p.warnings.append(Warning(
                    code="model_final_salvaged",
                    message=f"final answer was cut off (finish_reason={info['finish_reason']}); kept its "
                            f"{len(salvaged.functions)} complete function(s) and {len(salvaged.iocs)} IOC(s)"))
                tw.write({"event": "final_salvaged", "functions": len(salvaged.functions),
                          "iocs": len(salvaged.iocs)})
                return salvaged
            tokens = min(max_tokens, int(max(0.0, final_left() - MIN_TURN_S) * p.tokens_per_s / 1.25))
            if attempt or tokens < MIN_RETRY_TOKENS:
                break
            p.warnings.append(Warning(code="model_final_retry",
                                      message=f"final answer unusable (finish_reason={info['finish_reason']}); "
                                              f"asking once more with {tokens} tokens"))
            tw.write({"event": "final_retry", "max_tokens": tokens})
            messages[-1] = framer.final_retry()
        self._final_failed(p, tw, "malformed", "final answer is not the required JSON object")
        return None

    @staticmethod
    def _chat(model: Any, p: _Pass, tw: TranscriptWriter, budget: Callable[[], float],
              messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int,
              **kw: Any) -> Any:
        """One model request with the phase's remaining time as its timeout; an ``unavailable``
        failure (timeout, connection, HTTP) is retried once while ``budget()`` leaves a turn."""
        try:
            return model.chat(messages, tools, max_tokens, timeout_s=max(1.0, budget()), **kw)
        except ModelError as exc:
            if exc.kind != "unavailable" or not _retryable(str(exc)) or budget() < MIN_TURN_S:
                raise
            p.warnings.append(Warning(code="model_retry", message=f"{exc}; retrying once"[:2000]))
            tw.write({"event": "model_retry", "message": str(exc)[:2000]})
        return model.chat(messages, tools, max_tokens, timeout_s=max(1.0, budget()), **kw)

    @staticmethod
    def _turn_failed(p: _Pass, tw: TranscriptWriter, message: str) -> None:
        p.warnings.append(Warning(code="model_turn_failed",
                                  message=f"{message} after {p.good_turns} good turn(s); "
                                          f"asking for the final answer"[:2000]))
        tw.write({"event": "model_turn_failed", "message": message[:2000]})

    def _final_failed(self, p: _Pass, tw: TranscriptWriter, kind: str, message: str) -> None:
        """The final answer failed: ``budget`` (chain continues) once any turn succeeded."""
        if p.good_turns == 0:
            self._model_failed(p, tw, kind, message)
            return
        p.model_status = "budget"
        p.warnings.append(Warning(code=f"model_{kind}",
                                  message=f"final answer failed ({message}); sealed as budget"[:2000]))
        tw.write({"event": "model_error", "kind": kind, "message": message[:2000], "sealed_as": "budget"})

    @staticmethod
    def _model_failed(p: _Pass, tw: TranscriptWriter, kind: str, message: str) -> None:
        p.model_status = kind
        p.warnings.append(Warning(code=f"model_{kind}", message=message[:2000]))
        tw.write({"event": "model_error", "kind": kind, "message": message[:2000]})

    @staticmethod
    def _accept(answer: FinalAnswer, ev: _Evidence, explored_now: list[str], p: _Pass,
                tw: TranscriptWriter, sample: Path, remaining: Callable[[], float],
                clock: Callable[[], float]) -> None:
        dropped = 0
        for fn in answer.functions:
            if fn["address"] not in ev.addresses:
                dropped += 1
                continue
            fn["evidence"] = _dedup([e for e in fn["evidence"] if e in ev.results])
            p.functions.append(fn)
        if dropped:
            p.warnings.append(Warning(code="claims_dropped",
                                      message=f"{dropped} function claim(s) cited an address no tool result contained"))
        seen: set[tuple[str, str]] = set()
        unique = []
        for ioc in answer.iocs:
            k = (ioc["type"], ioc["value"])
            if k not in seen:
                seen.add(k)
                unique.append(ioc)
        reasons = ["cap"] * len(unique)
        candidates: list[int] = []
        for i, ioc in enumerate(unique[:MAX_VERIFY_IOCS]):
            if not MIN_IOC_CHARS <= len(ioc["value"]) <= MAX_IOC_VALUE:
                reasons[i] = "length"
            elif not ioc_shape_ok(ioc["type"], ioc["value"]):
                reasons[i] = "shape"
            else:
                candidates.append(i)
        # remaining() ends at the pass deadline, which already sits the pack/seal reserve before
        # Limits.timeout_s; VERIFY_BUDGET_S caps the scan below that.
        scan_deadline = clock() + max(0.0, min(VERIFY_BUDGET_S, remaining()))
        hits, timed_out = verify_iocs_in_sample(
            sample, [(unique[i]["type"], unique[i]["value"]) for i in candidates],
            lambda: scan_deadline - clock())
        for i, hit in zip(candidates, hits):
            reasons[i] = "" if hit else ("budget" if timed_out else "not_in_sample")
        for i, ioc in enumerate(unique):
            p.iocs.append({**ioc, "verified": reasons[i] == "", "reason": reasons[i]})
        if timed_out:
            p.warnings.append(Warning(code="iocs_unverified_budget",
                                      message=f"sample-byte IOC check stopped at its time budget; "
                                              f"{sum(r == 'budget' for r in reasons)} IOC(s) left unverified"))
        if len(unique) > MAX_VERIFY_IOCS:
            p.warnings.append(Warning(code="iocs_unverified_cap",
                                      message=f"{len(unique) - MAX_VERIFY_IOCS} IOC(s) beyond the "
                                              f"{MAX_VERIFY_IOCS}-IOC check cap left unverified"))
        explored = _dedup(p.explored + explored_now + [f["address"] for f in p.functions])
        done = set(explored)
        new_todo = [a for a in answer.todo if a in ev.addresses]
        p.explored = explored
        p.todo = [a for a in _dedup(p.todo + new_todo) if a not in done][:MAX_TODO]
        if answer.summary:
            p.summary = answer.summary
        p.done = answer.done
        p.accepted = True
        tw.write({"event": "final", "summary": p.summary[:TRANSCRIPT_TEXT], "functions": p.functions,
                  "iocs": p.iocs, "todo": p.todo, "done": p.done, "claims_dropped": dropped})

    @staticmethod
    def _continuation(outdir: Path, sample: Path, project: Path | None, state: State, limits: Limits,
                      transcript_reserve: int, p: _Pass) -> Path | None:
        dest = outdir / "continuation.tar.gz"
        try:
            pack(dest, sample=sample, project_dir=project, state=state)
        except Exception as exc:
            dest.unlink(missing_ok=True)
            p.warnings.append(Warning(code="continuation_failed", message=f"exception:{type(exc).__name__}"))
            return None
        size = dest.stat().st_size
        if size > limits.max_artifact_bytes or size + transcript_reserve > limits.max_total_artifact_bytes:
            dest.unlink(missing_ok=True)
            p.warnings.append(Warning(code="continuation_too_large",
                                      message=f"continuation is {size} bytes, over the artifact limit"))
            return None
        return dest

    @staticmethod
    def _payload(p: _Pass, more_pending: bool, limits: Limits) -> Record:
        functions, iocs = list(p.functions), list(p.iocs)
        budget = max(64 * 1024, limits.max_metadata_bytes // 2)

        def build() -> Record:
            return Record(fields={
                "schema": SCHEMA,
                "pass_no": p.pass_no,
                "model": p.model_id,
                "model_status": p.model_status,
                "steps": p.steps,
                "refused_calls": p.refused,
                "tool_calls": p.tool_calls,
                # Record values cannot be lists of objects: rows travel as parallel columns.
                "functions": Record(fields={
                    "address": [f["address"] for f in functions],
                    "name": [f["name"] for f in functions],
                    "claim": [f["claim"] for f in functions],
                    "evidence": [",".join(f["evidence"]) for f in functions],
                }),
                "iocs": Record(fields={
                    "type": [i["type"] for i in iocs],
                    "value": [i["value"] for i in iocs],
                    "source": [i["source"] for i in iocs],
                    "verified": [i["verified"] for i in iocs],
                    # "" when verified; else shape | length | not_in_sample | budget | cap
                    "reason": [i["reason"] for i in iocs],
                }),
                "summary": p.summary,
                "todo_count": len(p.todo),
                "explored_count": len(p.explored),
                "done": p.done,
                "more_pending": more_pending,
            })

        rec = build()
        while len(rec.model_dump_json()) > budget and (functions or iocs):
            functions = functions[: len(functions) // 2]
            iocs = iocs[: len(iocs) // 2]
            rec = build()
        if len(functions) < len(p.functions) or len(iocs) < len(p.iocs):
            p.warnings.append(Warning(code="payload_truncated",
                                      message="functions/iocs trimmed to fit the metadata limit; "
                                              "the transcript artifact has the full lists"))
        return rec


_HTTP_STATUS = re.compile(r"\bhttp_(\d{3})\b")


def _retryable(message: str) -> bool:
    """An ``unavailable`` failure worth one retry: not an HTTP 4xx other than 408/429."""
    m = _HTTP_STATUS.search(message)
    if m is None:
        return True
    code = int(m.group(1))
    return not 400 <= code < 500 or code in (408, 429)


def _response_info(resp: Any) -> dict[str, Any]:
    """``finish_reason`` and ``completion_tokens`` of a response for the transcript (None if absent)."""
    finish = tokens = None
    if isinstance(resp, dict):
        choices = resp.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            fr = choices[0].get("finish_reason")
            finish = fr[:32] if isinstance(fr, str) else None
        usage = resp.get("usage")
        if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
            tokens = usage["completion_tokens"]
    return {"finish_reason": finish, "completion_tokens": tokens}


def _parse_message(resp: Any) -> tuple[str | None, list[dict[str, Any]]] | None:
    """(content, tool calls) from a chat-completions response, or None when it is malformed.

    Each call is ``{"id", "name", "raw", "args"}``; ``args`` is None when the arguments are not
    a JSON object (that call is refused, not the whole response). ``reasoning_content`` is ignored.
    """
    if not isinstance(resp, dict):
        return None
    choices = resp.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    msg = choices[0].get("message")
    if not isinstance(msg, dict):
        return None
    content = msg.get("content")
    if content is not None and not isinstance(content, str):
        return None
    raw_calls = msg.get("tool_calls")
    if raw_calls is None:
        return content, []
    if not isinstance(raw_calls, list) or len(raw_calls) > 64:
        return None
    calls = []
    for c in raw_calls:
        fn = c.get("function") if isinstance(c, dict) else None
        if not isinstance(fn, dict):
            return None
        cid, name, raw = c.get("id"), fn.get("name"), fn.get("arguments", "{}")
        if not isinstance(cid, str) or not 0 < len(cid) <= 128 or not isinstance(name, str) or not name:
            return None
        if isinstance(raw, dict):
            raw = json.dumps(raw)
        if not isinstance(raw, str):
            return None
        too_long = len(raw) > MAX_ARGS_CHARS
        raw = raw[:MAX_ARGS_CHARS]
        args = None if too_long else _parse_json(raw)
        calls.append({"id": cid, "name": name[:128], "raw": raw,
                      "args": args if isinstance(args, dict) else None})
    return content, calls


def _compact_context(messages: list[dict[str, Any]], framer: Framer) -> None:
    """Elide the oldest tool results once the conversation exceeds ``CONTEXT_CHARS``.

    Elided evidence stays in ``_Evidence`` (still citable).
    """
    total = sum(len(m.get("content") or "") for m in messages)
    if total <= CONTEXT_CHARS:
        return
    tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    for i in tool_idx[:-KEEP_RECENT_TOOL_MSGS]:
        m = messages[i]
        hit = _RESULT_LEAD.match(m.get("content") or "")
        if hit is None:
            continue  # a refusal or already elided
        before = len(m["content"])
        messages[i] = framer.elided(m["tool_call_id"], hit.group(1))
        total -= before - len(messages[i]["content"])
        if total <= CONTEXT_CHARS:
            break
