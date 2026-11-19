"""``rea-agent`` — one model-driven reverse-engineering pass (pass 1 and later).

Input is a continuation archive (``continuation.unpack``). The pass, all under a fresh per-job
dir in ``BLASTBOX_WORK_DIR``:

1. unpack and check the continuation (sample hash, program name); a corrupt one is ``rejected``;
2. if it carries no Ghidra project (the sweep timed out), run ``run_ghidra_analysis`` first with
   the remaining budget, under the sweep's profile and analysis cut (``sweep._ghidra``);
3. start REA's MCP server (``[REA_BIN, "--mcp"]``) over the saved project with ``rea_env`` plus
   ``REA_ANALYSIS_PROVIDER/REA_GHIDRA_PROJECT_PATH/REA_GHIDRA_PROGRAM_NAME``; the child gets no
   proxy variables (only ``ModelClient``, in this process, talks to the network);
4. ``open_binary`` on the unpacked sample; when ``State.todo`` and ``State.explored`` are both empty
   (pass 1 after the sweep), seed the todo list with ``procedure_info(entry)`` and
   ``list_procedures(detail=complete)``, putting the functions capa matched (``State.sweep``
   ``capabilities``) right after the entry point and the main names;
5. the model loop: the model sees only allowlisted tools (``policy.py``); each call is checked by
   ``policy.check_call`` (a refusal never reaches MCP and is returned as a tool error), and each
   result is framed as untrusted evidence by ``prompts.Framer``;
6. the final JSON answer (``response_format`` json_schema, bounded by ``prompts.final_schema``,
   reasoning off unless ``REA_FINAL_THINKING``) is parsed defensively; a cut-off answer keeps its
   complete rows (``salvage_json_prefix``), an unusable one is asked for once more. Function claims
   are kept only for citable addresses (``_Evidence``, Ruling S); a proposed IOC is ``verified``
   only when its value occurs in the sample's own bytes (``verify_iocs_in_sample``, Ruling R),
   after a value read across a Go string literal's end is clipped to the literal
   (``gostrings.clip_overruns``);
7. the analysis report (G3, ``_report``): when the answer was accepted, one more schema-bound
   call (``prompts.report_schema``, reasoning off unless ``REA_FINAL_THINKING``) in its own short
   conversation, given this pass's findings, IOCs and summary, the sweep's evidence
   (``State.sweep``) and the previous report (``State.analysis_report``), sampled at
   ``REA_REPORT_TEMPERATURE`` (0; a negative value leaves it to the server). The model gives its
   own call and the grounds for it; ``verdict.apply`` checks the grounds, adds the sweep's own and
   sets the verdict's label and confidence by rule (transcript event ``verdict_rule``).
   ``report.validate_report``
   drops evidence addresses the analysis never saw and downgrades a section left without evidence;
   a skipped / failed / invalid report (``report_skipped_deadline`` / ``report_failed`` /
   ``report_invalid``) leaves the rest of the pass unchanged;
8. the deepening bar (``sufficiency.py``, ``_deepen``): an accepted pass with the report call on is
   checked against evidence the engine can verify (verdict strength, observed behaviour, capa
   leads the report left not analysed). Another pass follows
   only while the bar is unmet, the pass added a fact the chain did not have (else ``stalled``) and
   ``REA_MAX_PASSES`` (4) is not reached; the model's ``done`` flag is recorded but decides
   nothing. The gaps go to the next pass (``State.gaps``, ``open_gaps`` in its first message) and
   their capa target functions to the front of its todo list. With the report call off, ``done``
   and the todo list decide as before;
8a. the evidence-only pass (``_evidence_pass``): a continuation the sweep packed without a
   project because it had no disassembly to hand on (``State.ghidra_status`` timeout or failed,
   or skipped for a .NET assembly decompiled to C# instead) is not sent to Ghidra again. There
   is no MCP session and no tool turn: one report call writes ``rea.analysis/1`` from the
   sweep's evidence alone (``Framer.evidence_report_messages``), citing it by source
   (``basis: "evidence"``, rows ``{source, item, note}``), and the chain ends there with
   ``stop_reason`` ``evidence_only`` (or ``bar_met``). The pass seals ``model_status`` ok with no
   function claims and the ``evidence_only`` warning; a failed report call seals
   ``unavailable``, an invalid report ``malformed``;
9. the next continuation (same project, updated ``State``) and a capped JSONL transcript are
   declared, and a ``rea.pass/1`` Record is sealed. The continuation is packed only when another
   pass can follow (``more_pending``); a final pass seals the transcript alone.

Budgets: the pass wall clock is ``min(REA_PASS_WALL_S (540), Limits.timeout_s - reserve)`` where the
reserve keeps time for packing and sealing; REA's 13-20 s session start is inside it. Turns are
capped by ``REA_MAX_STEPS`` (16). Tool-choice turns ask for at most ``REA_TURN_MAX_TOKENS`` (2048)
completion tokens, the final answer for ``REA_MAX_COMPLETION_TOKENS`` (4096). The tail of the wall
(:func:`final_reserve`, sized from the final answer's plus the report's budget at
``REA_MODEL_TOKENS_PER_S``, at most half the wall) is kept for the final answer and the report:
once exploration reaches it, tool turns stop and the final answer is forced with the
evidence gathered so far. Each model request's timeout is the time left for that phase, capped by
``REA_MODEL_TIMEOUT_S`` only when it is set. A request that fails with ``unavailable`` (timeout,
connection, HTTP error) is retried once while the phase still has time. Every tool result shown to
the model is cut to ``TOOL_RESULT_CHARS`` (head + tail around a truncation marker), and
``analyze_function`` always runs at ``detail=summary``.

``rea.pass/1`` payload fields: ``schema``, ``pass_no``, ``model``, ``model_status``, ``steps``,
``refused_calls``, ``tool_calls``, ``functions`` (columns ``address``/``name``/``claim``/``evidence``),
``iocs`` (columns ``type``/``value``/``source``/``verified``/``reason``), ``summary``,
``todo_count``, ``explored_count``, ``done``, ``more_pending``; when the bar was applied,
``bar_met`` (bool), ``gaps`` (gap codes: ``no_report``, ``verdict_unknown``, ``verdict_low``,
``no_behaviour``, ``lead:<section>``) and ``stop_reason``
(``bar_met``/``stalled``/``pass_cap``/``evidence_only``, ``""`` while the chain continues); and, only when this pass wrote a
valid report, ``analysis_report``: the ``rea.analysis/1`` object as compact JSON text (a Record
cannot hold lists of objects), at most ``MAX_REPORT_JSON`` chars:

```text
{"schema": "rea.analysis/1", "pass": N,
 "verdict": {"label": benign|suspicious|malicious|unknown, "confidence": low|medium|high,
             "rationale": <= 600 chars},
 "sections": [{"key": overview|execution_flow|capabilities|network|persistence|host_activity|
                      anti_analysis|unknowns (each once, in this order),
               "title": <= 80, "status": observed|not_observed|not_analysed, "text": <= 1500,
               "evidence": [{"address": "0x<hex>", "function"?: <= 128, "note"?: <= 200}] <= 12}]}
```

The verdict's label and confidence are set by the verdict rule (``verdict.py``) from grounds the
engine checked or found itself; its rationale starts with the rule's line (``Rule: ...``), then
the model's own words. It is still an analysis opinion, never a detection, and everything else in
the object is untrusted model output.

The report call is capped at ``REA_REPORT_MAX_TOKENS`` (3500; 0 turns it off). The final reserve
plans for what the final answer and report actually use, not their caps: ``REA_RESERVE_TOKENS``
(4096; never more than the two caps together). Live G3 gate passes used at most 1816 + 1601. At
report time the call asks for ``min(REA_REPORT_MAX_TOKENS, what the
time left holds at the measured rate)`` and is skipped below ``MIN_REPORT_TOKENS``; the measured
rate is completion tokens over seconds of this pass's calls that reported usage.

Model failures never fail the job: ``model_status`` records ``unavailable``/``malformed``/
``out_of_credit``/``key_rejected``/``refused`` (prior summary kept, ``more_pending=False``; the last
three stop the pass at once, with no retry and no final answer; a failed report leaves it unchanged) or ``budget`` (``more_pending=True``). ``skipped`` means the
model was not consulted because no Ghidra project or MCP session could be had.
"""

from __future__ import annotations

import bisect
import hashlib
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
from blastbox.engines.rea.gostrings import clip_overruns, exact_iocs, go_strings
from blastbox.engines.rea.mcp_client import McpError, McpStdioClient
from blastbox.engines.rea.model import FATAL_KINDS, ModelClient, ModelError
from blastbox.engines.rea.reasoning_policy import capture_allowed
from blastbox.engines.rea.policy import ADDRESS_RE, TOOL_ALLOWLIST, CallRefused, check_call, model_tool_specs, safe_name
from blastbox.engines.rea.prompts import (
    IOC_TYPES,
    REPORT_BASIS,
    Framer,
    evidence_sources,
    final_response_format,
    report_response_format,
    script_sources,
)
from blastbox.engines.rea.report import ReportInvalid, complete_sections, report_addresses, validate_report
from blastbox.engines.rea.runner import classify, ghidra_profile, rea_env, run_ghidra_analysis
from blastbox.engines.rea.sufficiency import MAX_FACTS, assess, facts_of, sample_decompiled
from blastbox.engines.rea.sweep import (
    DEFAULT_SCRIPTS_DIR,
    GHIDRA_CUT_RESERVE_S,
    _env_seconds,
    _sha256,
    _string_leaves,
)
from blastbox.engines.rea.verdict import HOSTILE
from blastbox.engines.rea.verdict import apply as apply_verdict_rule
from blastbox.engines.rea.verdict import has_checked_ground, model_called
from blastbox.engines.rea.wellformed import well_formed
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

__all__ = ["TOOL_ALLOWLIST", "FinalAnswer", "ReaAgentEngine", "TranscriptWriter", "parse_final",
           "salvage_json_prefix"]

_log = logging.getLogger("blastbox.engines.rea.agent")

SCHEMA = "rea.pass/1"
DEFAULT_MODEL_ID = "deepseek-v4-flash"
DEFAULT_PASS_WALL_S = 540.0
DEFAULT_MAX_STEPS = 16  # Ruling O; 12 -> 16 in G3 (the bounded final answer freed the time)
DEFAULT_MAX_PASSES = 4  # REA_MAX_PASSES: the deepening bar's own pass cap (Loadout's chain cap also applies)
DEFAULT_MAX_TOKENS = 4096  # the final answer
DEFAULT_TURN_MAX_TOKENS = 2048  # each tool-choice turn
DEFAULT_TOKENS_PER_S = 30.0  # sizes the final-answer reserve (deepseek-v4-flash on vLLM, 1 sequence)
DEFAULT_REPORT_TEMPERATURE = 0.0  # REA_REPORT_TEMPERATURE; negative leaves sampling to the server
DEFAULT_REPORT_TOKENS = 3500  # the analysis-report call (REA_REPORT_MAX_TOKENS; 0 turns it off)
DEFAULT_RESERVE_TOKENS = 4096  # what the final reserve plans for (REA_RESERVE_TOKENS): final + report
MIN_REPORT_TOKENS = 1024  # below this the report call is skipped (report_skipped_deadline)
MAX_REPORT_JSON = 64 * 1024  # the sealed analysis_report JSON text
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
# A pass that keeps the model's reasoning may grow to this; MAX_TRANSCRIPT_BYTES of it stays
# reserved for everything else (TranscriptWriter drops reasoning first).
MAX_TRANSCRIPT_REASONING_BYTES = 16 * 1024 * 1024
_OFF = ("0", "false", "no", "off")
# The instructions in force: a digest of the prompts module as shipped (the ledger's `start`).
_PROMPT_SHA256 = hashlib.sha256(Path(__file__).with_name("prompts.py").read_bytes()).hexdigest()
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
MAX_PROGRAM_FUNCTIONS = 512
MAX_FINAL_CHARS = 1024 * 1024
MAX_SALVAGE_CHARS = 256 * 1024
MAX_SALVAGE_DEPTH = 64
MAX_SALVAGE_TRIES = 64
MIN_RETRY_TOKENS = 512  # a final-answer retry shorter than this cannot hold a useful answer

_MAIN_NAMES = ("main", "wmain", "_main", "WinMain", "wWinMain", "DllMain", "DllEntryPoint", "_start",
               "start", "entry")
_NAMED_SOURCES = frozenset({"imported", "user_defined", "user-defined", "user"})


def go_user_function(name: str) -> bool:
    """A Go function of the program's own packages, as Ghidra names it (``pkg::pkg.Func``).

    ``main`` is the program; an import path whose first element holds a dot (``github.com/...``)
    is a third-party module. Everything else is the standard library or the runtime. Compiler
    generated type helpers (``type:.eq.``) are not user code.
    """
    ns, sep, rest = name.partition("::")
    if not sep or rest.startswith("type:"):
        return False
    return ns == "main" or "." in ns.split("/", 1)[0]
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
# Tools whose result is a function's code: its decompilation, its disassembly, or the analysis of
# its body. One that returned this chain is what "the program's code was read" means to the
# verdict rule; naming a function (procedure_info, xrefs) or listing one in the answer is not.
CODE_TOOLS: frozenset[str] = frozenset({
    "analyze_function", "batch_decompile", "procedure_assembly", "procedure_pseudo_code",
    "read_function_instructions",
})
MAX_VERIFY_IOCS = 128  # Ruling R: sample-byte searches per pass
VERIFY_BUDGET_S = 60.0  # Ruling W: wall-clock cap on the sample-byte scan (also clamped to the pass)
VERIFY_RESERVE_S = 20.0  # kept out of the final answer's timeout for that scan
VERIFY_CHUNK = 8 * 1024 * 1024
GO_SCAN_S = 15.0  # Go string-header scan before the IOC byte check (gostrings.py)
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


def _code_addresses(args: dict[str, Any]) -> list[str]:
    """The addresses a CODE_TOOLS call asked for. A call that names its function instead gives
    none: that function counts as opened only once a call asks for it by address."""
    asked = [args.get("address"), args.get("procedure")]
    batch = args.get("addresses")
    if isinstance(batch, list):
        asked += batch
    return [a for a in map(norm_addr, asked) if a is not None]


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


def _report_temperature() -> float | None:
    """``REA_REPORT_TEMPERATURE`` in [0, 2]; ``None`` (a negative value) sends no temperature."""
    raw = os.environ.get("REA_REPORT_TEMPERATURE")
    value = DEFAULT_REPORT_TEMPERATURE
    if raw is not None:
        try:
            value = float(raw)
        except ValueError:
            value = float("nan")
        if value != value or value in (float("inf"), float("-inf")):
            _log.warning("REA_REPORT_TEMPERATURE=%r is not a number; using %s", raw, DEFAULT_REPORT_TEMPERATURE)
            value = DEFAULT_REPORT_TEMPERATURE
    return None if value < 0 else min(2.0, value)


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
    # strict=False: the model copies sample strings into its JSON, raw control characters and all
    # (a rejected report on a real ELF held one); they are cleaned where the text is kept. A lone
    # surrogate escape is replaced here: no later step could write it down (wellformed.py).
    try:
        return well_formed(json.loads(text, strict=False))
    except (ValueError, RecursionError):
        return None


def compact_for_model(text: str) -> str:
    """Drop REA's evidence boilerplate (profiles, limitations) and keep the result proper."""
    obj = _parse_json(text)
    if isinstance(obj, dict) and "normalized_result" in obj:
        keep = {k: obj[k] for k in ("operation", "parameters", "normalized_result") if k in obj}
        return json.dumps(keep, ensure_ascii=False)
    return text


BATCH_NOTE = ("not_shown were asked for and did not fit in this result: "
              "ask for them again, fewer per call")
MAX_BATCH_ITEMS = 64


def batch_view(text: str, asked: list[str], cap: int = TOOL_RESULT_CHARS) -> tuple[str, int, list[str]] | None:
    """What the model is shown of a batch decompile: ``(text, chars omitted, addresses read)``, or
    None when the result is not a batch.

    The result is rebuilt to hold whole functions, in the tool's order, up to ``cap``; the ones
    that do not fit are named under ``not_shown`` rather than lost in a cut through the middle of
    the JSON. A first function larger than the cap is shown with its code cut, as a single
    decompile is. ``addresses read`` are the asked-for functions shown with code: only those
    count as opened, so a batch of sixteen of which four were seen opens four."""
    obj = _parse_json(text)
    res = obj.get("normalized_result") if isinstance(obj, dict) and "normalized_result" in obj else obj
    if not isinstance(res, dict) or not isinstance(res.get("items"), list):
        return None
    items: list[Any] = res["items"]
    counts = {k: res[k] for k in ("total", "succeeded", "failed")
              if isinstance(res.get(k), int) and not isinstance(res.get(k), bool)}

    def label(item: Any) -> str:
        return (norm_addr(item.get("address")) if isinstance(item, dict) else None) or "?"

    def render(shown: list[Any], later: list[str]) -> str:
        body: dict[str, Any] = {"items": shown, **counts}
        if later:
            body["not_shown"], body["note"] = later, BATCH_NOTE
        return json.dumps({"operation": "batch_decompile", "normalized_result": body}, ensure_ascii=False)

    shown = list(items[:MAX_BATCH_ITEMS])
    later = [label(i) for i in items[MAX_BATCH_ITEMS:MAX_BATCH_ITEMS * 2]]
    sizes = [len(json.dumps(i, ensure_ascii=False)) for i in shown]
    keep, used = 0, 0
    while keep < len(shown) and (keep == 0 or used + sizes[keep] <= cap):
        used += sizes[keep]
        keep += 1
    shown, later = shown[:keep], [label(i) for i in shown[keep:]] + later
    out = render(shown, later)
    while len(out) > cap and len(shown) > 1:
        later.insert(0, label(shown.pop()))
        out = render(shown, later)
    cut = False
    if len(out) > cap:  # one function, larger than the cap on its own
        first = shown[0] if shown else None
        code = first.get("pseudocode") if isinstance(first, dict) else None
        if not isinstance(first, dict) or not isinstance(code, str):
            return None
        budget = cap
        while len(out) > cap and budget > 0:
            budget = budget * 3 // 4
            shown = [dict(first, pseudocode=cap_tool_text(code, budget)[0])]
            out = render(shown, later)
        if len(out) > cap:
            return None
        cut = True
    want = set(asked)
    read = [a for a in (label(i) for i in shown if isinstance(i, dict) and i.get("status") == "ok"
                        and isinstance(i.get("pseudocode"), str) and i["pseudocode"].strip())
            if a in want]
    omitted = max(0, len(compact_for_model(text)) - len(out)) if later or cut else 0
    return out, omitted, _dedup(read)


class TranscriptWriter:
    """JSONL, capped while writing; the last line is a truncation marker once the cap is hit."""

    _MARKER = json.dumps({"event": "truncated", "reason": "transcript cap reached"}) + "\n"

    def __init__(self, path: Path, cap: int, clock: Callable[[], float] = time.monotonic,
                 reasoning_reserve: int = 0) -> None:
        self.path = path
        # Bytes kept free of reasoning: a line whose reasoning would eat into them is written
        # without it (``reasoning_dropped``), so evidence outlives the model's thoughts.
        self.reasoning_reserve = max(0, reasoning_reserve)
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
        if ("reasoning" in stamped
                and self.size + len(line) + len(self._MARKER) > self.cap - self.reasoning_reserve):
            stamped = {k: v for k, v in stamped.items() if k != "reasoning"}
            stamped["reasoning_dropped"] = True
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


# Host-artifact shapes as they sit in a binary, which iocs.py's free-text rules (built to find
# IOCs in arbitrary strings, so hive-, drive- or Global\-anchored) reject: RegOpenKeyEx takes
# the hive as a handle, so the string is "Software\...\Run"; paths are "%APPDATA%\x.exe",
# "%s\cmds.dat", "/etc/rc.local" or a bare "dropper.exe"; a mutex is any name. Live 2026-11-04 every such IOC
# from a real worm was refused as "shape" before the byte check. The byte check is the gate:
# these only say the value is the kind of thing its type claims.
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_REG_RELATIVE = re.compile(r"(?:software|system|control panel|environment)\\\S", re.I)
_FILE_NAME = re.compile(r"[\w.$~{}-]+(?: [\w.$~{}-]+)*\.[A-Za-z][A-Za-z0-9]{1,3}")
_MUTEX_NAME = re.compile(r"[\w.{}#@$!-]{6,128}")
_POSIX_PATH = re.compile(r"/[^\s/]+(?:/[^\s/]*)*")


def ioc_shape_ok(typ: str, value: str) -> bool:
    """Ruling V: ``value`` alone must be exactly one IOC of ``typ`` under iocs.py's own rules.

    ``extract_iocs`` on the bare value must report this very ``(type, value)``, so "Rich" is no
    mutex, ".dll" no domain (a dot plus an allowlisted TLD is required), "This" no URL. A
    registry key, path or mutex may instead take its in-binary form (``_REG_RELATIVE``; a path
    with a backslash, an absolute POSIX path or a bare file name; ``_MUTEX_NAME``); none may hold a control character.
    """
    if any(i.type == typ and i.value == value for i in extract_iocs([("shape", value)], limit=16)):
        return True
    if _CTRL.search(value):
        return False
    if typ == "registry":
        return _REG_RELATIVE.match(value) is not None
    if typ == "path":
        return ("\\" in value.strip("\\") or _POSIX_PATH.fullmatch(value) is not None
                or _FILE_NAME.fullmatch(value) is not None)
    if typ == "mutex":
        return _MUTEX_NAME.fullmatch(value) is not None
    return False


# DeepSeek drops or garbles backslashes when it copies a Windows path into its answer (live
# 2026-11-05: "C:2 Usersdevsource..." for C:\Users\dev\source..., "SoftwareMicrosoftWindows..."),
# and the IOC fails its shape check. A host-artifact IOC whose letters-only form equals exactly one
# string a tool returned this pass takes that string. The byte check still decides: a snapped
# value is verified only if it occurs in the sample.
SNAP_TYPES = frozenset({"path", "registry", "mutex"})
MIN_SNAP_KEY = 10
MAX_SNAP_LEAVES = 200_000
_NOT_LETTER = re.compile(r"[^a-z]")


def _snap_key(value: str) -> str:
    return _NOT_LETTER.sub("", value.lower())


def snap_iocs(iocs: list[dict[str, Any]], texts: list[str]) -> int:
    """Replace each mangled host-artifact IOC value with the tool-result string it matches.

    Matching is on :func:`_snap_key` (letters only, case-folded), at least ``MIN_SNAP_KEY``
    letters, against the string leaves of the tool results' ``normalized_result``. Only a unique
    match is taken.
    Returns how many values changed.
    """
    wanted = {_snap_key(i["value"]) for i in iocs if i["type"] in SNAP_TYPES}
    wanted = {k for k in wanted if len(k) >= MIN_SNAP_KEY}
    if not wanted:
        return 0
    found: dict[str, set[str]] = {}
    seen = 0
    for text in texts:
        obj = _parse_json(text)
        # normalized_result only: a search tool echoes the model's own (mangled) query beside it.
        body = obj.get("normalized_result") if isinstance(obj, dict) else None
        for leaf in _string_leaves(body) if body is not None else ():
            seen += 1
            if seen > MAX_SNAP_LEAVES:
                break
            leaf = leaf.strip()
            if MIN_IOC_CHARS <= len(leaf) <= MAX_IOC_VALUE and (k := _snap_key(leaf)) in wanted:
                found.setdefault(k, set()).add(leaf)
    changed = 0
    for i in iocs:
        hits = found.get(_snap_key(i["value"])) if i["type"] in SNAP_TYPES else None
        if hits is not None and len(hits) == 1 and i["value"] not in hits:
            i["value"] = next(iter(hits))
            changed += 1
    return changed


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


def capa_functions(sweep: dict[str, Any]) -> list[str]:
    """The function addresses capa matched, in the sweep's rule order, each once."""
    out: list[str] = []
    caps = sweep.get("capabilities")
    for c in caps if isinstance(caps, list) else []:
        fns = c.get("functions") if isinstance(c, dict) else None
        for f in fns if isinstance(fns, list) else []:
            if isinstance(f, str) and f.startswith("0x") and f not in out:
                out.append(f)
    return out


def hash_sites(sweep: dict[str, Any]) -> list[int]:
    """The VAs where the sweep found hashed API constants (``api_hashes``), each once."""
    hashes = sweep.get("api_hashes")
    hits = hashes.get("hits") if isinstance(hashes, dict) else None
    out: list[int] = []
    for h in hits if isinstance(hits, list) else []:
        sites = h.get("sites") if isinstance(h, dict) else None
        for site in sites if isinstance(sites, list) else []:
            a = norm_addr(site)
            if a is not None and int(a, 16) not in out:
                out.append(int(a, 16))
    return out


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
    code_read: bool = False  # a CODE_TOOLS call returned code, this pass or an earlier one
    opened: list[str] = field(default_factory=list)  # the addresses those calls asked for
    touched: list[str] = field(default_factory=list)  # what this pass's own tool loop explored
    given: list[str] = field(default_factory=list)  # the todo list it started on (the state's, or its seeds)
    done: bool = False
    final_reserve_s: float = 0.0
    wall_s: float = 0.0
    turn_tokens: int = DEFAULT_TURN_MAX_TOKENS
    tokens_per_s: float = DEFAULT_TOKENS_PER_S
    final_thinking: bool = False  # REA_FINAL_THINKING: keep the model's reasoning on for the final answer
    retain_reasoning: bool = False  # write the model's reasoning to the transcript (never sent back)
    good_turns: int = 0  # model responses that parsed (with or without tool calls)
    report_tokens: int = DEFAULT_REPORT_TOKENS
    report: dict[str, Any] | None = None  # this pass's validated rea.analysis/1 report
    opinion: str | None = None  # the model's own call in that report, before the verdict rule
    prior_report: dict[str, Any] | None = None  # the continuation's (last valid) report
    prior_called: bool = False  # ... which carries the model's own call (not one cut off before it)
    sweep: dict[str, Any] = field(default_factory=dict)
    program_functions: list[str] = field(default_factory=list)
    model_tokens: int = 0  # completion tokens of the calls that reported usage ...
    model_seconds: float = 0.0  # ... and the seconds those calls took (the measured rate)
    accepted: bool = False  # _accept finished: functions/iocs/summary are one consistent answer
    # The deepening bar (sufficiency.py), set only when an accepted pass was assessed.
    assessed: bool = False
    bar_met: bool = False
    gaps: list[dict[str, str]] = field(default_factory=list)
    stop_reason: str = ""  # bar_met | stalled | pass_cap | evidence_only; "" when the chain continues
    evidence_only: bool = False  # no disassembly: the report was written from the sweep's evidence
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
        report_tokens = _env_int("REA_REPORT_MAX_TOKENS", DEFAULT_REPORT_TOKENS, 0, 131072)
        reserve_tokens = min(max_tokens + report_tokens,
                             _env_int("REA_RESERVE_TOKENS", DEFAULT_RESERVE_TOKENS, 256, 262144))
        model_id = os.environ.get("REA_MODEL_ID") or DEFAULT_MODEL_ID
        retain = (os.environ.get("REA_RETAIN_REASONING", "").strip().lower() not in _OFF
                  and capture_allowed(model_id))

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
                  todo=list(state.todo), given=list(state.todo), explored=list(state.explored),
                  code_read=state.code_read,
                  opened=list(state.opened),
                  final_reserve_s=final_reserve(wall, reserve_tokens, tokens_per_s), wall_s=wall,
                  turn_tokens=turn_tokens, tokens_per_s=tokens_per_s,
                  final_thinking=os.environ.get("REA_FINAL_THINKING", "").strip().lower()
                  in ("1", "true", "yes", "on"),
                  retain_reasoning=retain,
                  report_tokens=report_tokens, prior_report=_sealed_report(state.analysis_report),
                  prior_called=state.opinion is not None,
                  sweep=dict(state.sweep), program_functions=list(state.program_functions))
        transcript_path = outdir / "transcript.jsonl"
        base_cap = min(MAX_TRANSCRIPT_BYTES, limits.max_artifact_bytes)
        if p.retain_reasoning:
            tw = TranscriptWriter(transcript_path, min(MAX_TRANSCRIPT_REASONING_BYTES, limits.max_artifact_bytes),
                                  self._clock, reasoning_reserve=base_cap)
        else:
            tw = TranscriptWriter(transcript_path, base_cap, self._clock)
        tw.write({"event": "start", "pass_no": p.pass_no, "model": model_id, "wall_budget_s": round(wall, 1),
                  "max_steps": max_steps, "max_tokens": max_tokens, "turn_tokens": turn_tokens,
                  "report_tokens": report_tokens, "final_reserve_s": round(p.final_reserve_s, 1),
                  "rea_build": os.environ.get("REA_COMMIT", ""),
                  "tools_sha256": os.environ.get("REA_TOOLS_SHA256", ""),
                  "prompt_sha256": _PROMPT_SHA256, "retain_reasoning": p.retain_reasoning})

        ghidra_status: GhidraStatus = state.ghidra_status
        program_name = state.program_name
        gpr = project / "sample.gpr" if project is not None else None
        try:
            # 2. a project to work on
            no_project = gpr is None or not gpr.is_file() or program_name is None
            if no_project and state.ghidra_status != "ok" and evidence_sources(p.sweep):
                # The sweep had no disassembly to hand on, and a second Ghidra run would only
                # repeat: write the report from the sweep's evidence instead.
                project = None
                self._evidence_pass(state, p, tw, remaining)
            elif no_project:
                project = job / "u" / "project"
                ghidra_status = self._ghidra(sample, project, job, remaining() - MIN_MCP_S, p)
                if ghidra_status == "ok":
                    program_name = sample.name
                    if p.sweep.get("ghidra_analysis") == "cut":
                        state.sweep["ghidra_analysis"] = "cut"  # this pass's first message reads state.sweep
                else:
                    project = None
            # 3-6. MCP session + model loop
            if project is not None and program_name is not None:
                if remaining() < MIN_MCP_S:
                    p.model_status = "budget"
                else:
                    self._session(sample, project, program_name, state, p, tw, remaining, job,
                                  max_steps, max_tokens)
            elif p.model_status == "ok" and not p.evidence_only:
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
                p.report, p.accepted = None, False
            # else: the final answer was fully accepted before the failure (e.g. MCP close):
            # it is sealed as the ok pass it is.

        if not p.accepted:
            # A pass that lost its final answer hands on the lists it started on (a first pass,
            # its seeds). No answer covers what it explored, so none of that closes a lead or
            # leaves the todo list: it goes to the back, and the next pass starts on what this one
            # did not reach. Code it opened off the todo list joins the back too, unless an
            # earlier answer already covered it (an address it only gave a tool that reads no
            # code is not a function to queue).
            lost, covered = set(p.touched), set(state.explored) | set(p.given)
            p.explored = list(state.explored)
            p.todo = ([a for a in p.given if a not in lost] + [a for a in p.given if a in lost]
                      + [a for a in p.opened if a not in covered])
        facts = list(state.facts)
        if p.model_status == "ok" and p.accepted and p.report_tokens > 0:
            # With the report call off (REA_REPORT_MAX_TOKENS=0) there is no verdict to measure,
            # and the model's done flag decides as before.
            facts = self._deepen(p, state, tw)

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
            # Pass N+1 rewrites the latest valid report, this pass's or the one it was given.
            analysis_report=p.report if p.report is not None else p.prior_report,
            sweep=p.sweep,
            facts=facts,
            gaps=p.gaps if p.assessed else list(state.gaps),
            program_functions=p.program_functions[:MAX_PROGRAM_FUNCTIONS],
            opinion=p.opinion if p.report is not None else state.opinion,
            # What a pass read counts for later reports only with the answer it gave about it:
            # a pass that lost its answer left nothing of that reading for a later report to rest on.
            code_read=p.code_read if p.accepted else state.code_read,
            opened=p.opened[-MAX_EXPLORED:] if p.accepted else list(state.opened),
        )
        transcript_reserve = tw.cap
        if p.model_status == "ok" and p.assessed:
            more = not p.stop_reason
        elif p.model_status == "ok":
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
        # Same profile and analysis cut as the sweep's run (sweep._ghidra).
        profile = ghidra_profile(sample, classify(sample))
        cut = int(budget) - GHIDRA_CUT_RESERVE_S if budget >= 2 * GHIDRA_CUT_RESERVE_S else None
        try:
            status = self._ghidra_fn(sample, project, budget, env=rea_env(job / "ghidra", os.environ),
                                     profile=profile, analysis_timeout_s=cut,
                                     script_dir=Path(os.environ.get("REA_GHIDRA_SCRIPTS") or DEFAULT_SCRIPTS_DIR))
        except Exception as exc:
            status = "failed"
            p.warnings.append(Warning(code="ghidra_failed", message=f"exception:{type(exc).__name__}"))
            p.model_status = "skipped"
            return "failed"
        if status in ("ok", "partial") and (project / "sample.gpr").is_file():
            if status == "partial":
                p.sweep["ghidra_analysis"] = "cut"
                p.warnings.append(Warning(code="ghidra_partial",
                                          message=f"Ghidra's auto-analysis ({profile} profile) was cut at {cut}s: "
                                                  "the project is usable but incomplete"))
            return "ok"
        # A second miss would just repeat: stop the chain rather than loop on it.
        p.model_status = "skipped"
        if status == "timeout":
            p.warnings.append(Warning(code="ghidra_timeout",
                                      message=f"Ghidra analysis exceeded its {budget:.0f}s pass budget"))
            return "timeout"
        p.warnings.append(Warning(code="ghidra_failed", message="Ghidra analysis failed"))
        return "failed"

    def _model(self, p: _Pass) -> Any | None:
        """The model client, or None with ``model_status`` unavailable."""
        url = os.environ.get("REA_MODEL_URL")
        if not url:
            p.model_status = "unavailable"
            p.warnings.append(Warning(code="model_unavailable", message="REA_MODEL_URL is not set"))
            return None
        try:
            # No fixed per-request ceiling unless REA_MODEL_TIMEOUT_S is set: each request gets the
            # time left in its phase (a full answer at ~30 tok/s outlasts any fixed 240 s).
            return self._model_factory(url, p.model_id, _env_seconds("REA_MODEL_TIMEOUT_S", max(1.0, p.wall_s)))
        except ValueError as exc:
            p.model_status = "unavailable"
            p.warnings.append(Warning(code="model_unavailable", message=str(exc)[:2000]))
            return None

    def _evidence_pass(self, state: State, p: _Pass, tw: TranscriptWriter,
                       remaining: Callable[[], float]) -> None:
        """The report from the sweep's evidence alone (module docstring, step 8a)."""
        p.evidence_only = True
        sources = evidence_sources(p.sweep)
        tw.write({"event": "evidence_only", "ghidra_status": state.ghidra_status, "sources": sources})
        if p.report_tokens <= 0:  # the report call is switched off: nothing else can run
            p.model_status = "skipped"
            return
        model = self._model(p)
        if model is None:
            return
        outcome = self._report(model, p, tw, remaining, Framer(), state.sample_name, set(), sources=sources,
                               ghidra_status=state.ghidra_status)
        if outcome == "ok" and p.report is not None:
            overview = next((sec["text"] for sec in p.report["sections"] if sec["key"] == "overview"), "")
            p.summary = _cap(overview, MAX_SUMMARY)
            p.done, p.accepted = True, True
            p.warnings.append(Warning(
                code="evidence_only",
                message=f"no disassembly (Ghidra {state.ghidra_status}): the report was written from the "
                        f"sweep's evidence ({', '.join(sources)})"))
        else:
            p.model_status = {"invalid": "malformed", "failed": "unavailable"}.get(outcome, "skipped")

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
              remaining: Callable[[], float], capa_functions: list[str] | None = None,
              hash_sites: list[int] | None = None, program: list[str] | None = None) -> list[dict[str, str]]:
        """Todo seed from ``procedure_info(entry)`` + ``list_procedures(detail=complete)``.

        Order: the entry point, well-known main names (and Go's ``main.main``), functions capa
        matched (``capa_functions``, in the sweep's rule order; only those that are procedure entries
        here), the Go program's own functions (:func:`go_user_function`), functions named by
        the binary's own symbols (exports / symbol table, ``symbol.source == imported``), then the
        rest by address. Externals and thunks are skipped. At most ``SEED_TODO`` entries.
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
        main, go_main, go_user, named, rest = [], [], [], [], []
        by_addr: dict[str, dict[str, str]] = {}
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
            by_addr.setdefault(a, entry)
            if entry["name"] in _MAIN_NAMES:
                main.append(entry)
            elif entry["name"] == "main::main.main":
                go_main.append(entry)
            elif go_user_function(entry["name"]):
                go_user.append(entry)
            elif sym.get("source") in _NAMED_SOURCES:
                named.append(entry)
            else:
                rest.append(entry)
        main.sort(key=lambda e: _MAIN_NAMES.index(e["name"]))
        rest.sort(key=lambda e: int(e["address"], 16))
        matched = [by_addr[a] for a in (norm_addr(x) for x in capa_functions or []) if a in by_addr]
        # A hashed-API site is an instruction: its function is the nearest procedure entry at or
        # below it (an approximation that can name a neighbour for code between functions).
        starts = sorted(int(a, 16) for a in by_addr)
        hashed: list[dict[str, str]] = []
        for site in hash_sites or []:
            i = bisect.bisect_right(starts, site) - 1
            if i >= 0 and (e := by_addr[f"{starts[i]:#x}"]) not in hashed:
                hashed.append(e)
        seen = {s["address"] for s in seeds}
        # Go: the runtime and standard library are most of the symbols (1347 of 2167 runtime.* in
        # one live sample); the program's own packages come right after the entry points.
        for e in main + go_main + matched + hashed + go_user + named + rest:
            if len(seeds) >= SEED_TODO:
                break
            if e["address"] not in seen:
                seen.add(e["address"])
                seeds.append(e)
        if program is not None:
            program.extend(e["address"] for e in (go_main + go_user)[:MAX_PROGRAM_FUNCTIONS])
        tw.write({"event": "seed", "todo": seeds, "capa_functions": len(capa_functions or []),
                  "capa_matched": len(matched), "hash_functions": len(hashed)})
        return seeds

    def _loop(self, mcp: Any, listed: dict[str, str], sample: Path, state: State, p: _Pass,
              tw: TranscriptWriter, remaining: Callable[[], float], max_steps: int, max_tokens: int) -> None:
        explored_now: list[str] = []
        try:
            self._loop_body(mcp, listed, sample, state, p, tw, remaining, max_steps, max_tokens, explored_now)
        finally:
            # Every exit (ok, budget, failure) records what this pass explored and prunes the todo;
            # run() puts both lists back for a pass that lost its final answer.
            p.touched = _dedup(explored_now)
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
            seeds = self._seed(mcp, ev, tw, explore_left, capa_functions=capa_functions(state.sweep),
                               hash_sites=hash_sites(state.sweep), program=p.program_functions)
            p.todo = [s["address"] for s in seeds]
            p.given = list(p.todo)
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
        model = self._model(p)
        if model is None:
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
                if exc.kind in FATAL_KINDS:
                    # Credit, key and refusal failures repeat on every call: seal the class now,
                    # with no further turn and no final answer to spend.
                    self._model_failed(p, tw, exc.kind, str(exc))
                    return
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
                      **_response_info(resp), **_reasoning_fields(resp, p.retain_reasoning),
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
                view = None
                if not is_error and c["name"] in CODE_TOOLS:
                    read = _code_addresses(args)
                    if c["name"] == "batch_decompile":  # only what it showed the model was read
                        view = batch_view(text, read)
                        read = view[2] if view is not None else []
                    if read or c["name"] != "batch_decompile":
                        p.code_read = True
                    p.opened = _dedup(p.opened + read)
                    explored_now.extend(read)
                shown, omitted = view[:2] if view is not None else cap_tool_text(compact_for_model(text))
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
        if p.report_tokens > 0:
            known = ev.addresses | set(p.explored) | report_addresses(p.prior_report)
            self._report(model, p, tw, remaining, framer, state.sample_name, known)

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
                      **info, **_reasoning_fields(resp, p.retain_reasoning)})
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

    def _chat(self, model: Any, p: _Pass, tw: TranscriptWriter, budget: Callable[[], float],
              messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int,
              **kw: Any) -> Any:
        """One model request with the phase's remaining time as its timeout; an ``unavailable``
        failure (timeout, connection, HTTP) is retried once while ``budget()`` leaves a turn."""
        try:
            return self._timed_chat(model, p, messages, tools, max_tokens, budget, **kw)
        except ModelError as exc:
            if exc.kind != "unavailable" or not _retryable(str(exc)) or budget() < MIN_TURN_S:
                raise
            p.warnings.append(Warning(code="model_retry", message=f"{exc}; retrying once"[:2000]))
            tw.write({"event": "model_retry", "message": str(exc)[:2000]})
        return self._timed_chat(model, p, messages, tools, max_tokens, budget, **kw)

    def _timed_chat(self, model: Any, p: _Pass, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                    max_tokens: int, budget: Callable[[], float], **kw: Any) -> Any:
        """``model.chat``; a response that reports ``completion_tokens`` adds to the measured rate."""
        t0 = self._clock()
        resp = model.chat(messages, tools, max_tokens, timeout_s=max(1.0, budget()), **kw)
        tokens = _response_info(resp)["completion_tokens"]
        if isinstance(tokens, int) and tokens > 0:
            p.model_tokens += tokens
            p.model_seconds += max(0.0, self._clock() - t0)
        return resp

    @staticmethod
    def _measured_tps(p: _Pass) -> float:
        """Tokens/s over this pass's calls that reported usage (prompt time included), else the
        configured ``REA_MODEL_TOKENS_PER_S``; clamped to [1, 4 x configured]."""
        if p.model_tokens <= 0 or p.model_seconds <= 0:
            return p.tokens_per_s
        return max(1.0, min(4 * p.tokens_per_s, p.model_tokens / p.model_seconds))

    def _report(self, model: Any, p: _Pass, tw: TranscriptWriter, remaining: Callable[[], float],
                framer: Framer, sample_name: str, known: set[str], *, sources: list[str] | None = None,
                ghidra_status: str = "ok") -> str:
        """The analysis report (rea.analysis/1): one schema-bound call after the accepted answer,
        or, with ``sources`` (an evidence-only pass), the pass's only call. Returns ``ok``,
        ``skipped``, ``failed`` or ``invalid``.

        Skipped (``report_skipped_deadline``) when the time left cannot hold ``MIN_REPORT_TOKENS``
        at the measured rate; otherwise asks for ``min(REA_REPORT_MAX_TOKENS, what fits)``. A model
        error is ``report_failed``, a report that violates the schema ``report_invalid``; either
        way the rest of the pass seals unchanged. A cut-off report keeps its complete sections
        (``report_salvaged``); one the server cut off (``finish_reason: length``) before the
        model's call gets its verdict from the rule alone (and never meets the bar), or, when the
        last pass left a report with the model's call in it, is dropped for that one, unless that
        one is benign or unknown and this one finished a ground the engine could check.
        """
        try:
            tps = self._measured_tps(p)
            fit = int(max(0.0, remaining() - MIN_TURN_S) * tps / 1.25)
            if fit < MIN_REPORT_TOKENS:
                p.warnings.append(Warning(
                    code="report_skipped_deadline",
                    message=f"{remaining():.0f}s left at {tps:.1f} tok/s holds {fit} tokens, "
                            f"under the report's {MIN_REPORT_TOKENS}"))
                tw.write({"event": "report_skipped", "fit_tokens": fit, "tokens_per_s": round(tps, 2)})
                return "skipped"
            tokens = min(p.report_tokens, fit)
            # A function pass over a file an installer carried may cite the install script for a
            # ground: what the installer does is there, and a script has no address.
            script = [] if sources else script_sources(p.sweep)
            if sources:
                messages = framer.evidence_report_messages(pass_no=p.pass_no, sample_name=sample_name,
                                                           sweep=p.sweep, sources=sources,
                                                           ghidra_status=ghidra_status)
            else:
                messages = framer.report_messages(pass_no=p.pass_no, sample_name=sample_name, summary=p.summary,
                                                  functions=p.functions, iocs=p.iocs, sweep=p.sweep,
                                                  prior_report=p.prior_report, script_sources=script)
            kw: dict[str, Any] = {"response_format": report_response_format(sources, script_sources=script)}
            temperature = _report_temperature()
            if temperature is not None:  # the report is a reading of evidence, not a draw
                kw["temperature"] = temperature
            if not p.final_thinking:
                kw["chat_template_kwargs"] = {"thinking": False}
            content: str | None = None
            for retry in ("", "empty_at_length"):
                try:
                    resp = self._chat(model, p, tw, remaining, messages, [], tokens, **kw)
                except ModelError as exc:
                    p.warnings.append(Warning(code="report_failed", message=f"report call failed: {exc}"[:2000]))
                    tw.write({"event": "report_failed", "message": str(exc)[:2000]})
                    return "failed"
                parsed = _parse_message(resp)
                content = parsed[0] if parsed is not None else None
                info = _response_info(resp)
                tw.write({"event": "report_turn", "max_tokens": tokens,
                          "content": (content or "")[:TRANSCRIPT_TEXT], **info,
                          **_reasoning_fields(resp, p.retain_reasoning), **({"retry": retry} if retry else {})})
                # The whole output budget spent and nothing written (a host that reasons whatever
                # the request says): the same call once more, while the time left still holds it.
                if (content or "").strip() or info["finish_reason"] != "length":
                    break
                fit = int(max(0.0, remaining() - MIN_TURN_S) * self._measured_tps(p) / 1.25)
                if fit < MIN_REPORT_TOKENS:
                    break
                tokens = min(p.report_tokens, fit)
            obj = _parse_json(content.strip()) if isinstance(content, str) else None
            salvaged = False
            if not isinstance(obj, dict):
                obj = _parse_json(salvage_json_prefix(content) or "")
                salvaged = isinstance(obj, dict)
                if salvaged and isinstance(obj.get("sections"), dict):
                    obj["sections"] = complete_sections(obj["sections"])
            if isinstance(obj, dict):
                obj.pop("basis", None)  # the engine, not the model, says what the report rests on
            # The verdict rule: the model's call and grounds in, the wire verdict out (verdict.py).
            # ... benign only over code that was read: the sweep's decompiler read the assembly, or
            # (a function pass) a code tool returned a function's code to this chain. An address
            # in ``explored`` is not that: a metadata call or the model's own list puts one there.
            code_read = sample_decompiled(p.sweep) or (not sources and p.code_read)
            # A report the server says ran out of output loses the end of its verdict first (it is
            # written last). One cut before the model's call keeps its finished sections under a
            # verdict the rule sets without that call, unless the last pass left a report that
            # stands: one that is hostile or has the model's call in it. With both it always
            # stands; with one, until this report finishes a ground the engine could check (the
            # pass that reads the hostile code writes the longest report). JSON broken any other
            # way is not a cut, but a report read out of it with the model's call whole is kept
            # without its rationale.
            called = model_called(obj)
            length = info["finish_reason"] == "length"
            stands = False
            if p.prior_report is not None:
                hostile = p.prior_report["verdict"]["label"] not in ("benign", "unknown")
                grounded = has_checked_ground(obj, known=known, sources=sources or script)
                stands = (hostile and p.prior_called) or (not grounded and (hostile or p.prior_called))
            cut_off = salvaged and (called or (length and not stands))
            decision = apply_verdict_rule(obj, sweep=p.sweep, known=known, sources=sources or script,
                                          code_read=code_read, cut_off=cut_off)
            try:
                v = validate_report(obj, p.pass_no, known, sources=sources or (),
                                    basis=REPORT_BASIS if sources else None)
            except ReportInvalid as exc:
                p.warnings.append(Warning(code="report_invalid", message=f"analysis report dropped: {exc}"[:2000]))
                tw.write({"event": "report_invalid", "reason": str(exc)[:2000]})
                return "invalid"
            text = json.dumps(v.report, ensure_ascii=False, separators=(",", ":"))
            if len(text) > MAX_REPORT_JSON:
                p.warnings.append(Warning(code="report_invalid",
                                          message=f"analysis report is {len(text)} chars, over {MAX_REPORT_JSON}"))
                return "invalid"
            if salvaged:
                p.warnings.append(Warning(
                    code="report_salvaged",
                    message=("analysis report was cut off; its complete sections were kept" if length else
                             "analysis report was not plain JSON; the object in it was read")))
            if v.dropped:
                p.warnings.append(Warning(
                    code="report_evidence_dropped",
                    message=f"{v.dropped} report evidence row(s) citing what the analysis never saw were dropped"
                            + (f"; downgraded to not_analysed: {', '.join(v.downgraded)}" if v.downgraded else "")))
            p.report = v.report
            if decision is not None:
                p.opinion = decision.opinion if called else None
                tw.write({"event": "verdict_rule", "opinion": p.opinion, "label": decision.label,
                          "confidence": decision.confidence, "dropped": decision.dropped,
                          "grounds": [{"code": g.code, "tier": "hostile" if g.tier == HOSTILE else "concealing",
                                       "engine": g.engine, "cite": g.cite} for g in decision.grounds]})
            tw.write({"event": "report", "report": v.report, "evidence_dropped": v.dropped})
            return "ok"
        except Exception as exc:  # the report never costs the pass its findings
            _log.exception("rea-agent report failed")
            p.warnings.append(Warning(code="report_failed", message=f"exception:{type(exc).__name__}"))
            return "failed"

    @staticmethod
    def _turn_failed(p: _Pass, tw: TranscriptWriter, message: str) -> None:
        p.warnings.append(Warning(code="model_turn_failed",
                                  message=f"{message} after {p.good_turns} good turn(s); "
                                          f"asking for the final answer"[:2000]))
        tw.write({"event": "model_turn_failed", "message": message[:2000]})

    def _final_failed(self, p: _Pass, tw: TranscriptWriter, kind: str, message: str) -> None:
        """The final answer failed: ``budget`` (chain continues) once any turn succeeded."""
        if p.good_turns == 0 or kind in FATAL_KINDS:
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
        snapped = snap_iocs(answer.iocs, list(ev.results.values()))
        seen: set[tuple[str, str]] = set()
        unique = []
        for ioc in answer.iocs:
            k = (ioc["type"], ioc["value"])
            if k not in seen:
                seen.add(k)
                unique.append(ioc)
        if unique:
            # Go packs literals with no terminator: a value read across a literal's end (live
            # 2026-11-03, a URL plus the next literal's digits) still occurs in the sample bytes,
            # so it is clipped to the exact literal's IOC before the byte check.
            lits = go_strings(sample, deadline=clock() + max(0.0, min(GO_SCAN_S, remaining() / 4)), clock=clock)
            if lits:
                unique = clip_overruns(unique, exact_iocs(lits), key=lambda i: (i["type"], i["value"]),
                                       replace=lambda i, v: {**i, "value": v})
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
                  "iocs": p.iocs, "todo": p.todo, "done": p.done, "claims_dropped": dropped,
                  "iocs_snapped": snapped})

    @staticmethod
    def _deepen(p: _Pass, state: State, tw: TranscriptWriter) -> list[str]:
        """Apply the deepening bar to an accepted pass; returns the chain's facts so far.

        Sets ``p.bar_met``/``p.gaps``/``p.stop_reason`` and puts the gaps' target functions at the
        front of the todo list. The model's ``done`` flag is recorded but decides nothing.
        """
        report = p.report if p.report is not None else p.prior_report
        # A pass that wrote no report is measured on the carried one, with the call behind it,
        # and does not meet the bar: that report was written before what this pass read. Nor does
        # a report cut off before the model's call: its verdict is the rule's alone.
        suff = assess(report=report, sweep=p.sweep, explored=p.explored, opened=p.opened,
                      program_functions=p.program_functions,
                      opinion=p.opinion if p.report is not None else state.opinion,
                      carried=p.report is None, called=p.report is None or p.opinion is not None)
        known = set(state.facts)
        before = set(state.opened)
        fresh = [a for a in p.opened if a not in before]  # code first read this pass is progress too
        new = [f for f in _dedup(facts_of(report, p.functions, p.iocs)) if f not in known]
        max_passes = _env_int("REA_MAX_PASSES", DEFAULT_MAX_PASSES, 1, MAX_STEPS_CEILING)
        # A gap's targets are what it still needs (sufficiency.py leaves out what is done): a
        # function the chain touched but no code tool returned is still a target.
        targets = _dedup([t for g in suff.gaps for t in g.targets])
        todo = _dedup(targets + p.todo)[:MAX_TODO]
        if suff.met:
            stop = "bar_met"
        elif p.evidence_only:  # no tool can add to the sweep's evidence: one report, then stop
            stop = "evidence_only"
        elif p.pass_no >= 2 and not new and not fresh:
            stop = "stalled"
        elif p.pass_no >= max_passes:
            stop = "pass_cap"
        else:  # an open gap is work even with an empty todo list: stalled ends a pass that finds nothing
            stop = ""
        if not stop:
            p.todo = todo
        p.assessed, p.bar_met, p.stop_reason = True, suff.met, stop
        p.gaps = [{"code": g.code, "detail": g.detail} for g in suff.gaps]
        tw.write({"event": "deepen", "bar_met": suff.met, "gaps": p.gaps, "targets": targets,
                  "new_facts": len(new), "stop_reason": stop, "model_done": p.done})
        return (state.facts + new)[-MAX_FACTS:]

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
        # rea.analysis/1 travels as JSON text: Record values cannot hold lists of objects.
        report = (json.dumps(p.report, ensure_ascii=False, separators=(",", ":"))
                  if p.report is not None and p.model_status == "ok" else None)

        def build() -> Record:
            extra: dict[str, Any] = {"analysis_report": report} if report is not None else {}
            deepen: dict[str, Any] = ({"bar_met": p.bar_met, "gaps": [g["code"] for g in p.gaps],
                                       "stop_reason": p.stop_reason} if p.assessed else {})
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
                **deepen,
                **extra,
            })

        rec = build()
        while len(rec.model_dump_json()) > budget and (functions or iocs):
            functions = functions[: len(functions) // 2]
            iocs = iocs[: len(iocs) // 2]
            rec = build()
        if len(rec.model_dump_json()) > budget and report is not None:
            report = None
            rec = build()
            p.warnings.append(Warning(code="report_invalid",
                                      message="analysis_report dropped to fit the metadata limit"))
        if len(functions) < len(p.functions) or len(iocs) < len(p.iocs):
            p.warnings.append(Warning(code="payload_truncated",
                                      message="functions/iocs trimmed to fit the metadata limit; "
                                              "the transcript artifact has the full lists"))
        return rec


def _sealed_report(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    """The continuation's report when it is still a valid rea.analysis/1 object, else None."""
    if obj is None:
        return None
    pass_no = obj.get("pass")
    if not isinstance(pass_no, int) or isinstance(pass_no, bool) or pass_no < 1:
        return None
    try:
        return validate_report(obj, pass_no, None).report
    except ReportInvalid:
        return None


_HTTP_STATUS = re.compile(r"\bhttp_(\d{3})\b")


def _retryable(message: str) -> bool:
    """An ``unavailable`` failure worth one retry: not an HTTP 4xx other than 408/429."""
    m = _HTTP_STATUS.search(message)
    if m is None:
        return True
    code = int(m.group(1))
    return not 400 <= code < 500 or code in (408, 429)


def _response_info(resp: Any) -> dict[str, Any]:
    """``finish_reason`` and ``completion_tokens`` of a response for the transcript, and who served
    it when the response says (a router's ``provider`` and the ``model`` it ran): None if absent."""
    finish = tokens = provider = served = None
    if isinstance(resp, dict):
        provider = resp["provider"][:64] if isinstance(resp.get("provider"), str) else None
        served = resp["model"][:128] if isinstance(resp.get("model"), str) else None
        choices = resp.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            fr = choices[0].get("finish_reason")
            finish = fr[:32] if isinstance(fr, str) else None
        usage = resp.get("usage")
        if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
            tokens = usage["completion_tokens"]
    return {"finish_reason": finish, "completion_tokens": tokens, "provider": provider, "served_model": served}


def _reasoning(resp: Any) -> str | None:
    """The model's reasoning text from a chat-completions response, or None.

    ``message.reasoning`` (OpenRouter), else ``reasoning_content`` (vLLM), else the text of the
    ``reasoning.text`` / ``reasoning.summary`` items of ``reasoning_details``. Encrypted
    reasoning is no text and gives None. It is kept in the transcript only, never sent back.
    """
    if not isinstance(resp, dict):
        return None
    choices = resp.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    msg = choices[0].get("message")
    if not isinstance(msg, dict):
        return None
    for key in ("reasoning", "reasoning_content"):
        text = msg.get(key)
        if isinstance(text, str) and text:
            return text
    details = msg.get("reasoning_details")
    if not isinstance(details, list):
        return None
    parts = []
    for d in details:
        if not isinstance(d, dict):
            continue
        text = (d.get("text") if d.get("type") == "reasoning.text"
                else d.get("summary") if d.get("type") == "reasoning.summary" else None)
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts) or None


def _reasoning_fields(resp: Any, keep: bool) -> dict[str, Any]:
    """The transcript fields for a reply's reasoning: none unless ``keep`` and there is some."""
    text = _reasoning(resp) if keep else None
    if text is None:
        return {}
    return {"reasoning": text[:TRANSCRIPT_TEXT], "reasoning_chars": len(text)}


def _parse_message(resp: Any) -> tuple[str | None, list[dict[str, Any]]] | None:
    """(content, tool calls) from a chat-completions response, or None when it is malformed.

    Each call is ``{"id", "name", "raw", "args"}``; ``args`` is None when the arguments are not
    a JSON object (that call is refused, not the whole response). Reasoning is not part of the
    message: :func:`_reasoning` reads it for the transcript only.
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
