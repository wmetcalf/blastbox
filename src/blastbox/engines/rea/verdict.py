"""The verdict rule: the label and confidence of ``rea.analysis/1`` come from grounds, not from the model.

Live, the same sweep facts and the same code gave a different verdict on 8 of 20 samples between
two identical runs: the model picked its confidence, and sometimes its label, by mood. So the
model no longer picks either. It gives its own call (``label``) and the *grounds* for it, each one
a behaviour from a fixed vocabulary (``prompts.HOSTILE_GROUNDS`` / ``CONCEALING_GROUNDS``) with one
evidence row. The engine keeps the grounds it can check, adds the ones the sweep itself shows, and
:func:`decide` maps the set to a label and a confidence. The same grounds always give the same
verdict.

Engine grounds (:func:`engine_grounds`; deterministic, from the sweep's evidence):

```text
family_signature         hostile     a YARA rule matched whose meta names a malware family
dual_use_signature       concealing  ... whose meta names a dual-use tool (signatures.DUAL_USE)
pixel_hidden_executable  hostile     a PE decoded out of a resource image's pixels
hidden_payload           concealing  a hidden resource payload beside code that can load it (loader_refs)
emulated_concealment     concealing  emulation saw the stub hide a stage (any code but stalling)
installer_concealment    concealing  the installer hides what it runs (sufficiency.installer_concealment)
api_hashing              concealing  imports resolved by hash (sweep.api_hashes.hits)
```

A match of a rule that names no family (a rule for an obfuscator, say) is no ground: the model
sees it in the evidence and may cite what it means.

The model answers every code of the vocabulary, one citation or none (the report schema's
checklist). It used to list "up to four" grounds, and over the same evidence it listed one in one
run and four in the next while its prose described the same behaviours; the rule counts hostile
codes, so the confidence moved with the list. Model grounds (:func:`model_grounds`) are kept when
their code is in the vocabulary and their citation names something the pass has: an address it has seen (``known``), or, in a report
written from the sweep's evidence alone, a source the sweep holds (``sources``). That is all the
engine checks. It does not check that the cited function *does* what the ground says; a model
that cites a real address for a behaviour that is not there still moves the verdict. What the rule
removes is the free choice of confidence and the ungrounded malicious call, not the model's
judgement of code. A ground that fails the check is dropped and counted, never fatal. The grounds
kept do not depend on the order the model listed them in: one per code, hostile ones first, each
tier in vocabulary order. Every code that passes the check counts (the citations looked at are
bounded, ``PER_CODE`` and ``MAX_ROWS``), so a ground the model adds never pushes another out and never lowers the verdict;
the rule line shows as many as fit.

The rule (:func:`decide`):

```text
any hostile ground      malicious   high: the pixel-hidden executable, two hostile grounds, or an
                                    engine ground beside any second ground; else medium
  ... all of them the   suspicious  when the model's own call was not malicious. medium: its call
  model's                           was suspicious, or as for concealing grounds; else low
concealing grounds only suspicious  medium: an engine ground, or two model grounds; else low
no ground               suspicious/low when the model called it malicious or suspicious;
                        benign/medium when it called it benign, the code was read and no
                        resource image went unread; unknown/low otherwise
```

The wire shape does not change (``{"label", "confidence", "rationale"}``; a consumer that rejects
unknown verdict keys keeps working). The rule's line goes first in the rationale (``Rule: ...``)
and the model's own text follows, less any line of it that itself reads as a rule line. The line
is built from engine vocabulary, addresses and source names only: nothing the sample controls is
copied into it.

Thresholds are first guesses. The scoring set they were shaped on holds no benign programs, so
how often legitimately packed software reads ``suspicious`` here is unmeasured.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass, replace
from typing import Any

from blastbox.engines.rea.emulate import CONCEALMENT
from blastbox.engines.rea.prompts import (
    CONCEALING_GROUNDS,
    EVIDENCE_SOURCES,
    GEN_RATIONALE,
    HOSTILE_GROUNDS,
    REPORT_LABELS,
    REPORT_RATIONALE,
)
from blastbox.engines.rea.report import address_of
from blastbox.engines.rea.signatures import dual_use
from blastbox.engines.rea.sufficiency import STALLING, installer_concealment

__all__ = ["CONCEALING", "HOSTILE", "RULE_LINE", "Decision", "Ground", "apply", "decide", "engine_grounds",
           "model_grounds"]

HOSTILE, CONCEALING = 2, 1
RULE_LINE = "Rule: "
MODEL_LINE = "Model: "  # leads the model's own text, the rationale's second and last line
# A rationale within the generation limit is never cut to make room for the rule's line.
RULE_LINE_MAX = REPORT_RATIONALE - GEN_RATIONALE - 1 - len(MODEL_LINE)
MAX_ROWS = 16  # model ground rows looked at when the answer is a list
PER_CODE = 4  # citations looked at per code in a checklist answer; the schema allows one
_RATIONALE_READ = 4 * REPORT_RATIONALE  # of a model rationale, before it is cut to fit
CONCLUSIVE = "pixel_hidden_executable"
_PLAIN = re.compile(r"[^A-Za-z0-9_.\-]")
_ECHO = re.compile(r"\s*rule\s*:", re.IGNORECASE)
_MODEL_ECHO = re.compile(r"^(?:\s*model\s*:)+\s*", re.IGNORECASE)
_VOCABULARY = (*HOSTILE_GROUNDS, *CONCEALING_GROUNDS)  # hostile first
_SHOWN = tuple(c for c in CONCEALMENT if c not in STALLING)


@dataclass(frozen=True)
class Ground:
    code: str
    tier: int  # HOSTILE | CONCEALING
    engine: bool  # found by the sweep itself, not cited by the model
    cite: str  # what the rule line says; engine vocabulary only


@dataclass(frozen=True)
class Decision:
    label: str
    confidence: str
    grounds: list[Ground]
    opinion: str  # the model's own call
    rule_line: str
    dropped: int = 0  # model grounds that failed the check


def _plain(value: Any, cap: int) -> str:
    return _PLAIN.sub("", value)[:cap] if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def engine_grounds(sweep: dict[str, Any]) -> list[Ground]:
    """The grounds the sweep's evidence shows by itself, in a fixed order."""
    out: list[Ground] = []
    matches = [m for m in _list(_dict(sweep.get("signatures")).get("matches")) if isinstance(m, dict)]
    families: list[str] = []
    tools: list[str] = []
    for m in matches:
        name = _plain(m.get("family"), 32)  # a rule that names no family is no ground
        names = tools if dual_use(m.get("family")) else families
        if name and name not in names:
            names.append(name)

    def shown(names: list[str]) -> str:
        return ", ".join(names[:3]) + (f", +{len(names) - 3}" if len(names) > 3 else "")

    if families:
        out.append(Ground("family_signature", HOSTILE, True, f"family signature ({shown(families)})"))
    if tools:
        out.append(Ground("dual_use_signature", CONCEALING, True,
                          f"signature of a dual-use tool ({shown(tools)})"))
    res = _dict(sweep.get("dotnet_resources"))
    hidden = [h for h in _list(res.get("hidden_payloads")) if isinstance(h, dict)]
    # The decoding says where the PE was: ``image:...`` is the pixels of a resource image.
    if any(isinstance(h.get("decoded"), str) and h["decoded"].startswith("image:") for h in hidden):
        out.append(Ground(CONCLUSIVE, HOSTILE, True, "executable hidden in image pixels"))
    elif hidden and _list(res.get("loader_refs")):
        out.append(Ground("hidden_payload", CONCEALING, True, "hidden payload in resources beside loader code"))
    seen = _list(_dict(sweep.get("emulation")).get("concealment"))
    codes = [c for c in _SHOWN if c in [s for s in seen if isinstance(s, str)]]
    if codes:
        out.append(Ground("emulated_concealment", CONCEALING, True,
                          f"emulated concealment ({', '.join(codes[:4])})"))
    if installer_concealment(sweep):
        out.append(Ground("installer_concealment", CONCEALING, True, "installer hides what it runs"))
    hashes = _dict(sweep.get("api_hashes"))
    hits = _list(hashes.get("hits"))
    if hits:
        algorithm = _plain(hashes.get("algorithm"), 24)
        out.append(Ground("api_hashing", CONCEALING, True,
                          f"imports resolved by hash ({algorithm + ', ' if algorithm else ''}{len(hits)})"))
    return out


def model_grounds(raw: Any, *, known: set[str] | None,
                  sources: Collection[str] | None) -> tuple[list[Ground], int]:
    """The model's grounds the engine could check, and how many it dropped.

    ``known`` and ``sources`` are those of ``report.validate_report``: ``None`` skips that check; a
    pass that read functions passes ``sources=()`` (only addresses count), or the installer
    sources whose script the sweep read (``prompts.script_sources``: an installer's behaviour is in
    its script, which has no address), and an evidence-only one ``known=set()`` (only sources
    count). One ground per code (its lowest citation), hostile
    codes first and each tier in vocabulary order: the same rows in any order give the same
    grounds, and one more row never takes a ground away.

    ``raw`` is the checklist the report schema asks for, ``{code: [citation] or []}`` with every
    code answered (an empty or missing answer is "no", not a dropped ground), or a list of
    ``{"code", "evidence"}`` rows.
    """
    rows, dropped = _rows(raw)
    best: dict[str, tuple[int, str]] = {}
    for row in rows:
        code = row.get("code") if isinstance(row, dict) else None
        tier = (HOSTILE if isinstance(code, str) and code in HOSTILE_GROUNDS
                else CONCEALING if isinstance(code, str) and code in CONCEALING_GROUNDS else 0)
        evidence = row.get("evidence") if isinstance(row, dict) else None
        where = None
        if tier and isinstance(evidence, dict):
            if "address" in evidence:
                addr = address_of(evidence["address"])
                if addr is not None and (known is None or addr in known):
                    where = addr
            else:
                source = evidence.get("source")
                if (isinstance(source, str) and source in EVIDENCE_SOURCES
                        and (sources is None or source in sources)):
                    where = source
        if where is None:
            dropped += 1
        elif str(code) not in best or where < best[str(code)][1]:
            best[str(code)] = (tier, where)
    codes = sorted(best, key=_VOCABULARY.index)
    return [Ground(c, best[c][0], False, f"{c.replace('_', ' ')} ({best[c][1]})") for c in codes], dropped


def _rows(raw: Any) -> tuple[list[Any], int]:
    """The model's answer as ``{"code", "evidence"}`` rows, bounded, and what the bounds or the
    shape cost: rows past ``MAX_ROWS``, citations past ``PER_CODE``, an answer that is neither a
    citation nor a list of them, and a citation under a code outside the vocabulary."""
    if isinstance(raw, list):
        return raw[:MAX_ROWS], max(0, len(raw) - MAX_ROWS)
    if not isinstance(raw, dict):
        return [], 0
    rows: list[Any] = []
    dropped = sum(1 for code, answer in raw.items() if answer and code not in _VOCABULARY)
    for code in _VOCABULARY:
        answer = raw.get(code)
        if isinstance(answer, dict):
            answer = [answer]
        if not answer:
            continue
        if not isinstance(answer, list):
            dropped += 1
            continue
        dropped += max(0, len(answer) - PER_CODE)
        rows.extend({"code": code, "evidence": cite} for cite in answer[:PER_CODE])
    return rows, dropped


def _line(head: str, cites: list[str], tail: str) -> str:
    shown = list(cites)
    while True:
        more = len(cites) - len(shown)
        line = head + "; ".join(shown) + (f"; +{more} more" if more else "") + "."
        if len(line) <= RULE_LINE_MAX or len(shown) <= 1:
            break
        shown.pop()
    if tail and len(line) + len(tail) <= RULE_LINE_MAX:
        line += tail
    return line[:RULE_LINE_MAX]


def resources_unread(sweep: dict[str, Any]) -> str:
    """What the sweep's .NET resource scan did not read, as a clause for the rule line ("" when it
    read everything, or the sample has no such scan): the scan failed, or it left items unread at
    its time, size and count limits. Any of them may be a hidden payload. ``images_unread`` is the
    same count under the name an older sweep sealed it by."""
    res = _dict(sweep.get("dotnet_resources"))
    if res.get("scan_failed") is True:
        return "the resource scan failed"
    counts = (res.get("items_unread"), res.get("images_unread"))
    n = sum(c for c in counts if isinstance(c, int) and not isinstance(c, bool) and c > 0)
    if n:
        return f"{n} resource item(s) were not read (time, size or count limit)"
    return ""


def decide(opinion: str, grounds: list[Ground], *, code_read: bool, resources_unread: str = "") -> Decision:
    """The verdict for the model's call and the checked grounds.

    ``code_read``: the pass read the program's code (functions, or the sample's own decompiled
    C#), which a benign verdict needs. ``resources_unread``: what the .NET resource scan did not
    read (:func:`resources_unread`), any of which may hide an executable; a benign verdict needs
    it empty.
    """
    hostile = {g.code for g in grounds if g.tier == HOSTILE}
    concealing = [g for g in grounds if g.tier == CONCEALING]
    codes = {g.code for g in grounds}
    cites = [g.cite for g in sorted(grounds, key=lambda g: -g.tier)]  # hostile first; stable within a tier
    held = ""
    if hostile and (opinion == "malicious" or any(g.engine for g in grounds if g.tier == HOSTILE)):
        label = "malicious"
        strong = (CONCLUSIVE in hostile or len(hostile) >= 2
                  or (any(g.engine for g in grounds) and len(codes) >= 2))
        confidence = "high" if strong else "medium"
    elif hostile or concealing:
        # A hostile ground of the model's is checked only for existing evidence, so by itself it
        # does not outrank the call the model made with it.
        label = "suspicious"
        strong = (any(g.engine for g in concealing) or len({g.code for g in concealing}) >= 2
                  or (bool(hostile) and opinion == "suspicious"))
        confidence = "medium" if strong else "low"
        if hostile:
            held = f", not malicious (the model's call was {opinion} and no engine ground is hostile),"
    elif opinion in ("malicious", "suspicious"):
        label, confidence = "suspicious", "low"
        why = f"the model's call ({opinion}) cites no ground the engine could check."
    elif opinion == "benign" and code_read and not resources_unread:
        label, confidence = "benign", "medium"
        why = "no ground for suspicion in the code read."
    elif opinion == "benign":
        label, confidence = "unknown", "low"
        why = ("a benign call needs the program's code read, and it was not." if not code_read else
               f"a benign call needs the .NET resources read, and {resources_unread}.")
    else:
        label, confidence = "unknown", "low"
        why = "no ground either way."
    if grounds:
        line = _line(f"{RULE_LINE}{label}/{confidence}{held} on ", cites,
                     f" Model's call: {opinion}." if opinion != label and not held else "")
    else:
        line = f"{RULE_LINE}{label}/{confidence}; {why}"
    return Decision(label=label, confidence=confidence, grounds=list(grounds), opinion=opinion, rule_line=line)


def _echo(line: str) -> bool:
    """Whether a line of the model's text reads as a rule line, however it is dressed: width and
    compatibility forms folded, invisible characters removed."""
    bare = "".join(ch for ch in unicodedata.normalize("NFKC", line) if unicodedata.category(ch)[0] != "C")
    return _ECHO.match(bare) is not None


def _rationale(rule_line: str, text: str) -> str:
    """The engine's line, then the model's text as ONE line that says whose it is.

    A line of the model's that reads as a rule line (a copy of a previous report's, or a forged
    one) goes. No fold catches every look-alike of "Rule:", so the shape carries the guarantee:
    the first line is the engine's, and nothing after it stands on a line of its own."""
    own = " ".join(part for part in (line.strip() for line in text.splitlines() if not _echo(line)) if part)
    own = _MODEL_ECHO.sub("", own)  # the label the last report carried, copied back
    if not own:
        return rule_line
    room = REPORT_RATIONALE - len(rule_line) - 1 - len(MODEL_LINE)
    if len(own) > room:
        own = own[:room - 1].rstrip() + "…"
    return f"{rule_line}\n{MODEL_LINE}{own}"


def apply(obj: Any, *, sweep: dict[str, Any], known: set[str] | None, sources: Collection[str] | None,
          code_read: bool) -> Decision | None:
    """Replace a model-written report's verdict (``label``/``grounds``/``rationale``) with the
    rule's, in the wire shape, and return the decision.

    ``None`` and ``obj`` untouched when there is no verdict object or its label is outside the
    enum: ``validate_report`` rejects that report as it always did, and one whose rationale is
    not a string, which is left as it is. A rationale of any length is cut to fit beside the rule
    line: the generation schema's ``maxLength`` is not enforced by every server, and a model that
    wrote past ``REPORT_RATIONALE`` cost the sample its whole report.
    """
    verdict = obj.get("verdict") if isinstance(obj, dict) else None
    if not isinstance(verdict, dict):
        return None
    opinion = verdict.get("label")
    if not isinstance(opinion, str) or opinion not in REPORT_LABELS:
        return None
    cited, dropped = model_grounds(verdict.get("grounds"), known=known, sources=sources)
    decision = replace(decide(opinion, engine_grounds(sweep) + cited, code_read=code_read,
                              resources_unread=resources_unread(sweep)), dropped=dropped)
    rationale = verdict.get("rationale")
    if isinstance(rationale, str):
        rationale = _rationale(decision.rule_line, rationale[:_RATIONALE_READ])
    obj["verdict"] = {"label": decision.label, "confidence": decision.confidence, "rationale": rationale}
    return decision
