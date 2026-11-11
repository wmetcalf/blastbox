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
family_signature         hostile     a YARA family rule matched (sweep.signatures.matches)
pixel_hidden_executable  hostile     a PE decoded out of a resource image's pixels
hidden_payload           concealing  a hidden resource payload beside code that can load it (loader_refs)
emulated_concealment     concealing  emulation saw the stub hide a stage (any code but stalling)
installer_concealment    concealing  the installer hides what it runs (sufficiency.installer_concealment)
api_hashing              concealing  imports resolved by hash (sweep.api_hashes.hits)
```

Model grounds (:func:`model_grounds`) are kept when their code is in the vocabulary and their
evidence row cites something the pass has: an address it has seen (``known``), or, in a report
written from the sweep's evidence alone, a source the sweep holds (``sources``). That is all the
engine checks. It does not check that the cited function *does* what the ground says; a model
that cites a real address for a behaviour that is not there still moves the verdict. What the rule
removes is the free choice of confidence and the ungrounded malicious call, not the model's
judgement of code. A ground that fails the check is dropped and counted, never fatal.

The rule (:func:`decide`):

```text
any hostile ground      malicious   high: the pixel-hidden executable, two hostile grounds, or an
                                    engine ground beside any second ground; else medium
concealing grounds only suspicious  medium: an engine ground, or two model grounds; else low
no ground               suspicious/low when the model called it malicious or suspicious;
                        benign/medium when it called it benign and the code was read;
                        unknown/low otherwise
```

The wire shape does not change (``{"label", "confidence", "rationale"}``; a consumer that rejects
unknown verdict keys keeps working). The rule's line goes first in the rationale (``Rule: ...``)
and the model's own text follows. The line is built from engine vocabulary, addresses and source
names only: nothing the sample controls is copied into it.

Thresholds are first guesses. The scoring set they were shaped on holds no benign programs, so
how often legitimately packed software reads ``suspicious`` here is unmeasured.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass, replace
from typing import Any

from blastbox.engines.rea.emulate import CONCEALMENT
from blastbox.engines.rea.prompts import (
    CONCEALING_GROUNDS,
    EVIDENCE_SOURCES,
    GEN_GROUNDS,
    GEN_RATIONALE,
    HOSTILE_GROUNDS,
    REPORT_LABELS,
    REPORT_RATIONALE,
)
from blastbox.engines.rea.report import address_of
from blastbox.engines.rea.sufficiency import STALLING, installer_concealment

__all__ = ["CONCEALING", "HOSTILE", "RULE_LINE", "Decision", "Ground", "apply", "decide", "engine_grounds",
           "model_grounds"]

HOSTILE, CONCEALING = 2, 1
RULE_LINE = "Rule: "
# A rationale within the generation limit is never cut to make room for the rule's line.
RULE_LINE_MAX = REPORT_RATIONALE - GEN_RATIONALE - 1
MAX_ROWS = 16  # model ground rows looked at; the schema allows GEN_GROUNDS
CONCLUSIVE = "pixel_hidden_executable"
_PLAIN = re.compile(r"[^A-Za-z0-9_.\-]")
_ECHO = re.compile(r"^\s*rule:", re.IGNORECASE)
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
    if matches:
        families: list[str] = []
        for m in matches:
            name = _plain(m.get("family"), 32) or _plain(m.get("rule"), 32)
            if name and name not in families:
                families.append(name)
        shown = ", ".join(families[:3]) + (f", +{len(families) - 3}" if len(families) > 3 else "")
        out.append(Ground("family_signature", HOSTILE, True,
                          f"family signature ({shown})" if shown else "family signature"))
    res = _dict(sweep.get("dotnet_resources"))
    hidden = [h for h in _list(res.get("hidden_payloads")) if isinstance(h, dict)]
    if any(h.get("image") and h.get("decoded") for h in hidden):
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
    pass that read functions passes ``sources=()`` (only addresses count) and an evidence-only one
    ``known=set()`` (only sources count). One ground per code; at most ``GEN_GROUNDS``.
    """
    if not isinstance(raw, list):
        return [], 0
    out: list[Ground] = []
    dropped = max(0, len(raw) - MAX_ROWS)
    for row in raw[:MAX_ROWS]:
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
        elif any(g.code == code for g in out):
            continue
        elif len(out) >= GEN_GROUNDS:
            dropped += 1
        else:
            out.append(Ground(str(code), tier, False, f"{str(code).replace('_', ' ')} ({where})"))
    return out, dropped


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


def decide(opinion: str, grounds: list[Ground], *, code_read: bool) -> Decision:
    """The verdict for the model's call and the checked grounds.

    ``code_read``: the pass read the program's code (functions, or the sample's own decompiled
    C#), which a benign verdict needs.
    """
    hostile = {g.code for g in grounds if g.tier == HOSTILE}
    concealing = [g for g in grounds if g.tier == CONCEALING]
    codes = {g.code for g in grounds}
    cites = [g.cite for g in sorted(grounds, key=lambda g: -g.tier)]  # hostile first; stable within a tier
    if hostile:
        label = "malicious"
        strong = (CONCLUSIVE in hostile or len(hostile) >= 2
                  or (any(g.engine for g in grounds) and len(codes) >= 2))
        confidence = "high" if strong else "medium"
    elif concealing:
        label = "suspicious"
        strong = any(g.engine for g in concealing) or len({g.code for g in concealing}) >= 2
        confidence = "medium" if strong else "low"
    elif opinion in ("malicious", "suspicious"):
        label, confidence = "suspicious", "low"
        why = f"the model's call ({opinion}) cites no ground the engine could check."
    elif opinion == "benign" and code_read:
        label, confidence = "benign", "medium"
        why = "no ground for suspicion in the code read."
    elif opinion == "benign":
        label, confidence = "unknown", "low"
        why = "a benign call needs the program's code read, and it was not."
    else:
        label, confidence = "unknown", "low"
        why = "no ground either way."
    if grounds:
        line = _line(f"{RULE_LINE}{label}/{confidence} on ", cites,
                     f" Model's call: {opinion}." if opinion != label else "")
    else:
        line = f"{RULE_LINE}{label}/{confidence}; {why}"
    return Decision(label=label, confidence=confidence, grounds=list(grounds), opinion=opinion, rule_line=line)


def _rationale(rule_line: str, text: str) -> str:
    lines = text.strip().split("\n")
    while lines and _ECHO.match(lines[0]):  # the rule line of a previous report, copied
        lines.pop(0)
    own = "\n".join(lines).strip()
    if not own:
        return rule_line
    room = REPORT_RATIONALE - len(rule_line) - 1
    if len(own) > room:
        own = own[:room - 1].rstrip() + "…"
    return f"{rule_line}\n{own}"


def apply(obj: Any, *, sweep: dict[str, Any], known: set[str] | None, sources: Collection[str] | None,
          code_read: bool) -> Decision | None:
    """Replace a model-written report's verdict (``label``/``grounds``/``rationale``) with the
    rule's, in the wire shape, and return the decision.

    ``None`` and ``obj`` untouched when there is no verdict object or its label is outside the
    enum: ``validate_report`` rejects that report as it always did. A rationale it would reject
    (not a string, over ``REPORT_RATIONALE``) is left as it is for the same reason.
    """
    verdict = obj.get("verdict") if isinstance(obj, dict) else None
    if not isinstance(verdict, dict):
        return None
    opinion = verdict.get("label")
    if not isinstance(opinion, str) or opinion not in REPORT_LABELS:
        return None
    cited, dropped = model_grounds(verdict.get("grounds"), known=known, sources=sources)
    decision = replace(decide(opinion, engine_grounds(sweep) + cited, code_read=code_read), dropped=dropped)
    rationale = verdict.get("rationale")
    if isinstance(rationale, str) and len(rationale) <= REPORT_RATIONALE:
        rationale = _rationale(decision.rule_line, rationale)
    obj["verdict"] = {"label": decision.label, "confidence": decision.confidence, "rationale": rationale}
    return decision
