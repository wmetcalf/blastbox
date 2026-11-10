"""Validation of the agent's analysis report (``rea.analysis/1``, G3).

The model writes the report under ``prompts.report_schema`` (``sections`` as an object keyed by
section, decoded in order). :func:`validate_report` turns that, or an already-sealed report in the
wire shape (``sections`` as a list, as carried in the continuation), into the wire object:

```text
{"schema": "rea.analysis/1", "pass": N, "basis"?: "evidence",
 "verdict": {"label", "confidence", "rationale"},
 "sections": [{"key", "title", "status", "text",
               "evidence": [{"address", "function"?, "note"?} | {"source", "item"?, "note"?}]}]}
```

An evidence row cites either a function address or, in a report written without a disassembly
(``basis: "evidence"``: Ghidra timed out or failed, or a .NET assembly was decompiled to C#
instead), a piece of the sweep's evidence: ``source`` is one of ``prompts.EVIDENCE_SOURCES`` and
``item`` names what is cited inside it.

Rules (the interface, docs/.../g3-interface.md in Loadout):

- A shape violation (unknown enum, over-long string, more than ``REPORT_EVIDENCE`` entries, a
  malformed address, a missing field, a repeated or unknown key) rejects the whole report.
- Every key appears once, in ``REPORT_KEYS`` order; a missing one is filled as ``not_analysed``.
- An evidence address the pass has not seen (``known``) is dropped, not fatal, and so is a row
  citing a source the sweep evidence does not hold (``sources``). A section left
  ``observed`` with no evidence (other than overview/unknowns) is downgraded to ``not_analysed``
  and its unsupported text replaced. ``not_observed``/``not_analysed`` sections carry no evidence.
- An empty title, or one that only repeats the key, becomes the section's default title.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from blastbox.engines.rea.prompts import (
    EVIDENCE_SOURCES,
    REPORT_BASIS,
    REPORT_CONFIDENCES,
    REPORT_EVIDENCE,
    REPORT_FUNCTION,
    REPORT_ITEM,
    REPORT_KEYS,
    REPORT_LABELS,
    REPORT_NO_EVIDENCE_OK,
    REPORT_NOTE,
    REPORT_RATIONALE,
    REPORT_SCHEMA,
    REPORT_STATUSES,
    REPORT_TEXT,
    REPORT_TITLE,
    REPORT_TITLES,
)

__all__ = ["ReportInvalid", "Validated", "report_addresses", "validate_report"]

_ADDR = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
MISSING_TEXT = "Not covered by this report."
DOWNGRADED_TEXT = ("The report cited no address the analysis has seen for this section, so it is "
                   "marked not analysed.")
DOWNGRADED_EVIDENCE_TEXT = ("The report cited no evidence the sweep recorded for this section, so it is "
                            "marked not analysed.")
_FIELDS = ("title", "status", "text", "evidence")


class ReportInvalid(ValueError):
    """The report violates rea.analysis/1; the message says where."""


@dataclass
class Validated:
    report: dict[str, Any]
    dropped: int  # evidence entries citing an address the pass has not seen, or an absent source
    downgraded: list[str]  # observed sections left without evidence


_C0 = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # control characters other than \t and \n


def _str(value: Any, cap: int, what: str) -> str:
    if not isinstance(value, str) or len(value) > cap:
        raise ReportInvalid(f"{what}: not a string of at most {cap} chars")
    return _C0.sub(" ", value).strip()


def _norm(addr: str) -> str:
    return "0x" + (addr[2:].lower().lstrip("0") or "0")


def complete_sections(raw: dict[str, Any]) -> dict[str, Any]:
    """Generation-shape sections with every field present (a cut-off report's tail removed)."""
    return {k: v for k, v in raw.items() if isinstance(v, dict) and all(f in v for f in _FIELDS)}


def validate_report(obj: Any, pass_no: int, known: set[str] | None, *,
                    sources: Collection[str] | None = None, basis: str | None = None) -> Validated:
    """The wire report for ``obj``.

    ``known=None`` skips the seen-address check and ``sources=None`` the present-source check (a
    sealed report); a pass that read functions passes ``sources=()``, so only addresses count.
    ``basis`` marks the report being written (``REPORT_BASIS`` for an evidence-only one); a
    sealed report keeps its own.
    """
    if not isinstance(obj, dict):
        raise ReportInvalid("not an object")
    if basis is None:
        basis = obj.get("basis")
    if basis not in (None, REPORT_BASIS):
        raise ReportInvalid("basis outside the enum")
    verdict = obj.get("verdict")
    if not isinstance(verdict, dict):
        raise ReportInvalid("verdict missing")
    label, confidence = verdict.get("label"), verdict.get("confidence")
    if label not in REPORT_LABELS or confidence not in REPORT_CONFIDENCES:
        raise ReportInvalid("verdict label/confidence outside the enum")
    rationale = _str(verdict.get("rationale"), REPORT_RATIONALE, "verdict.rationale")

    raw = obj.get("sections")
    by_key: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for key, sec in raw.items():
            if key not in REPORT_KEYS:
                raise ReportInvalid(f"unknown section {str(key)[:32]!r}")
            by_key[key] = sec
    elif isinstance(raw, list):
        order = -1
        for sec in raw:
            key = sec.get("key") if isinstance(sec, dict) else None
            if key not in REPORT_KEYS or key in by_key or REPORT_KEYS.index(key) < order:
                raise ReportInvalid("sections: unknown, repeated or out-of-order key")
            order = REPORT_KEYS.index(key)
            by_key[key] = sec
    else:
        raise ReportInvalid("sections missing")

    dropped, downgraded = 0, []
    sections: list[dict[str, Any]] = []
    for key in REPORT_KEYS:
        sec = by_key.get(key)
        if sec is None:
            sections.append({"key": key, "title": REPORT_TITLES[key], "status": "not_analysed",
                             "text": MISSING_TEXT, "evidence": []})
            continue
        if not isinstance(sec, dict) or not all(f in sec for f in _FIELDS):
            raise ReportInvalid(f"{key}: missing fields")
        status = sec["status"]
        if status not in REPORT_STATUSES:
            raise ReportInvalid(f"{key}: status outside the enum")
        title = _str(sec["title"], REPORT_TITLE, f"{key}.title")
        if not title or title.lower().replace(" ", "_") == key:  # live: the model echoes the key
            title = REPORT_TITLES[key]
        text = _str(sec["text"], REPORT_TEXT, f"{key}.text")
        raw_ev = sec["evidence"]
        if not isinstance(raw_ev, list) or len(raw_ev) > REPORT_EVIDENCE:
            raise ReportInvalid(f"{key}: evidence is not a list of at most {REPORT_EVIDENCE}")
        evidence: list[dict[str, str]] = []
        seen: set[tuple[str, ...]] = set()
        for e in raw_ev:
            if not isinstance(e, dict):
                raise ReportInvalid(f"{key}: malformed evidence row")
            by_source = "address" not in e and "source" in e
            if by_source:
                if e["source"] not in EVIDENCE_SOURCES:
                    raise ReportInvalid(f"{key}: evidence source outside the enum")
                row = {"source": e["source"]}
                extra = (("item", REPORT_ITEM), ("note", REPORT_NOTE))
            else:
                if not isinstance(e.get("address"), str) or not _ADDR.fullmatch(e["address"]):
                    raise ReportInvalid(f"{key}: malformed evidence address")
                row = {"address": _norm(e["address"])}
                extra = (("function", REPORT_FUNCTION), ("note", REPORT_NOTE))
            for name, cap in extra:
                if e.get(name) is not None:
                    v = _str(e[name], cap, f"{key}.evidence.{name}")
                    if v:
                        row[name] = v
            if by_source:
                if sources is not None and row["source"] not in sources:
                    dropped += 1
                    continue
                ident: tuple[str, ...] = ("source", row["source"], row.get("item", ""))
            else:
                if known is not None and row["address"] not in known:
                    dropped += 1
                    continue
                ident = ("address", row["address"])
            if ident not in seen:
                seen.add(ident)
                evidence.append(row)
        if status != "observed":
            evidence = []
        elif not evidence and key not in REPORT_NO_EVIDENCE_OK:
            status, text = "not_analysed", DOWNGRADED_EVIDENCE_TEXT if basis else DOWNGRADED_TEXT
            downgraded.append(key)
        sections.append({"key": key, "title": title, "status": status, "text": text, "evidence": evidence})

    report: dict[str, Any] = {"schema": REPORT_SCHEMA, "pass": pass_no,
                              **({"basis": basis} if basis else {}),
                              "verdict": {"label": label, "confidence": confidence, "rationale": rationale},
                              "sections": sections}
    return Validated(report=report, dropped=dropped, downgraded=downgraded)


def report_addresses(report: dict[str, Any] | None) -> set[str]:
    """Every evidence address of a validated report."""
    out: set[str] = set()
    for sec in (report or {}).get("sections", []):
        for e in sec.get("evidence", []):
            if "address" in e:
                out.add(e["address"])
    return out
