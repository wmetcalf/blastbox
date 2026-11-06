"""The deepening bar: does the chain need another agent pass?

The model's own ``done`` flag is a self-assessment and decides nothing. After each accepted pass
the engine checks the latest analysis report and the pass's findings against evidence it can
verify itself, and lists what is still missing (``gaps``):

- ``no_report``: no valid ``rea.analysis/1`` report exists yet;
- ``verdict_unknown`` / ``verdict_low``: the verdict is ``unknown``, or its confidence is ``low``;
- ``no_behaviour``: no behaviour section (``BEHAVIOUR_KEYS``) is ``observed``;
- ``iocs_unverified``: at least ``MIN_IOCS_FOR_RATIO`` IOCs were proposed and fewer than
  ``MIN_VERIFIED_RATIO`` of them occur in the sample's bytes;
- ``claims_dropped``: more function claims were dropped (uncitable address) than kept;
- ``lead:<section>``: a capa rule with an ATT&CK id points at a report section
  (``LEAD_SECTIONS``) that the report left ``not_analysed``. Its unexplored functions are the
  gap's ``targets``, which go to the front of the next pass's todo list.

The bar is met when there are no gaps. Otherwise the chain continues unless a stop rule fires:
``stalled`` (a later pass added no fact the chain did not already have) or ``pass_cap``
(``REA_MAX_PASSES``). Facts are verified IOCs,
the addresses of kept function claims and the report sections marked ``observed``.

Thresholds are first guesses, to be calibrated on a labeled scoring set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["BEHAVIOUR_KEYS", "LEAD_SECTIONS", "Gap", "Sufficiency", "assess", "facts_of"]

MIN_IOCS_FOR_RATIO = 4
MIN_VERIFIED_RATIO = 0.5
MAX_TARGETS = 16  # per lead gap
MAX_GAPS = 16
MAX_FACTS = 4096
MAX_DETAIL = 300

BEHAVIOUR_KEYS = ("execution_flow", "capabilities", "network", "persistence", "host_activity",
                  "anti_analysis")
# capa namespace prefix -> the report section a match of it should be discussed in.
LEAD_SECTIONS: tuple[tuple[str, str], ...] = (
    ("communication", "network"),
    ("persistence", "persistence"),
    ("anti-analysis", "anti_analysis"),
    ("host-interaction", "host_activity"),
    ("collection", "capabilities"),
    ("impact", "capabilities"),
    ("data-manipulation/encryption", "capabilities"),
    ("load-code", "execution_flow"),
)


@dataclass
class Gap:
    code: str
    detail: str
    targets: list[str] = field(default_factory=list)


@dataclass
class Sufficiency:
    met: bool
    gaps: list[Gap]


def _section_of(namespace: str) -> str | None:
    for prefix, key in LEAD_SECTIONS:
        if namespace == prefix or namespace.startswith(prefix + "/"):
            return key
    return None


def _statuses(report: dict[str, Any] | None) -> dict[str, str]:
    sections = report.get("sections") if isinstance(report, dict) else None
    out: dict[str, str] = {}
    for s in sections if isinstance(sections, list) else []:
        if isinstance(s, dict) and isinstance(s.get("key"), str) and isinstance(s.get("status"), str):
            out[s["key"]] = s["status"]
    return out


def facts_of(report: dict[str, Any] | None, functions: list[dict[str, Any]],
             iocs: list[dict[str, Any]]) -> list[str]:
    """What a pass established that a later pass can be compared against."""
    out = [f"ioc:{i['type']}:{i['value']}" for i in iocs if i.get("verified")]
    out += [f"fn:{f['address']}" for f in functions]
    out += [f"sec:{k}" for k, st in _statuses(report).items() if st == "observed" and k in BEHAVIOUR_KEYS]
    return out


def assess(*, report: dict[str, Any] | None, functions_kept: int, claims_dropped: int,
           iocs: list[dict[str, Any]], sweep: dict[str, Any], explored: list[str]) -> Sufficiency:
    gaps: list[Gap] = []
    if not isinstance(report, dict):
        gaps.append(Gap("no_report", "no valid analysis report has been written yet"))
        statuses: dict[str, str] = {}
    else:
        raw = report.get("verdict")
        verdict: dict[str, Any] = raw if isinstance(raw, dict) else {}
        label, conf = verdict.get("label"), verdict.get("confidence")
        if label == "unknown":
            gaps.append(Gap("verdict_unknown", "the verdict is unknown: find what the sample does"))
        elif conf == "low":
            gaps.append(Gap("verdict_low", f"the verdict ({label}) has low confidence: find evidence "
                                           "that confirms or overturns it"))
        statuses = _statuses(report)
        if not any(statuses.get(k) == "observed" for k in BEHAVIOUR_KEYS):
            gaps.append(Gap("no_behaviour", "no behaviour section is backed by observed evidence"))
    proposed = len(iocs)
    verified = sum(1 for i in iocs if i.get("verified"))
    if proposed >= MIN_IOCS_FOR_RATIO and verified < MIN_VERIFIED_RATIO * proposed:
        gaps.append(Gap("iocs_unverified", f"only {verified} of {proposed} proposed IOCs occur in the "
                                           "sample's bytes: report only values read from the sample"))
    if claims_dropped > functions_kept:
        gaps.append(Gap("claims_dropped", f"{claims_dropped} function claims cited addresses no tool "
                                          "result contained"))
    if isinstance(report, dict):
        done = set(explored)
        leads: dict[str, Gap] = {}
        caps = sweep.get("capabilities")
        for c in caps if isinstance(caps, list) else []:
            if not isinstance(c, dict) or not c.get("attack") or not isinstance(c.get("namespace"), str):
                continue
            key = _section_of(c["namespace"])
            if key is None or statuses.get(key, "not_analysed") != "not_analysed":
                continue
            gap = leads.get(key)
            if gap is None:
                gap = leads[key] = Gap(f"lead:{key}", f"capa matched rules for the {key} section, which "
                                                       "the report left not analysed:")
            rule = str(c.get("rule") or "")[:80]
            if len(gap.detail) + len(rule) < MAX_DETAIL:
                gap.detail += f" {rule};"
            fns = c.get("functions")
            for f in fns if isinstance(fns, list) else []:
                if (isinstance(f, str) and f.startswith("0x") and f not in done and f not in gap.targets
                        and len(gap.targets) < MAX_TARGETS):
                    gap.targets.append(f)
        for gap in leads.values():
            gap.detail = gap.detail.rstrip(";")
        gaps.extend(leads.values())
    gaps = gaps[:MAX_GAPS]
    return Sufficiency(met=not gaps, gaps=gaps)
