"""The deepening bar: does the chain need another agent pass?

The model's own ``done`` flag is a self-assessment and decides nothing. After each accepted pass
the engine checks the latest analysis report and the pass's findings against evidence it can
verify itself, and lists what is still missing (``gaps``):

- ``no_report``: no valid ``rea.analysis/1`` report exists yet;
- ``verdict_unknown`` / ``verdict_low``: the verdict is ``unknown``, or its confidence is ``low``;
- ``no_behaviour``: no behaviour section (``BEHAVIOUR_KEYS``) is ``observed``;
- ``benign_unexplored``: the verdict is ``benign`` while some of the program's own functions
  (``program_functions``: for Go, ``main.*`` and third-party modules) are unexplored. A benign
  call is a claim about everything the program does; live, a Go sample whose ``main`` is a
  board-game decoy was called benign/medium with part of its own code unread. Its targets are
  those functions;
- ``benign_hidden_payload``: the verdict is ``benign`` while the sweep found a hidden payload in
  a .NET assembly's resources (``sweep["dotnet_resources"]["hidden_payloads"]``: a large
  high-entropy resource, or one that decodes to a PE). Live, Formbook and NanoCore carriers were
  described by their decoy UI and called benign with the encrypted payload unread. The code that
  loads it is not addressable (CIL tokens), so the gap has no targets; it holds until the verdict
  stops being benign or the chain stops (stalled, pass cap);
- ``lead:<section>``: a capa rule with an ATT&CK id points at a report section
  (``LEAD_SECTIONS``) that the report left ``not_analysed``. Its unexplored functions are the
  gap's ``targets``, which go to the front of the next pass's todo list; a lead with no target
  left is not a gap.

IOC precision and dropped claims are not gaps: they measure the model's care, not what is left
to analyse, and live they did not improve with another pass (a DLL's pass 2 verified 0 of 6
IOCs) while a pass could clear them by proposing nothing. Both stay visible in the payload (IOC
``verified`` column, the ``claims_dropped`` warning).

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


def _hidden_payloads(sweep: dict[str, Any]) -> list[str]:
    res = sweep.get("dotnet_resources")
    items = res.get("hidden_payloads") if isinstance(res, dict) else None
    out = []
    for h in items if isinstance(items, list) else []:
        if isinstance(h, dict):
            where = str(h.get("resource") or "?")[:80] + (f"/{str(h['entry'])[:40]}" if h.get("entry") else "")
            out.append(f"{where}: {h.get('size')} bytes, entropy {h.get('entropy')}")
    return out


def facts_of(report: dict[str, Any] | None, functions: list[dict[str, Any]],
             iocs: list[dict[str, Any]]) -> list[str]:
    """What a pass established that a later pass can be compared against."""
    out = [f"ioc:{i['type']}:{i['value']}" for i in iocs if i.get("verified")]
    out += [f"fn:{f['address']}" for f in functions]
    out += [f"sec:{k}" for k, st in _statuses(report).items() if st == "observed" and k in BEHAVIOUR_KEYS]
    return out


def assess(*, report: dict[str, Any] | None, sweep: dict[str, Any], explored: list[str],
           program_functions: list[str] | None = None) -> Sufficiency:
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
        if label == "benign":
            seen = set(explored)
            left = [f for f in program_functions or [] if f not in seen]
            if left:
                gaps.append(Gap("benign_unexplored",
                                f"the verdict is benign but {len(left)} of the program's own "
                                f"{len(program_functions or [])} functions are unexplored: read them "
                                "before ruling out hostile behaviour", left[:MAX_TARGETS]))
            hidden = _hidden_payloads(sweep)
            if hidden:
                gaps.append(Gap("benign_hidden_payload",
                                ("the verdict is benign but the assembly carries a hidden payload the analysis "
                                 "has not explained (" + "; ".join(hidden) + "): the visible program may be a "
                                 "decoy; find the code that loads it")[:MAX_DETAIL]))
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
        # A lead with nothing left to open (every function explored, or .NET tokens only, which the
        # agent cannot address) is closed: live, such leads kept a .NET chain running to the cap
        # with the same malicious/high verdict on every pass.
        gaps.extend(g for g in leads.values() if g.targets)
    gaps = gaps[:MAX_GAPS]
    return Sufficiency(met=not gaps, gaps=gaps)
