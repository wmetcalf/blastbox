"""The deepening bar: does the chain need another agent pass?

The model's own ``done`` flag is a self-assessment and decides nothing. After each accepted pass
the engine checks the latest analysis report and the pass's findings against evidence it can
verify itself, and lists what is still missing (``gaps``):

- ``no_report``: no valid ``rea.analysis/1`` report exists yet;
- ``verdict_unknown`` / ``verdict_low``: the verdict is ``unknown``, or its confidence is ``low``;
- ``no_behaviour``: no behaviour section (``BEHAVIOUR_KEYS``) is ``observed``;
- ``code_unread``: the report was written from the sweep's evidence alone (``basis``
  ``evidence``: the disassembler timed out or failed) and no decompiler output stood in for it
  (``sweep["decompiled"]`` holding excerpts of the analysed assembly itself, label ``sample``; a
  recovered stage's code does not cover the sample). Whatever the sample does beyond that evidence is unknown, so the bar
  is never met; no pass can close the gap, and the chain stops with ``evidence_only``;
- ``benign_unexplored``: the verdict is ``benign`` while a code tool has not returned some of
  the program's own functions (``program_functions``: for Go, ``main.*`` and third-party
  modules; ``opened``: the addresses the chain's decompile and disassembly calls asked for). A
  benign call is a claim about everything the program does; live, a Go sample whose ``main`` is
  a board-game decoy was called benign/medium with part of its own code unread. ``explored``
  does not count here: a metadata call or the model's own function list puts an address there
  without anyone reading the function. Its targets are those functions;
- ``benign_hidden_payload``: the verdict is ``benign`` while the sweep found a hidden payload in
  a .NET assembly's resources (``sweep["dotnet_resources"]["hidden_payloads"]``: a large
  high-entropy resource, one that decodes to a PE, or a picture whose pixels do or are noise). Live, Formbook and NanoCore carriers were
  described by their decoy UI and called benign with the encrypted payload unread. The code that
  loads it is not addressable (CIL tokens), so the gap has no targets; it holds until the verdict
  stops being benign or the chain stops (stalled, pass cap);
- ``benign_emulated_stage``: the verdict is ``benign`` while emulating the stub showed it hiding
  a stage (``sweep["emulation"]["concealment"]``: executable allocations, code run outside its
  image, a PE written into memory, its own code rewritten, injection APIs) and no captured stage
  replaced it (``sweep["emulation"]["payload_sha256"]`` absent; when one did, the report is about
  that stage and the usual bar applies). Live, obfuscated loaders were described by their stub. No
  targets; it holds until the verdict stops being benign or the chain stops;
- ``benign_installer_concealment``: the verdict is ``benign`` while the sweep's installer
  evidence says the installer hides what it runs: its archive signature was altered
  (``"signature": "altered"`` in ``sweep["unpacked"]`` or ``sweep["installer_stub"]``), or it
  carries no program of its own, only the ``System.dll`` plugin beside data files of
  ``OPAQUE_MEMBER_BYTES`` or more (``sweep["installer_stub"]``: the script-driven shellcode
  loader). Live, a GuLoader-style NSIS installer was called a standard installer on its stub's
  code. No targets; it holds until the verdict stops being benign or the chain stops;
- ``lead:<section>``: a capa rule with an ATT&CK id points at a report section
  (``LEAD_SECTIONS``) that the report left ``not_analysed``. Its unexplored functions are the
  gap's ``targets``, which go to the front of the next pass's todo list; a lead with no target
  left is not a gap.

- ``suspicious_concealment``: the verdict is ``suspicious`` while the sweep shows one of the
  three concealments above (a hidden resource payload, a stage emulation saw hidden and did not
  capture, an installer that hides what it runs), and the model's reading was not benign (then the
  benign gaps above hold instead). A suspicious label on concealment says the sample hides
  something, not what. Live, the same loaders read malicious/high on one run and
  suspicious/medium on the next, by whether pass 1 happened to reach the code behind the
  concealment; the suspicious run met the bar and no pass went looking. No targets; it holds until
  the verdict changes or the chain stops (``stalled``: a pass that finds nothing new ends it;
  ``pass_cap``). It costs passes on legitimately packed software, which is unmeasured: the scoring
  set holds no benign programs;

The three hidden-evidence gaps (``benign_hidden_payload``, ``benign_emulated_stage``,
``benign_installer_concealment``) also hold when the *model* read the sample as benign and the
verdict rule (``verdict.py``) overrode it on that same concealment (``opinion``, carried in the
continuation with the report it stands behind): the rule fixes the label, but the model has still not explained what is
hidden, and the next pass should. ``benign_unexplored`` goes by the final label alone.

IOC precision and dropped claims are not gaps: they measure the model's care, not what is left
to analyse, and live they did not improve with another pass (a DLL's pass 2 verified 0 of 6
IOCs) while a pass could clear them by proposing nothing. Both stay visible in the payload (IOC
``verified`` column, the ``claims_dropped`` warning).

The bar is met when there are no gaps. Otherwise the chain continues unless a stop rule fires:
``stalled`` (a later pass added no fact the chain did not already have), ``pass_cap``
(``REA_MAX_PASSES``) or ``evidence_only`` (the pass had no disassembly: one report, then stop). Facts are verified IOCs,
the addresses of kept function claims and the report sections marked ``observed``.

Thresholds are first guesses, to be calibrated on a labeled scoring set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["BEHAVIOUR_KEYS", "LEAD_SECTIONS", "STALLING", "Gap", "Sufficiency", "assess", "facts_of",
           "installer_concealment", "sample_decompiled"]

MAX_TARGETS = 16  # per lead gap
MAX_GAPS = 16
MAX_FACTS = 4096
MAX_DETAIL = 300
OPAQUE_MEMBER_BYTES = 64 * 1024  # a data file this large in a program-less installer needs explaining

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
            raw_stage = h.get("stage")
            stage: dict[str, Any] = raw_stage if isinstance(raw_stage, dict) else {}
            how = (f", decodes ({str(h['decoded'])[:48]}) to a PE" if h.get("decoded") else
                   ", image pixels are noise" if h.get("noise") else "")
            module = f" {str(stage['module'])[:60]}" if stage.get("module") else ""
            out.append(f"{where}: {h.get('size')} bytes, entropy {h.get('entropy')}{how}{module}")
    return out


def installer_concealment(sweep: dict[str, Any]) -> str:
    """Why the installer evidence rules out a benign call ("" when it does not)."""
    unpacked, stub = sweep.get("unpacked"), sweep.get("installer_stub")
    layers = [unpacked, *(unpacked.get("inner") or [])] if isinstance(unpacked, dict) else []
    why = []
    if any(isinstance(layer, dict) and layer.get("signature") == "altered" for layer in [*layers, stub]):
        why.append("its archive signature was altered to defeat extraction tools")
    if isinstance(stub, dict):
        plugins = [str(p)[:40] for p in stub.get("plugins") or [] if isinstance(p, str)]
        data = [d for d in stub.get("data_members") or [] if isinstance(d, dict)
                and isinstance(d.get("size"), int) and d["size"] >= OPAQUE_MEMBER_BYTES]
        if data and any(p.lower() == "system.dll" for p in plugins):
            names = ", ".join(f"{str(d.get('name'))[-40:]} {d['size']} bytes" for d in data[:2])
            why.append(f"it carries no program, only System.dll and {len(data)} opaque data file(s) ({names})")
    return "; ".join(why)


STALLING = frozenset({"delay_loop"})


# A decompiler run's code counts as read on these statuses, given excerpts: a run cut short by its
# clock or its size cap still left real C#; one that failed left whatever it left.
DECOMPILE_READ = ("ok", "timeout", "too_large")


def sample_decompiled(sweep: dict[str, Any]) -> bool:
    """Whether the sweep's decompiler read the analysed assembly itself (label ``sample``)."""
    decompiled = sweep.get("decompiled")
    images = decompiled.get("images") if isinstance(decompiled, dict) else None
    return isinstance(images, list) and any(
        isinstance(i, dict) and i.get("label") == "sample" and isinstance(i.get("status"), str)
        and i["status"] in DECOMPILE_READ and bool(i.get("excerpts")) for i in images)


def _concealment(sweep: dict[str, Any]) -> list[str]:
    em = sweep.get("emulation")
    if not isinstance(em, dict) or em.get("payload_sha256"):
        return []
    items = em.get("concealment")
    found = [str(c)[:40] for c in items if isinstance(c, str)][:8] if isinstance(items, list) else []
    # Stalling alone is not a hidden stage: plenty of honest programs sleep on a timer.
    return found if any(c not in STALLING for c in found) else []


def facts_of(report: dict[str, Any] | None, functions: list[dict[str, Any]],
             iocs: list[dict[str, Any]]) -> list[str]:
    """What a pass established that a later pass can be compared against."""
    out = [f"ioc:{i['type']}:{i['value']}" for i in iocs if i.get("verified")]
    out += [f"fn:{f['address']}" for f in functions]
    out += [f"sec:{k}" for k, st in _statuses(report).items() if st == "observed" and k in BEHAVIOUR_KEYS]
    return out


def assess(*, report: dict[str, Any] | None, sweep: dict[str, Any], explored: list[str],
           program_functions: list[str] | None = None, opinion: str | None = None,
           opened: list[str] | None = None) -> Sufficiency:
    """``opinion``: the model's own call behind ``report``, before the verdict rule (``verdict.py``).
    ``opened``: the addresses a code tool was asked for and returned (``agent.CODE_TOOLS``)."""
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
        if report.get("basis") == "evidence" and not sample_decompiled(sweep):
            gaps.append(Gap("code_unread", "the report rests on the sweep's evidence alone: the disassembler "
                                           "produced no code to read, so what the sample does beyond that "
                                           "evidence is unknown"))
        said = ("the verdict is benign" if label == "benign"
                else "the analysis reads the sample as benign" if opinion == "benign" else "")
        if label == "benign":
            seen = set(opened or [])
            left = [f for f in program_functions or [] if f not in seen]
            if left:
                gaps.append(Gap("benign_unexplored",
                                f"the verdict is benign but {len(left)} of the program's own "
                                f"{len(program_functions or [])} functions are unexplored: decompile "
                                "them by address before ruling out hostile behaviour", left[:MAX_TARGETS]))
        if said:
            hidden = _hidden_payloads(sweep)
            if hidden:
                gaps.append(Gap("benign_hidden_payload",
                                (said + " but the assembly carries a hidden payload the analysis "
                                 "has not explained (" + "; ".join(hidden) + "): the visible program may be a "
                                 "decoy; find the code that loads it")[:MAX_DETAIL]))
            installer = installer_concealment(sweep)
            if installer:
                gaps.append(Gap("benign_installer_concealment",
                                (said + " but the installer hides what it runs: " + installer
                                 + "; explain what its script loads")[:MAX_DETAIL]))
            concealed = _concealment(sweep)
            if concealed:
                gaps.append(Gap("benign_emulated_stage",
                                (said + " but emulating the stub showed it concealing a stage ("
                                 + ", ".join(concealed) + "): the analysed code is a loader; explain what it "
                                 "decrypts and runs")[:MAX_DETAIL]))
        elif label == "suspicious":
            concealed_by = [what for what in ("; ".join(_hidden_payloads(sweep)), installer_concealment(sweep),
                                              ", ".join(_concealment(sweep))) if what]
            if concealed_by:
                gaps.append(Gap("suspicious_concealment",
                                ("the verdict is suspicious on concealment alone: " + "; ".join(concealed_by)
                                 + ": find what the concealed part does (the stage it decrypts, loads or "
                                   "runs) and cite it as a ground, or show that it is harmless")[:MAX_DETAIL]))
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
