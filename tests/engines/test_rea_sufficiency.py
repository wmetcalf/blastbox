"""The deepening bar (``sufficiency.assess`` / ``facts_of``)."""

from __future__ import annotations

from blastbox.engines.rea.sufficiency import assess, facts_of


def _rep(label="malicious", confidence="high", **statuses):
    secs = {"overview": "observed", "execution_flow": "observed"}
    secs.update(statuses)
    return {"verdict": {"label": label, "confidence": confidence, "rationale": "r"},
            "sections": [{"key": k, "status": v} for k, v in secs.items()]}


def _ioc(v, ok):
    return {"type": "domain", "value": v, "verified": ok}


def _codes(**kw):
    base = {"report": _rep(), "sweep": {}, "explored": []}
    base.update(kw)
    return [g.code for g in assess(**base).gaps]


def test_a_confident_report_with_observed_behaviour_meets_the_bar():
    s = assess(report=_rep(), sweep={}, explored=[])
    assert s.met and s.gaps == []


def test_verdict_gaps():
    assert _codes(report=None) == ["no_report"]
    assert _codes(report=_rep("unknown", "high")) == ["verdict_unknown"]
    assert _codes(report=_rep("benign", "low")) == ["verdict_low"]
    assert _codes(report=_rep("benign", "medium")) == []


def test_no_observed_behaviour_is_a_gap_even_with_an_observed_overview():
    assert _codes(report=_rep(execution_flow="not_observed")) == ["no_behaviour"]
    assert _codes(report=_rep(execution_flow="not_observed", network="observed")) == []


def test_capa_leads_point_at_sections_left_not_analysed():
    caps = [
        {"rule": "connect TCP", "namespace": "communication/socket/tcp", "attack": ["T1071"],
         "functions": ["0x10", "0x20", "token:0x6000001"]},
        {"rule": "send HTTP", "namespace": "communication/http", "attack": ["T1071.001"],
         "functions": ["0x30", "0x10"]},
        {"rule": "get file size", "namespace": "host-interaction/file-system", "attack": [],
         "functions": ["0x40"]},  # no ATT&CK id: not a lead
        {"rule": "contain loop", "namespace": "internal", "attack": ["T0000"], "functions": ["0x50"]},
        "junk",
    ]
    s = assess(report=_rep(), sweep={"capabilities": caps}, explored=["0x20"])
    assert [g.code for g in s.gaps] == ["lead:network"]
    g = s.gaps[0]
    assert g.targets == ["0x10", "0x30"]  # explored and token entries left out, each once
    assert "connect TCP" in g.detail and "send HTTP" in g.detail and not g.detail.endswith(";")
    # A section the model looked at and found nothing in closes the lead.
    assert _codes(report=_rep(network="not_observed"), sweep={"capabilities": caps}) == []
    # So does having nothing left to open: all explored, or .NET tokens only.
    assert _codes(sweep={"capabilities": caps}, explored=["0x10", "0x20", "0x30"]) == []
    dotnet = [{"rule": "connect TCP", "namespace": "communication/socket/tcp", "attack": ["T1071"],
               "functions": ["token:0x6000001"]}]
    assert _codes(sweep={"capabilities": dotnet}) == []


def test_facts_are_verified_iocs_kept_claims_and_observed_behaviour():
    facts = facts_of(_rep(network="not_observed"), [{"address": "0x10"}],
                     [_ioc("a.example", True), _ioc("b.example", False)])
    assert sorted(facts) == ["fn:0x10", "ioc:domain:a.example", "sec:execution_flow"]
    assert facts_of(None, [], []) == []


def test_a_benign_verdict_needs_the_programs_own_code_read():
    own = ["0x10", "0x20", "0x30"]
    s = assess(report=_rep("benign", "medium"), sweep={}, explored=["0x10"], program_functions=own)
    assert [g.code for g in s.gaps] == ["benign_unexplored"] and s.gaps[0].targets == ["0x20", "0x30"]
    assert "2 of the program's own 3" in s.gaps[0].detail
    assert assess(report=_rep("benign", "medium"), sweep={}, explored=own, program_functions=own).met
    # Only a benign call carries that burden; and with no program list there is nothing to check.
    assert assess(report=_rep("malicious", "high"), sweep={}, explored=[], program_functions=own).met
    assert assess(report=_rep("benign", "medium"), sweep={}, explored=[]).met
