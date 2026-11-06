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
    base = {"report": _rep(), "functions_kept": 1, "claims_dropped": 0, "iocs": [], "sweep": {},
            "explored": []}
    base.update(kw)
    return [g.code for g in assess(**base).gaps]


def test_a_confident_report_with_observed_behaviour_meets_the_bar():
    s = assess(report=_rep(), functions_kept=3, claims_dropped=0, iocs=[_ioc("a.example", True)], sweep={},
               explored=[])
    assert s.met and s.gaps == []


def test_verdict_gaps():
    assert _codes(report=None) == ["no_report"]
    assert _codes(report=_rep("unknown", "high")) == ["verdict_unknown"]
    assert _codes(report=_rep("benign", "low")) == ["verdict_low"]
    assert _codes(report=_rep("benign", "medium")) == []


def test_no_observed_behaviour_is_a_gap_even_with_an_observed_overview():
    assert _codes(report=_rep(execution_flow="not_observed")) == ["no_behaviour"]
    assert _codes(report=_rep(execution_flow="not_observed", network="observed")) == []


def test_ioc_precision_needs_enough_iocs_to_judge():
    assert _codes(iocs=[_ioc(f"{i}.example", i == 0) for i in range(4)]) == ["iocs_unverified"]
    assert _codes(iocs=[_ioc(f"{i}.example", i < 2) for i in range(4)]) == []
    assert _codes(iocs=[_ioc(f"{i}.example", False) for i in range(3)]) == []


def test_claims_dropped_only_when_they_outnumber_the_kept_ones():
    assert _codes(functions_kept=1, claims_dropped=2) == ["claims_dropped"]
    assert _codes(functions_kept=2, claims_dropped=2) == []


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
    s = assess(report=_rep(), functions_kept=1, claims_dropped=0, iocs=[], sweep={"capabilities": caps},
               explored=["0x20"])
    assert [g.code for g in s.gaps] == ["lead:network"]
    g = s.gaps[0]
    assert g.targets == ["0x10", "0x30"]  # explored and token entries left out, each once
    assert "connect TCP" in g.detail and "send HTTP" in g.detail and not g.detail.endswith(";")
    # A section the model looked at and found nothing in closes the lead.
    assert _codes(report=_rep(network="not_observed"), sweep={"capabilities": caps}) == []


def test_facts_are_verified_iocs_kept_claims_and_observed_behaviour():
    facts = facts_of(_rep(network="not_observed"), [{"address": "0x10"}],
                     [_ioc("a.example", True), _ioc("b.example", False)])
    assert sorted(facts) == ["fn:0x10", "ioc:domain:a.example", "sec:execution_flow"]
    assert facts_of(None, [], []) == []
