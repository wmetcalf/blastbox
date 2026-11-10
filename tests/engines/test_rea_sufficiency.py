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


def test_a_benign_verdict_does_not_stand_on_an_installer_that_hides_what_it_runs():
    big = {"name": "heteroalbumose.ube", "size": 904637, "entropy": 0.16}
    stub = {"packer": "nsis", "member_count": 15, "plugins": ["System.dll"], "data_members": [big]}
    s = assess(report=_rep("benign", "medium"), sweep={"installer_stub": stub}, explored=[])
    assert [g.code for g in s.gaps] == ["benign_installer_concealment"] and s.gaps[0].targets == []
    assert "System.dll" in s.gaps[0].detail and "heteroalbumose.ube 904637 bytes" in s.gaps[0].detail
    assert len(s.gaps[0].detail) <= 300
    # Only a benign call carries the burden.
    assert _codes(report=_rep("suspicious", "medium"), sweep={"installer_stub": stub}) == []
    # An altered archive signature, on the payload's installer or a nested one, or on a stub.
    altered = {"packer": "nsis", "payload_member": "carved/item-2.bin", "signature": "altered"}
    assert _codes(report=_rep("benign", "high"), sweep={"unpacked": altered}) == ["benign_installer_concealment"]
    nested = {"packer": "inno", "inner": [{"packer": "nsis", "signature": "altered"}]}
    assert _codes(report=_rep("benign", "high"), sweep={"unpacked": nested}) == ["benign_installer_concealment"]
    s = assess(report=_rep("benign", "high"), sweep={"installer_stub": {**stub, "signature": "altered"}},
               explored=[])
    assert "signature was altered" in s.gaps[0].detail and "no program" in s.gaps[0].detail


def test_ordinary_installers_and_program_less_ones_without_a_loader_shape_are_not_concealment():
    benign = _rep("benign", "medium")
    small = {"name": "license.txt", "size": 4096, "entropy": 4.2}
    big = {"name": "data.bin", "size": 1 << 20, "entropy": 7.9}
    for sweep in ({"unpacked": {"packer": "nsis", "payload_member": "app.exe"}},
                  {"unpacked": {"packer": "upx"}},
                  {"installer_stub": {"packer": "nsis", "plugins": ["System.dll"], "data_members": [small]}},
                  {"installer_stub": {"packer": "nsis", "plugins": ["nsDialogs.dll"], "data_members": [big]}},
                  {"installer_stub": {"packer": "inno", "member_count": 3, "data_members": [big]}},
                  {"installer_stub": {"packer": "nsis", "plugins": "System.dll", "data_members": [None, 7]}},
                  {"installer_stub": "nsis", "unpacked": ["x"]}):
        assert _codes(report=benign, sweep=sweep) == [], sweep


def test_an_evidence_only_report_leaves_the_code_unread():
    from blastbox.engines.rea.sufficiency import assess
    report = {"basis": "evidence", "verdict": {"label": "malicious", "confidence": "high"},
              "sections": [{"key": "network", "status": "observed"}]}
    assert [g.code for g in assess(report=report, sweep={}, explored=[]).gaps] == ["code_unread"]
    # Decompiler output stands in for the disassembly: the usual bar applies.
    image = {"label": "sample", "excerpts": [{"type": "Stub", "member": "Main", "why": [], "code": "x"}]}
    assert assess(report=report, sweep={"decompiled": {"images": [image]}}, explored=[]).met
    # ... but only for the assembly itself: a recovered stage's code, or an outline alone, does not.
    for images in ([{**image, "label": "stage Inner.dll (member-2)"}], [{**image, "excerpts": []}], "x", [None]):
        got = assess(report=report, sweep={"decompiled": {"images": images}}, explored=[])
        assert [g.code for g in got.gaps] == ["code_unread"], images
    assert assess(report={**report, "basis": None}, sweep={}, explored=[]).met
