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
    s = assess(report=_rep("benign", "medium"), sweep={}, explored=[], opened=["0x10"], program_functions=own)
    assert [g.code for g in s.gaps] == ["benign_unexplored"] and s.gaps[0].targets == ["0x20", "0x30"]
    assert "2 of the program's own 3" in s.gaps[0].detail
    assert assess(report=_rep("benign", "medium"), sweep={}, explored=[], opened=own, program_functions=own).met
    # Read means a code tool returned it: an address the chain merely touched or listed is not.
    s = assess(report=_rep("benign", "medium"), sweep={}, explored=own, program_functions=own)
    assert [g.code for g in s.gaps] == ["benign_unexplored"] and s.gaps[0].targets == own
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
    # A suspicious call owes what the concealment hides (not the benign burden): see below.
    assert _codes(report=_rep("suspicious", "medium"), sweep={"installer_stub": stub}) == ["suspicious_concealment"]
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
    image = {"label": "sample", "status": "ok",
             "excerpts": [{"type": "Stub", "member": "Main", "why": [], "code": "x"}]}
    for status in ("ok", "timeout", "too_large"):  # a partial tree still holds real C#
        assert assess(report=report, sweep={"decompiled": {"images": [{**image, "status": status}]}}, explored=[]).met
    # ... but only for the assembly itself: a recovered stage's code, or an outline alone, does not;
    # nor does whatever a decompiler that failed left behind.
    unstated = {k: v for k, v in image.items() if k != "status"}
    for images in ([{**image, "label": "stage Inner.dll (member-2)"}], [{**image, "excerpts": []}], "x", [None],
                   [{**image, "status": "failed"}], [{**image, "status": "unavailable"}], [{**image, "status": 1}],
                   [unstated]):
        got = assess(report=report, sweep={"decompiled": {"images": images}}, explored=[])
        assert [g.code for g in got.gaps] == ["code_unread"], images
    assert assess(report={**report, "basis": None}, sweep={}, explored=[]).met


def test_a_benign_reading_the_rule_overrode_still_owes_an_explanation_of_what_is_hidden():
    """The verdict rule (verdict.py) turns a benign call into suspicious when the sweep shows
    concealment, so the label alone would meet the bar with the hidden part unexplained."""
    ruled = _rep("suspicious", "medium")
    hidden = {"dotnet_resources": {"hidden_payloads": [{"resource": "r", "size": 9, "entropy": 7.9}]}}
    assert _codes(report=ruled, sweep=hidden) == ["suspicious_concealment"]
    s = assess(report=ruled, sweep=hidden, explored=[], opinion="benign")
    assert [g.code for g in s.gaps] == ["benign_hidden_payload"]
    assert s.gaps[0].detail.startswith("the analysis reads the sample as benign but ")
    assert assess(report=_rep("benign", "medium"), sweep=hidden, explored=[],
                  opinion="benign").gaps[0].detail.startswith("the verdict is benign but ")
    emulated = {"emulation": {"concealment": ["exec_alloc"]}}
    assert _codes(report=ruled, sweep=emulated, opinion="benign") == ["benign_emulated_stage"]
    altered = {"unpacked": {"packer": "nsis", "signature": "altered"}}
    assert _codes(report=ruled, sweep=altered, opinion="benign") == ["benign_installer_concealment"]
    # Any other reading, or none (the report is an earlier pass's), owes no benign explanation;
    # a suspicious label over that concealment owes the one below instead.
    for opinion in ("suspicious", "malicious", "unknown", None):
        assert _codes(report=ruled, sweep={**hidden, **emulated, **altered},
                      opinion=opinion) == ["suspicious_concealment"]
    # Unread program code is a burden of the benign verdict itself, not of the reading.
    assert _codes(report=ruled, sweep={}, explored=[], program_functions=["0x10"], opinion="benign") == []


def test_a_suspicious_call_that_rests_on_concealment_owes_what_the_concealed_part_does():
    """Live, the same loader read malicious/high on one run and suspicious/medium on the next: the
    verdict followed whether pass 1 happened to reach the hostile code behind the concealment, and
    a suspicious label met the bar, so no pass went looking."""
    hidden = {"dotnet_resources": {"hidden_payloads": [{"resource": "r", "size": 9, "entropy": 7.9}]}}
    emulated = {"emulation": {"concealment": ["exec_alloc"]}}
    altered = {"unpacked": {"packer": "nsis", "signature": "altered"}}
    for sweep, what in ((hidden, "r: 9 bytes"), (emulated, "exec_alloc"), (altered, "archive signature")):
        for conf in ("medium", "high"):
            s = assess(report=_rep("suspicious", conf), sweep=sweep, explored=[])
            assert [g.code for g in s.gaps] == ["suspicious_concealment"] and not s.met
            assert s.gaps[0].targets == [] and what in s.gaps[0].detail
            assert s.gaps[0].detail.startswith("the verdict is suspicious on concealment alone: ")
    # A malicious call has established what the sample does; a benign one owes the benign gaps.
    for label, codes in (("malicious", []), ("benign", ["benign_hidden_payload"])):
        assert _codes(report=_rep(label, "high"), sweep=hidden) == codes
    # Suspicious without concealment (the model's own reading of code) owes nothing more.
    assert _codes(report=_rep("suspicious", "medium"), sweep={}) == []
    # Stalling is not concealment, and a stage emulation captured is the code the report read.
    for sweep in ({"emulation": {"concealment": ["delay_loop"]}},
                  {"emulation": {"concealment": ["exec_alloc"], "payload_sha256": "ab" * 32}}):
        assert _codes(report=_rep("suspicious", "medium"), sweep=sweep) == []
    # Low confidence already has its gap; the concealment one joins it.
    assert _codes(report=_rep("suspicious", "low"), sweep=hidden) == ["verdict_low", "suspicious_concealment"]
