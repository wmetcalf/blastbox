"""Federated placement eligibility.

One rule under test throughout: authority comes from the certificate, and everything the
node said about itself is a hint. A node must never be able to widen what it may run by
writing a bigger number into its own heartbeat.
"""
from __future__ import annotations

import time

from blastbox.host.node_registry import NodeClaims, NodeRecord
from blastbox.host.pki import NodeGrants
from blastbox.host.placement import (
    eligible,
    over_claiming_nodes,
    rank,
    unverified_nodes,
)


def rec(node_id, **claims):
    return NodeRecord(node_id=node_id, ts=time.time(), claims=NodeClaims(**claims))


BOXJS = NodeGrants(engines=("boxjs",), tiers=("openvpn",))
BOTH = NodeGrants(engines=("boxjs", "clamav"), tiers=("openvpn", "wireguard"))
CREDENTIALED = NodeGrants(engines=("boxjs",), tiers=("openvpn",), credentials=True)


# --------------------------------------------------- claims cannot widen eligibility

def test_a_node_claiming_an_engine_it_is_not_granted_is_not_eligible():
    """THE test. If a heartbeat could widen eligibility, the certificate would be
    decoration and any compromised node could elect itself for any work."""
    view = [rec("liar", engines=("boxjs", "clamav", "everything"))]
    grants = {"liar": BOXJS}
    assert [c.node_id for c in eligible(view, grants, engine="boxjs")] == ["liar"]
    assert eligible(view, grants, engine="clamav") == ()
    assert eligible(view, grants, engine="everything") == ()


def test_a_node_that_claims_nothing_is_still_eligible_for_what_it_is_granted():
    """The inverse: grants are authority, so an empty or lagging heartbeat does not
    revoke them. Otherwise a node would lose eligibility the moment its claims list
    drifted from its cert."""
    view = [rec("quiet")]
    assert [c.node_id for c in eligible(view, {"quiet": BOXJS}, engine="boxjs")] == ["quiet"]


def test_an_unknown_node_is_not_eligible():
    """Fail-closed, and the common rollout case: registered but with no verifiable
    certificate — expired, foreign, or never enrolled."""
    assert eligible([rec("stranger", engines=("boxjs",))], {}, engine="boxjs") == ()


def test_empty_grants_authorise_nothing():
    assert eligible([rec("bare")], {"bare": NodeGrants()}, engine="boxjs") == ()


# ------------------------------------------------------------------------ tiers

def test_a_tier_the_node_is_not_granted_excludes_it():
    view = [rec("toolz3")]
    grants = {"toolz3": BOXJS}                      # openvpn only
    assert eligible(view, grants, engine="boxjs", tier="openvpn")
    assert eligible(view, grants, engine="boxjs", tier="wireguard") == ()
    assert eligible(view, grants, engine="boxjs", tier="tor") == ()


def test_a_job_with_no_tier_ignores_tier_grants():
    assert eligible([rec("toolz3")], {"toolz3": NodeGrants(engines=("boxjs",))},
                    engine="boxjs") != ()


# ------------------------------------------------------------------ credentials

def test_credentialed_work_does_not_land_on_a_credential_free_node():
    """A global-mode worker node is issued credentials=False precisely so it never has
    to hold a provider profile. This is what enforces that."""
    view = [rec("worker"), rec("exit")]
    grants = {"worker": BOXJS, "exit": CREDENTIALED}
    got = eligible(view, grants, engine="boxjs", require_credentials=True)
    assert [c.node_id for c in got] == ["exit"]
    # ...and without the requirement, both are fine.
    assert len(eligible(view, grants, engine="boxjs")) == 2


# ------------------------------------------------------------------- determinism

def test_eligibility_is_deterministically_ordered():
    """Every dispatcher runs this over the same view and must agree, or placement
    oscillates."""
    view = [rec(n) for n in ("zeta", "alpha", "mid")]
    grants = {n: BOTH for n in ("zeta", "alpha", "mid")}
    assert [c.node_id for c in eligible(view, grants, engine="boxjs")] == \
        ["alpha", "mid", "zeta"]


def test_ranking_prefers_an_idle_node_and_is_total():
    busy = rec("busy", slots=8, backlog=40)
    idle = rec("idle", slots=8, backlog=0)
    roomy = rec("roomy", slots=32, backlog=0)
    grants = {n: BOXJS for n in ("busy", "idle", "roomy")}
    order = [c.node_id for c in rank(eligible([busy, idle, roomy], grants, engine="boxjs"))]
    assert order == ["roomy", "idle", "busy"]


def test_ranking_ties_break_on_node_id():
    view = [rec(n, slots=4, backlog=1) for n in ("c", "a", "b")]
    grants = {n: BOXJS for n in ("a", "b", "c")}
    assert [c.node_id for c in rank(eligible(view, grants, engine="boxjs"))] == \
        ["a", "b", "c"]


def test_an_over_claiming_node_sinks_in_the_ranking_rather_than_being_trusted():
    """Being wrong about capacity costs latency, not containment: a node that
    over-claims attracts work, runs it slowly, and its backlog climbs — so it demotes
    itself. That self-correction is why claims are usable for ordering at all."""
    grants = {"honest": BOXJS, "liar": BOXJS}
    # Before: the liar's inflated slot count wins.
    before = rank(eligible([rec("honest", slots=4), rec("liar", slots=999)],
                           grants, engine="boxjs"))
    assert before[0].node_id == "liar"
    # After reality catches up with it:
    after = rank(eligible([rec("honest", slots=4, backlog=0),
                           rec("liar", slots=999, backlog=250)], grants, engine="boxjs"))
    assert after[0].node_id == "honest"


# ------------------------------------------------------------------ observability

def test_unverified_nodes_are_reported_not_merely_dropped():
    """A fleet quietly shrinking because certs lapsed looks identical to an idle fleet.
    Placement must stay silent; the operator must not have to guess."""
    view = [rec("ok"), rec("lapsed"), rec("stranger")]
    assert unverified_nodes(view, {"ok": BOXJS}) == ("lapsed", "stranger")
    assert unverified_nodes(view, {n: BOXJS for n in ("ok", "lapsed", "stranger")}) == ()


def test_over_claiming_is_reported_so_an_operator_can_tell_stale_from_probing():
    """Harmless to placement — eligible() reads grants — but it is either a grant that
    needs updating or a node asking for work it is not entitled to, and those want
    different responses."""
    view = [rec("toolz3", engines=("boxjs", "clamav", "secret-engine")), rec("fine",
                                                                            engines=("boxjs",))]
    grants = {"toolz3": BOXJS, "fine": BOXJS}
    assert over_claiming_nodes(view, grants) == (
        ("toolz3", ("clamav", "secret-engine")),
    )


def test_an_unverified_node_is_not_also_reported_as_over_claiming():
    """It has no grants to exceed; reporting it twice would just be noise on the one
    screen an operator reads during a rollout."""
    view = [rec("stranger", engines=("boxjs",))]
    assert unverified_nodes(view, {}) == ("stranger",)
    assert over_claiming_nodes(view, {}) == ()


def test_the_module_says_plainly_that_nothing_calls_it_yet():
    """THE ONE RULE is written in the present tense — "grants decide eligibility, full
    stop" — and a reader can reasonably take that as a description of the running
    system. It is not one: nothing in src/ consults this module when placing a job, so
    a compromised node cannot in fact be stopped by it from electing itself for work it
    is not granted. The docstring must say so until dispatch actually calls it, and
    this test is the thing that notices when that stops being true."""
    import pathlib
    import subprocess

    from blastbox.host import node_registry, placement

    root = pathlib.Path(placement.__file__).resolve().parents[3]
    hits = subprocess.run(
        ["grep", "-rIl", "-e", "host.placement", "-e", "host import placement",
         "-e", "host.node_registry", "-e", "host import node_registry",
         "--include=*.py", str(root / "blastbox")],
        capture_output=True, text=True).stdout.split()
    callers = {pathlib.Path(h).name for h in hits} - {"placement.py", "node_registry.py"}

    for mod in (placement, node_registry):
        if callers:
            assert "NOT YET WIRED" not in (mod.__doc__ or ""), (
                f"{mod.__name__} IS now called from {sorted(callers)} — remove the "
                "not-wired banner from both modules and from this test's premise"
            )
        else:
            assert "NOT YET WIRED" in (mod.__doc__ or ""), (
                f"{mod.__name__} is imported by nothing in src/, so its present-tense "
                "guarantees describe a system that does not exist yet; say so"
            )
