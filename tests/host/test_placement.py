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


def test_the_modules_say_accurately_which_half_is_wired():
    """THE ONE RULE is written in the present tense — "grants decide eligibility, full
    stop" — and for a while nothing in src/ consulted either module, so a reader could
    reasonably take it as a description of the running system when it was not one.

    Now the SELF-CHECK is wired (a dispatcher asks `refusal` about itself) and the
    FLEET view is not (nothing builds a NodeRegistry). The docstrings must track that
    split in both directions, so this asserts against what actually imports what rather
    than against a banner someone remembered to update.

    An earlier version of this test grepped a path that does not exist on this layout,
    found no callers, and passed while asserting the opposite of the truth — hence the
    assertion below that the directory being searched is real.
    """
    import pathlib
    import subprocess

    from blastbox.host import node_registry, placement

    pkg = pathlib.Path(placement.__file__).resolve().parents[1]
    assert (pkg / "host" / "dispatch.py").exists(), f"{pkg} is not the blastbox package"

    def callers_of(*needles):
        args = []
        for n in needles:
            args += ["-e", n]
        hits = subprocess.run(
            ["grep", "-rIl", *args, "--include=*.py", str(pkg)],
            capture_output=True, text=True).stdout.split()
        return {pathlib.Path(h).name for h in hits} - {"placement.py", "node_registry.py"}

    placement_callers = callers_of("host.placement", "host import placement")
    registry_callers = callers_of("host.node_registry", "host import node_registry")

    assert "dispatch.py" in placement_callers, (
        "the self-check is supposed to be wired; if it was removed, restore the "
        "NOT-YET-WIRED banner to placement.py rather than leaving it claiming otherwise"
    )
    assert "WIRED INTO DISPATCH" in (placement.__doc__ or "")
    assert "NOT YET WIRED" not in (placement.__doc__ or "")

    if registry_callers:
        assert "NOT YET WIRED" not in (node_registry.__doc__ or ""), (
            f"node_registry IS now called from {sorted(registry_callers)} — update its "
            "docstring; its present-tense guarantees are in force now"
        )
    else:
        assert "NOT YET WIRED" in (node_registry.__doc__ or ""), (
            "nothing builds a fleet view, so node_registry's present-tense guarantees "
            "still describe a system that does not exist yet; say so"
        )


def test_the_self_check_and_the_fleet_filter_are_one_predicate():
    """`eligible` (which nodes may run this) and a dispatcher's self-check (may I) must
    not be two implementations of "what the grants permit". The spec's leaderless
    convergence depends on every node deciding the same way from the same inputs."""
    import inspect

    from blastbox.host import placement

    assert "refusal(" in inspect.getsource(placement.eligible), (
        "eligible() has stopped going through the shared predicate"
    )


def test_an_unverifiable_certificate_refuses_rather_than_abstaining():
    """`None` grants is a REFUSAL, not an absence of opinion. A node that registered but
    whose certificate the reader could not verify — expired, foreign, unenrolled — may
    not be given work; treating "I could not check" as "no objection" is how a lapsed
    identity silently becomes an unrestricted one."""
    from blastbox.host.placement import refusal

    why = refusal(None, engine="boxjs")
    assert why and "no verifiable node certificate" in why


def test_the_refusal_names_what_was_granted_so_an_operator_can_act():
    from blastbox.host.pki import NodeGrants
    from blastbox.host.placement import refusal

    g = NodeGrants(engines=("clamav",), tiers=("direct",), credentials=False)
    assert refusal(g, engine="clamav", tier="direct") is None
    assert "boxjs" in (refusal(g, engine="boxjs") or "")
    assert "clamav" in (refusal(g, engine="boxjs") or ""), "say what IS granted too"
    assert "wireguard" in (refusal(g, engine="clamav", tier="wireguard") or "")
    assert "credentials=False" in (
        refusal(g, engine="clamav", tier="direct", require_credentials=True) or "")
