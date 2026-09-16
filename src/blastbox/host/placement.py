"""Which nodes may run what — the eligibility half of federated placement.

WIRED INTO DISPATCH AS OF 2026-09-16, and only the self-check is. A dispatcher calls
:func:`refusal` about ITSELF before running a claimed job — "may I run this" — using the
grants resolved from its own node certificate. That is the leaderless shape the spec's
§4.2 argues for: no elected placer, every node applying the same deterministic predicate
to the same inputs. It is OPT-IN per node (a node with no certificate to be judged
against runs unrestricted, as every first-party deployment does today), because making
it mandatory would stop every existing install dead on upgrade.

What is still NOT wired: :func:`eligible` and :func:`rank` over a FLEET view, which is
the "choose a node for this job" half. Nothing builds that view — `build_node_registry`
is called by nothing — so the ordering functions below have no production caller yet.

A CORRECTION TO THE SPEC THIS IMPLEMENTS. The design note
(``docs/superpowers/specs/2026-09-15-federated-node-identity-and-placement.md``, step 3)
said "eligibility filtering in ``plan_sizes``". That was wrong about the code:
:func:`blastbox.host.node_sizer.plan_sizes` sizes the POOLS ON ONE NODE against that
node's RAM/vCPU budget. It knows nothing about other machines and should not learn.
Fleet placement is a separate question — *which node should this job go to at all* — and
it gets its own module rather than being bolted onto a working local allocator.

THE ONE RULE
------------
Authority comes from the certificate; everything the node said is a hint.

* **Grants** (:class:`blastbox.host.pki.NodeGrants`) are resolved by the READER from a
  CA-signed cert. They decide eligibility, full stop.
* **Claims** (:class:`blastbox.host.node_registry.NodeClaims`) are what the node asserted
  about itself. They may order or weight an already-eligible set. They may never widen
  it.

Keeping that asymmetry in one place is the point of the module: a future caller that
wants "nodes that can run boxjs" gets a function that cannot accidentally be satisfied by
a node claiming it can.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from blastbox.host.node_registry import NodeRecord
from blastbox.host.pki import NodeGrants

__all__ = [
    "Candidate",
    "eligible",
    "rank",
    "unverified_nodes",
    "over_claiming_nodes",
]


@dataclass(frozen=True)
class Candidate:
    """An eligible node, with the claims that may order it (never widen it)."""

    node_id: str
    record: NodeRecord
    grants: NodeGrants

    @property
    def free_slots(self) -> int:
        """A HINT. The node's own number, bounded by validation but not verified."""
        return max(0, self.record.claims.slots)

    @property
    def backlog(self) -> int:
        return max(0, self.record.claims.backlog)


def refusal(
    grants: NodeGrants | None,
    *,
    engine: str,
    tier: str | None = None,
    require_credentials: bool = False,
) -> str | None:
    """Why these grants forbid this work, or ``None`` if they permit it.

    ONE PREDICATE, TWO CALLERS, AND THAT IS THE POINT. :func:`eligible` asks it about
    every node in a fleet view — "who may run this" — and a dispatcher asks it about
    ITSELF before claiming — "may I". The spec's §4.2 argues for leaderless convergence,
    where every dispatcher runs the same deterministic decision over the same inputs;
    two implementations of "what the grants permit" would be the fastest way to lose
    that, and the self-check is the one that is actually enforcing anything.

    ``None`` grants is a REFUSAL, not an absence of opinion: a node that has registered
    but whose certificate the reader could not verify — expired, foreign, unenrolled —
    may not be given work. The reason names that case separately from empty grants so an
    operator can tell a lapsed cert from a deliberate revocation, which
    :func:`unverified_nodes` exists to surface; the DECISION is identical either way.
    """
    if grants is None:
        return ("no verifiable node certificate, so nothing is granted (expired, "
                "foreign, or never enrolled)")
    if not grants.allows_engine(engine):
        return f"engine {engine!r} is not granted (granted: {list(grants.engines) or 'none'})"
    if tier is not None and not grants.allows_tier(tier):
        return f"netpolicy tier {tier!r} is not granted (granted: {list(grants.tiers) or 'none'})"
    if require_credentials and not grants.credentials:
        return ("this work needs a node that may hold provider credentials, and this "
                "certificate grants credentials=False")
    return None


def eligible(
    view: Sequence[NodeRecord],
    grants: Mapping[str, NodeGrants],
    *,
    engine: str,
    tier: str | None = None,
    require_credentials: bool = False,
) -> tuple[Candidate, ...]:
    """Nodes permitted to run ``engine`` (and ``tier``, when the job needs one).

    A node absent from ``grants`` is NOT eligible. That is the fail-closed case and the
    common one during a rollout: a node that has registered but whose certificate the
    reader could not verify (expired, foreign, unenrolled) simply does not appear. It is
    deliberately indistinguishable here from a node with empty grants — both mean "this
    node may not be given work" — and :func:`unverified_nodes` exists so an operator can
    tell the two apart without this function having to soften.

    ``require_credentials`` is for work that needs a node holding a provider profile —
    a local VPN/proxy exit. A global-mode worker node should be issued
    ``credentials=False``, so this is what stops such work landing on a node that would
    have to hold secrets it was never meant to.
    """
    out: list[Candidate] = []
    for rec in view:
        g = grants.get(rec.node_id)
        if refusal(g, engine=engine, tier=tier,
                   require_credentials=require_credentials) is None:
            assert g is not None          # refusal() returns a reason when it is
            out.append(Candidate(node_id=rec.node_id, record=rec, grants=g))
    # Deterministic: every dispatcher runs this over the same view and must agree.
    return tuple(sorted(out, key=lambda c: c.node_id))


def rank(candidates: Sequence[Candidate]) -> tuple[Candidate, ...]:
    """Order eligible candidates best-first, using CLAIMS ONLY.

    Ordering is where unverified numbers are allowed to matter, because being wrong here
    costs latency rather than containment: a node that over-claims capacity attracts work
    it then runs slowly, and its backlog climbs, and it sinks in this ordering on its own.
    That self-correction is the whole reason claims are usable for scheduling and never
    for authority.

    Ties break on ``node_id`` so the order is total and every dispatcher agrees.
    """
    return tuple(sorted(
        candidates,
        key=lambda c: (c.backlog, -c.free_slots, c.node_id),
    ))


def unverified_nodes(
    view: Sequence[NodeRecord], grants: Mapping[str, NodeGrants]
) -> tuple[str, ...]:
    """Registered nodes with no resolvable grants — invisible to :func:`eligible`.

    Silence is correct for placement and wrong for an operator: a fleet quietly shrinking
    because certificates lapsed looks identical to a fleet that is simply idle. Surface
    it so the cause is one command away.
    """
    return tuple(sorted(r.node_id for r in view if r.node_id not in grants))


def over_claiming_nodes(
    view: Sequence[NodeRecord], grants: Mapping[str, NodeGrants]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Nodes advertising engines their certificate does not grant.

    Harmless to placement — :func:`eligible` reads grants, so the claim changes nothing —
    but worth reporting rather than discarding. It is either a stale grant after an
    operator added an engine to a node, or a node probing for work it is not entitled to.
    An operator should be able to tell which; a silent filter denies them that.
    """
    out: list[tuple[str, tuple[str, ...]]] = []
    for rec in view:
        g = grants.get(rec.node_id)
        if g is None:
            continue
        extra = tuple(sorted(e for e in rec.claims.engines if not g.allows_engine(e)))
        if extra:
            out.append((rec.node_id, extra))
    return tuple(sorted(out))
