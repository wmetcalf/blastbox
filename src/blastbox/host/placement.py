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

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

from blastbox.host.node_registry import NodeRecord

if TYPE_CHECKING:
    import logging
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


# --------------------------------------------------------------------------------------
# This node's own grants — the half that actually enforces.
# --------------------------------------------------------------------------------------

#: "No grants gate is configured on this node." Distinct from ``None``, which means the
#: gate IS configured and this node's certificate did not verify — opposite decisions,
#: and collapsing them is how a lapsed identity becomes an unrestricted one.
NO_GATE = object()

#: Exit drivers that need NO tier grant. A sealed job's personality is ``none`` (and a
#: dropped one ``drop``) — the tiers that carry no traffic anywhere and therefore
#: delegate no authority. This is not a nicety: ``none`` is the DEFAULT personality and
#: a truthy string, so requiring a grant for it made a node issued the documented
#: `--tier openvpn --tier wireguard` refuse every ordinary job, release it to a fleet
#: where no peer was granted it either, and stop draining the queue entirely.
#: NO EMPTY STRING. It was in this tuple, and a real `Personality` never has an empty
#: `exit_driver` — netpolicy validates it against a closed list — so "" was unreachable
#: by any legitimate path and fired only when the gate FAILED TO READ a personality
#: (a renamed attribute, a duck-typed stand-in). That is precisely the case that must
#: refuse, and instead it skipped both the tier and the credentials check.
UNGOVERNED_TIERS = ("none", "drop")

#: Exit drivers whose sidecar carries a PROVIDER SECRET on this host. socks and httpproxy
#: run against a local sidecar in BOTH egress modes — the SOCKS URL and the proxy URL are
#: exactly the credentials this project refuses to put on a command line — so a node
#: running them holds credentials regardless of mode. openvpn and wireguard hold a
#: profile only in LOCAL mode; in global mode they forward over the overlay to a host
#: that does, and demanding the grant there would idle every correctly-issued worker
#: node. ``tor`` is deliberately absent: a local tor daemon is not a provider account.
ALWAYS_CREDENTIALED = ("socks", "httpproxy")
CREDENTIALED_IN_LOCAL_MODE = ("openvpn", "wireguard")


class SelfGrants:
    """What THIS node's certificate permits. Read and verified PER CALL.

    ONE IMPLEMENTATION, SHARED BY EVERY DISPATCH CLASS. It lived on ``Dispatcher``
    first, which meant ``VmJobDispatcher`` — the AWS / static-pool / cascade path, i.e.
    the REMOTE workers this whole control exists to constrain — was entirely ungoverned,
    and ``Dispatcher``'s own warm path bypassed it too. Two dispatch classes with two
    copies of "may I run this" is how one of them ends up with no copy at all.

    THREE STATES, NOT TWO:

    * :data:`NO_GATE` — no certificate configured. Runs everything. Enforcement is
      opt-in per node; mandatory would stop every existing first-party deployment dead
      on upgrade, and until third-party registration exists there is nothing to
      constrain.
    * a :class:`~blastbox.host.pki.NodeGrants` — verified. Runs exactly what it grants.
    * ``None`` — configured but UNVERIFIABLE (expired, foreign, missing, unreadable).
      Runs nothing. "Revocation is stop renewing" bounds exposure only if something acts
      on the lapse.

    WHAT THIS IS, AND WHAT IT CANNOT BE: A NODE LIMITING ITSELF.
    ------------------------------------------------------------
    This gate is read and enforced by the node it constrains, so its strength is bounded by
    that: it is a control against MISCONFIGURATION, and a good one -- a node that should not
    run `clamav` does not, and says why. It is not, and cannot be, a control against a
    compromised or curious operator on that node, who can point ``BLASTBOX_NODE_CERT`` at any
    CA-signed certificate or simply delete this check. Adding a local key-binding test (derive
    the WireGuard pubkey from the private key on this host and require it to match the
    certificate) closes the copy-a-certificate path and nothing else -- the same person can copy
    the key or patch the comparison.

    Where identity actually AUTHORISES something, it is already sound and does not depend on
    this: the exit host maps WireGuard pubkey to node id from its OWN copies of the
    certificates, never from anything a node published, and using a tunnel requires the
    matching private key.

    Binding grants against a hostile node means binding them at the point work changes hands --
    mTLS on the job store / control plane, with grants resolved by the READER from the peer
    certificate ("grants decide, claims advise", the rule `node_registry` already states and
    the federation spec already requires). That is issue #178, and it is deliberately not
    attempted here. Keep this as defence-in-depth against a misconfigured dispatcher.

    WHAT THIS CANNOT DO: EXPIRY IS ONLY AS HONEST AS THE HOST CLOCK.
    ----------------------------------------------------------------
    ``node_identity`` checks ``not_after`` against the wall clock, so a host whose clock
    is rolled back far enough verifies a certificate the CA has already retired. Deleting
    the cache did not fix that — it removed one of two causes. With a cache, one stale
    verdict was reused; without one, every call is fooled afresh. Neither is worse; both
    are wrong for the same reason.

    IT IS NOT FIXABLE HERE, and the attempts are recorded because two of them shipped. A
    monotonic deadline anchored at first sight bounds the exposure to one certificate
    lifetime, which sounds like a fix and is not: it cannot survive a restart (the anchor
    is process-local), and the two versions built to carry it produced a fail-open on a
    backward step and then a permanent silent refusal on a forward one. Closing this
    properly needs a time source the host cannot edit — a signed timestamp from the CA,
    an OCSP-style freshness check, or a monotonic anchor persisted outside the node — and
    each of those is a design change with its own failure modes, not a patch.

    So it is a STATED LIMIT: a node whose clock an attacker controls can extend its own
    authority up to the point the CA stops signing. That is bounded by the enrolment
    process, not by this code, and an operator relying on short certificate lifetimes for
    revocation should know that the lifetime is measured on the node's own clock.

    THERE IS NO CACHE, AND THAT IS THE DESIGN.
    -----------------------------------------
    An earlier version cached the verified grants behind a TTL. Across five attempts,
    that cache produced substantially every defect this class has had: a timestamp
    published before the value, so a concurrent worker got the previous grants
    mid-refresh; freshness measured on a settable clock, so a backward NTP step made the
    cache permanently fresh; expiry enforced only at parse time, so a certificate that
    lapsed inside the window kept authorising; a monotonic deadline recomputed on every
    refresh, so a rolled-back clock pushed it out forever; and then a ratchet fixing THAT
    which made one transient forward clock step refuse every job for the rest of the
    certificate's life, silently. Five bugs, one cause, each fix introducing the next.

    So the cache is gone. Every call opens the file, verifies the CA signature, and
    checks expiry — the same work ``pki show-node`` does, measured in single-digit
    milliseconds, against a job that is about to detonate malware in a VM. Nothing here
    now depends on a clock this process cannot trust, on state surviving between calls,
    or on two threads agreeing about either. `node_identity` is the only expiry
    authority, consulted fresh, every time.

    The cost is one file read and one ECDSA verify per claimed job. The benefit is that
    the failure modes above are not merely fixed — they are unrepresentable.
    """

    #: Env var that ARMS the gate. Deliberately NOT ``BLASTBOX_NODE_ID``: that name is
    #: already taken by ``dispatcher_sizer`` for the physical-host slug, is documented
    #: for an unrelated NFS-share-scoping reason, and overloading it made a node that
    #: set it for THAT reason refuse every job with a message about PKI renewal.
    #: Backstop on the warn-once set. See :meth:`_warn_once`.
    WARN_CAP = 64

    CERT_ENV = "BLASTBOX_NODE_CERT"
    GATE_ENV = "BLASTBOX_NODE_GRANTS_GATE"
    PKI_ENV = "BLASTBOX_PKI_DIR"
    #: Only consulted to WARN that a node looks configured the old way. Never to arm.
    LEGACY_ID_ENV = "BLASTBOX_NODE_ID"

    def __init__(self, *, log: "logging.Logger | None" = None) -> None:
        import logging as _logging

        self._log = log or _logging.getLogger("blastbox.host.placement")
        self._node_id = ""
        self._warned: set = set()

    def _warn_once(self, key: str, msg: str, *args: object) -> None:
        """Log a configuration warning the first time only, per (key, arguments).

        These fire from paths that run once per JOB. An identical line per job does not
        inform anyone; it hides the line that would have. Keyed on the arguments too, so
        a value that CHANGES is reported again.
        """
        # BOUNDED. The key used to include every argument, and one caller passes an
        # EXCEPTION — whose text carries paths, errnos and addresses that vary per
        # failure, so a flapping mount produced a new key per job and the set grew
        # without bound in a long-lived dispatcher. Keying on the first two arguments
        # keeps "the value changed, say so again" for configuration values while the
        # variable tail of an exception cannot mint new entries, and the cap is a
        # backstop for any caller that still varies within those.
        stamp = (key, args[:2])
        if stamp in self._warned:
            return
        if len(self._warned) >= self.WARN_CAP:
            # Not a cache to be clever with: at this point something is emitting far more
            # distinct configuration warnings than a node can have problems, so stop
            # growing and say so once.
            if ("__capped__", ()) not in self._warned:
                self._warned.add(("__capped__", ()))
                self._log.warning(
                    "suppressing further configuration warnings: %d distinct ones already "
                    "reported, which is more than a correctly-configured node can have",
                    len(self._warned))
            return
        self._warned.add(stamp)
        self._log.warning(msg, *args)

    # -- inputs ------------------------------------------------------------------
    def cert_path(self) -> "Path | None":
        """Where this node's certificate should be, or None if no identity is configured.

        A VARIABLE THAT IS SET AT ALL IS A CONFIGURED IDENTITY, even if it renders empty
        — ``BLASTBOX_NODE_CERT= `` in a systemd EnvironmentFile, or a template that
        interpolated an unset value. Treating that as "not configured" gave an operator
        who could see the variable set an unrestricted node. Existence is deliberately
        NOT checked: a path that cannot be read fails inside :meth:`grants`, where every
        failure is already a refusal, instead of collapsing into "no identity".
        """
        if self.CERT_ENV not in os.environ:
            self._warn_if_legacy_arming()
            return None
        raw = os.environ[self.CERT_ENV].strip()
        return Path(raw) if raw else Path(f"<{self.CERT_ENV} is set but empty>")

    def _warn_if_legacy_arming(self) -> None:
        """Say so when a node LOOKS armed the old way. Never arm from it.

        The gate once resolved ``<pki>/node-<BLASTBOX_NODE_ID>.crt``. Removing that was
        right — the name is already the sizer's documented host slug — but it silently
        un-gates any node that had armed that way, so a later version honoured the old
        path when the file existed. That was worse: ``pki issue-node`` writes
        ``node-<id>.crt`` into the pki dir by default and the exit host holds one for
        EVERY node it ever issued, so a host setting the slug for the documented NFS
        reason armed itself with a PEER'S IDENTITY — grants, credentials and all. And
        deleting that file put it back to ungated, reintroducing the fail-open it was
        added to close.

        Neither behaviour is defensible, so this does neither. It warns, once, and the
        operator arms the gate explicitly or not at all. The gate has never shipped
        enabled, so there is no fleet silently relying on the old route.
        """
        node_id = os.environ.get(self.LEGACY_ID_ENV, "").strip()
        if not node_id:
            return
        pki_dir = Path(os.environ.get(self.PKI_ENV, "/var/lib/blastbox/pki"))
        try:
            looks_legacy = (pki_dir / f"node-{node_id}.crt").exists()
        except OSError:
            looks_legacy = False
        if looks_legacy:
            self._warn_once(
                "legacy-arming", 
                "%s=%s and %s/node-%s.crt exists, which looks like the OLD way of arming "
                "the grants gate. It does NOT arm it: that route was removed because %s "
                "is also the sizer's host slug, and honouring it armed hosts with another "
                "node's identity. This node is UNGATED. Set %s explicitly to arm it.",
                self.LEGACY_ID_ENV, node_id, pki_dir, node_id, self.LEGACY_ID_ENV,
                self.CERT_ENV)

    def gate_forced(self) -> str:
        """``"on"``, ``"off"`` or ``""`` (unset) from :data:`GATE_ENV`.

        The OFF-list is closed and everything else is ON. These used to be two closed
        lists, so ``enforce`` / ``enabled`` / ``y`` / ``strict`` matched neither and fell
        through to the permissive default, silently. The variable exists to FORCE the
        gate; an unparsed value meaning "off" is the one reading nobody wants.
        """
        raw = os.environ.get(self.GATE_ENV, "").strip()
        if not raw:
            return ""
        if raw.lower() in ("0", "false", "no", "off"):
            return "off"
        if raw.lower() not in ("1", "true", "yes", "on"):
            self._warn_once(
                "gate-value",
                "%s=%r is not a value I recognise. Treating it as ON, because a "
                "hardening knob that silently does nothing is worse than a loud one. "
                "Use 1/true/yes/on or 0/false/no/off.", self.GATE_ENV, raw)
        return "on"

    # -- the answer --------------------------------------------------------------
    def grants(self):
        """This node's grants, :data:`NO_GATE`, or ``None``. Verified fresh, every call."""
        forced = self.gate_forced()
        if forced == "off":
            return NO_GATE
        path = self.cert_path()
        if path is None:
            if forced == "on":
                self._warn_once(
                    "forced-no-cert",
                    "%s is on but no certificate is configured (%s). Refusing all work "
                    "rather than running ungoverned.", self.GATE_ENV, self.CERT_ENV)
                return None
            return NO_GATE
        try:
            from blastbox.host.pki import load_trust_anchor, node_identity
            pki_dir = Path(os.environ.get(self.PKI_ENV, "/var/lib/blastbox/pki"))
            ident = node_identity(load_trust_anchor(pki_dir), path.read_bytes())
        except Exception as exc:      # noqa: BLE001 - every failure is a refusal
            self._warn_once(
                "verify-failed",
                "this node's certificate (%s) does not verify: %s. Refusing work until "
                "it is renewed — `blastbox pki issue-node` for the same node id and wg "
                "key. This is revocation working, not a bug.", path, exc)
            self._node_id = ""
            return None
        self._node_id = ident.node_id
        return ident.grants

    @property
    def node_id(self) -> str:
        """The verified identity, for diagnostics. "" until a successful verification."""
        return self._node_id

    # -- what the job needs ------------------------------------------------------
    def egress_mode(self) -> str:
        """This node's persisted egress mode, or "" when the tier does not manage it.

        A MANAGED NODE THAT CANNOT SAY IS TREATED AS LOCAL — for the credentials question
        only, and conservatively. Guessing "global" on a local node drops the credentials
        requirement from the nodes most likely to hold a provider profile; guessing
        "local" on a global node demands a grant it was correctly issued without, which
        idles it. Only the first is a containment failure, so the guess goes that way.
        """
        from blastbox.host.egress_apply import ENV_FILE, load_persisted_env
        try:
            managed = ENV_FILE.exists()
        except OSError:
            managed = True          # cannot tell; assume the stricter answer
        if not managed:
            return ""
        try:
            mode = load_persisted_env().get("BLASTBOX_EGRESS_MODE", "")
        except Exception:           # noqa: BLE001
            mode = ""
        if not mode:
            self._warn_once(
                "egress-mode",
                "%s exists but declares no BLASTBOX_EGRESS_MODE (truncated, unreadable "
                "or hand-edited). Assuming local mode for the credentials check, which "
                "is the conservative guess: a global-mode node judged local is idled, a "
                "local-mode node judged global holds provider credentials it was not "
                "granted. Fix the file — and note that `blastbox egress check` will NOT "
                "flag this, because persisted_config() only raises when the file is "
                "entirely unreadable, not when it parses without a MODE line.", ENV_FILE)
            return "local"
        return mode

    def holds_credentials(self, personality) -> bool:
        """Would running this personality HERE mean this node holds a provider secret?"""
        driver = getattr(personality, "exit_driver", "") or ""
        if driver in ALWAYS_CREDENTIALED:
            return True
        return driver in CREDENTIALED_IN_LOCAL_MODE and self.egress_mode() == "local"

    def refuse(self, *, engine: str, personality) -> str | None:
        """The whole question in one call: why may this node not run this, or None."""
        value = self.grants()
        if value is NO_GATE:
            return None
        driver = getattr(personality, "exit_driver", "") or ""
        if not driver:
            # Unreadable, not ungoverned. See UNGOVERNED_TIERS.
            return ("this job's network personality could not be read, so the tier it "
                    "would run under is unknown and cannot be checked against the grants")
        tier = None if driver in UNGOVERNED_TIERS else driver
        from typing import cast
        return refusal(cast("NodeGrants | None", value), engine=engine, tier=tier,
                       require_credentials=self.holds_credentials(personality))
