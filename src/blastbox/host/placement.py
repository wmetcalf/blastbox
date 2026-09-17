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
import time
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
    """What THIS node's certificate permits, cached, with every failure a refusal.

    ONE IMPLEMENTATION, SHARED BY EVERY DISPATCH CLASS. It lived on ``Dispatcher`` first,
    which meant ``VmJobDispatcher`` — the AWS / static-pool / cascade path, i.e. the
    REMOTE workers this whole control exists to constrain — was entirely ungoverned, and
    ``Dispatcher``'s own warm path bypassed it too. Two dispatch classes with two copies
    of "may I run this" is how one of them ends up with no copy at all.

    THREE STATES, NOT TWO:

    * :data:`NO_GATE` — no certificate configured. Runs everything. Enforcement is
      opt-in per node; mandatory would stop every existing first-party deployment dead
      on upgrade, and until third-party registration exists there is nothing to
      constrain.
    * a :class:`~blastbox.host.pki.NodeGrants` — verified. Runs exactly what it grants.
    * ``None`` — configured but UNVERIFIABLE (expired, foreign, missing, unreadable).
      Runs nothing. "Revocation is stop renewing" bounds exposure only if something acts
      on the lapse.
    """

    #: Env var that ARMS the gate. Deliberately NOT ``BLASTBOX_NODE_ID``: that name is
    #: already taken by ``dispatcher_sizer`` for the physical-host slug, is documented
    #: for an unrelated NFS-share-scoping reason, and overloading it made a node that
    #: set it for THAT reason refuse every job with a message about PKI renewal.
    CERT_ENV = "BLASTBOX_NODE_CERT"
    GATE_ENV = "BLASTBOX_NODE_GRANTS_GATE"
    TTL_ENV = "BLASTBOX_NODE_GRANTS_TTL_S"
    PKI_ENV = "BLASTBOX_PKI_DIR"

    @property
    def _ttl(self) -> float:
        """Read per call, like every other variable this class consults.

        It was read once in ``__init__`` while CERT_ENV, GATE_ENV and PKI_ENV were all
        per-call — so an operator could hot-swap the certificate or arm the gate on a
        running dispatcher, but changing the TTL silently did nothing until restart, and
        `pki node-status` (a fresh instance) would confirm a change that had not taken
        effect in the process that matters. A garbage value is reported, not raised: it
        used to crash `node-status`, the command whose job is reporting misconfiguration.
        """
        raw = os.environ.get(self.TTL_ENV, "") or "300"
        try:
            return max(5.0, float(raw))
        except ValueError:
            self._log.warning("%s=%r is not a number; using 300s", self.TTL_ENV, raw)
            return 300.0

    def __init__(self, *, log: "logging.Logger | None" = None) -> None:
        import logging as _logging
        import threading

        self._log = log or _logging.getLogger("blastbox.host.placement")
        self._lock = threading.Lock()
        self._cached: "NodeGrants | None | object" = NO_GATE
        #: MONOTONIC, not wall clock. `time.time()` is settable: a backward NTP step of
        #: D seconds makes `now - self._at` negative — trivially "fresh" — so the cache
        #: never expired, and because the expiry guard used the same clock `now >=
        #: self._until` was false too. BOTH of the gate's bounds failed in the same
        #: direction, open, and a revoked certificate kept authorising work for the
        #: length of the step. This repo has a documented prior incident with exactly
        #: this cause (retention.py: a 1h rollback deleting live job trees).
        self._at = 0.0
        #: The cached certificate's not_after, as a WALL-CLOCK timestamp — not_after is
        #: an absolute instant. Deliberately NOT zeroed on a failed verification: doing
        #: that made the expiry guard inert on the failure branch, so a stale `_at`
        #: pinned the refusal for a whole TTL (which has no ceiling).
        self._until = 0.0
        #: ...and the SAME deadline on the monotonic clock, which is the one that
        #: actually holds under a rollback. Switching only cache freshness to monotonic
        #: was half a fix: after the TTL elapsed, `node_identity` re-verified against the
        #: rolled-back WALL clock, decided the expired certificate was still valid, and
        #: republished its grants — so the process kept authorising an expired identity
        #: until wall time caught up, or forever if it never did. A deadline recorded in
        #: elapsed time cannot be moved by setting the clock.
        self._until_mono = 0.0
        self._node_id = ""
        self._warned: set = set()

    # -- inputs ------------------------------------------------------------------
    def _warn_once(self, key: str, msg: str, *args: object) -> None:
        """Log a configuration warning the first time only, per (key, arguments).

        These fire from paths that run once per JOB. An identical line per job does not
        inform anyone; it hides the line that would have. Keyed on the arguments too, so
        a value that CHANGES is reported again.
        """
        stamp = (key, args)
        if stamp in self._warned:
            return
        self._warned.add(stamp)
        self._log.warning(msg, *args)

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
            return self._legacy_cert_path()
        raw = os.environ[self.CERT_ENV].strip()
        return Path(raw) if raw else Path(f"<{self.CERT_ENV} is set but empty>")

    def _legacy_cert_path(self) -> "Path | None":
        """The pre-CERT_ENV arming route, honoured only when its certificate really exists.

        A FAIL-OPEN UPGRADE, INTRODUCED BY THE FIX FOR THE OPPOSITE BUG. The gate first
        armed from ``BLASTBOX_NODE_ID`` by resolving ``<pki>/node-<id>.crt``. That was
        removed because the name is ALREADY the sizer's physical-host slug, documented
        for an unrelated NFS reason, so setting it for that reason armed a security
        control the operator had never heard of. Correct — but it also means every node
        that had genuinely armed the gate that way goes SILENTLY UNGATED on upgrade,
        which is the one direction this module is never allowed to fail.

        The two cases are distinguishable by a fact rather than a guess: whether the
        derived certificate is actually there. A sizer-only node has no
        ``node-<slug>.crt`` and stays ungated; a node that armed the old way has one and
        keeps its gate. Deprecated, and it says so once, because silently changing what a
        security control does across an upgrade is worse than either behaviour.
        """
        node_id = os.environ.get("BLASTBOX_NODE_ID", "").strip()
        if not node_id:
            return None
        pki_dir = Path(os.environ.get(self.PKI_ENV, "/var/lib/blastbox/pki"))
        candidate = pki_dir / f"node-{node_id}.crt"
        if not candidate.exists():
            return None          # the sizer's host slug; nothing to do with this gate
        self._warn_once(
            "legacy-arming",
            "BLASTBOX_NODE_ID=%s resolves to %s, so this node's grants gate is armed the "
            "OLD way. That route is deprecated because the variable is also the sizer's "
            "host slug: set %s explicitly instead. Honouring it here so an upgrade does "
            "not silently un-gate a node that was gated.", node_id, candidate,
            self.CERT_ENV)
        return candidate

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
            # ONCE. `gate_forced()` runs on every `grants()`, i.e. once per job, so an
            # unrecognised value printed an identical line per job forever — burying the
            # very signal that would have told the operator about the typo.
            self._warn_once(
                "gate-value",
                "%s=%r is not a value I recognise. Treating it as ON, because a "
                "hardening knob that silently does nothing is worse than a loud one. "
                "Use 1/true/yes/on or 0/false/no/off.", self.GATE_ENV, raw)
        return "on"

    # -- the answer --------------------------------------------------------------
    def grants(self):
        """This node's grants, :data:`NO_GATE`, or ``None``. Cached under a lock."""
        forced = self.gate_forced()
        if forced == "off":
            return NO_GATE
        path = self.cert_path()
        if path is None:
            if forced == "on":
                self._log.warning(
                    "%s is on but no certificate is configured (%s). Refusing all work "
                    "rather than running ungoverned.", self.GATE_ENV, self.CERT_ENV)
                return None
            return NO_GATE
        # ONE REFRESH AT A TIME, AND THE TIMESTAMP IS PUBLISHED WITH THE VALUE. Setting
        # the timestamp before the verification let a second dispatch worker see a fresh
        # stamp and take the PREVIOUS value — so a just-revoked certificate kept
        # authorising work for the length of one signature check, once per TTL.
        with self._lock:
            now = time.monotonic()
            fresh = self._at and (now - self._at) < self._ttl
            # EXPIRY OUTRANKS THE TTL. node_identity enforces not_after at PARSE time, so
            # a certificate that lapsed mid-window kept authorising until the next
            # refresh — and the TTL has a floor but no ceiling, so an operator "reducing
            # PKI I/O" could make that window outlast the seven-day lifetime that IS the
            # revocation mechanism.
            if fresh and not self._expired(now):
                return self._cached
            prev_until = self._until
            try:
                from blastbox.host.pki import load_trust_anchor, node_identity
                pki_dir = Path(os.environ.get(self.PKI_ENV, "/var/lib/blastbox/pki"))
                ident = node_identity(load_trust_anchor(pki_dir), path.read_bytes())
                value: "NodeGrants | None" = ident.grants
                self._node_id = ident.node_id
                self._until = ident.not_after.timestamp()
                # The same instant measured in ELAPSED time. `node_identity` has just
                # confirmed the certificate is valid NOW, so however wrong the wall clock
                # is, it has at most (not_after - now) of validity left from this moment.
                fresh_deadline = now + max(0.0, self._until - time.time())
                # A DEADLINE MAY ONLY MOVE FORWARD FOR A GENUINELY NEWER CERTIFICATE.
                # Recomputing it unconditionally re-introduced the exact bug it exists to
                # prevent: the rolled-back wall clock made `not_after - time.time()` look
                # enormous, so every re-verification pushed the deadline further out and
                # the expired identity was republished forever. `not_after` is the only
                # thing that distinguishes a renewal from the same certificate seen
                # again through a lying clock — and it comes from the signed payload, not
                # from the host.
                if self._until_mono and ident.not_after.timestamp() <= prev_until:
                    self._until_mono = min(self._until_mono, fresh_deadline)
                else:
                    self._until_mono = fresh_deadline
                if self._expired(time.monotonic()):
                    value = None        # already past it; do not publish
            except Exception as exc:      # noqa: BLE001 - every failure is a refusal
                self._log.warning(
                    "this node's certificate (%s) does not verify: %s. Refusing work "
                    "until it is renewed — `blastbox pki issue-node` for the same node "
                    "id and wg key. This is revocation working, not a bug.", path, exc)
                value = None
                self._node_id = ""     # the old identity is not this node's any more
            self._cached = value
            self._at = time.monotonic()
            return value

    def _expired(self, now_mono: float) -> bool:
        """Has the cached certificate passed its not_after, by EITHER clock?

        Both are consulted and either one is enough. The wall clock catches the ordinary
        case and the monotonic deadline catches the rollback case, where the wall clock
        is the thing lying. Requiring both to agree would mean a rolled-back clock could
        veto the deadline that exists because of it.
        """
        if self._until and time.time() >= self._until:
            return True
        return bool(self._until_mono and now_mono >= self._until_mono)

    @property
    def node_id(self) -> str:
        """The verified identity, for diagnostics. "" until a successful verification."""
        return self._node_id

    # -- what the job needs ------------------------------------------------------
    def egress_mode(self) -> str:
        """This node's persisted egress mode, or "" when the tier does not manage it.

        A MANAGED NODE THAT CANNOT SAY IS TREATED AS LOCAL — for the credentials
        question only, and conservatively.

        THE ORIGINAL JUSTIFICATION HERE WAS FALSE and is recorded so it is not repeated:
        it claimed "BLASTBOX_EGRESS_MODE was added only recently, so every egress.env
        written before it has no MODE line". It is the FIRST line ``to_env_lines()``
        emits and has been since the commit that introduced the file, so no such legacy
        file exists. What the default actually covers is the other case: a truncated,
        empty or unreadable egress.env, where ``load_persisted_env`` returns {}.

        That case is real but it cuts both ways, and the cut is asymmetric. Guessing
        "global" on a local node drops the credentials requirement from the nodes most
        likely to hold a provider profile; guessing "local" on a global node demands a
        grant it was correctly issued without, which idles it. Both are bad; only the
        first is a containment failure, so the guess goes that way — and it is LOUD,
        because ``persisted_config()`` treats the identical condition as a hard error
        ("this node is marked managed and its egress configuration cannot be
        determined") and an operator should hear about the file rather than about a
        certificate.
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
            self._log.warning(
                "%s exists but declares no BLASTBOX_EGRESS_MODE (truncated, unreadable "
                "or hand-edited). Assuming local mode for the credentials check, which "
                "is the conservative guess — but fix the file: `blastbox egress check` "
                "treats this same state as a hard error.", ENV_FILE)
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
