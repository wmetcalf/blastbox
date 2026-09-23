"""Hand work to a node only after proving which node it is (#178).

THE GAP THIS CLOSES. Today a node calls ``claim_next()`` DIRECTLY against the job store
and then enforces its own grants, so the control that decides what a node may run is
executed by the node it limits. A node publishing under another node's id inherits its
grants, and by the time anything disagrees the input has already been fetched.
``placement.fleet_grants`` answers "what is node X permitted"; nothing answered "is this
caller node X".

These two routes are the other side of that hand-over. The node proves possession of its
certificate's key, the server resolves the grants FROM THAT CERTIFICATE, and a job is
claimed only if the grants allow it -- so a refused node never receives the input rather
than being asked not to look at it.

OPT-IN BY THE PRESENCE OF A PKI, WITH NO SWITCH TO SET. When there is no trust anchor to
verify against, the routes are NOT REGISTERED AT ALL and every deployment behaves exactly
as it does today. That is deliberate: a route that exists but waves everyone through is
indistinguishable from this feature working, which is the failure mode the whole issue is
about. A 404 cannot be mistaken for an authorisation decision.

WHAT THIS DOES NOT DO, AND IT MATTERS MORE THAN WHAT IT DOES
------------------------------------------------------------
THIS IS NOT PREVENTION FOR A NODE THAT HOLDS STORE CREDENTIALS. The dispatch process
requires ``BLASTBOX_DATABASE_URL`` and talks to the job store directly, so a node running
a dispatcher can call ``claim_next()`` itself and never come here at all. For such a node
these routes are DEFENCE IN DEPTH and an audit trail -- not a gate it cannot walk around.

Do not read "grants enforced at the hand-over" as more than that. Overstating it would be
the same defect class this whole area keeps producing: a control that is PRESENT rather
than IN FORCE, reported as though it were in force.

THE CREDENTIAL-LESS NODE NOW EXISTS, and that is where the prevention lives. A node whose
``BLASTBOX_DATABASE_URL`` is an ``https://`` control plane gets
:class:`~blastbox.host.jobs.http_store.HttpJobStore` instead of a database handle, so these
routes are the ONLY path it has -- and then a refusal here is prevention, not advice.
``tests/host/jobs/test_credential_less_node.py`` asserts both halves: that such a node
cannot obtain ungranted work, and that it has no second route to try.

So the limit above is a statement about CONFIGURATION, not about this module: point a node
at a DSN and it walks around these routes; point it at the control plane and it cannot.
Which of those a deployment does is the operator's choice, and DEPLOYMENT.md says so.

THE API KEY DOES NOT APPLY TO THESE ROUTES. ``BearerAuthMiddleware`` exempts the
``/v1/nodes/`` prefix, because these routes authenticate with a CA-issued certificate and a
session bound to it -- stronger than the key and orthogonal to it -- and requiring the key too
would put the SUBMITTER's credential on every node, letting every node submit jobs. An earlier
version of this docstring advised running nodes against a keyless listener instead; that advice
was stale AND actively harmful, because the API key is also the pepper for the store-held
signing key, so a keyed and a keyless ingress on one queue sign with DIFFERENT keys.

WHY NOT mTLS. ``issue_node`` stamps a critical private EKU and never ``clientAuth``,
because ``tls.py`` verifies the CA chain only -- a node cert carrying ``clientAuth`` would
be accepted by every worker AS THE DISPATCHER'S. See :mod:`blastbox.host.node_auth`, which
records the measurements: OpenSSL rejects a node cert in a handshake outright, and uvicorn
exposes no peer certificate to an ASGI app in any case.
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Header, HTTPException, Query, Response
from pydantic import BaseModel, Field

from blastbox.host import node_auth
from blastbox.host.jobs.base import NODE_CLAIM_PREFIX as _NODE_CLAIM_PREFIX

if TYPE_CHECKING:                       # pragma: no cover - typing only
    from fastapi import FastAPI

    from blastbox.host.jobs.base import JobStore

_log = logging.getLogger("blastbox.ingress.node_claim")

#: Default location of the fleet PKI. Same default as ``SelfGrants``, deliberately: an
#: operator who set it for the grants gate does not set it again here.
PKI_ENV = "BLASTBOX_PKI_DIR"
DEFAULT_PKI_DIR = "/var/lib/blastbox/pki"

#: The session header. NOT ``Authorization``: ``BearerAuthMiddleware`` requires that header
#: to start with ``Bearer `` and rejects anything else with 401 BEFORE the request reaches
#: these routes -- so an API-keyed deployment could not authenticate a node at all. The
#: earlier design sent ``Authorization: Node <token>`` and DOCUMENTED that nodes would need
#: the API key too; that was wrong, not merely awkward, because one header cannot carry both
#: credentials. A separate header lets the two coexist: the API key proves "this caller may
#: talk to this service at all", the session proves "and it is this node".
SESSION_HEADER = "x-blastbox-node-session"

#: Fields a node may write. An ALLOWLIST, because `JobStore.update` accepts any `Job` field
#: and an authenticated node could otherwise rewrite ``result_dir`` (pointing this host's
#: result write somewhere of its choosing), ``engine``, ``target_tier`` or another node's
#: ``claim_id``. Those are not untidy, they are privilege escalation. What remains is what a
#: dispatcher legitimately reports about a run it is performing.
#: DERIVED, NOT JUDGED. `tests/host/ingress/test_node_writable_fields.py` walks the AST of
#: `dispatch` and `vm_dispatch` and fails if either writes a field missing from this set. It
#: had to: I curated this list by hand and left out `expires_at` and `security_warnings`,
#: which every terminal write carries -- so a credential-less node could not mark ANY job DONE
#: or FAILED, and the whole feature was non-functional while the suite stayed green, because
#: the tests only ever wrote the fields I had happened to allow.
NODE_WRITABLE_FIELDS = frozenset({
    "status", "error", "started_at", "finished_at", "worker_runtime", "worker_tier",
    "result_summary", "input_sha256", "materialise_attempts", "claimable_after",
    # Terminal writes carry these. Neither is an authorisation surface: expires_at is the
    # retention clock for the node's own result, security_warnings is what the run observed.
    "expires_at", "security_warnings",
    # claim_id is here for ONE value only -- None, which is releasing the job. Setting it to
    # anything else would let a node re-stamp ownership and defeat every fence built on it.
    "claim_id",
})

#: Job fields that are enums on the dataclass but strings on the wire. JSON has no enums, so
#: ``{"status": "done"}`` arrives as ``str`` and `update` would happily store it -- every
#: terminal write from a node would put a string where the rest of the system expects a
#: `JobStatus`, and comparisons against the enum would quietly stop matching.
_ENUM_FIELDS = ("status",)

#: Set to refuse a claim this host cannot fully authorise, rather than warning. Off by
#: default: an ingress with no netpolicy registry would otherwise refuse every ordinary job,
#: which is the `UNGOVERNED_TIERS` outage all over again. On, it is real prevention.
STRICT_TIERS_ENV = "BLASTBOX_NODE_CLAIM_STRICT_TIERS"

#: How many jobs one claim request may walk past before giving up. Bounds the work a single
#: request can do while still letting a node reach work behind a job it may not run.
_MAX_CLAIM_PROBES = 8

#: How long this control plane remembers that a given node may not run a given job, and how
#: many such remembered jobs one claim walk will step over.
#:
#: WHY IT IS NEEDED. A refused job is deferred only while it is young (MAX_TOTAL_DEFERRAL_S) and
#: is then released immediately claimable, so that an entitled peer can have it. On an all-federated
#: fleet there IS no entitled peer, so it stays at the head of the queue permanently -- and
#: `claim_next` returns the OLDEST eligible job, so each such job consumed one of
#: `_MAX_CLAIM_PROBES` on EVERY later poll. Eight of them therefore starved the node of work it
#: IS granted, for as long as they existed: the probe cap, which is only a cost cap, became the
#: mechanism. The memo lets the walk step over that wall without re-paying to judge it.
#:
#: KEYED BY THE NODE'S GRANTS, SO THE TTL NEED NOT BE SHORT. It was 60 s, for one reason: a
#: certificate can be re-issued with MORE grants while a job sits there, and the node should not
#: keep stepping over work it can now run. But a short TTL raced the walk itself -- a poll judges
#: at most eight fresh jobs and a dispatcher polls about once a second, so refusals from the head
#: of a wall deeper than ~480 expired before the walk got past it, `claim_next` offered the
#: oldest refused job again, and the node never crossed (measured on a simulated clock: 400 deep
#: crossed in 51 polls, 700 never). The memo is now keyed by (node, grants fingerprint): a
#: re-issued certificate changes the key and every refusal is re-judged on the very next poll,
#: which is the newly-entitled case handled EXACTLY rather than approximately. The TTL is then
#: only a backstop and can be long. What still bounds a wall is the memo's size, not the clock.
_REFUSAL_MEMO_TTL_S = 3600.0
#: How many already-judged jobs one walk will step over. SMALL, because stepping over one is
#: not free: `claim_next` is the only way to see a job, so each skip costs a claim, the prefix
#: stamp (which must happen before anything can go wrong -- see the stamp comment in the walk)
#: and a release. At 64 that was ~192 store writes for a single poll that then answered 204,
#: and a node polls on a timer. 16 still steps over a wall deeper than the probe budget could
#: reach while keeping the per-poll cost in the same order as the parent commit's.
#:
#: NOW ONLY A BACKSTOP. Since round seven the walk passes every job this node has already been
#: refused to `claim_next(exclude=...)`, so the store never offers a remembered job and stepping
#: over one costs nothing. This branch only runs for a refusal the memo no longer holds (evicted
#: past its size bound) -- i.e. for walls deeper than the memo, thousands of jobs.
#:
#: RESIDUAL, stated rather than hidden: a wall of work no enrolled node can run is still WALKED
#: once per memo TTL -- eight fresh judgements a poll -- by every node granted its engine. The
#: real cure is to FAIL work no certificate in the fleet grants (the control plane can see every
#: node's grants) rather than to keep re-judging it; that is a separate change.
_MAX_CLAIM_SKIPS = 16

#: How many jobs the fleet-wide unrunnable set holds. 20,000 so that it PLUS a full per-node memo
#: (8,192) stays inside SQLite's 32,766 bound parameters -- the two are passed together as one
#: exclusion. At 30,000 the union could exceed it, and the store would trim the head of the wall.
_MAX_UNRUNNABLE = 20_000

#: How long a job this node may NOT run is deferred for EVERYONE after a refusal. This is ALSO
#: the write-amplification bound the DoS finding wanted: a refused job flips RUNNING->QUEUED at
#: most once per this window, so a node hammering /claim cannot churn the head of the queue --
#: after the first walk everything it cannot run is deferred and later polls find nothing
#: claimable and touch no rows. A node-level back-off was tried on top and removed: it 204'd the
#: poll after an all-refused walk, which re-broke the very starvation the deferral fixes (a node
#: could not reach entitled work sitting behind more than a probe-budget of refusable jobs). This replaced
#: a per-process refusal memo, which review showed still starved the node: memoised jobs kept
#: consuming the probe budget, so nine refusable jobs at the head of the queue blocked the tenth
#: forever, and forked ingress workers each held their own memo anyway. A deferral is honoured by
#: `claim_next` itself on every backend, so the walk simply does not see the job again for a
#: while -- and neither does an adversary trying to flap it, which bounds that to once per
#: window. The cost is that an ENTITLED peer also waits this long for it; short on purpose.
#:
#: AND IT ONLY BOUNDS THE CHURN WHILE THE JOB IS YOUNG. Past MAX_TOTAL_DEFERRAL_S a refused job
#: is released claimable, so the "at most one flip per window" property above holds for its first
#: two minutes and not after: from then on the store EXCLUDES it for this node (the refusal memo
#: is passed to `claim_next`), which costs no writes and still hands it to any entitled peer
#: immediately. See _MAX_CLAIM_SKIPS.
_REFUSAL_DEFER_S = 20.0

#: Prefix the control plane re-stamps onto the claim id of every job it hands to a node. It
#: exists so the control-plane reclaim sweep can tell ITS claims from a DB-backed dispatcher's:
#: on a mixed fleet the sweep otherwise failed healthy jobs those dispatchers were still running
#: -- their cold jobs have NO time bound by design (docker-ps liveness), and the sweep's own floor
#: sat below their warm cutoff -- and discarded the finished result when the owner's DONE write
#: then lost its CAS. Reviewed and reproduced. claim_id is opaque everywhere (one log line
#: slices it for display), so a prefix is safe; the node receives the re-stamped id and the
#: receipt is minted over it, so every later fence still matches.
#: ...and it is DEFINED in `jobs.base` so the dispatcher's recovery can read it without
#: importing this module (which would drag FastAPI into the dispatcher). Re-exported here
#: because this is where readers look for it.
NODE_CLAIM_PREFIX = _NODE_CLAIM_PREFIX

#: The TOTAL time, from submission, over which refusals may keep one job deferred -- about
#: three deferral windows, which is what the old per-process count was reaching for.
MAX_TOTAL_DEFERRAL_S = 120.0

#: The furthest ahead a node may set a result's retention deadline, and it must be in the
#: future at all. This was the one node-writable timestamp with no bound: 1e18 pinned a
#: tenant's result and its blob beyond any policy's reach, and a value in the PAST had the next
#: retention tick delete the result before the submitter could fetch it, while the API reported
#: success. The job is a submitter's and the policy is the operator's; neither is the node's.
MAX_RESULT_TTL_S = 400 * 86400.0

#: How long resolved grants may be reused. Bounds how long an EXPIRED certificate keeps
#: authorising: the file does not change when it lapses, so the directory signature cannot see
#: it and only a clock can. Short enough that expiry is still a revocation mechanism, long
#: enough that a node polling in a loop cannot force a full fleet re-verify per request.
_GRANTS_CACHE_TTL_S = 15.0

#: Skew a node may be ahead of this host by when it reports a timestamp. Anything further into
#: the future is refused: `started_at` is the ONE field the reclaim sweep judges by, and a node
#: could write 9e18 into it and become permanently unreclaimable. Backwards is harmless -- it only
#: makes the job MORE reclaimable.
MAX_FUTURE_SKEW_S = 300.0

#: The furthest into the future a node may defer a job. `claimable_after` exists for short
#: capacity deferrals, and `claim_next` SKIPS a job until it passes -- so an unbounded value let
#: an authenticated node write {status: queued, claimable_after: 4102444800} and remove any job
#: it was granted from every node's view PERMANENTLY. Nothing recovered it: the requeue sweep
#: only looks at RUNNING, retention only at terminal states, and _fail_stale_queued_jobs is
#: opt-in and runs where the database is. Quieter than writing FAILED to achieve the same denial
#: honestly, which is what made it worth closing.
MAX_DEFERRAL_S = 3600.0

def _grants_fingerprint(grants) -> str:
    """A stable key for WHAT a node is granted, so a refusal is remembered per grant set.

    A refusal is a function of (the node's grants, the job's policy). Keying the memo by node
    alone meant a certificate re-issued with the grant it lacked was still refused from memory
    until the entry expired; keyed by this, the new certificate simply has no memory yet.
    """
    import json

    # STRUCTURED, not joined. With ",".join a tier literally named "socks,vpn" and the pair
    # ("socks", "vpn") produced the same key, so correcting a certificate from one to the other
    # left a stale exclusion in place. Grant values are not validated against delimiters at
    # issuance, so no delimiter is safe; JSON of sorted lists is unambiguous by construction.
    return json.dumps([sorted(getattr(grants, "engines", ()) or ()),
                       sorted(getattr(grants, "tiers", ()) or ()),
                       bool(getattr(grants, "credentials", False))],
                      separators=(",", ":"))


class _UnrunnableSet:
    """Jobs NO enrolled certificate is granted, fenced to the grants generation they were judged in.

    Why a class and a lock: sync FastAPI handlers run in a threadpool. One thread could judge a job
    against the OLD grants while another refreshed the grants and cleared this set; the first then
    inserted its stale verdict into the fresh set, whose generation already named the new grants --
    so nothing ever invalidated it, and a newly entitled node could not claim the job until some
    other certificate changed. A verdict now carries the generation it was computed from, and is
    kept only if that is still the current one, checked under the same lock that clears.
    """

    def __init__(self, limit: "int | None" = None) -> None:
        import threading

        self._ids: dict[str, str] = {}
        self._gen: "str | None" = None
        # Read at CONSTRUCTION, not bound as a default argument at import -- so the module constant
        # is the one source of truth (and a test that lowers it is actually testing the cap).
        self._limit = _MAX_UNRUNNABLE if limit is None else limit
        self._lock = threading.Lock()
        self._said_full = False

    def current(self, generation: str) -> "frozenset[str]":
        """The exclusion for `generation`; a new generation voids every earlier verdict."""
        with self._lock:
            if generation != self._gen:
                # THE CERTIFICATE SET CHANGED -- a node enrolled, renewed, lapsed or was removed.
                # Any of those can make a job runnable, so every judgement is void.
                self._ids.clear()
                self._gen = generation
                self._said_full = False
            return frozenset(self._ids)

    def note(self, job_id: str, why: str, *, generation: str) -> bool:
        """Record a verdict if it is still current and there is room. True if it was recorded."""
        with self._lock:
            if generation != self._gen or job_id in self._ids:
                return False
            if len(self._ids) >= self._limit:
                # FULL MEANS STOP ADDING -- never evict. Evicting discarded the HEAD of the wall,
                # which is what oldest-first `claim_next` offers next, so the set cycled over the
                # same prefix. Refusing new entries keeps the head excluded and the walk moving.
                # And SAY SO, once: past this point work behind the wall can starve again, which
                # is the documented bound, and a bound reached silently is worse than none.
                if not self._said_full:
                    self._said_full = True
                    _log.error("node_claim: the fleet-wide exclusion is full (%d jobs that no "
                               "enrolled node can run). Work queued behind them may no longer "
                               "be reached. Enrol a node that holds the missing grants, or set "
                               "BLASTBOX_MAX_QUEUED_AGE_S so such work is failed on a deadline.",
                               self._limit)
                return False
            self._ids[job_id] = why
            return True


class _RefusalMemo:
    """Which (node, job) pairs this control plane has already judged, and for how long.

    See _REFUSAL_MEMO_TTL_S: without it, a wall of jobs a node may not run consumed the whole
    probe budget on every poll and the node never reached work it was granted.
    """

    def __init__(self, ttl_s: float = _REFUSAL_MEMO_TTL_S, limit: int = 8192) -> None:
        self._until: dict[tuple[str, str], float] = {}
        self._ttl_s = ttl_s
        self._limit = limit

    def remember(self, node_id: str, job_id: str) -> None:
        self._until[(node_id, job_id)] = time.time() + self._ttl_s
        if len(self._until) > self._limit:
            # pop(), not del. FastAPI runs these handlers in a threadpool, so two claims for the
            # same node run this eviction concurrently: the keys were listed before the loop, a
            # peer removed some of them first, and `del` then raised KeyError from inside the
            # claim walk -- a 500 for a request whose honest answer was "nothing for you".
            for key in list(self._until)[: self._limit // 2]:
                self._until.pop(key, None)

    def remembered_for(self, node_id: str, *, limit: "int | None" = None) -> "frozenset[str]":
        """The jobs this node has been refused and whose refusal is still fresh.

        Handed to `claim_next(exclude=...)` so the STORE never offers them -- see
        _MAX_CLAIM_SKIPS for why stepping over them afterwards could not work.

        NOT CAPPED BELOW THE MEMO ITSELF. The first version capped this at 256 with the skip
        branch as the backstop, which only moved the cliff: every refusal past the cap had to be
        stepped over by hand, 16 at most per poll, so a wall of ~272 refused jobs was crossed
        and a wall of 300 never was (measured, 199 polls). The bound that matters is the memo's
        own size, and that is also comfortably inside what the stores accept as bound
        parameters (SQLite 3.45 takes 32,767; Postgres 65,535). `limit` exists for tests.
        """
        if limit is None:
            limit = self._limit
        now = time.time()
        fresh = now + self._ttl_s
        out: list[str] = []
        for (nid, jid), until in list(self._until.items()):
            if nid == node_id and until > now:
                out.append(jid)
                # REFRESHED ON USE. An entry the walk is actively excluding is by definition
                # still standing between this node and newer work; letting it lapse on a clock
                # made the walk re-judge the head of the wall before it had crossed the tail, so
                # any wall deeper than (judgements per poll x polls per TTL) was never crossed.
                # While the node keeps polling with the same grants, its refusals stay live;
                # a changed certificate changes the key (see _grants_fingerprint) instead.
                self._until[(nid, jid)] = fresh
                if len(out) >= limit:
                    break
        return frozenset(out)

    def remembers(self, node_id: str, job_id: str) -> bool:
        key = (node_id, job_id)
        until = self._until.get(key)
        if until is None:
            return False
        if until <= time.time():
            # Same race, same fix: two threads both see it expired and both drop it. No lock,
            # because this memo is ADVISORY -- losing an entry costs one re-judgement of one
            # job, which is exactly what it cost before the memo existed.
            self._until.pop(key, None)
            return False
        return True




#: What a refused caller is told. ONE message for every cause -- a wrong CA, an unheld key,
#: an ungranted engine and an expired challenge are all simply "no". Distinguishing them
#: over the wire would let a caller map the fleet's grants by probing; the real reason is
#: logged server-side, where it is diagnosis rather than a disclosure.
_REFUSED = "not authorised to claim this work"


class SessionRequest(BaseModel):
    """A node proving possession of its certificate's key, once per session."""

    cert_pem: str = Field(..., max_length=16384,
                          description="the node's certificate, PEM")
    challenge: str = Field(..., max_length=512)
    signature: str = Field(..., max_length=1024, description="base64 ECDSA over the payload")


class ClaimRequest(BaseModel):
    """A node asking for work it is entitled to, holding a session token.

    NO ``tier`` AND NO ``require_credentials`` HERE, deliberately. They used to be request
    fields, which meant the NODE chose what it was checked against: omit ``tier`` and the
    tier grant went unexamined, omit ``require_credentials`` and the credentials grant did
    too. A caller selecting its own authorisation predicate is not an authorisation check.
    Both are now derived on this host from the job actually being handed over.

    ``engine`` is OPTIONAL. Omitted means "anything this certificate grants", which is what a
    dispatcher without engine scoping asks for -- ``dispatch.py`` calls
    ``claim_next(claimant_tier=...)`` with no engine at all by default, and requiring one
    here made every such node raise on every claim.
    """

    engine: str | None = Field(None, max_length=64)
    claimant_tier: str | None = Field(
        None, max_length=64,
        description="NOT ACCEPTED over this path -- see the claim route. Present so a client "
                    "sending it gets a reason rather than silence.")


class UpdateRequest(BaseModel):
    """A node reporting on a job it holds the claim for.

    ``claim_id`` is not decoration. It is the per-claim ownership token `claim_next` stamps,
    and requiring it is what stops a node writing to a job another node now owns: a job that
    was reclaimed after a timeout has a NEW token, so the old holder's write is refused
    rather than clobbering the live run. The store's own ``update_if_status`` already CASes
    on ``(status, claim_id)`` for exactly this reason; this carries it over the wire.
    """

    claim_id: str = Field(..., max_length=128)
    receipt: str = Field(..., max_length=128,
                         description="the claim receipt this server returned at hand-over")
    fields: dict[str, Any] = Field(default_factory=dict)
    expect_status: str | None = Field(None, max_length=32)


def resolve_pki_dir(pki_dir: "Path | str | None" = None) -> Path | None:
    """The PKI directory to verify against, or None when this deployment has no PKI.

    A DIRECTORY WITH NO CA IS NOT A PKI. The check is for the trust anchor specifically,
    not for the directory: an empty ``/var/lib/blastbox/pki`` exists on a host that has
    merely had the package installed, and arming on its existence would register routes
    that can verify nobody -- refusing every node on a deployment that never opted in.
    """
    raw = pki_dir if pki_dir is not None else os.environ.get(PKI_ENV, DEFAULT_PKI_DIR)
    # SET-BUT-EMPTY IS NOT A PATH. Deployment tooling emits `BLASTBOX_PKI_DIR=` from an
    # unset compose variable, and `Path("")` is the CURRENT DIRECTORY -- so a blank value
    # would have this looking for a trust anchor in whatever directory the process happened
    # to start in, and arming or not arming on that. Treat blank as unset.
    if not str(raw).strip():
        raw = DEFAULT_PKI_DIR
    d = Path(raw).expanduser()
    anchor = d / "ca.crt"
    if not anchor.exists():
        return None                     # genuinely not opted in
    try:
        from blastbox.host.pki import load_trust_anchor

        load_trust_anchor(d)
    except Exception as exc:            # noqa: BLE001 - present but unreadable or malformed
        # NOT None. A truncated ca.crt mid re-issue, or a permissions mistake, used to read as
        # "no PKI": the routes silently vanished for the life of the process, DB-backed nodes
        # fell back to unrestricted claim_next(), and the log said at INFO to run `pki init`
        # -- a control that was in force and silently stopped being. A trust anchor that
        # exists and cannot be loaded is an outage, and it is raised as one.
        raise RuntimeError(
            f"{anchor} exists but cannot be loaded ({exc}). Refusing to start without the "
            "node-claim routes: a broken trust anchor is not the same as none.") from exc
    return d


def _overrides_allowed() -> bool:
    """Whether a job may select its own network personality (BLASTBOX_ALLOW_NETPOLICY_OVERRIDE).
    One reading, shared by the claim walk and the backlog, so the two cannot disagree."""
    return (os.environ.get("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "").strip().lower()
            in ("1", "true", "yes", "on"))


def _job_requirements(job) -> "tuple[str | None, bool, bool]":
    """(tier grant needed, credentials needed, whether this host could tell).

    DERIVED HERE, never taken from the request -- a caller choosing its own authorisation
    predicate is not an authorisation check.

    THE ENGINE DEFAULT IS THE USUAL CASE, and getting it wrong made this whole check a
    no-op. An earlier version hardcoded ``engine_default="none"``, but a job's personality
    normally comes from ``BLASTBOX_ENGINE_<NAME>_NETPOLICY`` (cli.py reads exactly that
    when it builds the dispatcher's EngineSpecs), and ``job.net_policy`` is only ever
    stored when ``BLASTBOX_ALLOW_NETPOLICY_OVERRIDE`` is on -- which is OFF by default. So
    every job resolved to ``none`` here, took the ungoverned branch, and neither the tier
    nor the credentials grant was ever examined. The tests passed because they set a
    per-job override, i.e. they exercised the one path that worked.

    THE THIRD RETURN VALUE IS "COULD I TELL". An ingress host with no
    ``BLASTBOX_NETPOLICY_*`` registry cannot distinguish a genuinely ungoverned job from
    one whose personality it simply cannot see, and quietly treating the second as the
    first is how this became a no-op. It reports the doubt instead, and the caller decides.

    UNGOVERNED TIERS REMAIN NO REQUIREMENT -- a lesson already paid for in
    `placement.UNGOVERNED_TIERS`: ``none`` is the DEFAULT personality and demanding a grant
    for it made correctly-issued nodes refuse every ordinary job.

    WHAT IT STILL CANNOT DERIVE: whether openvpn/wireguard imply credentials depends on the
    NODE's own egress mode, which is node-local. Those stay with the node's `SelfGrants`;
    only the always-credentialed drivers are required here.
    """
    from blastbox.host.netpolicy import parse_personalities, resolve_net_policy
    from blastbox.host.placement import ALWAYS_CREDENTIALED, UNGOVERNED_TIERS

    registry = parse_personalities(os.environ)
    # The same env convention cli.py uses to build the dispatcher's EngineSpecs, so both
    # sides resolve one job to one personality.
    # .lower() LIKE cli.py DOES (it builds the dispatcher's EngineSpecs with
    # `.strip().lower()`), because `parse_personalities` keys the registry in lower case.
    # Without it `BLASTBOX_ENGINE_CLAMAV_NETPOLICY=VPN` read as a personality this host has
    # not got: in non-strict mode that is "nothing to check", so the job was handed to a node
    # with no tier or credentials grant -- and the node, lowercasing the same value, resolved
    # it to a real wireguard exit. Both sides must normalise identically or the hand-over
    # authorises against a personality the run will not use.
    engine_default = (os.environ.get(
        f"BLASTBOX_ENGINE_{job.engine.upper().replace('-', '_')}_NETPOLICY")
        or "none").strip().lower() or "none"
    # CAN THIS HOST RESOLVE WHAT THIS JOB NEEDS? Precisely, not by counting entries.
    #
    # * engine_default "none" and no per-job override -> the job genuinely IS ungoverned,
    #   which is the ordinary all-none deployment. Nothing to look up, nothing unknown.
    # * engine_default names a personality this host HAS -> resolvable.
    # * engine_default names one this host has NOT got -> `resolve_net_policy` silently
    #   falls back to "none", and THAT is the silent hole: an operator declared a policy
    #   this host cannot see, so the tier and credentials grants would go unchecked while
    #   looking exactly like an ungoverned job. Unknown, and it must not read as permissive.
    # _overrides_allowed(), not a second inline parse: /backlog decides from the same function,
    # and two parsers that agree only by coincidence are how the two routes drift apart.
    allow_override = _overrides_allowed()
    can_tell = engine_default == "none" or engine_default in registry
    job_policy = (job.net_policy or "").strip().lower() or None
    if allow_override and job_policy and job_policy not in registry:
        # The job SELECTS a personality this host has not got. `resolve_net_policy` falls
        # through to the engine default -- possibly "none" -- so it would look ungoverned
        # here while a node whose registry DOES hold that name resolves it to a real exit
        # driver and runs it with no tier or credentials check. An explicitly selected but
        # undeclared override is unknown, and in strict mode refused, exactly like an
        # undeclared engine default.
        can_tell = False
    try:
        personality = resolve_net_policy(
            job_net_policy=(job.net_policy or "").strip().lower() or None,
            engine_default=engine_default,
            registry=registry, allow_override=allow_override)
        driver = getattr(personality, "exit_driver", "") or ""
    except Exception:               # noqa: BLE001
        return None, False, False
    if not driver or driver in UNGOVERNED_TIERS:
        # Genuinely ungoverned IF this host could have told. If it could not, the answer
        # is "unknown", and the caller must not read it as "unrestricted".
        return None, False, can_tell
    # can_tell, NOT a literal True. The arm above computes "this host cannot resolve the
    # personality this job selected" and this return threw it away whenever the FALLBACK
    # driver happened to be governed -- so the strict-mode refusal only ever fired for an
    # ungoverned fallback, which is the case that needed it least. A node whose registry
    # DOES hold that name would have run the job under a real exit driver with its tier and
    # credentials grants unchecked.
    return driver, driver in ALWAYS_CREDENTIALED, can_tell


def register_node_claim_routes(
    app: "FastAPI", *, job_store: "JobStore", pki_dir: "Path | str | None" = None,
    pepper: bytes | None = None,
) -> bool:
    """Mount the claim routes if this deployment has a PKI. Returns whether it did."""
    resolved = resolve_pki_dir(pki_dir)
    if resolved is None:
        _log.info("node_claim: no trust anchor (%s); nodes claim directly from the store, "
                  "as before. Run `blastbox pki init` to enforce grants at the hand-over.",
                  pki_dir if pki_dir is not None
                  else os.environ.get(PKI_ENV, DEFAULT_PKI_DIR))
        return False

    from blastbox.host.pki import load_trust_anchor

    router = APIRouter(prefix="/v1/nodes", tags=["nodes"])

    def _anchor():
        """Loaded PER REQUEST, not once at startup.

        Re-issuing the CA, or adding a node, must take effect without restarting ingress --
        and more importantly a cached anchor would keep verifying against a CA an operator
        has deliberately replaced. `SelfGrants` carries the same note about why its own
        verification holds no cache: every cached authorisation verdict this codebase has
        had produced a defect, five of them from one cache.
        """
        return load_trust_anchor(resolved)

    @router.get("/challenge")
    def challenge() -> dict[str, Any]:
        """Mint a challenge for a claim attempt. Unauthenticated, and safe to be.

        It carries no secret and grants nothing: it is a value this server will later
        recognise as its own, so that a signature cannot be replayed indefinitely. Handing
        one to an unauthenticated caller costs a MAC.
        """
        return {
            "challenge": node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT,
                                                 secret=_secret()),
            "expires_in": node_auth.CHALLENGE_TTL_S,
            "scope": node_auth.SCOPE_CLAIM_NEXT,
        }

    # Resolved ONCE, here, and raised if it cannot be: every ingress process must sign with the
    # key its peers verify against, and the job store is where they agree. See
    # node_auth.resolve_claim_secret for the precedence and why None fails closed.
    _signing_key = node_auth.resolve_claim_secret(job_store, resolved, pepper=pepper)

    def _secret() -> bytes:
        return _signing_key

    def _node_from_token(token: str | None) -> str:
        """The node id this caller has already proved, or 403.

        The token names the node and nothing more; what it MAY DO is resolved below from
        this server's own certificate store, per request. See `node_auth.issue_session`.
        """
        # 401, NOT 403, and the difference is a traffic control. 403 means "you may not have
        # this"; 401 means "your session is no good, get another". The client re-handshakes only
        # on 401, so a node that is simply not granted something stops paying a full
        # challenge+session handshake on every refused request -- measured at 22 requests where
        # 5 were correct, i.e. the amplification the retry was supposed to prevent.
        if not token or not token.strip():
            raise HTTPException(status_code=401, detail="node session required")
        try:
            return node_auth.verify_session(token.strip(), secret=_secret())
        except node_auth.ClaimRefused as exc:
            _log.warning("node_claim: session rejected: %s", exc)
            raise HTTPException(status_code=401, detail="node session required") from None

    def _grants_now(node_id: str):
        """What this node may do, read fresh from the certificates on THIS host.

        Never from the token, and never from anything the node published. A certificate
        that has lapsed or been removed since the token was issued resolves to absent here,
        so the node is refused within the token's lifetime rather than at its expiry.
        """
        from blastbox.host.placement import fleet_grants

        sig = _pki_signature()
        now = time.time()
        if sig != _grants_cache["sig"] or now >= _grants_cache["until"]:
            _grants_cache["map"] = fleet_grants(resolved)
            _grants_cache["sig"] = sig
            _grants_cache["until"] = now + _GRANTS_CACHE_TTL_S
        return _grants_cache["map"].get(node_id)

    @router.post("/session", response_model=None)
    def session(req: SessionRequest) -> dict[str, Any]:
        """Prove possession once; get a short-lived token for the requests that follow.

        WHY NOT SIGN EVERY REQUEST. Binding a signature to each operation would cost a
        challenge round trip plus a signature per call -- three requests to update one
        job's status, on the path a dispatcher walks for every job. The handshake is paid
        once per session instead.
        """
        try:
            signature = base64.b64decode(req.signature, validate=True)
        except (binascii.Error, ValueError):
            _log.warning("node_claim: session refused, signature is not base64")
            raise HTTPException(status_code=403, detail=_REFUSED) from None
        try:
            ident = node_auth.admit_identity(
                _anchor(), req.cert_pem.encode(), challenge=req.challenge,
                scope=node_auth.SCOPE_CLAIM_NEXT, signature=signature, secret=_secret())
        except node_auth.ClaimRefused as exc:
            # NAME THE LIKELIEST CAUSE. "challenge was not issued by this server" behind a
            # load balancer almost always means the challenge was minted by a DIFFERENT
            # ingress host with its own key -- a deployment fault that reads as a node
            # problem, and would otherwise be debugged on the node for a long time.
            hint = ""
            if "not issued by this server" in str(exc):
                hint = (f" -- if more than one ingress host serves this address, they must "
                        f"share the claim key; set {node_auth.SECRET_FILE_ENV} to one "
                        f"location on every host")
            _log.warning("node_claim: session refused: %s%s", exc, hint)
            raise HTTPException(status_code=403, detail=_REFUSED) from None
        _log.info("node_claim: session opened for node=%s", ident.node_id)
        return {
            "token": node_auth.issue_session(ident.node_id, secret=_secret()),
            "expires_in": node_auth.SESSION_TTL_S,
            "node_id": ident.node_id,
        }

    # response_model=None: the handler returns either a dict or a bare 204 Response, and
    # FastAPI cannot build a response model from that union (it raises at import).
    @router.post("/claim", response_model=None)
    def claim(req: ClaimRequest, response: Response,
              x_blastbox_node_session: str | None = Header(None)) -> dict[str, Any] | Response:
        """Admit, claim, then verify what was actually handed over -- and release it if the
        node is not entitled to THAT job.

        The engine check happens before the claim, so an ungranted engine never moves a job.
        The tier and credentials checks cannot: what a job requires is a property OF THE JOB,
        and the job is not known until one is claimed. So the order is claim -> derive ->
        release-and-refuse. The node still never receives the record: the response is
        withheld and the job goes back to QUEUED with its claim cleared, which is the same
        state a crashed dispatcher leaves behind and the reclaim path already handles.
        """
        from blastbox.host.jobs.base import JobStatus
        from blastbox.host.placement import refusal

        node_id = _node_from_token(x_blastbox_node_session)
        if req.claimant_tier:
            # REFUSED, not ignored, and not honoured.
            #
            # `claim_next(claimant_tier=...)` decides which target_tier-PINNED jobs a caller may
            # take, and pinning is an operator containment control -- dispatch pins work so "a
            # BLASTBOX_POOL_RUNTIME drift can't silently route it onto a public-AWS/remote worker
            # with a different egress posture". Taken from the request it was exactly the defect
            # ClaimRequest's docstring says it fixed by deleting `tier`: a caller selecting its
            # own authorisation predicate. Measured: a node running a plain cold pool asked for
            # claimant_tier="firecracker" and received the hardware-isolated job.
            #
            # It cannot be authorised here either, because a node's RUNTIME tier is not in its
            # certificate -- `NodeGrants` carries engines, netpolicy tiers and credentials, and
            # none of those is "this node runs firecracker". So it is refused with a reason
            # instead of silently dropped, which would leave a node believing it was routing.
            # Binding runtime tier to identity needs a NodeGrants field and an issuance change;
            # until then pinned work stays with dispatchers that hold the queue.
            _log.warning("node_claim: refused node=%s claimant_tier=%r: a node cannot assert "
                         "its own runtime tier", node_id, req.claimant_tier)
            raise HTTPException(
                status_code=400,
                detail="claimant_tier is not accepted over the node claim path: a node's "
                       "runtime tier is not carried in its certificate, so it cannot be "
                       "authorised. Jobs pinned with target_tier stay with dispatchers that "
                       "hold the queue.")
        grants = _grants_now(node_id)
        if grants is None:
            _log.warning("node_claim: refused node=%s: no verifiable certificate", node_id)
            raise HTTPException(status_code=403, detail=_REFUSED)

        # Which engines may this node be offered? Its own ask, intersected with its grants --
        # never its ask alone.
        wanted = [req.engine] if req.engine else list(grants.engines)
        allowed = [e for e in wanted if grants.allows_engine(e)]
        if not allowed:
            _log.warning("node_claim: refused node=%s engines=%s not granted",
                         node_id, wanted)
            raise HTTPException(status_code=403, detail=_REFUSED)

        # KEEP LOOKING PAST A JOB THIS NODE MAY NOT RUN. `claim_next` always returns the
        # OLDEST eligible job, and a refused job goes back to QUEUED -- so returning after one
        # refusal meant the next poll re-selected the SAME job forever and the node NEVER
        # reached newer work it was entitled to. Refused jobs are now released with a short
        # deferral (see _REFUSAL_DEFER_S), which `claim_next` honours on every backend, so each
        # probe here sees a job it has not yet judged. The loop bound is a cost cap, not the
        # mechanism.
        skipped: list[Any] = []
        job = None
        probes = 0
        skips = 0
        # The refusal memo is per (node, GRANTS): see _REFUSAL_MEMO_TTL_S.
        memo_key = f"{node_id}#{_grants_fingerprint(grants)}"
        try:
            while probes < _MAX_CLAIM_PROBES and skips < _MAX_CLAIM_SKIPS:
                # EXCLUDE WHAT THIS NODE HAS ALREADY BEEN REFUSED, in the store query itself.
                # `claim_next` is strictly oldest-first, so stepping over refused jobs AFTER
                # they were handed out meant a wall deeper than _MAX_CLAIM_SKIPS was the same
                # prefix on every poll -- the walk stopped before reaching anything behind it,
                # forever, and paid a claim, a stamp and a release per remembered job for the
                # privilege. With the exclusion the store simply does not offer them: nothing
                # to release, nothing to re-stamp, and nothing in the way.
                candidate = job_store.claim_next(
                    engine=frozenset(allowed),
                    exclude=_refusals.remembered_for(memo_key) | _unrunnable_now())
                if candidate is None:
                    break
                # STAMP THE PREFIX FIRST, before judging and before the memo check. The prefix
                # is what tells `reclaim_stale_claims` "this claim is mine to judge", so every
                # way this walk could leave a job behind -- a release that raises, a killed
                # worker mid-`finally` -- used to produce a RUNNING row with an unprefixed claim
                # id, which no sweep ever looks at again: not QUEUED (fail_stale_queued skips
                # it), not terminal (retention and the scratch reaper skip it), not prefixed
                # (the stale-claim sweep skips it). Immortal, with the untrusted sample on disk.
                # CAS-fenced: losing it means a sweep took the job between the two writes.
                stamped = NODE_CLAIM_PREFIX + (candidate.claim_id or "")
                if not job_store.update_if_status(candidate.job_id, JobStatus.RUNNING,
                                                  expect_claim_id=candidate.claim_id,
                                                  claim_id=stamped):
                    probes += 1         # CHARGED: see below
                    continue
                candidate = job_store.get(candidate.job_id)
                if candidate is None or candidate.claim_id != stamped:
                    # CHARGED TOO. These two paths replaced a `for _ in range(...)` with a
                    # `while`, and neither counted -- so a store that keeps losing the stamp CAS
                    # made the walk bounded by the QUEUE DEPTH rather than by eight probes: one
                    # request against a 500-job queue issued 501 claims and left all 500 RUNNING
                    # with unprefixed claim ids, which is the immortal-row state stamping early
                    # exists to prevent. A cost cap that only counts the paths that succeed is
                    # not a cost cap.
                    probes += 1
                    continue            # taken from under us; not ours to release either
                if _refusals.remembers(memo_key, candidate.job_id):
                    # Judged already, and recently. Stepping over it costs a claim and a release
                    # but NOT one of the eight probes -- see _REFUSAL_MEMO_TTL_S: charging the
                    # probe budget for a wall of permanently-refused jobs meant the node never
                    # reached anything behind it.
                    skipped.append(candidate)
                    skips += 1
                    continue
                probes += 1
                tier, needs_credentials, could_tell = _job_requirements(candidate)
                why = refusal(grants, engine=candidate.engine, tier=tier,
                              require_credentials=needs_credentials)
                if why is None and not could_tell and _strict_tiers():
                    # This host cannot see the job's personality, so it cannot prove the tier
                    # and credentials grants are satisfied. In strict mode that is a refusal,
                    # not a pass -- the same direction `SelfGrants.refuse` takes for an
                    # unreadable driver ("Unreadable, not ungoverned").
                    why = ("this host cannot resolve the job's network personality, so the "
                           "tier and credentials grants cannot be checked")
                if why is None:
                    job = candidate     # already stamped and re-read above
                    break
                skipped.append(candidate)
                _refusals.remember(memo_key, candidate.job_id)
                can_run, generation = _fleet_verdict(candidate)
                if not can_run:
                    _note_unrunnable(candidate, why, generation)
                else:
                    _log.warning("node_claim: released job=%s from node=%s: %s",
                                 candidate.job_id, node_id, why)
        finally:
            # Put back everything not handed over, including on an exception: a job claimed
            # inside this loop and not returned would otherwise be stranded RUNNING.
            for other in skipped:
                _release(other)

        if job is None:
            # 204, not 404: the node is entitled to work and there is none right now (or none
            # it may run). A 404 would be indistinguishable from the routes not existing, which
            # is how a node decides to fall back to claiming from the store directly.
            response.status_code = 204
            return response

        _log.info("node_claim: handed job=%s engine=%s to node=%s",
                  job.job_id, job.engine, node_id)
        return {
            "job": job.to_dict(),
            "node_id": node_id,
            # The receipt, not just the claim id: see node_auth.claim_receipt for why
            # knowing a claim id must not be sufficient to write to a job.
            "receipt": node_auth.claim_receipt(
                job.job_id, job.claim_id or "", node_id, secret=_secret()),
        }

    #: fleet_grants is O(certificates) with a full X.509 verify per file, and it ran on EVERY
    #: request -- 77 ms of ingress CPU per poll at 200 certificates, from a request a node can
    #: issue for nothing. Cached on the directory's signature (name, mtime, size of every
    #: *.crt) AND a short deadline.
    #:
    #: THE DEADLINE IS NOT BELT-AND-BRACES, it is the whole correctness of the cache. A
    #: certificate that EXPIRES does not change its name, mtime or size -- so signature alone
    #: kept authorising a lapsed identity indefinitely, which broke the one revocation
    #: mechanism this design has ("stop renewing"). Removal and replacement do change the
    #: signature and are caught immediately; expiry needs the clock. Reviewed and confirmed.
    _grants_cache: "dict[str, Any]" = {"sig": None, "map": {}, "until": 0.0}

    def _pki_signature() -> tuple:
        try:
            return tuple(sorted(
                (c.name, c.stat().st_mtime_ns, c.stat().st_size)
                for c in resolved.glob("*.crt")))
        except OSError:
            return ("unreadable", time.time())

    def _strict_tiers() -> bool:
        return (os.environ.get(STRICT_TIERS_ENV, "").strip().lower()
                in ("1", "true", "yes", "on"))

    #: Per-app state for the two refusal controls. Classes rather than closures so a test can
    #: drive the bounds directly: both were reverted in a mutation pass with the suite green,
    #: because nothing could reach them without ~4000 requests.
    _refusals = _RefusalMemo()

    #: job_id -> the refusal reason, for jobs NO enrolled certificate is granted. The per-node memo
    #: above could only ever approximate this: it is per node, so every node re-judged the same
    #: wall, and it had to forget something eventually -- a size cap, then a TTL -- and each time
    #: it forgot the HEAD of the wall first, which is exactly what `claim_next` offers next. Four
    #: review rounds found four edges of that one mechanism. This set is judged once per
    #: certificate set, shared by every node, never expires, and is invalidated the moment the
    #: certificate set changes -- because that is the only thing that can make such a job runnable.
    #: Disposing of the work is NOT done here: BLASTBOX_MAX_QUEUED_AGE_S already fails stale
    #: queued jobs (opt-in, retention-correct, deleting the staged sample), and once these stop
    #: being churned they sit undeferred for that sweep to find.
    _unrunnable = _UnrunnableSet()

    def _fleet_now() -> "dict[str, Any]":
        """Every enrolled node's grants, from the same cache `_grants_now` keeps fresh."""
        _grants_now("")
        return _grants_cache["map"]

    def _fleet_fingerprint(fleet: "dict[str, Any]") -> str:
        """What the whole fleet is granted, as content. The exclusion is a function of THIS, so it
        is keyed on this -- not on the certificate files' (name, mtime, size), which a certificate
        replaced by metadata-preserving tooling leaves unchanged while its grants move. Grants are
        re-read on content every _GRANTS_CACHE_TTL_S; the exclusion now follows the same read."""
        return "|".join(f"{node}={_grants_fingerprint(g)}" for node, g in sorted(fleet.items()))

    def _unrunnable_now() -> "frozenset[str]":
        return _unrunnable.current(_fleet_fingerprint(_fleet_now()))

    def _fleet_verdict(job) -> "tuple[bool, str]":
        """Can ANY enrolled certificate run this job, and in which grants generation was that
        decided? One fleet snapshot for both, so the verdict and its generation cannot disagree.
        The same test the walk applies to one node, applied to all -- a job a peer IS granted is
        never excluded here."""
        from blastbox.host.placement import refusal as _refusal

        fleet = _fleet_now()
        generation = _fleet_fingerprint(fleet)
        tier, needs_credentials, could_tell = _job_requirements(job)
        if not could_tell and _strict_tiers():
            return False, generation    # nobody can be shown to satisfy an unresolvable policy
        return any(_refusal(g, engine=job.engine, tier=tier,
                            require_credentials=needs_credentials) is None
                   for g in fleet.values()), generation

    def _note_unrunnable(job, why: str, generation: str) -> None:
        if _unrunnable.note(job.job_id, why, generation=generation):
            # ONCE PER JOB, and it names the missing grant. Queued-forever with nothing in the log
            # was half of this problem: the operator could not tell a wall from an empty fleet.
            _log.warning("node_claim: job=%s engine=%s is excluded from every node: no enrolled "
                         "node is granted what it needs (%s). Enrol a node that is, or set "
                         "BLASTBOX_MAX_QUEUED_AGE_S to fail work like this after a deadline.",
                         job.job_id, job.engine, why)

    def _defer_until(job) -> "float | None":
        """How long to hold a wrongly-offered job back, or None for "claimable immediately".

        AGE FROM SUBMISSION, not a per-process count. The count was the whole enforcement of the
        old cap and it could not be enforced: the map is per forked ingress worker and per host,
        so the real allowance was cap x workers x hosts, a restart reset it, and its own size
        bound handed a spent allowance back. `created_at` is stamped by the submitting host,
        shared by every ingress that can see the queue, and not in NODE_WRITABLE_FIELDS -- so
        this bounds the TOTAL time any number of nodes can keep one job out of an entitled
        peer's view, which is what the cap was trying to say.
        """
        now = time.time()
        if now - getattr(job, "created_at", 0.0) > MAX_TOTAL_DEFERRAL_S:
            return None                 # spent: an entitled peer wins from here on
        return now + _REFUSAL_DEFER_S

    def _release(job) -> None:
        """Put a wrongly-offered job back, fenced on the claim we are releasing.

        Fenced, because between the claim and here the job could already have been reclaimed
        (a slow release racing a timeout sweep); an unconditional write would then drag a
        live run back to QUEUED.
        """
        from blastbox.host.jobs.base import JobStatus

        try:
            # started_at=None too, exactly as dispatch's own requeue does (dispatch.py clears
            # it deliberately): `claim_next` stamps it, so a job refused here would otherwise
            # go back to the queue carrying a start time for a run that never happened -- and
            # that value is public on the job record.
            job_store.update_if_status(job.job_id, JobStatus.RUNNING,
                                       expect_claim_id=job.claim_id,
                                       status=JobStatus.QUEUED, claim_id=None,
                                       started_at=None, worker_runtime=None,
                                       worker_tier=None,
                                       # Deferred, not merely requeued: see _REFUSAL_DEFER_S --
                                       # and only while the job is young (MAX_TOTAL_DEFERRAL_S),
                                       # so no number of nodes can hold governed work away from
                                       # an entitled peer by renewing the deferral on every poll.
                                       claimable_after=_defer_until(job))
        except Exception:               # noqa: BLE001 - the reclaim sweep is the backstop
            _log.exception("node_claim: could not release job=%s; the reclaim path will "
                           "pick it up", job.job_id)

    @router.get("/backlog", response_model=None)
    def backlog(engine: "list[str] | None" = Query(None),
                untargeted_only: bool = Query(False),
                x_blastbox_node_session: str | None = Header(None)) -> dict[str, Any]:
        """How much QUEUED work is waiting for the engines this node is granted.

        A COUNT IS NOT AN ENUMERATION, which is why this can exist while `list` cannot. It
        returns one integer, scoped to engines the caller's certificate already grants -- so it
        reveals nothing the node did not already know it was entitled to, and no job ids, no
        filenames, no peers' work.

        WHY IT IS NEEDED. Without it a node's sizer cannot read a backlog at all, and the
        failure is invisible: `DispatcherSizer` falls back to a last-known value that starts at
        zero and never advances, so the warm pool sits at its floor and the cold gate at its
        floor however deep the queue is. Raising on `count` was necessary but not sufficient --
        a bare `except` downstream turned it into exactly the silent under-serving the raise was
        meant to prevent.
        """
        node_id = _node_from_token(x_blastbox_node_session)
        grants = _grants_now(node_id)
        if grants is None:
            raise HTTPException(status_code=403, detail=_REFUSED)
        wanted = [e for e in (engine or []) if e] or list(grants.engines)
        allowed = sorted({e for e in wanted if grants.allows_engine(e)})
        # ENGINE GRANT IS NOT ELIGIBILITY. A node granted an engine but NOT the network tier
        # (or the credentials) its queued jobs need has every such job REFUSED by /claim after
        # `_job_requirements` -- while this route counted them, and that number goes straight
        # into DispatcherSizer. The pool then grows to its ceiling for work it can never run
        # and takes that share of the node budget from a sibling pool that could drain it.
        #
        # Resolved PER ENGINE, not per job, because that is what a count can afford: the tier
        # requirement comes from the engine's default personality, so one probe per engine
        # answers it without enumerating the queue (which is the thing a node may not do). A
        # job carrying its own `net_policy` override can still be counted and then refused;
        # that is a narrower over-count than the engine-wide one, and it is the same
        # approximation `untargeted_only` makes.
        # ...BUT ONLY WHEN A JOB CANNOT CHOOSE ITS OWN POLICY. With
        # BLASTBOX_ALLOW_NETPOLICY_OVERRIDE on, a job may select a personality this node CAN
        # run even though the engine's default needs a tier it lacks -- /claim hands that job
        # over, and filtering the whole engine here reported zero for it, pinning the node's
        # sizer at its floor with runnable work queued. Per-job eligibility would need the queue
        # enumerated, which a node may not have; so with overrides on this falls back to the
        # engine grant alone, which over-counts rather than hiding work that can run.
        if not _overrides_allowed():
            allowed = [e for e in allowed if _engine_is_claimable(grants, e)]
        if not allowed:
            # Nothing granted is not an error: it is a backlog of zero, for this caller.
            return {"queued": 0, "engines": []}
        from blastbox.host.jobs.base import JobStatus

        # untargeted_only narrows to jobs with no target_tier -- the only jobs this node can
        # ever be handed -- so passing it through is a SUBSET of the granted count, never more.
        return {
            "queued": int(job_store.count(JobStatus.QUEUED, engine=allowed,
                                          untargeted_only=untargeted_only)),
            "engines": allowed,
        }

    def _engine_is_claimable(grants, engine_name: str) -> bool:
        """Would a plain job for this engine survive the claim route's own refusal check?

        The same `_job_requirements` + `refusal` pair the walk uses, so the backlog cannot
        promise work the hand-over would refuse. A host that cannot resolve the engine's
        personality answers "yes" here unless strict mode is on -- matching the walk exactly,
        which is the property that matters: these two must agree or the sizer is lied to.
        """
        from blastbox.host.jobs.base import Job, JobStatus
        from blastbox.host.placement import refusal

        probe = Job(job_id="", engine=engine_name, filename="", status=JobStatus.QUEUED,
                    created_at=0.0)
        tier, needs_credentials, could_tell = _job_requirements(probe)
        why = refusal(grants, engine=engine_name, tier=tier,
                      require_credentials=needs_credentials)
        if why is None and not could_tell and _strict_tiers():
            return False
        return why is None

    def _owned_job(job_id: str, node_id: str, claim_id: str, receipt: str):
        """The job, if this node may write to it. Otherwise 403 -- and 403 for "no such job"
        too, so a node cannot enumerate the queue by probing ids it does not own.

        THE RECEIPT IS THE OWNERSHIP PROOF, not the claim id. The claim id only says "a
        claim exists"; the receipt says "this server gave this job to the node whose session
        token you are holding". Checking the claim id alone was a bearer check, and a node
        granted the same engine could write to a peer's job with it.
        """
        job = job_store.get(job_id)
        if job is None or not job.claim_id or job.claim_id != claim_id:
            _log.warning("node_claim: write refused node=%s job=%s (claim mismatch or "
                         "no such job)", node_id, job_id)
            raise HTTPException(status_code=403, detail=_REFUSED)
        try:
            node_auth.check_claim_receipt(receipt, job_id, job.claim_id, node_id,
                                          secret=_secret())
        except node_auth.ClaimRefused as exc:
            _log.warning("node_claim: write refused node=%s job=%s: %s",
                         node_id, job_id, exc)
            raise HTTPException(status_code=403, detail=_REFUSED) from None
        if refusal_for_job(node_id, job) is not None:
            raise HTTPException(status_code=403, detail=_REFUSED)
        return job

    def refusal_for_job(node_id: str, job) -> str | None:
        """Still granted this job's engine? Checked on WRITE as well as on claim.

        A certificate can lapse, or an engine can be removed from it, while a job is in
        flight. Re-checking here means the grant has to hold for the whole run rather than
        only at the instant of the hand-over.
        """
        from blastbox.host.placement import refusal

        return refusal(_grants_now(node_id), engine=job.engine)

    def _typed(out: dict[str, Any]) -> None:
        """Reject a value whose type the store would accept and the readers would choke on."""
        from blastbox.host.jobs.base import JobStatus

        def bad(name: str, why: str) -> None:
            raise HTTPException(status_code=400, detail=f"{name}: {why}")

        if out.get("status") in (JobStatus.EXPIRED, "expired"):
            # EXPIRED is written in exactly one place in this codebase -- the retention sweep,
            # where the policy lives -- and it is not a status any dispatcher reports. A node
            # that could write it hid the submitter's result (open_output is DONE-gated) AND made
            # the row permanently uncollectable, because `expire_due` skips a row whose
            # expires_at is null, so `_expire_job` and the blob delete never ran for it. That is
            # the same outcome MAX_RESULT_TTL_S exists to prevent, through a different door.
            bad("status", "a node may not expire a job: retention is the operator's policy")
        if "status" in out and not isinstance(out["status"], (str, JobStatus)):
            # JSON also carries ints, bools, lists. `{"status": 7}` was written straight
            # through and stored; from then on `get()` and the unfiltered `list()` raised
            # "'7' is not a valid JobStatus" FOREVER -- GET /v1/jobs, and the retention sweep
            # this branch added to ingress, both dead fleet-wide at WARNING. Reproduced.
            bad("status", "must be a status name")
        now_s = time.time()
        horizon = now_s + MAX_FUTURE_SKEW_S
        if out.get("expires_at") is not None:
            try:
                ttl = float(out["expires_at"])
            except (TypeError, ValueError, OverflowError):
                bad("expires_at", "must be a numeric timestamp or null")
            if not math.isfinite(ttl) or ttl <= now_s:
                bad("expires_at", "must be a timestamp in the future")
            if ttl > now_s + MAX_RESULT_TTL_S:
                bad("expires_at",
                    f"must be within {MAX_RESULT_TTL_S / 86400:.0f} days: the retention policy "
                    "is the operator's, not a node's")
        for name in ("started_at", "finished_at", "expires_at"):
            if name in out and out[name] is not None:
                if isinstance(out[name], bool) or not isinstance(out[name], (int, float)):
                    bad(name, "must be a numeric timestamp or null")
                try:
                    # float() on a 400-digit JSON integer raises OverflowError, which is neither
                    # TypeError nor ValueError -- so it escaped this validator entirely and the
                    # contract's 400 became a 500 with a traceback, from an authenticated node's
                    # ordinary report.
                    value = float(out[name])
                except OverflowError:
                    bad(name, "must be a timestamp, not an arbitrarily large integer")
                if not math.isfinite(value) or value < 0:
                    bad(name, "must be a finite, non-negative timestamp")
                if name != "expires_at" and value > horizon:
                    bad(name, "must not be in the future")
                out[name] = value
        if "materialise_attempts" in out:
            v = out["materialise_attempts"]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 1_000_000:
                bad("materialise_attempts", "must be a non-negative integer")
        for name, cap in (("error", 8192), ("worker_runtime", 64), ("worker_tier", 64),
                          ("input_sha256", 64)):
            if name in out and out[name] is not None:
                if not isinstance(out[name], str) or len(out[name]) > cap:
                    bad(name, f"must be a string of at most {cap} characters or null")
        if out.get("input_sha256") is not None and (
                len(out["input_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in out["input_sha256"].lower())):
            bad("input_sha256", "must be 64 hex characters")
        if "result_summary" in out and out["result_summary"] is not None:
            v = out["result_summary"]
            if not isinstance(v, dict) or len(str(v)) > 65536:
                bad("result_summary", "must be an object of at most 64 KiB")
        if "security_warnings" in out and out["security_warnings"] is not None:
            v = out["security_warnings"]
            if (not isinstance(v, list) or len(v) > 256
                    or any(not isinstance(x, str) or len(x) > 1024 for x in v)):
                bad("security_warnings", "must be a list of at most 256 short strings")

    def _vetted_fields(fields: dict[str, Any]) -> dict[str, Any]:
        """Only what a node may write, with wire values converted to what the store expects.

        Two separate failures this closes, both found by review rather than by tests:

        * `JobStore.update` accepts ANY `Job` field, so an authenticated node could rewrite
          ``result_dir`` -- choosing where this host writes a result -- or ``engine``, or
          another node's ``claim_id``. Anything outside :data:`NODE_WRITABLE_FIELDS` is now
          refused with 400 rather than dropped, because a silently-ignored field makes a
          dispatcher believe it reported something it did not.
        * JSON has no enums, so ``{"status": "done"}`` arrives as a ``str``. Stored as-is,
          every terminal write from a node would put a string where the rest of the system
          compares against `JobStatus`, and those comparisons would quietly stop matching.
        """
        from blastbox.host.jobs.base import JobStatus

        rejected = sorted(set(fields) - NODE_WRITABLE_FIELDS)
        if rejected:
            raise HTTPException(
                status_code=400,
                detail=f"a node may not write: {', '.join(rejected)}")
        out = dict(fields)
        # TYPES, NOT JUST NAMES. The store writes whatever it is given: with SQLite,
        # started_at="not-a-time" was stored, and every later read of that job raised while
        # converting it back -- the reclaim sweep, the listing, the API, all of them. One write
        # from one node made a row unreadable to the whole fleet. Reviewed and reproduced.
        _typed(out)
        for name in _ENUM_FIELDS:
            if isinstance(out.get(name), str):
                try:
                    out[name] = JobStatus(out[name])
                except ValueError:
                    raise HTTPException(status_code=400,
                                        detail=f"unknown {name}") from None
        if "claim_id" in out and out["claim_id"] is not None:
            # Releasing a job (claim_id=None) is legitimate. Re-stamping ownership is not:
            # every fence in this module is built on the claim id, so a node that could set
            # it could hand itself a job it never claimed.
            raise HTTPException(
                status_code=400,
                detail="claim_id may only be cleared, not set")
        # AFTER the enum conversion above, not before. This compared the WIRE value -- the
        # string "queued" -- against the enum member, so it never matched and a node could
        # NEVER release a job: every release was a 400. Three independent reviewers found it,
        # and it was mine, introduced in the same change that added the release semantics.
        if out.get("status") is JobStatus.QUEUED and "claim_id" not in out:
            # THE RULE HELD IN ONE DIRECTION ONLY. Clearing claim_id required status=queued,
            # but queueing did not require clearing claim_id -- so a node could write
            # {"status": "queued", "claimable_after": now+3600} while KEEPING ownership. A
            # deferred row is invisible to `claim_next`, so no peer can take it, and the holder
            # stays authorised (its claim id and receipt still match) to renew before each hour
            # expires: indefinite burial of a job it is granted, straight through both the
            # per-write deferral ceiling and the total-burial bound this branch added.
            raise HTTPException(
                status_code=400,
                detail="a release must clear the claim: send claim_id null in the same write "
                       "as status \"queued\"")
        if "claim_id" in out and out.get("status") is not JobStatus.QUEUED:
            # Clearing the claim WITHOUT queueing left a job RUNNING with no owner: unclaimable
            # (claim_next sees only QUEUED), unwritable (_owned_job needs a claim id) and, with a
            # future started_at, unreclaimable. A release is status=queued AND claim_id=null,
            # together, and it gets the same deferral a refused job does.
            raise HTTPException(
                status_code=400,
                detail="clearing claim_id is a release: status must be \"queued\" in the "
                       "same write")
        if "started_at" in out and out["started_at"] is None and "claim_id" not in out:
            # `reclaim_stale_claims` judges a claim's age on started_at and SKIPS a row where it
            # is None, so a node could write {"started_at": null} while staying RUNNING and hold
            # the job -- and its staged sample on this host's disk -- forever. The field is
            # writable because a RELEASE clears it (dispatch.py's requeue does), and a release
            # says so: status=queued with claim_id=null, handled just above.
            raise HTTPException(
                status_code=400,
                detail="started_at may only be cleared as part of a release (status "
                       "\"queued\" with claim_id null)")
        if "claim_id" in out:
            out.setdefault("claimable_after", time.time() + _REFUSAL_DEFER_S)
            out.setdefault("started_at", None)
        if out.get("claimable_after") is not None:
            try:
                deferred = float(out["claimable_after"])
            except (TypeError, ValueError, OverflowError):
                raise HTTPException(status_code=400,
                                    detail="claimable_after must be a timestamp") from None
            if not math.isfinite(deferred):
                # NaN passes float() and fails EVERY comparison, so it slid under the ceiling
                # below and then sat in the store as a value `claim_next` would never consider
                # due -- the permanent bury, back through a different door. inf is the same
                # bury without the disguise.
                raise HTTPException(status_code=400,
                                    detail="claimable_after must be a finite timestamp")
            out["claimable_after"] = deferred        # store the normalised float, not the wire value
            ceiling = time.time() + MAX_DEFERRAL_S
            if deferred > ceiling:
                # Clamped, not refused: a legitimate deferral near the boundary should still
                # work, and the only thing worth preventing is a job vanishing for a decade.
                _log.warning("node_claim: clamped claimable_after from %.0f to %.0f",
                             deferred, ceiling)
                out["claimable_after"] = ceiling
        return out

    @router.get("/jobs/{job_id}", response_model=None)
    def get_job(job_id: str,
                x_blastbox_node_session: str | None = Header(None),
                x_blastbox_claim_id: str | None = Header(None),
                x_blastbox_receipt: str | None = Header(None)) -> dict[str, Any]:
        """Ownership proof in HEADERS. It was in the query string, which lands in every access
        and proxy log on the path -- and the receipt is the proof of ownership."""
        node_id = _node_from_token(x_blastbox_node_session)
        if not x_blastbox_claim_id or not x_blastbox_receipt:
            raise HTTPException(status_code=403, detail=_REFUSED)
        return {"job": _owned_job(job_id, node_id, x_blastbox_claim_id,
                                  x_blastbox_receipt).to_dict()}

    @router.get("/jobs/{job_id}/disposition", response_model=None)
    def disposition(job_id: str,
                    x_blastbox_node_session: str | None = Header(None)) -> dict[str, Any]:
        """Is this job finished, and who holds it? THREE FIELDS, for a job the caller names.

        WHY THIS HAD TO EXIST. A node's only disk bound is `reap_stale_scratch`, which walks its
        OWN job_root and asks the store whether each tree's job is terminal. When `get()` raised
        for everything the process had no receipt for -- which is EVERY job after a restart --
        the reaper treated all of them as "unconfirmed" and skipped them. It fails safe, and
        safe had become "never reclaim anything": job_root grew without bound with untrusted
        samples still on disk. That is issue #84's class, on the topology this branch creates.

        NOT AN ENUMERATION. The caller must already know the job id, and on the path that needs
        this it knows it because the directory is on its own disk. It gets status, claim_id and
        expires_at -- what retention decides with -- and nothing about content: no filename, no
        engine, no result_dir, no params.
        """
        node_id = _node_from_token(x_blastbox_node_session)
        if _grants_now(node_id) is None:
            # AUTHORISE, like every other route here. This was the one session-gated route that
            # never called _grants_now, so a certificate the operator had just deleted kept
            # answering for the rest of the session TTL -- and _grants_now is precisely the
            # mechanism the design leans on for "revocation takes effect inside the token's
            # lifetime". A node with no resolvable certificate gets nothing.
            raise HTTPException(status_code=403, detail=_REFUSED)
        job = job_store.get(job_id)
        if job is None:
            # Truthfully absent. The node's reaper reads this as "genuine orphan, reclaimable",
            # which is correct: the row is gone, so nobody needs the tree.
            return {"job": None}
        return {"job": {"job_id": job.job_id, "status": job.status.value,
                        "claim_id": job.claim_id, "expires_at": job.expires_at}}

    @router.post("/jobs/{job_id}", response_model=None)
    def update_job(job_id: str, req: UpdateRequest,
                   x_blastbox_node_session: str | None = Header(None)) -> dict[str, Any]:
        """Write to a job this node holds the claim for, and only that.

        ``expect_status`` routes to the store's compare-and-swap form. That is not an
        optimisation: the CAS on ``(status, claim_id)`` is what closes the ABA hole where a
        job goes RUNNING -> QUEUED -> RUNNING under another node and a stale owner's
        terminal write lands on the new run.
        """
        from blastbox.host.jobs.base import JobStatus

        node_id = _node_from_token(x_blastbox_node_session)
        current = _owned_job(job_id, node_id, req.claim_id, req.receipt)
        fields = _vetted_fields(req.fields)
        if req.expect_status is not None:
            try:
                expect = JobStatus(req.expect_status)
            except ValueError:
                raise HTTPException(status_code=400,
                                    detail="unknown status") from None
            # Returns a BOOL, not a Job, and the kwarg is expect_claim_id -- read from
            # the protocol rather than assumed, because guessing either would have made
            # every CAS write look like it had succeeded.
            applied = job_store.update_if_status(
                job_id, expect, expect_claim_id=req.claim_id, **fields)
            if not applied:
                # NOT an error: losing a CAS is the normal outcome of a race the caller is
                # expected to handle. 409 says "somebody else got there", which is what the
                # store's False means.
                raise HTTPException(status_code=409, detail="status changed")
            fresh = job_store.get(job_id)
            if fresh is None:
                raise HTTPException(status_code=409, detail="status changed")
            return {"job": fresh.to_dict()}
        # FENCED even without expect_status. `_owned_job` read the claim a moment ago, and an
        # unconditional write here would apply after a timeout sweep had already reclaimed the
        # job -- a stale owner's report landing on somebody else's run. The CAS on
        # (status, claim_id) closes that window; losing it is a 409, same as an explicit one.
        applied = job_store.update_if_status(
            job_id, current.status, expect_claim_id=req.claim_id, **fields)
        if not applied:
            raise HTTPException(status_code=409, detail="status changed")
        fresh = job_store.get(job_id)
        if fresh is None:
            raise HTTPException(status_code=409, detail="status changed")
        return {"job": fresh.to_dict()}

    app.include_router(router)
    _log.info("node_claim: enforcing node grants at the hand-over (pki=%s)", resolved)
    from blastbox.host.ingress.node_reclaim import RECLAIM_AFTER_ENV, reclaim_after_s

    if not reclaim_after_s():
        # A node that claims through these routes cannot run the dispatcher's own orphan sweep
        # (its store refuses to enumerate). Without the control-plane sweep, every claim lost to a
        # restart or a dropped response stays RUNNING forever. That is a deployment that will
        # quietly fill with stuck jobs, so it is said at startup, where it can be acted on.
        _log.warning("node_claim: %s is not set. Nodes claiming through this control plane have "
                     "NO reclaim path for lost claims -- a restart mid-job leaves the job RUNNING "
                     "forever. Set it (seconds; floored at 900) to the longest run a node may take.",
                     RECLAIM_AFTER_ENV)
    return True
