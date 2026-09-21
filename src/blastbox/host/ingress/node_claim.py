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

BEARER AUTH APPLIES WHEN ``BLASTBOX_API_KEY`` IS SET. These routes are not in
``BearerAuthMiddleware._ALWAYS_PUBLIC``, so an API-keyed deployment requires nodes to
present the API key as well as their certificate. That is deliberate belt-and-braces, but
note what it means operationally: the API key is the SUBMITTER's credential, so handing it
to every node also lets every node submit jobs. Either accept that, or run nodes against a
listener without an API key and let the certificate be the only authentication -- which is
what it is designed to be.

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
_REFUSAL_DEFER_S = 20.0

#: Prefix the control plane re-stamps onto the claim id of every job it hands to a node. It
#: exists so the control-plane reclaim sweep can tell ITS claims from a DB-backed dispatcher's:
#: on a mixed fleet the sweep otherwise failed healthy jobs those dispatchers were still running
#: -- their cold jobs have NO time bound by design (docker-ps liveness), and the sweep's own floor
#: sat below their warm cutoff -- and discarded the finished result when the owner's DONE write
#: then lost its CAS. Reviewed and reproduced. claim_id is opaque everywhere (one log line
#: slices it for display), so a prefix is safe; the node receives the re-stamped id and the
#: receipt is minted over it, so every later fence still matches.
NODE_CLAIM_PREFIX = "node:"

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
        try:
            for _ in range(_MAX_CLAIM_PROBES):
                candidate = job_store.claim_next(engine=frozenset(allowed))
                if candidate is None:
                    break
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
                    # RE-STAMP the claim so the reclaim sweep can tell this hand-over from a
                    # DB-backed dispatcher's own claim (see NODE_CLAIM_PREFIX). CAS-fenced on
                    # the id claim_next gave us; losing it means a sweep took the job between
                    # the two writes, and then it is simply not ours to hand over.
                    stamped = NODE_CLAIM_PREFIX + (candidate.claim_id or "")
                    if job_store.update_if_status(candidate.job_id, JobStatus.RUNNING,
                                                  expect_claim_id=candidate.claim_id,
                                                  claim_id=stamped):
                        job = job_store.get(candidate.job_id)
                        if job is None or job.claim_id != stamped:
                            job = None
                            continue
                        break
                    continue
                skipped.append(candidate)
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
        engine_default = (os.environ.get(
            f"BLASTBOX_ENGINE_{job.engine.upper().replace('-', '_')}_NETPOLICY")
            or "none").strip() or "none"
        # CAN THIS HOST RESOLVE WHAT THIS JOB NEEDS? Precisely, not by counting entries.
        #
        # * engine_default "none" and no per-job override -> the job genuinely IS ungoverned,
        #   which is the ordinary all-none deployment. Nothing to look up, nothing unknown.
        # * engine_default names a personality this host HAS -> resolvable.
        # * engine_default names one this host has NOT got -> `resolve_net_policy` silently
        #   falls back to "none", and THAT is the silent hole: an operator declared a policy
        #   this host cannot see, so the tier and credentials grants would go unchecked while
        #   looking exactly like an ungoverned job. Unknown, and it must not read as permissive.
        allow_override = (os.environ.get("BLASTBOX_ALLOW_NETPOLICY_OVERRIDE", "").strip()
                          .lower() in ("1", "true", "yes", "on"))
        can_tell = engine_default == "none" or engine_default in registry
        if allow_override and job.net_policy and job.net_policy not in registry:
            # The job SELECTS a personality this host has not got. `resolve_net_policy` falls
            # through to the engine default -- possibly "none" -- so it would look ungoverned
            # here while a node whose registry DOES hold that name resolves it to a real exit
            # driver and runs it with no tier or credentials check. An explicitly selected but
            # undeclared override is unknown, and in strict mode refused, exactly like an
            # undeclared engine default.
            can_tell = False
        try:
            personality = resolve_net_policy(
                job_net_policy=job.net_policy, engine_default=engine_default,
                registry=registry, allow_override=allow_override)
            driver = getattr(personality, "exit_driver", "") or ""
        except Exception:               # noqa: BLE001
            return None, False, False
        if not driver or driver in UNGOVERNED_TIERS:
            # Genuinely ungoverned IF this host could have told. If it could not, the answer
            # is "unknown", and the caller must not read it as "unrestricted".
            return None, False, can_tell
        return driver, driver in ALWAYS_CREDENTIALED, True

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
                                       # Deferred, not merely requeued: see _REFUSAL_DEFER_S.
                                       claimable_after=time.time() + _REFUSAL_DEFER_S)
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

        if "status" in out and not isinstance(out["status"], (str, JobStatus)):
            # JSON also carries ints, bools, lists. `{"status": 7}` was written straight
            # through and stored; from then on `get()` and the unfiltered `list()` raised
            # "'7' is not a valid JobStatus" FOREVER -- GET /v1/jobs, and the retention sweep
            # this branch added to ingress, both dead fleet-wide at WARNING. Reproduced.
            bad("status", "must be a status name")
        horizon = time.time() + MAX_FUTURE_SKEW_S
        for name in ("started_at", "finished_at", "expires_at"):
            if name in out and out[name] is not None:
                if isinstance(out[name], bool) or not isinstance(out[name], (int, float)):
                    bad(name, "must be a numeric timestamp or null")
                if not math.isfinite(float(out[name])) or float(out[name]) < 0:
                    bad(name, "must be a finite, non-negative timestamp")
                if name != "expires_at" and float(out[name]) > horizon:
                    bad(name, "must not be in the future")
                out[name] = float(out[name])
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
        if "claim_id" in out and out.get("status") is not JobStatus.QUEUED:
            # Clearing the claim WITHOUT queueing left a job RUNNING with no owner: unclaimable
            # (claim_next sees only QUEUED), unwritable (_owned_job needs a claim id) and, with a
            # future started_at, unreclaimable. A release is status=queued AND claim_id=null,
            # together, and it gets the same deferral a refused job does.
            raise HTTPException(
                status_code=400,
                detail="clearing claim_id is a release: status must be \"queued\" in the "
                       "same write")
        if "claim_id" in out:
            out.setdefault("claimable_after", time.time() + _REFUSAL_DEFER_S)
            out.setdefault("started_at", None)
        if out.get("claimable_after") is not None:
            try:
                deferred = float(out["claimable_after"])
            except (TypeError, ValueError):
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
        _node_from_token(x_blastbox_node_session)
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
                     "forever. Set it (seconds; >= 300) to the longest run a node may take.",
                     RECLAIM_AFTER_ENV)
    return True
