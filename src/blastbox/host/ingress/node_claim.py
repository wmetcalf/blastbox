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
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Header, HTTPException, Response
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
        description="routing hint: claim only jobs whose target_tier matches (NOT a grant)")


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
    try:
        from blastbox.host.pki import load_trust_anchor

        load_trust_anchor(d)
    except Exception:                   # noqa: BLE001 - no CA, unreadable, malformed
        return None
    return d


def register_node_claim_routes(
    app: "FastAPI", *, job_store: "JobStore", pki_dir: "Path | str | None" = None,
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
        secret = node_auth.challenge_secret(resolved)
        return {
            "challenge": node_auth.challenge_for(node_auth.SCOPE_CLAIM_NEXT,
                                                 secret=secret),
            "expires_in": node_auth.CHALLENGE_TTL_S,
            "scope": node_auth.SCOPE_CLAIM_NEXT,
        }

    def _secret() -> bytes:
        return node_auth.challenge_secret(resolved)

    def _node_from_token(token: str | None) -> str:
        """The node id this caller has already proved, or 403.

        The token names the node and nothing more; what it MAY DO is resolved below from
        this server's own certificate store, per request. See `node_auth.issue_session`.
        """
        if not token or not token.strip():
            raise HTTPException(status_code=403, detail=_REFUSED)
        try:
            return node_auth.verify_session(token.strip(), secret=_secret())
        except node_auth.ClaimRefused as exc:
            _log.warning("node_claim: session refused: %s", exc)
            raise HTTPException(status_code=403, detail=_REFUSED) from None

    def _grants_now(node_id: str):
        """What this node may do, read fresh from the certificates on THIS host.

        Never from the token, and never from anything the node published. A certificate
        that has lapsed or been removed since the token was issued resolves to absent here,
        so the node is refused within the token's lifetime rather than at its expiry.
        """
        from blastbox.host.placement import fleet_grants

        return fleet_grants(resolved).get(node_id)

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
        from blastbox.host.placement import refusal

        node_id = _node_from_token(x_blastbox_node_session)
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

        job = job_store.claim_next(claimant_tier=req.claimant_tier,
                                   engine=frozenset(allowed))
        if job is None:
            # 204, not 404: the node is entitled to work and there is none right now.
            # A 404 here would be indistinguishable from the routes not existing, which is
            # how a node would decide to fall back to claiming directly from the store.
            response.status_code = 204
            return response

        tier, needs_credentials = _job_requirements(job)
        why = refusal(grants, engine=job.engine, tier=tier,
                      require_credentials=needs_credentials)
        if why is not None:
            _release(job)
            _log.warning("node_claim: released job=%s from node=%s: %s",
                         job.job_id, node_id, why)
            raise HTTPException(status_code=403, detail=_REFUSED)

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

    def _job_requirements(job) -> "tuple[str | None, bool]":
        """(tier grant this job needs, whether running it means holding credentials).

        DERIVED HERE, never taken from the request. Resolved from the job's own network
        personality, so a node cannot dodge a check by omitting a field.

        UNGOVERNED TIERS ARE NOT A GRANT REQUIREMENT, and that is a lesson already paid for
        in `placement.UNGOVERNED_TIERS`: ``none`` is the DEFAULT personality and requiring a
        grant for it made correctly-issued nodes refuse every ordinary job. Same here -- an
        unresolvable or ungoverned personality asks for no tier grant.

        WHAT THIS CANNOT DERIVE: whether the node holds a provider secret for openvpn or
        wireguard depends on that node's own egress MODE, which is a node-local fact this
        host does not know. So credentials are required for the drivers that always imply
        them (a local socks/httpproxy sidecar) and the mode-dependent pair is left to the
        node's own `SelfGrants`. Stated rather than silently assumed.
        """
        from blastbox.host.netpolicy import parse_personalities, resolve_net_policy
        from blastbox.host.placement import ALWAYS_CREDENTIALED, UNGOVERNED_TIERS

        driver = ""
        try:
            # The registry is read from THIS host's environment, the same source the
            # dispatcher reads, so both resolve a job to the same personality. Read per call
            # rather than cached: `parse_personalities` is a dict comprehension over env, and
            # a cached authorisation input is how this codebase has been bitten repeatedly.
            personality = resolve_net_policy(
                job_net_policy=job.net_policy, engine_default="none",
                registry=parse_personalities(os.environ), allow_override=True)
            driver = getattr(personality, "exit_driver", "") or ""
        except Exception:               # noqa: BLE001 - unknown policy asks for no grant
            driver = ""
        if not driver or driver in UNGOVERNED_TIERS:
            return None, False
        return driver, driver in ALWAYS_CREDENTIALED

    def _release(job) -> None:
        """Put a wrongly-offered job back, fenced on the claim we are releasing.

        Fenced, because between the claim and here the job could already have been reclaimed
        (a slow release racing a timeout sweep); an unconditional write would then drag a
        live run back to QUEUED.
        """
        from blastbox.host.jobs.base import JobStatus

        try:
            job_store.update_if_status(job.job_id, JobStatus.RUNNING,
                                       expect_claim_id=job.claim_id,
                                       status=JobStatus.QUEUED, claim_id=None)
        except Exception:               # noqa: BLE001 - the reclaim sweep is the backstop
            _log.exception("node_claim: could not release job=%s; the reclaim path will "
                           "pick it up", job.job_id)

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
        if "claim_id" in out and out["claim_id"] is not None:
            # Releasing a job (claim_id=None) is legitimate. Re-stamping ownership is not:
            # every fence in this module is built on the claim id, so a node that could set
            # it could hand itself a job it never claimed.
            raise HTTPException(
                status_code=400,
                detail="claim_id may only be cleared, not set")
        for name in _ENUM_FIELDS:
            if isinstance(out.get(name), str):
                try:
                    out[name] = JobStatus(out[name])
                except ValueError:
                    raise HTTPException(status_code=400,
                                        detail=f"unknown {name}") from None
        return out

    @router.get("/jobs/{job_id}", response_model=None)
    def get_job(job_id: str, claim_id: str, receipt: str,
                x_blastbox_node_session: str | None = Header(None)) -> dict[str, Any]:
        node_id = _node_from_token(x_blastbox_node_session)
        return {"job": _owned_job(job_id, node_id, claim_id, receipt).to_dict()}

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
    return True
