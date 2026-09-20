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
    """A node asking for work it is entitled to, holding a session token."""

    engine: str = Field(..., max_length=64)
    tier: str | None = Field(None, max_length=64)
    require_credentials: bool = False


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

    def _node_from_token(authorization: str | None) -> str:
        """The node id this caller has already proved, or 403.

        The token names the node and nothing more; what it MAY DO is resolved below from
        this server's own certificate store, per request. See `node_auth.issue_session`.
        """
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "node" or not token:
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
            _log.warning("node_claim: session refused: %s", exc)
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
              authorization: str | None = Header(None)) -> dict[str, Any] | Response:
        """Admit or refuse, THEN claim. Order is the whole point of this module.

        Nothing touches the queue until the caller is admitted, so a refused node does not
        move a job out of QUEUED and never learns it existed.
        """
        from blastbox.host.placement import refusal

        node_id = _node_from_token(authorization)
        why = refusal(_grants_now(node_id), engine=req.engine, tier=req.tier,
                      require_credentials=req.require_credentials)
        if why is not None:
            _log.warning("node_claim: refused node=%s engine=%s tier=%s: %s",
                         node_id, req.engine, req.tier, why)
            raise HTTPException(status_code=403, detail=_REFUSED)

        job = job_store.claim_next(engine=req.engine)
        if job is None:
            # 204, not 404: the node is entitled to work and there is none right now.
            # A 404 here would be indistinguishable from the routes not existing, which is
            # how a node would decide to fall back to claiming directly from the store.
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

    @router.get("/jobs/{job_id}", response_model=None)
    def get_job(job_id: str, claim_id: str, receipt: str,
                authorization: str | None = Header(None)) -> dict[str, Any]:
        node_id = _node_from_token(authorization)
        return {"job": _owned_job(job_id, node_id, claim_id, receipt).to_dict()}

    @router.post("/jobs/{job_id}", response_model=None)
    def update_job(job_id: str, req: UpdateRequest,
                   authorization: str | None = Header(None)) -> dict[str, Any]:
        """Write to a job this node holds the claim for, and only that.

        ``expect_status`` routes to the store's compare-and-swap form. That is not an
        optimisation: the CAS on ``(status, claim_id)`` is what closes the ABA hole where a
        job goes RUNNING -> QUEUED -> RUNNING under another node and a stale owner's
        terminal write lands on the new run.
        """
        from blastbox.host.jobs.base import JobStatus

        node_id = _node_from_token(authorization)
        _owned_job(job_id, node_id, req.claim_id, req.receipt)
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
                job_id, expect, expect_claim_id=req.claim_id, **req.fields)
            if not applied:
                # NOT an error: losing a CAS is the normal outcome of a race the caller is
                # expected to handle. 409 says "somebody else got there", which is what the
                # store's False means.
                raise HTTPException(status_code=409, detail="status changed")
            fresh = job_store.get(job_id)
            if fresh is None:
                raise HTTPException(status_code=409, detail="status changed")
            return {"job": fresh.to_dict()}
        return {"job": job_store.update(job_id, **req.fields).to_dict()}

    app.include_router(router)
    _log.info("node_claim: enforcing node grants at the hand-over (pki=%s)", resolved)
    return True
