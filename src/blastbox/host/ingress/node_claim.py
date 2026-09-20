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

What this DOES do is make a credential-less node possible: a node given only a certificate
and this endpoint, and NO store credentials, cannot claim work it is not granted, because
the only path it has is this one. Getting there needs the control plane to front the
result/update path too, so that a node never needs the store at all. That is the remaining
half of #178 and it is a topology change, not a patch.

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

from fastapi import APIRouter, HTTPException, Response
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


class ClaimRequest(BaseModel):
    """A node asking for work it is entitled to."""

    cert_pem: str = Field(..., max_length=16384,
                          description="the node's certificate, PEM")
    challenge: str = Field(..., max_length=512)
    signature: str = Field(..., max_length=1024, description="base64 ECDSA over the payload")
    engine: str = Field(..., max_length=64)
    tier: str | None = Field(None, max_length=64)
    require_credentials: bool = False


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

    # response_model=None: the handler returns either a dict or a bare 204 Response, and
    # FastAPI cannot build a response model from that union (it raises at import).
    @router.post("/claim", response_model=None)
    def claim(req: ClaimRequest, response: Response) -> dict[str, Any] | Response:
        """Admit or refuse, THEN claim. Order is the whole point of this module.

        Nothing touches the queue until the caller is admitted, so a refused node does not
        move a job out of QUEUED and never learns it existed.
        """
        try:
            # validate=True is for a CLEAR LOG LINE, not a distinct security boundary:
            # mutation-checked, and relaxing it fails no test because a non-base64 blob
            # decodes to garbage that then fails the signature check anyway. Kept so the
            # operator sees "not base64" instead of "does not prove possession", which
            # points at the wrong thing entirely when a client is mis-encoding.
            signature = base64.b64decode(req.signature, validate=True)
        except (binascii.Error, ValueError):
            _log.warning("node_claim: refused, signature is not base64")
            raise HTTPException(status_code=403, detail=_REFUSED) from None
        try:
            ident = node_auth.admit(
                _anchor(), req.cert_pem.encode(),
                challenge=req.challenge,
                scope=node_auth.SCOPE_CLAIM_NEXT,
                signature=signature,
                secret=node_auth.challenge_secret(resolved),
                engine=req.engine,
                tier=req.tier,
                require_credentials=req.require_credentials,
            )
        except node_auth.ClaimRefused as exc:
            # The reason is logged, never returned. See _REFUSED.
            _log.warning("node_claim: refused engine=%s tier=%s: %s",
                         req.engine, req.tier, exc)
            raise HTTPException(status_code=403, detail=_REFUSED) from None

        job = job_store.claim_next(engine=req.engine)
        if job is None:
            # 204, not 404: the node is entitled to work and there is none right now.
            # A 404 here would be indistinguishable from the routes not existing, which is
            # how a node would decide to fall back to claiming directly from the store.
            response.status_code = 204
            return response
        _log.info("node_claim: handed job=%s engine=%s to node=%s",
                  job.job_id, job.engine, ident.node_id)
        return {"job": job.to_dict(), "node_id": ident.node_id}

    app.include_router(router)
    _log.info("node_claim: enforcing node grants at the hand-over (pki=%s)", resolved)
    return True
