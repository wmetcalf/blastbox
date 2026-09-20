"""A JobStore that asks the control plane instead of holding database credentials (#178).

WHY THIS IS THE FIX RATHER THAN A GATE IN FRONT OF ONE. `JobStore` is a ``Protocol`` and
`dispatch` depends on nothing else, so a node configured with an ``https://`` control plane
gets no database credentials at all -- and a node with no database credentials has no path
to ``claim_next`` except the authenticated one. Every earlier attempt at this issue layered
a check on top of a path the node could still walk around; this removes the path.

    # on a federated node
    BLASTBOX_DATABASE_URL=https://control-plane.example:8443

`dispatch.py` is untouched. The thing it holds simply resolves differently.

A NODE'S SURFACE IS SMALLER THAN A DISPATCHER'S, AND THAT IS DELIBERATE. ``create``,
``delete``, ``list`` and ``count`` RAISE here. A node with database credentials can today
submit jobs and destroy other nodes' records; it has no business doing either, and the way
to ensure that is for the capability to be absent rather than merely unused. They raise
loudly rather than returning empty, because a silent no-op would make a mis-deployed
serve/retention process look healthy while doing nothing.

KNOWN RESIDUAL: NO BLOB-TARGET AGREEMENT CHECK. `canary.check_blob_target_agreement` gates
on ``isinstance(store, BlobTargetRegistry)`` and this store does not implement it, so a
credential-less dispatcher loses the check that proves it writes results where the ingress
reads them -- the protection added after a 17,626-job incident. It is NOT silent: the canary
already logs ``canary.blob_target_unverified ... agreement is NOT being checked``, naming
this class. Closing it properly means another authenticated route mirroring the
compare-and-swap, which is follow-up work; until then the warning is the operator's signal
and this paragraph is why it fires.

WHAT A RESTART COSTS. The claim receipt (see `node_auth.claim_receipt`) is PROCESS-LOCAL by
design -- it is the proof this server handed this job to this node, and the server keeps no
table of that. So a node that restarts mid-job cannot report on its in-flight claims. That
is correct rather than unfortunate: a restarted dispatcher has lost the worker that was
running the job too, and the existing reclaim-on-timeout path is exactly what should pick
those jobs up. Nothing here tries to be cleverer than that.
"""

from __future__ import annotations

import base64
import json as _json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from blastbox.host import node_auth

if TYPE_CHECKING:                       # pragma: no cover - typing only
    from blastbox.host.jobs.base import Job, JobStatus

_log = logging.getLogger("blastbox.host.jobs.http_store")

#: (status, parsed body or None)
Response = tuple[int, "dict[str, Any] | None"]
Transport = Callable[..., Response]

DEFAULT_TIMEOUT_S = 30.0

#: Renew a session this long before it actually expires, so a request never races the
#: expiry it was authorised under. A clock skew between node and control plane inside this
#: margin costs one extra handshake; outside it, a 403 triggers a renew-and-retry anyway.
_RENEW_MARGIN_S = 30.0


class NodeStoreUnsupported(NotImplementedError):
    """This operation is not something a NODE may do. Not a gap -- a boundary.

    Its own exception type so a caller can tell "the control plane does not expose this"
    from "this store is broken", and so a test can assert the boundary exists rather than
    matching on a message.
    """


class HttpJobStore:
    """A node's view of the queue: only what it is entitled to, over an authenticated link."""

    def __init__(
        self,
        base_url: str,
        *,
        cert_path: "Path | str | None" = None,
        key_path: "Path | str | None" = None,
        ca_path: "Path | str | None" = None,
        transport: Transport | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s
        cert = cert_path or os.environ.get("BLASTBOX_NODE_CERT", "")
        if not cert:
            raise ValueError(
                "a control-plane JobStore needs this node's identity: set "
                "BLASTBOX_NODE_CERT to the node-*.crt issued by `blastbox pki issue-node`")
        self._cert_path = Path(cert)
        # The key is the sibling of the cert, which is how `IssuedCert.write` puts it there.
        # Overridable because an operator may have split them across mounts.
        self._key_path = Path(
            key_path or os.environ.get("BLASTBOX_NODE_KEY", "")
            or self._cert_path.with_suffix(".key"))
        self._ca_path = Path(
            ca_path or os.environ.get("BLASTBOX_NODE_CA", "")
            or (Path(os.environ.get("BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki"))
                / "ca.crt"))
        self._transport = transport or self._urllib_transport
        # ONE lock over the session, because a dispatcher claims from several threads and
        # an unsynchronised renew would have each of them open its own session -- N
        # handshakes per expiry instead of one, and a thundering herd every 10 minutes.
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_expires_at = 0.0
        #: job_id -> (claim_id, receipt). BOTH are needed on every write: the server
        #: matches the claim id against the job's current one (so a reclaimed job refuses a
        #: stale owner) and the receipt against this node's identity. Process-local; see the
        #: module docstring on what a restart costs.
        self._claims: dict[str, tuple[str, str]] = {}

    # -- transport ---------------------------------------------------------------
    def _urllib_transport(self, method: str, path: str, *, json: dict | None = None,
                          params: dict | None = None,
                          headers: dict | None = None) -> Response:
        url = self._base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        body = None if json is None else _json.dumps(json).encode()
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("content-type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        context = None
        if url.lower().startswith("https://"):
            from blastbox.tls import client_ssl_context

            # The CA is REQUIRED for https, never the system trust store: this link
            # authenticates a control plane issued by our own private CA, and falling back
            # to public roots would trust any valid certificate on the internet for it.
            if not self._ca_path.exists():
                raise ValueError(
                    f"control-plane CA {self._ca_path} not found; copy ca.crt from the "
                    "issuing host (the PUBLIC half only) or set BLASTBOX_NODE_CA")
            context = client_ssl_context(str(self._ca_path))
        try:
            with urllib.request.urlopen(req, timeout=self._timeout,
                                        context=context) as resp:
                raw = resp.read()
                return resp.status, (_json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, (_json.loads(raw) if raw else None)
            except ValueError:
                return exc.code, None

    # -- session -----------------------------------------------------------------
    def _handshake(self) -> str:
        status, body = self._transport("GET", "/v1/nodes/challenge")
        if status != 200 or not body:
            raise RuntimeError(
                f"control plane did not issue a challenge (HTTP {status}). If this is a 404 "
                "the control plane has no PKI and is not enforcing node grants; point "
                "BLASTBOX_DATABASE_URL at the database instead.")
        challenge = body["challenge"]
        scope = body.get("scope", node_auth.SCOPE_CLAIM_NEXT)
        cert_pem = self._cert_path.read_bytes()
        # The node id comes from OUR OWN certificate, parsed and not verified -- we are not
        # authorising ourselves here, only reading which name to sign under. The control
        # plane re-derives it from the certificate we present and will not take our word.
        node_id = _node_id_from_cert(cert_pem)
        signature = node_auth.sign_claim(self._key_path.read_bytes(), challenge, scope,
                                         node_id)
        status, body = self._transport(
            "POST", "/v1/nodes/session",
            json={"cert_pem": cert_pem.decode(), "challenge": challenge,
                  "signature": base64.b64encode(signature).decode()})
        if status != 200 or not body:
            raise PermissionError(
                f"control plane refused this node's identity (HTTP {status}). Check the "
                f"certificate {self._cert_path} verifies against the control plane's CA and "
                "has not expired -- `blastbox pki node-status` says which.")
        self._token = body["token"]
        self._token_expires_at = time.time() + float(
            body.get("expires_in", node_auth.SESSION_TTL_S))
        _log.info("http_store: session opened as node=%s", body.get("node_id"))
        return self._token

    def _auth(self) -> dict[str, str]:
        from blastbox.host.ingress.node_claim import SESSION_HEADER

        with self._lock:
            if self._token is None or time.time() >= self._token_expires_at - _RENEW_MARGIN_S:
                self._handshake()
            # A DEDICATED header, not Authorization: an API-keyed control plane needs
            # `Authorization: Bearer <api key>` and rejects anything else with 401 before the
            # request reaches the node routes at all. One header cannot carry both
            # credentials, so they get one each and coexist.
            return {SESSION_HEADER: self._token or ""}

    def _call(self, method: str, path: str, **kw) -> Response:
        """One retry on 403, and exactly one.

        A 403 is ambiguous: an expired session, or grants that no longer allow this. Retry
        once with a fresh session to cover the first; do NOT loop, because the second case
        is a permanent refusal and retrying it would turn a revoked certificate into a hot
        loop against the control plane.
        """
        headers = dict(kw.pop("headers", {}) or {})
        headers.update(self._auth())
        status, body = self._transport(method, path, headers=headers, **kw)
        if status != 403:
            return status, body
        with self._lock:
            self._token = None
        headers.update(self._auth())
        return self._transport(method, path, headers=headers, **kw)

    # -- the JobStore surface a node needs ---------------------------------------
    def claim_next(self, *, claimant_tier: str | None = None,
                   engine: "str | Any | None" = None) -> "Job | None":
        """Claim work this node is granted. The control plane decides, not this process."""
        from blastbox.host.jobs.base import Job

        # engine=None is LEGITIMATE and must not raise: `dispatch.py` calls
        # claim_next(claimant_tier=...) with no engine whenever engine scoping is off, which
        # is the DEFAULT -- an earlier version raised here, so a credential-less dispatcher
        # on default configuration failed on every claim. Omitting the engine asks the
        # control plane for anything this certificate grants, which it can answer because it
        # holds the certificate store.
        engines: list[str | None] = list(_as_engine_list(engine)) or [None]
        for name in engines:
            body_out: dict[str, Any] = {}
            if name is not None:
                body_out["engine"] = name
            if claimant_tier:
                # claimant_tier is TARGET-TIER ROUTING (claim only jobs aimed at this
                # dispatcher), not a netpolicy grant. Conflating the two sent a routing hint
                # into the authorisation predicate and lost the routing entirely.
                body_out["claimant_tier"] = claimant_tier
            status, body = self._call("POST", "/v1/nodes/claim", json=body_out)
            if status == 204:
                continue                # entitled, nothing queued for this engine
            if status == 403:
                # Not an error to log loudly per claim: a node asking for an engine it is
                # not granted is a configuration mismatch, and the dispatcher will ask
                # again in a moment. Said once per engine at INFO, not per attempt.
                _log.info("http_store: not authorised for engine=%s", name)
                continue
            if status != 200 or not body:
                raise RuntimeError(f"control plane claim failed (HTTP {status})")
            job = _job_from_dict(body["job"], Job)
            receipt = body.get("receipt")
            if not receipt:
                raise RuntimeError(
                    "control plane handed over a job without a claim receipt; this node "
                    "could not then report on it. Refusing the job rather than running "
                    "work whose result cannot be delivered.")
            if not job.claim_id:
                raise RuntimeError(
                    "control plane handed over a job with no claim id; every write would "
                    "then be refused, so the job is declined rather than started")
            self._claims[job.job_id] = (job.claim_id, receipt)
            return job
        return None

    def get(self, job_id: str) -> "Job | None":
        from blastbox.host.jobs.base import Job

        held = self._claims.get(job_id)
        if held is None:
            # A node may read only what it holds. Without the claim id and receipt there is
            # nothing to ask with, and inventing them would just be a 403 from the server.
            return None
        claim_id, receipt = held
        status, body = self._call("GET", f"/v1/nodes/jobs/{job_id}",
                                 params={"claim_id": claim_id, "receipt": receipt})
        if status == 403:
            return None
        if status != 200 or not body:
            raise RuntimeError(f"control plane get failed (HTTP {status})")
        return _job_from_dict(body["job"], Job)

    def update(self, job_id: str, **fields) -> "Job":
        from blastbox.host.jobs.base import Job

        status, body = self._write(job_id, fields, expect_status=None)
        if status != 200 or not body:
            raise RuntimeError(f"control plane update failed (HTTP {status})")
        job = _job_from_dict(body["job"], Job)
        self._retire_if_settled(job_id, job)
        return job

    def _retire_if_settled(self, job_id: str, job: "Job | None") -> None:
        """Forget a job we can no longer write to, so the claim map is bounded.

        Nothing removed entries before, so a long-lived dispatcher accumulated one per job it
        had ever claimed -- small each, unbounded in total, and precisely the shape of leak
        that only shows up after weeks of uptime. A terminal status, or a release, means the
        receipt is spent.
        """
        from blastbox.host.jobs.base import JobStatus

        terminal = {JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED, JobStatus.QUEUED}
        if job is None or job.status in terminal or not job.claim_id:
            self._claims.pop(job_id, None)

    def update_if_status(self, job_id: str, expect_status: "JobStatus", *,
                         expect_claim_id: str | None = None, **fields) -> bool:
        status, _body = self._write(job_id, fields,
                                   expect_status=getattr(expect_status, "value",
                                                         str(expect_status)),
                                   claim_id=expect_claim_id)
        if status == 409:
            return False                # lost the CAS; the caller's normal branch
        if status == 403:
            return False                # no longer ours to write, which is also "did not apply"
        if status != 200:
            raise RuntimeError(f"control plane conditional update failed (HTTP {status})")
        from blastbox.host.jobs.base import JobStatus

        if isinstance(fields.get("status"), (str, JobStatus)):
            raw = fields["status"]
            settled = raw if isinstance(raw, JobStatus) else JobStatus(str(raw))
            if settled in (JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED,
                           JobStatus.QUEUED):
                self._claims.pop(job_id, None)
        return True

    @staticmethod
    def _wire_fields(fields: dict) -> dict:
        """Enums as their values. `json.dumps` cannot serialise a `JobStatus`, and `JobStatus`
        subclasses `str` so it would silently encode as the enum's REPR on some paths -- the
        control plane then rejects it as an unknown status, which reads as a server bug."""
        return {k: (v.value if hasattr(v, "value") else v) for k, v in fields.items()}

    def _write(self, job_id: str, fields: dict, *, expect_status: str | None,
               claim_id: str | None = None) -> Response:
        held = self._claims.get(job_id)
        if held is None:
            raise PermissionError(
                f"no claim receipt for job {job_id}: this process did not claim it (or was "
                "restarted since). The job will be reclaimed by the control plane's normal "
                "timeout path; see http_store's module docstring.")
        held_claim_id, receipt = held
        if claim_id is not None and claim_id != held_claim_id:
            # The caller is fencing against a claim id that is not the one we hold. That is
            # a lost race by definition -- report it as such rather than sending a write the
            # server would refuse for a different-looking reason.
            return 409, None
        payload: dict[str, Any] = {"claim_id": held_claim_id, "receipt": receipt,
                                   "fields": self._wire_fields(fields)}
        if expect_status is not None:
            payload["expect_status"] = expect_status
        return self._call("POST", f"/v1/nodes/jobs/{job_id}", json=payload)

    # -- the surface a node must NOT have ----------------------------------------
    def create(self, job: "Job") -> None:
        raise NodeStoreUnsupported(
            "a node may not submit jobs. Submission is the ingress API's job; if this "
            "process is meant to serve submissions it needs the database, not a "
            "control-plane URL, in BLASTBOX_DATABASE_URL")

    def delete(self, job_id: str) -> None:
        raise NodeStoreUnsupported(
            "a node may not delete jobs. Retention runs where the database is")

    def list(self, *args, **kw):
        raise NodeStoreUnsupported(
            "a node may not enumerate the queue; it claims what it is granted")

    def count(self, *args, **kw):
        raise NodeStoreUnsupported(
            "a node may not enumerate the queue; it claims what it is granted")


def _node_id_from_cert(cert_pem: bytes) -> str:
    """This node's own id, read from its certificate's subject.

    PARSE-ONLY, and that is safe here precisely because it authorises nothing: it selects
    which name to SIGN under. The control plane re-derives the identity from the
    certificate presented and verifies it against its own CA, so a node lying to itself
    here simply fails the signature check there.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_pem_x509_certificate(cert_pem)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn:
        raise ValueError("this node's certificate has no common name")
    return str(cn[0].value)


def _as_engine_list(engine: Any) -> list[str]:
    if engine is None:
        return []
    if isinstance(engine, str):
        return [engine]
    return sorted(str(e) for e in engine)


def _job_from_dict(d: dict, job_cls) -> "Job":
    """Rebuild a Job from the wire, ignoring fields this version does not know.

    TOLERANT ON PURPOSE, in this direction only: a control plane upgraded before its nodes
    will send fields an older node has never heard of, and refusing them would make every
    rolling upgrade an outage. Unknown fields are dropped rather than guessed.
    """
    from blastbox.host.jobs.base import JobStatus

    known = {f for f in job_cls.__dataclass_fields__}
    kw = {k: v for k, v in d.items() if k in known}
    if isinstance(kw.get("status"), str):
        kw["status"] = JobStatus(kw["status"])
    return job_cls(**kw)
