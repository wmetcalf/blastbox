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

WHAT A LOST CLAIM COSTS, AND WHY IT IS BOUNDED. The claim receipt (see
`node_auth.claim_receipt`) is PROCESS-LOCAL by design -- it is the proof this server handed
this job to this node, and the server keeps no table of that. Three situations end with a
job claimed and no local receipt, and they are ALL the same situation:

* the node restarts mid-job;
* the claim response is lost in flight, so the job is RUNNING and this process never learned
  its id -- a later claim then takes a DIFFERENT job while the first sits orphaned;
* the process is killed between claiming and recording.

None of them is recoverable here, and none should be. In every case the worker that was
running the job is gone too, so "recovering" the claim would mean reporting on work nobody
did. The existing reclaim-on-timeout path is exactly what picks these up, and it is the same
path a crashed dispatcher has always relied on -- the bound on the damage is that timeout,
not this module. Making the claim idempotent instead would need a server-side table of which
node holds what, which is the stateful design the session and receipt were built to avoid.
Nothing here tries to be cleverer than the reclaim path.
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

#: How many claims to remember. Bounds the map while keeping a settled job readable long
#: enough for dispatch's terminal `finally` to read it back three times. A dispatcher does not
#: have hundreds of jobs in flight; this is headroom, not a working set.
_MAX_TRACKED_CLAIMS = 512

#: Renew a session this long before it actually expires, so a request never races the
#: expiry it was authorised under. A clock skew between node and control plane inside this
#: margin costs one extra handshake; outside it, a 403 triggers a renew-and-retry anyway.
_RENEW_MARGIN_S = 30.0


class ClaimNotHeld(RuntimeError):
    """This node cannot speak for this job -- it never held the claim, or has lost it.

    RAISED, NEVER RETURNED AS None, and that distinction destroyed data before it was fixed.
    In every other store `get() -> None` means THE ROW DOES NOT EXIST, and `dispatch` relies
    on exactly that: ``_delete_input_if_owned`` and ``_purge_job_dir_if_owned`` both treat
    None as "nobody needs these bytes" and delete. Returning None for "not mine" made those
    gates delete a PEER's staged malware sample and its whole job tree mid-detonation --
    reproduced, not theorised.

    Dispatch already has the correct path for this: both gates catch exceptions and leave the
    bytes alone, because "if we cannot PROVE we still own the tree we leave it alone. A leaked
    dir is recoverable; a job whose input vanished under it is not." So this raises into that
    contract rather than inventing a new one, and a genuinely-deleted job leaks a directory
    instead of destroying a live one. That is the safe direction of the same trade.
    """


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
        env_only: bool = True,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout_s
        # env_only=False means a caller passed an explicit mapping: do NOT reach for
        # os.environ for the pieces it omitted. Pairing an injected certificate with the
        # ambient key produced a signature that could not verify, and the server's
        # deliberately-opaque 403 made it look like the node was simply ungranted.
        cert = cert_path or (os.environ.get("BLASTBOX_NODE_CERT", "") if env_only else "")
        if not cert:
            raise ValueError(
                "a control-plane JobStore needs this node's identity: set "
                "BLASTBOX_NODE_CERT to the node-*.crt issued by `blastbox pki issue-node`")
        self._cert_path = Path(cert)
        # The key is the sibling of the cert, which is how `IssuedCert.write` puts it there.
        # Overridable because an operator may have split them across mounts.
        self._key_path = Path(
            key_path or (os.environ.get("BLASTBOX_NODE_KEY", "") if env_only else "")
            or self._cert_path.with_suffix(".key"))
        self._ca_path = Path(
            ca_path or (os.environ.get("BLASTBOX_NODE_CA", "") if env_only else "")
            or (Path(os.environ.get("BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki")
                     if env_only else self._cert_path.parent) / "ca.crt"))
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
        #: job ids whose terminal write has gone through: evictable before live ones.
        self._settled: set[str] = set()
        self._tier_hint_noted = False

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
        """One retry, and only when the SESSION is the problem.

        RETRY ON 401, NOT 403. The first version retried on 403, which conflates "your session
        is no good" with "you may not have this" -- so a node that was simply not granted
        something discarded a valid session and paid a full challenge+session handshake on
        EVERY refused request. Measured at 22 requests where 5 were correct: the amplification
        the retry was written to prevent. The control plane now answers 401 for a session
        problem and 403 for an authorisation one, so this retries exactly the recoverable case.
        """
        headers = dict(kw.pop("headers", {}) or {})
        headers.update(self._auth())
        status, body = self._transport(method, path, headers=headers, **kw)
        if status != 401:
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
            # claimant_tier is NOT SENT, and NOT an error either. `Dispatcher` passes it on
            # EVERY claim -- its default is the non-empty string "cold" -- so raising here (as the
            # previous version did) broke every credential-less dispatcher before its first
            # claim. Reviewed and reproduced. What the hint means is "only give me jobs pinned to
            # my runtime tier"; the control plane cannot authorise a runtime tier (it is not in
            # the certificate), so it passes NO tier to claim_next and the store skips every
            # target_tier-pinned job on its own. Unpinned work flows; pinned work stays with
            # dispatchers that hold the queue. Said once, at INFO, so an operator who expected
            # pinned routing over this path learns why it does not happen.
            if claimant_tier and not self._tier_hint_noted:
                self._tier_hint_noted = True
                _log.info("http_store: claimant_tier=%r is not sent to the control plane -- a "
                          "node's runtime tier is not in its certificate, so target_tier-pinned "
                          "jobs are never handed over this path; unpinned work is unaffected",
                          claimant_tier)
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
            self._record_claim(job.job_id, job.claim_id, receipt)
            return job
        return None

    def _record_claim(self, job_id: str, claim_id: str, receipt: str) -> None:
        """Take ownership of a job, UNDER THE LOCK.

        The lock is not about the two statements agreeing with each other. `_evict_locked`
        SCANS `_claims` for a victim, and this insert used to run outside the lock -- so a
        dispatcher's claiming thread could change the dict's size while a reporting thread was
        iterating it, which surfaces as "dictionary changed size during iteration" raised from
        `_evict_tracked` AFTER the terminal write already landed: the job is terminal in the
        store and `dispatch_once` unwinds past every post-write step (page-hash indexing, the
        pending-upload marker, the job-dir purge) with no CAS-fenced retry able to repair it.
        Holding the lock for two dict operations costs nothing; there is no I/O in here, and
        `_call`/`_auth` take the same lock, so nothing may hold it across a request.

        AND THE SETTLED FLAG IS DISCARDED FIRST. A job released back to QUEUED and claimed
        again -- an ordinary requeue, or a refusal deferral that expired -- was still in
        `_settled` from its previous life, so the fresh receipt of a LIVE job was the preferred
        eviction victim from the moment it was recorded. Membership describes the CLAIM, not
        the job id.
        """
        with self._lock:
            self._settled.discard(job_id)
            # POP BEFORE INSERT. Assigning an existing key keeps its ORIGINAL insertion
            # position, and `_evict_locked`'s live-entry fallback is `next(iter(self._claims))`
            # -- documented as oldest-first. So a re-claimed job's fresh, LIVE receipt stayed at
            # position 0 and was the first live entry thrown away, ahead of hundreds of older
            # claims. Position describes the claim, exactly as membership does.
            self._claims.pop(job_id, None)
            self._claims[job_id] = (claim_id, receipt)

    def get(self, job_id: str) -> "Job | None":
        """The job, if this node can prove it holds it. Otherwise RAISE -- never None.

        See :class:`ClaimNotHeld` for why the distinction is load-bearing: None means "no such
        row" to every caller in this codebase, and two of them delete files on the strength of
        it.
        """
        from blastbox.host.jobs.base import Job

        held = self._claims.get(job_id)
        if held is None:
            # NO RECEIPT -- but "I cannot speak for this job" is not the same as "I know
            # nothing about it". Raising for everything made the node's ONLY disk bound
            # (`reap_stale_scratch`, which asks about each tree it finds) treat every job as
            # unconfirmed after a restart, so nothing was ever reclaimed and job_root grew
            # without bound with untrusted samples on disk. So ask the control plane for the
            # disposition: a TRUTHFUL answer, which is what the original defect lacked.
            # A real claim_id comes back, so dispatch's ownership gates still see the mismatch
            # and still leave a peer's files alone; None still means genuinely gone.
            status, body = self._call("GET", f"/v1/nodes/jobs/{job_id}/disposition")
            if status == 403:
                raise ClaimNotHeld(
                    f"the control plane will not answer for job {job_id}")
            if status != 200 or body is None:
                raise RuntimeError(f"control plane disposition failed (HTTP {status})")
            row = body.get("job")
            if row is None:
                return None
            return _job_from_dict(
                {"job_id": row["job_id"], "engine": "", "filename": "",
                 "status": row["status"], "created_at": 0.0,
                 "claim_id": row.get("claim_id"), "expires_at": row.get("expires_at")}, Job)
        claim_id, receipt = held
        # HEADERS, not query parameters: a query string lands in every access log and proxy
        # log on the path, and the receipt is the proof of ownership.
        status, body = self._call("GET", f"/v1/nodes/jobs/{job_id}",
                                 headers={"x-blastbox-claim-id": claim_id,
                                          "x-blastbox-receipt": receipt})
        if status == 403:
            raise ClaimNotHeld(
                f"the control plane will not confirm this node's claim on {job_id}; it was "
                "most likely reclaimed. Leaving its files to whoever owns them now.")
        if status != 200 or not body:
            raise RuntimeError(f"control plane get failed (HTTP {status})")
        return _job_from_dict(body["job"], Job)

    def update(self, job_id: str, **fields) -> "Job":
        from blastbox.host.jobs.base import Job

        generation = self._claims.get(job_id)
        status, body = self._write(job_id, fields, expect_status=None)
        if status != 200 or not body:
            raise RuntimeError(f"control plane update failed (HTTP {status})")
        job = _job_from_dict(body["job"], Job)
        from blastbox.host.jobs.base import JobStatus

        if job.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED,
                          JobStatus.QUEUED):
            self._mark_settled(job_id, generation)
        self._evict_tracked()
        return job

    def _mark_settled(self, job_id: str, generation: "tuple[str, str] | None") -> None:
        """Record that THIS claim is settled -- under the lock, and only if it is still current.

        `_settled` membership decides which receipts eviction throws away first, so a marker
        that lands on the WRONG claim is a live job orphaned by bookkeeping. Keying on the job
        id alone (and adding outside the lock) made that reachable with two ordinary dispatcher
        threads: A releases job J to QUEUED while B immediately reclaims it, and if A's marker
        lands after B's `_record_claim` it settles B's brand-new live receipt. Eviction then
        discards it first and B's terminal write is refused as "no claim receipt".

        `generation` is the (claim_id, receipt) the caller's write actually used; a marker for a
        superseded generation is dropped.
        """
        with self._lock:
            if generation is not None and self._claims.get(job_id) != generation:
                return
            self._settled.add(job_id)

    def _evict_tracked(self) -> None:
        """Bound the claim map WITHOUT breaking the read-back that follows a terminal write.

        The first version popped the entry the moment a terminal status was written. That is
        wrong: dispatch reads the job back from its terminal `finally` three times -- for the
        outcome metric and for both ownership gates -- so popping immediately made every
        completed job unreadable by the process that had just completed it. The metric would
        have recorded `outcome="failed"` for every successful job on a federated node.

        So entries are EVICTED BY AGE, oldest first, once the map exceeds a bound. A settled
        job stays readable for as long as anything plausibly looks at it, and the map cannot
        grow for the life of the process. Python dicts preserve insertion order, which is the
        eviction order wanted here.
        """
        # UNDER THE LOCK. A dispatcher claims and reports from several threads, and this scans
        # _claims for a victim -- "dictionary changed size during iteration" would surface as a
        # RuntimeError inside a terminal write, losing the job's result. The lock is the one
        # already guarding the session, so this cannot deadlock with it.
        with self._lock:
            self._evict_locked()

    def _evict_locked(self) -> None:
        while len(self._claims) > _MAX_TRACKED_CLAIMS:
            # SETTLED FIRST. A status-blind oldest-first eviction could drop the receipt of a
            # job that is still RUNNING once enough newer claims arrived, after which its own
            # terminal write would be refused as "no claim receipt" -- a live job orphaned by
            # bookkeeping. Settled entries are only kept for the post-terminal read-back, so they
            # go first; a live entry is evicted only past the hard cap, and that is logged.
            victim = next((k for k in self._claims if k in self._settled), None)
            if victim is None:
                victim = next(iter(self._claims))
                _log.warning("http_store: evicting the receipt of a LIVE job %s (more than %d "
                             "claims tracked); its terminal write will be refused", victim,
                             _MAX_TRACKED_CLAIMS)
            self._claims.pop(victim, None)
            self._settled.discard(victim)

    def update_if_status(self, job_id: str, expect_status: "JobStatus", *,
                         expect_claim_id: str | None = None, **fields) -> bool:
        generation = self._claims.get(job_id)
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
            if (raw if isinstance(raw, JobStatus) else JobStatus(str(raw))) in (
                    JobStatus.DONE, JobStatus.FAILED, JobStatus.EXPIRED, JobStatus.QUEUED):
                self._mark_settled(job_id, generation)
        self._evict_tracked()
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
        """Refused -- a node may not enumerate the queue.

        WHAT THIS BREAKS, SAID OUT LOUD, because three consumers call it and each fails
        differently:

        * `requeue_orphaned_jobs` / `_fail_stale_queued_jobs` -- the reclaim sweep. Moved to the
          control plane (`ingress.node_reclaim`), which is where the queue lives. Nothing to do
          here.
        * `JobRetentionSweeper.expire_due` -- retention. Expiring needs to FIND candidates, and
          a node scanning the fleet's queue is the thing this store exists to prevent. So it runs
          on the CONTROL PLANE now (`ingress.app`'s maintenance thread), which is where the queue
          is -- the same reasoning that moved the stale-claim sweep. The node keeps the half it
          can do without enumerating: `reap_stale_scratch` walks its OWN job_root by age, and
          since `get()` raises rather than returning None it now fails SAFE there, retaining a
          sealed last copy instead of reclaiming it as a "genuine orphan".
        * the node sizer's backlog -- answered by :meth:`count` over a scoped route.
        """
        raise NodeStoreUnsupported(
            "a node may not enumerate the queue; it claims what it is granted. Retention and "
            "the reclaim sweep must run where the database is (the control plane runs the "
            "stale-claim sweep; see BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S)")

    def count(self, status: "JobStatus | None" = None, *, q: str | None = None,
              engine: "str | Any | None" = None, claimant_tier: str | None = None,
              untargeted_only: bool = False) -> int:
        """QUEUED work waiting for the engines this node is granted, over the backlog route.

        A COUNT IS NOT AN ENUMERATION -- one integer, scoped server-side to engines this
        certificate already grants -- which is why this is answerable while `list` is not.

        THE NARROW CONTRACT IS DELIBERATE, and each unsupported argument is handled the way its
        consequence deserves -- the earlier version of this paragraph said all three "raise",
        which two of them do not:

        * `q` (a filename search) and any status but QUEUED RAISE. Both would need the server to
          search the fleet's queue, which is the thing a node may not do, and a number computed
          from a DIFFERENT question than the caller asked is worse than a refusal -- a sizer
          acting on a silently-wrong backlog has no symptom.
        * `claimant_tier` is DROPPED with one INFO line: the sizer passes it on every call, so
          raising starved every credential-less node, and the control plane cannot authorise a
          runtime tier anyway (it is not in the certificate).
        * `untargeted_only` is IGNORED because the count is ALWAYS of untargeted work -- see the
          request below. A pinned job is never handed over this path, so counting one would be
          reporting demand this node cannot drain.

        And the reason this route had to exist rather than leaving `count` refused:
        `DispatcherSizer` catches any store error and falls back to a last-known backlog that
        starts at 0 and never advances, so a permanent refusal was indistinguishable from an
        empty queue -- floors everywhere, silently. Raising was necessary and not sufficient.
        """
        from blastbox.host.jobs.base import JobStatus

        if status is not None and status is not JobStatus.QUEUED:
            raise NodeStoreUnsupported(
                f"a node may only count QUEUED work, not {status}: counting other states means "
                "reading the fleet's queue, which is what it may not do")
        if q is not None:
            raise NodeStoreUnsupported(
                "a node's backlog count cannot filter by filename: that is a search over the "
                "fleet's queue, and a number computed from a different question than you asked "
                "is worse than a refusal -- a sizer acting on a silently-wrong backlog has no "
                "symptom")
        # claimant_tier is DROPPED, not refused. The sizer passes it on every call
        # (cli.py builds local_backlog_fn(store, served, claimant_tier=tier)), so refusing it
        # starved every credential-less node's sizer -- and my test passed only because it
        # called local_backlog_fn WITHOUT the arguments the real caller uses. The control plane
        # cannot authorise a runtime tier, so the count is of unpinned work for the granted
        # engines, which is exactly what this node can claim. untargeted_only=True narrows to
        # unpinned work explicitly and is passed through: it is a SUBSET, never a widening.
        if claimant_tier and not self._tier_hint_noted:
            self._tier_hint_noted = True
            _log.info("http_store: claimant_tier=%r is not sent to the control plane for the "
                      "backlog count either; the count is of unpinned work for granted engines",
                      claimant_tier)
        # ALWAYS untargeted, not only when the caller asks. `claim_next` over this path sends
        # no tier, so the control plane never hands over a `target_tier`-pinned job -- and
        # `DispatcherSizer` takes TWO backlog callables, of which only `untargeted_backlog_fn`
        # passes the flag. The other one therefore counted pinned work this node can never be
        # given, and sized a pool for a queue it could not drain. The comment above already
        # claimed this property; now the request carries it.
        params: list[tuple[str, str]] = [("engine", name) for name in _as_engine_list(engine)]
        params.append(("untargeted_only", "1"))
        status_code, body = self._call("GET", "/v1/nodes/backlog",
                                       params=params or None)
        if status_code != 200 or not body:
            raise RuntimeError(f"control plane backlog failed (HTTP {status_code})")
        return int(body["queued"])


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
