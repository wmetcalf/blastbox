"""Authenticate a NODE at the hand-over point, before it receives a job's input (#178).

WHY THIS EXISTS. ``placement.fleet_grants`` answers "what is node X permitted"; it does
not answer "is this caller node X". In a pull model the node claims work from the store
and then enforces its own grants, so a node that publishes under another node's id
inherits its grants, and by the time anything disagrees the input has already been
fetched. This module is the other half: the decision happens on the READER's side of the
hand-over, and a refused claim never sees the bytes.

WHY NOT mTLS, since the fleet already has a CA. Because ``issue_node`` stamps a CRITICAL
private EKU (:data:`~blastbox.host.pki.OID_NODE_AUTH`) and deliberately never
``clientAuth`` -- ``tls.py`` verifies the CA chain only, with no EKU or CN check, so a
node cert carrying ``clientAuth`` would be accepted by every worker AS THE DISPATCHER'S
client cert. That is privilege escalation on a federated fleet, and it is why OpenSSL
rejects a node cert presented in a TLS handshake outright::

    ssl.SSLError: [SSL: SSLV3_ALERT_UNSUPPORTED_CERTIFICATE] sslv3 alert unsupported certificate

Adding ``clientAuth`` to node certs to make mTLS work would open a hole strictly worse
than the one this closes. Measured, not assumed: uvicorn (0.48.0) also exposes no peer
certificate to an ASGI application -- its scope carries no transport and it implements no
ASGI TLS extension -- so a route could not read one even if the handshake succeeded.

So possession is proved ONE LAYER UP: server-authenticated TLS for the channel, and an
ECDSA challenge-response over the node key the node already holds. The EKU is checked
here, which is precisely what ``OID_NODE_AUTH``'s own comment says the control plane
should do when it learns to authenticate nodes.

WHAT THIS DOES NOT DO. Possession of the key IS the identity, so whoever holds a node's
certificate AND its private key is that node. That is inherent to key-based identity and
is bounded by enrolment and the 7-day default certificate lifetime, not by this module.
``SelfGrants``'s stated limit also still applies: expiry is measured on a host clock.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:                       # pragma: no cover - typing only
    from blastbox.host.pki import NodeIdentity, TrustAnchor

#: How long a challenge is valid. Short: it exists to make a captured signature useless,
#: and every legitimate claim redeems one within a round trip of minting it.
CHALLENGE_TTL_S = 60.0

#: Domain separation. A signature produced for this protocol must not be replayable as a
#: signature for any other thing this fleet's keys sign.
_SIG_DOMAIN = b"blastbox/node-claim/v1"

#: The scope a node uses to ask for whatever work its certificate entitles it to. The
#: server resolves the grants and chooses the job, so there is no job id to bind.
SCOPE_CLAIM_NEXT = "claim-next"
_MAC_DOMAIN = b"blastbox/node-challenge/v1"


#: Where the challenge-signing secret lives, inside the PKI directory the grants feature
#: already requires. Never an env var: a secret on a command line or in a unit file is
#: exactly what this project refuses elsewhere (see the SOCKS/proxy URL handling).
SECRET_FILE = "claim-challenge.key"

#: OVERRIDE for where the key lives. A PATH, never the secret itself -- a secret on a command
#: line or in a unit file is what this project refuses elsewhere.
#:
#: This is no longer how multi-host ingress is made correct; the job store is (see
#: :func:`resolve_claim_secret` and `jobs.base.ClaimKeyRegistry`). It remains for two cases: a
#: third-party store that does not implement the registry, and an operator who has a reason to
#: hold the key outside the queue. When set, it wins -- an explicit instruction outranks an
#: inferred one.
SECRET_FILE_ENV = "BLASTBOX_CLAIM_SECRET_FILE"

#: 32 bytes of HMAC key. Shorter is not rejected for being unfashionable -- it is rejected
#: because a truncated file is the observable symptom of an interrupted first write, and
#: serving challenges keyed on 4 surviving bytes is worse than refusing to serve them.
_SECRET_BYTES = 32


def challenge_secret(pki_dir: "Path | str") -> bytes:
    """The challenge-signing key, created on first use. Shared by every serving process.

    WHY A FILE AND NOT A PROCESS SECRET. Ingress runs with ``workers>1``, and uvicorn
    forks: a per-process ``token_bytes`` would mint challenges on one worker that every
    other worker rejects as forged, so roughly ``1 - 1/workers`` of all claims would fail
    and retry until they happened to land on the minting worker. That is a load-dependent
    intermittent failure, which is the worst kind to diagnose.

    WRITE COMPLETE, THEN LINK INTO PLACE. The obvious shape -- ``O_EXCL`` on the real
    path, then write -- is wrong, and the concurrency test caught it: ``O_EXCL`` publishes
    an EMPTY file immediately, so a losing process reading a moment later gets zero bytes
    and concludes the key was truncated by an interrupted write. Writing a private temp
    file first and then ``os.link``-ing it into place means the real path never exists in
    an incomplete state, and the link is the compare-and-swap: exactly one process wins,
    every loser reads the winner's complete bytes. Same reasoning as ``claim_blob_target``
    being a CAS rather than a read-then-write.

    0600, and never logged. A short read-back RAISES rather than being padded or
    regenerated: regenerating would invalidate every challenge the other workers have
    already minted, and padding would serve a key an interrupted write chose.
    """
    import secrets
    import threading

    override = os.environ.get(SECRET_FILE_ENV, "").strip()
    path = Path(override) if override else Path(pki_dir) / SECRET_FILE
    try:
        data = path.read_bytes()
        if len(data) >= _SECRET_BYTES:
            return data
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RuntimeError(f"cannot read the claim challenge key {path}: {exc}") from exc

    tmp = path.with_name(f"{SECRET_FILE}.tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(_SECRET_BYTES))
                fh.flush()
                os.fsync(fh.fileno())   # durable before it is linkable
            try:
                os.link(tmp, path)      # atomic CAS: fails if somebody already won
            except FileExistsError:
                pass                    # a peer won; its bytes are what we will read
            except OSError:
                # SOME FILESYSTEMS HAVE NO HARD LINKS (assorted FUSE and network mounts).
                # os.replace would work but is last-writer-wins, which is no CAS at all -- two
                # hosts would each keep their own key believing they agreed. So publish
                # exclusively instead and accept the narrow window the link was avoiding; the
                # read-back below is already bounded and retried, and the STORE-backed key
                # (ClaimKeyRegistry) is the supported multi-host path anyway.
                try:
                    fd2 = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    pass
                else:
                    with os.fdopen(fd2, "wb") as fh2:
                        fh2.write(tmp.read_bytes())
                        fh2.flush()
                        os.fsync(fh2.fileno())
        finally:
            try:
                os.unlink(tmp)
            except OSError:             # nothing to clean up, or already gone
                pass
    except OSError as exc:
        # Creating the key failed outright (read-only mount, no such directory). If a peer
        # has meanwhile published one, use it; otherwise this is fatal and must say why.
        if not path.exists():
            raise RuntimeError(
                f"cannot create the claim challenge key {path}: {exc}") from exc

    data = path.read_bytes()
    if len(data) < _SECRET_BYTES:
        # One bounded retry: on a filesystem without hard links the publish above is not
        # atomic, so a reader can catch a partial write. Anything still short after this is a
        # genuinely truncated key and must not be padded or regenerated.
        import time as _t

        _t.sleep(0.25)
        data = path.read_bytes()
    if len(data) < _SECRET_BYTES:
        raise RuntimeError(
            f"the claim challenge key {path} is {len(data)} bytes, not {_SECRET_BYTES} -- "
            "an interrupted first write. Delete it and restart; in-flight challenges are "
            "invalidated, which is correct, and they expire within "
            f"{CHALLENGE_TTL_S:.0f}s anyway.")
    return data


def resolve_claim_secret(job_store: object, pki_dir: "Path | str", *,
                         pepper: bytes | None = None) -> bytes:
    """The key every ingress process must agree on, resolved ONCE at route registration.

    PRECEDENCE, and why it is in this order:

    1. ``BLASTBOX_CLAIM_SECRET_FILE`` set -> that file. An operator said so; an explicit
       instruction outranks an inferred one.
    2. The job store implements `ClaimKeyRegistry` -> claim through it. This is the design: the
       documented role-separated topology rejects a shared filesystem, and the queue is the only
       thing every ingress process shares by definition. Every store this repo ships implements
       it, so a multi-host deployment now needs NOTHING configured. A node cannot read it -- it
       has no database credentials, which is the point of #178.
    3. Otherwise -> the per-host file, with a warning that a second host will not interoperate.
       Only a third-party store lands here.

    THE STORED VALUE IS NOT THE KEY WHEN A PEPPER IS GIVEN. Review made the point precisely:
    a queue is read by more than ingress -- a read-only reporting credential, a replica, every
    backup -- and a plaintext signing key there lets any of them mint a session for ANY node id
    with no certificate and no challenge. "Widens nothing" was wrong for those. So the effective
    key is HMAC(pepper, stored): the queue holds a random half, and the pepper is something every
    ingress host already shares and a queue reader does not -- `build_app` passes the API key.
    Without a pepper (no API key configured) the stored value IS the key and a warning says so:
    then it is exactly as private as the queue, which the operator has chosen.

    NONE IS NOT AGREEMENT, so it RAISES. `claim_signing_key` returns None when the registry
    could not be read back -- a clear racing the claim, an eviction. Falling back to a locally
    generated key there would make this process sign with a key no peer holds, which is exactly
    the split this exists to prevent, produced by the machinery meant to prevent it. A serving
    process that cannot read its own queue should not come up quietly.
    """
    import secrets

    from blastbox.host.jobs.base import ClaimKeyRegistry

    if os.environ.get(SECRET_FILE_ENV, "").strip():
        return challenge_secret(pki_dir)

    if isinstance(job_store, ClaimKeyRegistry):
        candidate = secrets.token_hex(_SECRET_BYTES)
        try:
            recorded = job_store.claim_signing_key(candidate)
        except Exception as exc:        # noqa: BLE001 - the queue is down; say so, do not guess
            raise RuntimeError(
                f"could not claim the node signing key from the job store: {exc}. Refusing to "
                "generate a local one -- it would be a key no other ingress holds.") from exc
        if recorded is None:
            raise RuntimeError(
                "the job store could not confirm the node signing key (a rotation may be "
                "racing this boot). Refusing to guess; retry once the store settles.")
        try:
            key = bytes.fromhex(recorded)
        except ValueError:
            key = b""
        if len(key) < _SECRET_BYTES:
            raise RuntimeError(
                "the node signing key recorded in the job store is malformed "
                f"({len(key)} bytes). Rotate it: `blastbox claim-key reset` on a stopped "
                "fleet, then restart every ingress.")
        if pepper:
            return hmac.new(pepper, key, hashlib.sha256).digest()
        logging.getLogger("blastbox.host.node_auth").warning(
            "the node signing key is held on the job queue with no pepper (no BLASTBOX_API_KEY "
            "configured), so it is exactly as private as the queue: any credential that can "
            "read the queue -- a replica, a backup, a reporting login -- can mint node "
            "sessions. Set BLASTBOX_API_KEY on every ingress, or hold the key in a file with "
            "%s.", SECRET_FILE_ENV)
        return key

    logging.getLogger("blastbox.host.node_auth").warning(
        "the job store (%s) does not implement ClaimKeyRegistry, so the node signing key is a "
        "per-host file. A second ingress host will NOT interoperate unless %s points every host "
        "at one file.", type(job_store).__name__, SECRET_FILE_ENV)
    return challenge_secret(pki_dir)


class ClaimRefused(Exception):
    """This caller may not have this job. The message is for an operator's log.

    ONE exception for every failure, deliberately: "your certificate is not signed by
    this CA", "you do not hold that key" and "you are not granted that engine" are all
    simply "no" to the caller, and distinguishing them over the wire would let a probe
    map the fleet's grants. The reason is logged server-side, where it is diagnosis.
    """


#: How long a session token is good for. SHORT, because it is the window in which a
#: revoked or expired certificate still buys access: grants are re-resolved from the
#: server's own certificate store on every request, but the token itself is only re-checked
#: against the CA when it is renewed. Ten minutes bounds that without making the
#: challenge-response handshake a per-request cost.
SESSION_TTL_S = 600.0

_SESSION_DOMAIN = b"blastbox/node-session/v1"


def issue_session(node_id: str, *, secret: bytes, now: float | None = None,
                  ttl_s: float = SESSION_TTL_S) -> str:
    """A bearer token naming an ALREADY-AUTHENTICATED node. ``<node_id>:<expiry>:<mac>``.

    WHY A TOKEN AT ALL, given the challenge-response works. Because binding a signature to
    each operation would mean a challenge round trip plus a signature per call -- three
    requests to update one job's status, on the path a dispatcher walks for every job. The
    handshake happens once per :data:`SESSION_TTL_S` instead, which is the shape every
    comparable agent protocol settles on (kubelet, Nomad, Buildkite).

    WHAT THE TOKEN DOES NOT CARRY: the grants. It names the node and nothing else, so the
    server re-resolves what that node may do FROM ITS OWN CERTIFICATE STORE on every
    request. Freezing grants into the token would make it a capability that outlives the
    certificate it came from -- revocation here is "stop renewing the certificate", and a
    token asserting last week's grants would quietly defeat it for its whole lifetime.
    This is exactly what `placement.fleet_grants` exists to answer.

    STATELESS, for the same reason the challenge is: ingress forks, and a session table in
    one worker's memory would reject tokens it issued in another.
    """
    expires_at = (time.time() if now is None else now) + ttl_s
    payload = b"\x00".join((_SESSION_DOMAIN, node_id.encode(), repr(expires_at).encode()))
    mac = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return f"{node_id}:{expires_at!r}:{mac}"


def verify_session(token: str, *, secret: bytes, now: float | None = None) -> str:
    """The node id this token names, or raise :class:`ClaimRefused`."""
    # Cut from the RIGHT. Equivalent to cutting from the left TODAY -- mutation-checked,
    # and no test distinguishes them -- because `pki._NODE_ID_RE` forbids ":" in a node id
    # and a float's repr has none either, so both parses agree on every issuable token. It
    # is written this way against the id shape loosening: the MAC is the last field and is
    # fixed-shape hex, so anchoring there stays correct if an id ever gains a separator,
    # whereas anchoring on the first ":" would silently mis-split. Not a live defence, and
    # said so rather than implying one.
    head, _, mac = token.rpartition(":")
    node_id, _, raw = head.rpartition(":")
    if not node_id or not raw or not mac:
        raise ClaimRefused("malformed session token")
    try:
        expires_at = float(raw)
    except ValueError:
        raise ClaimRefused("malformed session token") from None
    payload = b"\x00".join((_SESSION_DOMAIN, node_id.encode(), repr(expires_at).encode()))
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ClaimRefused("session token was not issued by this server")
    if (time.time() if now is None else now) > expires_at:
        raise ClaimRefused("session token has expired")
    return node_id


_RECEIPT_DOMAIN = b"blastbox/claim-receipt/v1"


def claim_receipt(job_id: str, claim_id: str, node_id: str, *, secret: bytes) -> str:
    """Proof that THIS server handed THIS job to THIS node.

    WHY A CLAIM ID IS NOT ENOUGH, and this was a real hole found by a test written only
    because a mutation showed the previous test was weak. `claim_next` stamps a per-claim
    ownership token, and checking "does the caller know the claim id" is a BEARER check: any
    node that learns another's claim id inherits its write access. Worse, it is not even a
    secret by construction -- it travels in job records and logs.

    The receipt binds all three together under the server's key. A peer cannot forge one for
    its own node id (no key), and cannot reuse the holder's receipt either, because the
    server recomputes the expected value using the node id from the CALLER'S OWN session
    token. So presenting somebody else's receipt computes a different MAC and is refused.

    Stateless, for the same reason as the session token: ingress forks, and a table of
    "which node holds which job" in one worker's memory would refuse writes another worker
    authorised. It also needs no `Job` schema change across four store backends.
    """
    payload = b"\x00".join((_RECEIPT_DOMAIN, job_id.encode(), claim_id.encode(),
                             node_id.encode()))
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def check_claim_receipt(receipt: str, job_id: str, claim_id: str, node_id: str, *,
                        secret: bytes) -> None:
    """Raise :class:`ClaimRefused` unless *receipt* was issued to *node_id* for this claim."""
    if not hmac.compare_digest(
            receipt, claim_receipt(job_id, claim_id, node_id, secret=secret)):
        raise ClaimRefused("this job was not handed to this node")


def _mac(secret: bytes, scope: str, expires_at: float) -> str:
    payload = b"\x00".join((_MAC_DOMAIN, scope.encode(), repr(expires_at).encode()))
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def challenge_for(scope: str, *, secret: bytes, now: float | None = None,
                  ttl_s: float = CHALLENGE_TTL_S) -> str:
    """Mint a challenge this server can later recognise as its own. ``<expiry>:<mac>``.

    ``scope`` is WHAT THE CHALLENGE IS FOR, and it is inside the MAC, so a challenge minted
    for one purpose cannot be redeemed for another. Two shapes are in use:
    :data:`SCOPE_CLAIM_NEXT` when the node is asking for whatever work it is entitled to
    (the server picks the job AFTER authenticating, so there is no id to bind yet), and a
    job id when a specific job is being handed over.

    STATELESS ON PURPOSE. Ingress runs with ``workers>1``, so any in-process nonce table
    would admit a claim on one worker and reject the identical retry on another. The MAC
    means no shared state is needed to prove "this server issued this, for this scope,
    and it has not expired". Single-use is not this layer's job and does not need to be: the
    claim it authorises is a compare-and-swap in the store, so a replay inside the TTL
    cannot take a job twice.
    """
    expires_at = (time.time() if now is None else now) + ttl_s
    # ":" and not ".", because a float's repr CONTAINS a dot -- partitioning on "." put
    # half the timestamp into the MAC and every single claim was refused as unrecognised.
    # repr() round-trips exactly in Python 3, so the value the MAC covers is recoverable.
    return f"{expires_at!r}:{_mac(secret, scope, expires_at)}"


def _check_challenge(challenge: str, scope: str, *, secret: bytes,
                     now: float | None = None) -> None:
    raw, _, mac = challenge.partition(":")
    if not raw or not mac:
        raise ClaimRefused("malformed challenge")
    try:
        expires_at = float(raw)
    except ValueError:
        raise ClaimRefused("malformed challenge") from None
    # compare_digest, not ==: the MAC is a secret-keyed value and a timing oracle on it
    # is a forgery oracle. Also computed over the CLAIMED scope, so a challenge minted
    # for one scope cannot be redeemed for another -- the MAC simply will not match.
    if not hmac.compare_digest(mac, _mac(secret, scope, expires_at)):
        raise ClaimRefused("challenge was not issued by this server for this scope")
    if (time.time() if now is None else now) > expires_at:
        raise ClaimRefused("challenge has expired")


def signing_payload(challenge: str, scope: str, node_id: str) -> bytes:
    """Exactly what a node signs.

    All three are inside the signature. The challenge makes a captured signature useless
    after the TTL; the scope stops one admitted claim being a reusable ticket for a
    different purpose; the node id is rebuilt from the VERIFIED certificate on the server
    side, so a caller cannot sign as somebody else -- there is no request-supplied identity
    for the certificate to disagree with.
    """
    return b"\x00".join((_SIG_DOMAIN, challenge.encode(), scope.encode(),
                         node_id.encode()))


def sign_claim(key_pem: bytes, challenge: str, scope: str, node_id: str) -> bytes:
    """Sign a claim with this node's own certificate key. Runs on the claiming node."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        # Not pedantry for mypy's benefit: this fleet's CA issues P-256 only, so anything
        # else here is the wrong key file -- a CA key, a WireGuard key, an RSA host key --
        # and saying so beats an AttributeError from deep inside `cryptography`.
        raise TypeError(
            f"node key is {type(key).__name__}, not an elliptic-curve key; "
            "this should be the .key written beside the node's .crt")
    return key.sign(signing_payload(challenge, scope, node_id),
                    ec.ECDSA(hashes.SHA256()))


def admit_identity(
    anchor: "TrustAnchor",
    cert_pem: bytes,
    *,
    challenge: str,
    scope: str,
    signature: bytes,
    secret: bytes,
    now: float | None = None,
) -> "NodeIdentity":
    """WHO this caller is, proved. Says nothing about what it may do.

    Split out from :func:`admit` because identity and authorisation are checked at
    different times in the control-plane flow: identity once per session, authorisation on
    every request from the server's own certificate store. Deliberately ONE implementation
    of the identity half rather than two -- `SelfGrants` records what this codebase paid
    for having two copies of "may I run this".
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from blastbox.host.pki import node_identity

    _check_challenge(challenge, scope, secret=secret, now=now)

    # NO SECOND EKU CHECK HERE. `node_identity` already requires OID_NODE_AUTH
    # (pki.py, "it is a transport cert, not a node identity"), so the dispatcher's client
    # cert and any other CA-signed non-node cert are refused by the call below. A copy of
    # that check was written here first and mutation testing showed it dead: deleting it
    # failed nothing, because nothing can reach it.
    try:
        ident = node_identity(anchor, cert_pem)
    except Exception as exc:            # noqa: BLE001 - any verify problem is a refusal
        raise ClaimRefused(f"certificate does not verify: {exc}") from None

    public_key = x509.load_pem_x509_certificate(cert_pem).public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        # REFUSED, not crashed. The CA issues P-256 only, so a node cert with any other
        # key type did not come from `issue_node`; verifying it would mean guessing which
        # signature scheme the caller meant, and a scheme the CALLER chooses is not a
        # check. Fail closed on the unexpected shape.
        raise ClaimRefused("certificate does not carry an elliptic-curve key")
    try:
        # POSSESSION. The payload is rebuilt from the verified identity, so a signature can
        # only verify for the node the certificate actually names.
        public_key.verify(signature, signing_payload(challenge, scope, ident.node_id),
                          ec.ECDSA(hashes.SHA256()))
    except Exception:                   # noqa: BLE001 - InvalidSignature, or a bad blob
        raise ClaimRefused(
            "does not prove possession of this certificate's key") from None
    return ident


def admit(
    anchor: "TrustAnchor",
    cert_pem: bytes,
    *,
    challenge: str,
    scope: str,
    signature: bytes,
    secret: bytes,
    engine: str,
    tier: str | None = None,
    require_credentials: bool = False,
    now: float | None = None,
) -> "NodeIdentity":
    """Identity AND authorisation in one call, for a caller that does both at once.

    The grants come from the certificate presented, which is correct for a single-shot
    hand-over. A control plane holding a certificate STORE should prefer
    :func:`admit_identity` plus `placement.fleet_grants`, so that a certificate removed or
    lapsed since issuance stops authorising immediately rather than at session expiry.
    """
    from blastbox.host.placement import refusal

    ident = admit_identity(anchor, cert_pem, challenge=challenge, scope=scope,
                           signature=signature, secret=secret, now=now)
    why = refusal(ident.grants, engine=engine, tier=tier,
                  require_credentials=require_credentials)
    if why is not None:
        raise ClaimRefused(why)
    return ident
