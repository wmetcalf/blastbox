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
    import os
    import secrets
    import threading

    path = Path(pki_dir) / SECRET_FILE
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
        raise RuntimeError(
            f"the claim challenge key {path} is {len(data)} bytes, not {_SECRET_BYTES} -- "
            "an interrupted first write. Delete it and restart; in-flight challenges are "
            "invalidated, which is correct, and they expire within "
            f"{CHALLENGE_TTL_S:.0f}s anyway.")
    return data


class ClaimRefused(Exception):
    """This caller may not have this job. The message is for an operator's log.

    ONE exception for every failure, deliberately: "your certificate is not signed by
    this CA", "you do not hold that key" and "you are not granted that engine" are all
    simply "no" to the caller, and distinguishing them over the wire would let a probe
    map the fleet's grants. The reason is logged server-side, where it is diagnosis.
    """


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
    """The whole decision, in the order that fails cheapest first. Raises or returns.

    Every step is a refusal, never a fall-through: a malformed certificate, an
    unparseable signature and an ungranted engine all end in :class:`ClaimRefused`, so
    there is no path that reaches the caller's input without having verified all of it.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from blastbox.host.pki import node_identity
    from blastbox.host.placement import refusal

    _check_challenge(challenge, scope, secret=secret, now=now)

    # CA signature, expiry, and CN/node_id agreement. This is the authorisation check.
    try:
        ident = node_identity(anchor, cert_pem)
    except Exception as exc:            # noqa: BLE001 - any verify problem is a refusal
        raise ClaimRefused(f"certificate does not verify: {exc}") from None

    # NO SECOND EKU CHECK HERE. `node_identity` already requires OID_NODE_AUTH
    # (pki.py, "it is a transport cert, not a node identity"), so the dispatcher's client
    # cert and any other CA-signed non-node cert are refused by the call above. A copy of
    # that check was written here first and mutation testing showed it dead: deleting it
    # failed nothing, because nothing can reach it. Two copies of "is this a node" is how
    # one of them ends up being the only one maintained -- `SelfGrants` has the same note
    # about two dispatch classes each holding their own "may I run this".

    # POSSESSION. The payload is rebuilt from the verified identity, so a signature can
    # only verify for the node the certificate actually names.
    public_key = x509.load_pem_x509_certificate(cert_pem).public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        # REFUSED, not crashed. The CA issues P-256 only, so a node cert with any other
        # key type did not come from `issue_node`; verifying it would mean guessing which
        # signature scheme the caller meant, and a scheme the CALLER chooses is not a
        # check. Fail closed on the unexpected shape.
        raise ClaimRefused("certificate does not carry an elliptic-curve key")
    try:
        public_key.verify(signature, signing_payload(challenge, scope, ident.node_id),
                          ec.ECDSA(hashes.SHA256()))
    except Exception:                   # noqa: BLE001 - InvalidSignature, or a bad blob
        raise ClaimRefused(
            "does not prove possession of this certificate's key") from None

    why = refusal(ident.grants, engine=engine, tier=tier,
                  require_credentials=require_credentials)
    if why is not None:
        raise ClaimRefused(why)
    return ident
