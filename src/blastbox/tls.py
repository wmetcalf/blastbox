"""SSL context builders shared by the worker agent (server side) and the host transport (client side).

Stdlib ``ssl`` only -- **no ``cryptography``** -- so the lightweight worker can build a TLS/mTLS context
from cert *files* without pulling the host's CA-issuance code. Cert *generation* lives in
``blastbox.host.pki`` (dispatcher/host only).
"""

from __future__ import annotations

import ssl


def server_ssl_context(cert_file: str, key_file: str, *, client_ca_file: str | None = None) -> ssl.SSLContext:
    """Server context for the agent. With ``client_ca_file`` it **requires** a client cert signed by
    that CA (mTLS) -- the cryptographic 'allowed caller' gate: only the dispatcher's cert gets in."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    if client_ca_file:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(client_ca_file)
    return ctx


def client_ssl_context(
    ca_file: str,
    *,
    cert_file: str | None = None,
    key_file: str | None = None,
    verify_hostname: bool = True,
) -> ssl.SSLContext:
    """Client context for the transport: verify the worker's server cert against ``ca_file`` and (for
    mTLS) present the dispatcher's client cert.

    ``verify_hostname=False`` keeps full CA-chain verification (``verify_mode`` stays
    ``CERT_REQUIRED``) but drops the SAN/hostname match, so any cert **signed by ``ca_file``** is
    trusted regardless of which address answered. This is the correct identity model for a pool of
    interchangeable, dynamically-addressed workers (e.g. disposable EC2, where each slot gets a fresh
    IP a baked server cert can't name): identity is "issued by our private CA", not "is this exact
    IP". It is safe **only because ``ca_file`` is a private CA that signs nothing but our own
    workers** -- against a public CA it would trust any valid cert. An untrusted / self-signed /
    wrong-CA server cert is still rejected either way (chain verification is unchanged).
    """
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    if not verify_hostname:
        ctx.check_hostname = False   # CA-chain trust only; verify_mode stays CERT_REQUIRED
    if cert_file and key_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx
