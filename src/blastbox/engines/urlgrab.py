"""URL-grabber engine: fetch one URL, seal the response.

The first *network* blastbox engine — the consumer of the netpolicy/egress tiers. Given an input
file containing a single URL, it does ONE bounded HTTP GET and seals the response body as an
artifact plus structured metadata (status, final URL after redirects, content-type, server,
body sha256/len). It does NOT execute or render anything — it is a *fetch*, not a browser.

Isolation + egress are the dispatcher's job: this engine runs in a disposable hardened worker
whose network is whatever the resolved netpolicy granted —
  * ``net_policy=fakenet`` → FakeNet-NG answers (safe smoke test of the whole stack),
  * ``net_policy=socks``/``vpn`` → real fetch through tor / PIA (attribution-protected),
  * ``net_policy=none`` → the fetch simply fails closed (recorded, not an error).
netd captures the worker's pcap independently and the host seals it alongside this engine's body.

A failed reach-out (DNS NXDOMAIN, connection refused, timeout) is a NORMAL result for a dead /
sinkholed malware URL → ``status="ok"`` with the error recorded, NOT ``engine_error`` (which would
fail the job). Only a malformed input URL is ``rejected``.

The actual fetch is an injected seam (``fetch_fn``) so the engine logic is unit-testable without a
network; the default uses ``urllib`` with a redirect cap and a capped read.
"""
from __future__ import annotations

import hashlib
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

_DEFAULT_MAX_REDIRECTS = 5
_DEFAULT_UA = "blastbox-urlgrab/1"
_VERIFY_TLS_ENV = "BLASTBOX_URLGRAB_VERIFY_TLS"


class FetchError(Exception):
    """The reach-out itself failed (DNS, connection, timeout) — a valid 'dead URL' outcome."""


@dataclass(frozen=True)
class FetchResult:
    final_url: str
    status: int
    content_type: str
    server: str
    body: bytes               # already capped to max_bytes by the fetcher
    truncated: bool
    redirects: int = 0
    headers: dict[str, str] = field(default_factory=dict)


def _detected(content_type: str) -> Detection:
    return Detection(
        label="urlgrab",
        mime=(content_type.split(";", 1)[0].strip() or "application/octet-stream")[:255],
        confidence=1.0,
        source="urlgrab",
    )


def _read_url(input_path: Path) -> str:
    """Take the first non-empty line of the input as the URL (the job input carries one URL)."""
    text = input_path.read_text(errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


class _CappedRedirect(urllib.request.HTTPRedirectHandler):
    max_repeats = _DEFAULT_MAX_REDIRECTS
    max_redirections = _DEFAULT_MAX_REDIRECTS


def _default_fetch(
    url: str, *, timeout: float, max_bytes: int, max_redirects: int, verify_tls: bool = True
) -> FetchResult:
    """One GET via urllib: cap redirects + body, treat a 4xx/5xx as a real response (it has a
    body), and raise :class:`FetchError` only on a transport failure (DNS/connection/timeout).

    ``verify_tls=False`` accepts ANY TLS cert (self-signed, FakeNet's MITM, expired). A grabber's
    job is to *retrieve* whatever the URL serves — the body is untrusted + sealed-as-artifact
    regardless — and most malware C2 / fakenet uses certs a public trust store would reject."""
    handlers: list[urllib.request.BaseHandler] = [_CappedRedirect()]
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_UA}, method="GET")
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:  # 4xx/5xx are responses, not transport failures
        resp = e
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
        raise FetchError(str(e)) from e
    with resp:
        raw = resp.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        body = raw[:max_bytes]
        hdrs = {k.lower(): v for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
        return FetchResult(
            final_url=getattr(resp, "url", url) or url,
            status=int(getattr(resp, "status", 0) or getattr(resp, "code", 0) or 0),
            content_type=hdrs.get("content-type", ""),
            server=hdrs.get("server", ""),
            body=body,
            truncated=truncated,
            headers=hdrs,
        )


class UrlGrabEngine:
    """Fetch one URL (from the input file) and seal the response."""

    name = "urlgrab"
    formats = frozenset({"*"})

    def __init__(self, *, fetch_fn=None, name: str | None = None, verify_tls: bool | None = None) -> None:
        self._fetch = fetch_fn or _default_fetch
        # Verify TLS certs? Default ON (safe); operators run a grabber with
        # BLASTBOX_URLGRAB_VERIFY_TLS=0 to fetch self-signed / MITM (FakeNet) / expired-cert URLs.
        if verify_tls is not None:
            self._verify_tls = verify_tls
        else:
            self._verify_tls = os.environ.get(_VERIFY_TLS_ENV, "1").strip().lower() not in (
                "0", "false", "no", "off",
            )
        # Sealed-into-envelope name; the host trust gate requires it to match the EngineSpec name.
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        url = _read_url(input)
        if not _is_valid_url(url):
            return DetonationResult(
                payload=Record(fields={"url": url[:2000], "error": "invalid_url"}),
                artifacts=[],
                detected=_detected(""),
                warnings=[Warning(code="invalid_url", message="input is not an http(s) URL")],
                status="rejected",
            )

        warnings: list[Warning] = []
        try:
            r = self._fetch(
                url,
                timeout=limits.timeout_s,
                max_bytes=limits.max_artifact_bytes,
                max_redirects=_DEFAULT_MAX_REDIRECTS,
                verify_tls=self._verify_tls,
            )
        except FetchError as exc:
            # A dead / sinkholed / blocked URL is a normal verdict, not an engine failure.
            return DetonationResult(
                payload=Record(fields={"url": url, "fetched": False, "error": str(exc)[:1000]}),
                artifacts=[],
                detected=_detected(""),
                warnings=[Warning(code="fetch_failed", message=str(exc)[:2000])],
                status="ok",
            )

        (outdir / "body.bin").write_bytes(r.body)
        if r.truncated:
            warnings.append(Warning(
                code="body_truncated",
                message=f"body capped at {limits.max_artifact_bytes} bytes",
            ))
        return DetonationResult(
            payload=Record(fields={
                "url": url,
                "fetched": True,
                "final_url": r.final_url[:2000],
                "status": r.status,
                "content_type": r.content_type[:255],
                "server": r.server[:255],
                "body_sha256": hashlib.sha256(r.body).hexdigest(),
                "body_len": len(r.body),
                "truncated": r.truncated,
                "tls_verified": self._verify_tls,
            }),
            artifacts=[DeclaredArtifact(id="body", path="body.bin", kind="raw")],
            detected=_detected(r.content_type),
            warnings=warnings,
            status="ok",
        )


if __name__ == "__main__":  # pragma: no cover
    import sys

    from blastbox.worker.harness import main

    sys.exit(main(UrlGrabEngine()))  # type: ignore[arg-type]
