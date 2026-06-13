"""ASGI middleware: body-size limiting and bearer-token auth."""
from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

from blastbox.observability import record_rejection


class BodySizeLimitMiddleware:
    """Reject HTTP requests whose body exceeds *max_bytes*.

    Security guarantee:
    - If ``Content-Length`` is present and exceeds the limit, 413 is returned
      *before* reading any of the body (O(1) check).
    - For chunked / no-Content-Length uploads the body is consumed via a
      streaming wrapper that raises as soon as the running total exceeds the
      limit — the body never fully reaches application code or disk.

    Both paths call ``record_rejection("body_too_large")`` so the metric is
    accurate regardless of how the upload is framed.

    For chunked uploads, Starlette's multipart parser may catch the
    ``RuntimeError`` from ``wrapped_receive`` and convert it to a 400 before
    the middleware's outer ``except`` can see it.  To handle this, the
    middleware tracks the over-limit condition in ``scope["state"]`` and
    wraps ``send`` to intercept any 4xx that the inner app emits after the
    flag is set, replacing it with a definitive 413.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self._max = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Fast path: Content-Length header present
        headers = dict(scope.get("headers", []))
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl) > self._max:
                    record_rejection("body_too_large")
                    response = PlainTextResponse(
                        f"request body exceeds {self._max} bytes", status_code=413
                    )
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = PlainTextResponse("invalid content-length", status_code=400)
                await response(scope, receive, send)
                return

        # Streaming path: count bytes as they arrive.
        # Use scope["state"] to share over-limit condition with wrapped_send.
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["body_too_large"] = False

        body_size = 0
        headers_sent = False

        async def wrapped_receive():
            nonlocal body_size
            msg = await receive()
            if msg["type"] == "http.request":
                body_size += len(msg.get("body", b""))
                if body_size > self._max:
                    scope["state"]["body_too_large"] = True
                    raise RuntimeError("request_body_too_large")
            return msg

        async def wrapped_send(msg):
            nonlocal headers_sent
            # If the body was too large, intercept any response the inner app
            # tries to send (the multipart parser may have swallowed the
            # RuntimeError and converted it to 400) and replace it with 413.
            if scope["state"]["body_too_large"]:
                if msg["type"] == "http.response.start":
                    # Emit our 413 instead and skip the inner app's response.
                    record_rejection("body_too_large")
                    err_response = PlainTextResponse(
                        f"request body exceeds {self._max} bytes", status_code=413
                    )
                    await err_response(scope, receive, send)
                    headers_sent = True
                # Swallow the inner app's body frames — we already sent ours.
                return
            if msg["type"] == "http.response.start":
                headers_sent = True
            await send(msg)

        try:
            await self.app(scope, wrapped_receive, wrapped_send)
        except RuntimeError as exc:
            if str(exc) == "request_body_too_large":
                if headers_sent:
                    # Response already started — cannot change status code.
                    return
                record_rejection("body_too_large")
                response = PlainTextResponse(
                    f"request body exceeds {self._max} bytes", status_code=413
                )
                await response(scope, receive, send)
                return
            raise


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Optional bearer-token authentication gate.

    Installed only when ``BLASTBOX_API_KEY`` is set.  Compares tokens
    via ``hmac.compare_digest`` to prevent timing-oracle attacks.

    ``/v1/healthz`` and ``/v1/version`` are always public (proxy health checks
    must not require auth).  ``GET /metrics`` is public by *default* so a Prometheus
    scraper on the same host can reach it without a token; set ``metrics_public=False``
    (``BLASTBOX_METRICS_PUBLIC=false``) to require the bearer token for ``/metrics`` too,
    for deployments whose scraper can present the token.
    """

    _ALWAYS_PUBLIC: frozenset[str] = frozenset({"/v1/healthz", "/v1/version"})

    def __init__(self, app, api_key: str, *, metrics_public: bool = True) -> None:
        super().__init__(app)
        self._key = api_key
        self._public = (
            self._ALWAYS_PUBLIC | {"/metrics"} if metrics_public else self._ALWAYS_PUBLIC
        )

    async def dispatch(self, request, call_next):
        if request.url.path in self._public:
            return await call_next(request)
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return PlainTextResponse("missing bearer token", status_code=401)
        provided = header.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(provided, self._key):
            return PlainTextResponse("invalid bearer token", status_code=401)
        return await call_next(request)


# Default Content-Security-Policy: blocks external resource loads + framing, but
# tolerates inline <script>/<style> because the engine UIs use them (clippyshot's
# index.html inlines its JS; both inline style attrs). Engines that don't need
# inline (e.g. redtusk's external app.js) can tighten via BLASTBOX_CSP. The app
# still escapes all untrusted text (filenames / extracted text / QR payloads) at
# render time, so 'unsafe-inline' is defense-in-depth-weakened, not the only guard.
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    """Set hardening response headers on every response.

    Restores the posture the engines' bespoke hosts enforced before the
    blastbox.host migration (clickjacking, MIME-sniffing, referrer leakage, and a
    baseline CSP) — a host that processes untrusted uploads and renders
    attacker-influenced strings in its UI must not ship these open. CSP is
    overridable via ``BLASTBOX_CSP`` (empty string disables the CSP header only;
    the other three headers are unconditional).

    Pure ASGI (not BaseHTTPMiddleware): it only injects headers into the
    ``http.response.start`` message and never touches the body, so it is safe for
    the host's many streaming ``FileResponse``s (pdf / pages / result zip) — which
    BaseHTTPMiddleware would buffer.
    """

    def __init__(self, app, csp: str = DEFAULT_CSP) -> None:
        self.app = app
        self._headers: list[tuple[bytes, bytes]] = [
            (b"x-frame-options", b"DENY"),
            (b"x-content-type-options", b"nosniff"),
            (b"referrer-policy", b"no-referrer"),
        ]
        if csp:
            self._headers.append((b"content-security-policy", csp.encode("latin-1")))

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                present = {k.lower() for k, _ in headers}
                for k, v in self._headers:
                    if k not in present:  # don't clobber a header a route already set
                        headers.append((k, v))
            await send(message)

        await self.app(scope, receive, send_with_headers)
