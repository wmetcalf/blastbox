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
    must not require auth).  ``GET /metrics`` is also public by default so
    a Prometheus scraper on the same host can reach it without a token.
    """

    _PUBLIC: frozenset[str] = frozenset({"/v1/healthz", "/v1/version", "/metrics"})

    def __init__(self, app, api_key: str) -> None:
        super().__init__(app)
        self._key = api_key

    async def dispatch(self, request, call_next):
        if request.url.path in self._PUBLIC:
            return await call_next(request)
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return PlainTextResponse("missing bearer token", status_code=401)
        provided = header.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(provided, self._key):
            return PlainTextResponse("invalid bearer token", status_code=401)
        return await call_next(request)
