"""REA model gateway: the only holder of hosted-model credentials.

The REA sandbox reaches this over plain HTTP through a tinyproxy URL filter. A
request may carry a per-job grant in ``X-Rea-Grant`` (sealed by Loadout to this
gateway's X25519 key); the gateway opens it, checks the route and model, forces
OpenRouter zero-data-retention routing, injects the provider key and forwards over
verified TLS. With no grant header the operator key for the route is used, unless
``REA_GW_REQUIRE_GRANT=1``: then a request without a grant answers 401 even when an
operator key is configured (per-job keys only; no operator spend from the sandbox).

On the grant path the body is pinned to the granted model: ``model`` must equal the
grant's model, an OpenRouter ``models`` fallback list is allowed only as exactly
``[grant.model]``, and ``route`` / ``plugins`` are refused outright, so a grant can
never spend its key on another model or on paid plugins. Bodies holding NaN or
Infinity are refused (400) rather than re-serialised as invalid JSON.

Nothing secret is ever logged: one line per request carries method, route, status
and elapsed milliseconds, and nothing else.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol

from blastbox.engines.rea.grant import GrantRejected, load_private_key, open_grant

log = logging.getLogger("blastbox.rea.model_gateway")

MAX_BODY = 16 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
UPSTREAM_TIMEOUT = 600.0
CLIENT_TIMEOUT = 120.0
MAX_OPERATOR_KEY = 4096

ROUTES = {
    "/api/v1/chat/completions": "openrouter",
    "/anthropic/v1/chat/completions": "anthropic",
}
PRODUCTION_UPSTREAM = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/chat/completions",
}
OPERATOR_KEY_ENV = {
    "openrouter": "REA_GW_OPERATOR_KEY_FILE_OPENROUTER",
    "anthropic": "REA_GW_OPERATOR_KEY_FILE_ANTHROPIC",
}
REQUIRE_GRANT_ENV = "REA_GW_REQUIRE_GRANT"
# Body fields that would let a grant reach models or paid features it does not name.
_UNPINNED_FIELDS = ("route", "plugins")
_LOGGED_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

_GRANT_REJECTED = b'{"error":{"message":"grant rejected"}}'
_MODEL_NOT_GRANTED = b'{"error":{"message":"model not granted"}}'
_BAD_BODY = b'{"error":{"message":"invalid request body"}}'
_FORBIDDEN = b'{"error":{"message":"forbidden"}}'
_LENGTH_REQUIRED = b'{"error":{"message":"content-length required"}}'
_TOO_LARGE = b'{"error":{"message":"request body too large"}}'
_BAD_GATEWAY = b'{"error":{"message":"upstream unavailable"}}'


class Opener(Protocol):
    def open(self, fullurl: Any, data: Any = ..., timeout: float = ...) -> Any: ...


@dataclass
class GatewayConfig:
    private_key: bytes | None = field(repr=False)
    operator_keys: dict[str, str] = field(repr=False)
    upstream: dict[str, str] = field(default_factory=lambda: dict(PRODUCTION_UPSTREAM))
    opener: Opener | None = None
    now: Callable[[], int] = lambda: int(time.time())
    require_grant: bool = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the 3xx is relayed as an HTTPError instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def production_opener() -> urllib.request.OpenerDirector:
    """Verified TLS, no redirects, and no proxy from the environment."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def read_operator_key(path: str) -> str:
    """Read a bare provider key from a private regular file (no symlinks)."""
    fd = -1
    data = b""
    ok = False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode) and not st.st_mode & 0o077:
            data = os.read(fd, MAX_OPERATOR_KEY + 1)
            ok = True
    except OSError:
        ok = False
    finally:
        if fd >= 0:
            os.close(fd)
    key = data.strip()
    if (
        not ok
        or len(data) > MAX_OPERATOR_KEY
        or not key
        or any(b < 0x21 or b > 0x7E for b in key)
    ):
        raise ValueError("invalid operator key file")
    return key.decode("ascii")


def operator_keys_from_env(env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ) if env is None else env
    keys: dict[str, str] = {}
    for provider, var in OPERATOR_KEY_ENV.items():
        path = env.get(var, "")
        if path:
            keys[provider] = read_operator_key(path)
    return keys


def require_grant_from_env(env: dict[str, str] | None = None) -> bool:
    env = dict(os.environ) if env is None else env
    value = env.get(REQUIRE_GRANT_ENV, "")
    if value in ("", "0"):
        return False
    if value == "1":
        return True
    raise ValueError("invalid REA_GW_REQUIRE_GRANT (use 0 or 1)")


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def _model_pinned(body: Any, model: str) -> bool:
    if not isinstance(body, dict) or body.get("model") != model:
        return False
    if "models" in body and body["models"] != [model]:
        return False
    return not any(k in body for k in _UNPINNED_FIELDS)


def _upstream_headers(provider: str, key: str) -> dict[str, str]:
    if provider == "anthropic":
        return {
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Title": "loadout-rea",
    }


class _Handler(BaseHTTPRequestHandler):
    server: _GatewayServer
    timeout = CLIENT_TIMEOUT
    server_version = "rea-model-gw"
    sys_version = ""

    # --- logging: the base class must never print request lines or headers ---
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        return

    def send_error(self, code: int, message: str | None = None,
                   explain: str | None = None) -> None:
        # Malformed request lines/headers: answer without echoing anything back.
        self.close_connection = True
        self._reply(code, _FORBIDDEN if code == 403 else b"")

    def _reply(self, status: int, body: bytes,
               content_type: str = "application/json") -> None:
        self._status = status
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def handle_one_request(self) -> None:
        self._status = 0
        self._t0 = time.monotonic()
        try:
            super().handle_one_request()
        finally:
            if self._status:
                method = self.command if self.command in _LOGGED_METHODS else "-"
                path = (getattr(self, "path", "") or "").split("?", 1)[0]
                route = path if path in ROUTES else "-"
                ms = int((time.monotonic() - self._t0) * 1000)
                log.info("%s %s %d %dms", method, route, self._status, ms)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._forbidden
        raise AttributeError(name)

    def _forbidden(self) -> None:
        self._reply(403, _FORBIDDEN)

    # --- the one real handler ---
    def do_POST(self) -> None:  # noqa: N802
        provider = ROUTES.get(self.path)
        if provider is None:
            self._reply(403, _FORBIDDEN)
            return
        raw = self._read_body()
        if raw is None:
            return
        cfg = self.server.cfg
        grant_token = self.headers.get("X-Rea-Grant")
        try:
            body = json.loads(raw, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            body = None
        if grant_token is not None:
            if cfg.private_key is None:
                self._reply(401, _GRANT_REJECTED)
                return
            try:
                grant = open_grant(grant_token, cfg.private_key, cfg.now())
            except GrantRejected:
                self._reply(401, _GRANT_REJECTED)
                return
            if grant.provider != provider:
                self._reply(401, _GRANT_REJECTED)
                return
            if not _model_pinned(body, grant.model):
                self._reply(400, _MODEL_NOT_GRANTED)
                return
            key = grant.key
        else:
            op_key = None if cfg.require_grant else cfg.operator_keys.get(provider)
            if not op_key:
                self._reply(401, _GRANT_REJECTED)
                return
            if not isinstance(body, dict):
                self._reply(400, _BAD_BODY)
                return
            key = op_key
        if provider == "openrouter":
            prior = body.get("provider")
            body["provider"] = {
                **(prior if isinstance(prior, dict) else {}),
                "zdr": True,
                "data_collection": "deny",
            }
        self._forward(provider, key, json.dumps(body, separators=(",", ":")).encode())

    def _read_body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding") is not None:
            self._reply(411, _LENGTH_REQUIRED)
            return None
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            self._reply(411, _LENGTH_REQUIRED)
            return None
        if len(lengths) != 1 or not lengths[0].strip().isdigit() \
                or not lengths[0].strip().isascii():
            self._reply(400, _BAD_BODY)
            return None
        n = int(lengths[0].strip())
        if n > MAX_BODY:
            self._reply(413, _TOO_LARGE)
            return None
        try:
            raw = self.rfile.read(n)
        except OSError:
            raw = b""
        if len(raw) != n:
            self._reply(400, _BAD_BODY)
            return None
        return raw

    def _forward(self, provider: str, key: str, data: bytes) -> None:
        cfg = self.server.cfg
        opener = cfg.opener if cfg.opener is not None else production_opener()
        req = urllib.request.Request(
            cfg.upstream[provider],
            data=data,
            headers=_upstream_headers(provider, key),
            method="POST",
        )
        try:
            try:
                resp = opener.open(req, timeout=UPSTREAM_TIMEOUT)
            except urllib.error.HTTPError as e:
                resp = e
            with resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                ctype = resp.headers.get("Content-Type") or "application/json"
                out = resp.read(MAX_RESPONSE + 1)
        except Exception:
            self._reply(502, _BAD_GATEWAY)
            return
        if len(out) > MAX_RESPONSE:
            self._reply(502, _BAD_GATEWAY)
            return
        self._reply(status, out, ctype)


class _GatewayServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], cfg: GatewayConfig) -> None:
        self.cfg = cfg
        super().__init__(address, _Handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Never print a traceback: frames may hold keys, grants or bodies.
        log.warning("request handler error")


def make_server(cfg: GatewayConfig,
                address: tuple[str, int] = ("0.0.0.0", 8080)) -> ThreadingHTTPServer:
    if cfg.opener is None:
        cfg.opener = production_opener()
    return _GatewayServer(address, cfg)


def _parse_listen(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError("invalid REA_GW_LISTEN")
    return (host.strip("[]") or "0.0.0.0", int(port))


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    try:
        key_path = os.environ.get("REA_GW_PRIVATE_KEY_FILE", "")
        private_key = load_private_key(key_path) if key_path else None
        operator_keys = operator_keys_from_env()
        require_grant = require_grant_from_env()
        address = _parse_listen(os.environ.get("REA_GW_LISTEN", "0.0.0.0:8080"))
    except ValueError as e:
        # Messages are fixed strings that never carry key material.
        log.error("rea-model-gw: fatal: %s", e)
        raise SystemExit(2) from None
    cfg = GatewayConfig(
        private_key=private_key, operator_keys=operator_keys, require_grant=require_grant
    )
    server: ThreadingHTTPServer | None = None
    try:
        server = make_server(cfg, address)
    except OSError:
        pass
    if server is None:
        # Outside the except block so no traceback or chained context survives.
        log.error("rea-model-gw: fatal: cannot listen on %s:%d", address[0], address[1])
        raise SystemExit(2)
    log.info(
        "rea-model-gw listening on %s:%d grants=%s require_grant=%s operator=%s",
        address[0], address[1], private_key is not None, require_grant,
        sorted(operator_keys),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
