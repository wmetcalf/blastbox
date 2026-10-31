"""OpenAI-compatible chat-completions client for the rea-agent model (DeepSeek on vLLM).

- POSTs ``<url>/chat/completions`` with only ``Content-Type``/``Accept`` headers. No
  ``Authorization`` header is ever sent, and no key is read from the environment (the
  endpoint is open on the DMZ; any key-like env variable is ignored).
- The default opener is ``urllib``'s, so ``HTTP(S)_PROXY`` from *this* process's env is
  honoured (the sealed route is an allowlisting proxy). Redirects are not followed.
- The response body is capped at :data:`MAX_RESPONSE_BYTES` while reading.
- Transport and HTTP failures raise ``ModelError("unavailable")``; an oversized, non-JSON or
  non-object body raises ``ModelError("malformed")``. Interpreting ``choices`` is the
  caller's job (the agent parses it defensively); ``reasoning_content`` is never used.
"""

from __future__ import annotations

import http.client
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Literal
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_log = logging.getLogger("blastbox.engines.rea.model")

ModelErrorKind = Literal["unavailable", "malformed"]


class ModelError(Exception):
    def __init__(self, kind: ModelErrorKind, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind: ModelErrorKind = kind


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> None:
        return None


def default_opener() -> urllib.request.OpenerDirector:
    """urllib's default handlers (incl. the env ProxyHandler) minus redirect following."""
    return urllib.request.build_opener(_NoRedirect)


class ModelClient:
    def __init__(self, url: str, model: str, timeout_s: float,
                 opener: urllib.request.OpenerDirector | Any | None = None) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"model URL must be http(s)://host[:port]/...: {url!r}")
        self.url = url.rstrip("/") + "/chat/completions"
        self.model = model
        self.timeout_s = timeout_s
        # Built per client (not at import) so the proxy env in force at job time applies.
        self._opener = opener if opener is not None else default_opener()

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int, *,
             response_format: dict[str, Any] | None = None, timeout_s: float | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "max_tokens": int(max_tokens)}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if response_format is not None:
            body["response_format"] = response_format
        # ensure_ascii: lone surrogates in hostile evidence survive as escapes, never break encoding.
        data = json.dumps(body, ensure_ascii=True).encode("ascii")
        req = urllib.request.Request(self.url, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        timeout = self.timeout_s if timeout_s is None else max(1.0, min(self.timeout_s, timeout_s))
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            _log.warning("model endpoint returned HTTP %s", exc.code)
            raise ModelError("unavailable", f"http_{exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            _log.warning("model endpoint unreachable: %s", type(exc).__name__)
            raise ModelError("unavailable", type(exc).__name__) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ModelError("malformed", "response_too_large")
        try:
            out = json.loads(raw)
        except (ValueError, RecursionError):
            raise ModelError("malformed", "invalid_json") from None
        if not isinstance(out, dict):
            raise ModelError("malformed", "response is not an object")
        return out
