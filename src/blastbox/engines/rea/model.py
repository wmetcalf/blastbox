"""OpenAI-compatible chat-completions client for the rea-agent model (DeepSeek on vLLM).

- POSTs ``<url>/chat/completions`` with only ``Content-Type``/``Accept`` headers. No
  ``Authorization`` header is ever sent, and no key is read from the environment (the
  endpoint is open on the DMZ; any key-like env variable is ignored).
- The default opener is ``urllib``'s, so ``HTTP(S)_PROXY`` from *this* process's env is
  honoured (the sealed route is an allowlisting proxy). Redirects are not followed.
- The response body is capped at :data:`MAX_RESPONSE_BYTES` while reading.
- Each call has a TOTAL deadline (``min(timeout_s ctor, timeout_s call)``), not just urllib's
  per-socket-operation timeout: the exchange runs in a worker thread that reads in chunks and
  checks the deadline, and the caller stops waiting at the deadline. A proxy trickling bytes
  can therefore not stretch a call past the pass budget (Ruling Q).
- Transport and HTTP failures raise ``ModelError("unavailable")``; an oversized, non-JSON or
  non-object body raises ``ModelError("malformed")``. Interpreting ``choices`` is the
  caller's job (the agent parses it defensively); ``reasoning_content`` is never used.
- ``REA_MODEL_DIALECT`` (baked into the agent image; default ``vllm``) says how the "thinking
  off" switch is spelled: ``vllm`` sends ``chat_template_kwargs``; ``openrouter`` sends
  ``reasoning: {"enabled": false}`` (OpenRouter ignores ``chat_template_kwargs``). Credentials
  for a hosted endpoint live in the operator's gateway, never here.
- OpenRouter serves one model id from many hosts, and they differ: some write a schema's keys
  in schema order and some alphabetically, and some ignore the thinking switch. Two image
  settings, both off by default and both refused under ``vllm``, narrow the choice:
  ``REA_MODEL_PROVIDERS`` (comma-separated host slugs, at most eight) sends
  ``provider.only``, and ``REA_MODEL_REQUIRE_PARAMETERS=1`` sends
  ``provider.require_parameters`` (only hosts that support every parameter of the request).
  A setting that leaves no host fails the call as ``unavailable``; it is never widened here.
  Every OpenRouter request also sends ``provider.zdr`` and ``provider.data_collection: deny``
  (``DATA_POLICY``), whatever the settings: no host that retains or trains on prompts is used.
"""

from __future__ import annotations

import http.client
import os
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Literal
from urllib.parse import urlsplit

from blastbox.engines.rea.wellformed import well_formed

MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_log = logging.getLogger("blastbox.engines.rea.model")

ModelErrorKind = Literal["unavailable", "malformed"]


DIALECTS = ("vllm", "openrouter")
_MAX_PROVIDERS = 8
_PROVIDER_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,47}")


#: Sent on every OpenRouter request: zero data retention and no training on prompts.
DATA_POLICY: dict[str, Any] = {"zdr": True, "data_collection": "deny"}


def _routing(dialect: str) -> dict[str, Any] | None:
    """The OpenRouter ``provider`` object the image asked for, or None. Raises on a bad setting."""
    raw_only = (os.environ.get("REA_MODEL_PROVIDERS") or "").strip()
    raw_req = (os.environ.get("REA_MODEL_REQUIRE_PARAMETERS") or "").strip()
    if raw_req not in ("", "0", "1"):
        raise ValueError(f"REA_MODEL_REQUIRE_PARAMETERS must be 0 or 1: {raw_req!r}")
    # Every entry is a host: a list that is set and names none ("," or a stray comma) is refused,
    # not read as "no restriction".
    only = [part.strip() for part in raw_only.split(",")] if raw_only else []
    if "" in only:
        raise ValueError("REA_MODEL_PROVIDERS has an empty entry (a stray or trailing comma)")
    if len(only) > _MAX_PROVIDERS:
        raise ValueError(f"REA_MODEL_PROVIDERS must be at most {_MAX_PROVIDERS} comma-separated host slugs")
    if not all(_PROVIDER_SLUG.fullmatch(slug) for slug in only):
        raise ValueError("REA_MODEL_PROVIDERS has an entry that is not a host slug "
                         "(letters, digits and . _ / -, at most 48 characters)")
    routing: dict[str, Any] = {}
    if dialect == "openrouter":
        # Not a setting: an OpenRouter request always forbids retention and training, so a
        # model no such host serves fails the call rather than reaching one that keeps prompts.
        routing.update(DATA_POLICY)
    if only:
        routing["only"] = only
    if raw_req == "1":
        routing["require_parameters"] = True
    if (only or raw_req == "1") and dialect != "openrouter":
        raise ValueError("REA_MODEL_PROVIDERS and REA_MODEL_REQUIRE_PARAMETERS need REA_MODEL_DIALECT=openrouter")
    return routing or None


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
                 opener: urllib.request.OpenerDirector | Any | None = None, dialect: str | None = None) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(f"model URL must be http(s)://host[:port]/...: {url!r}")
        self.url = url.rstrip("/") + "/chat/completions"
        self.dialect = dialect if dialect is not None else (os.environ.get("REA_MODEL_DIALECT") or "vllm")
        if self.dialect not in DIALECTS:
            raise ValueError(f"REA_MODEL_DIALECT must be one of {', '.join(DIALECTS)}: {self.dialect!r}")
        self._routing = _routing(self.dialect)
        self.model = model
        self.timeout_s = timeout_s
        # Built per client (not at import) so the proxy env in force at job time applies.
        self._opener = opener if opener is not None else default_opener()

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int, *,
             response_format: dict[str, Any] | None = None, timeout_s: float | None = None,
             chat_template_kwargs: dict[str, Any] | None = None,
             temperature: float | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "max_tokens": int(max_tokens)}
        if temperature is not None:  # unset: the server's default sampling
            body["temperature"] = float(temperature)
        if chat_template_kwargs is not None:
            if self.dialect == "openrouter":
                # OpenRouter's spelling; only the thinking switch has an equivalent.
                if "thinking" in chat_template_kwargs:
                    body["reasoning"] = {"enabled": bool(chat_template_kwargs["thinking"])}
            else:
                # vLLM extension; {"thinking": False} turns DeepSeek's reasoning off for this request.
                body["chat_template_kwargs"] = chat_template_kwargs
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if response_format is not None:
            body["response_format"] = response_format
        if self._routing is not None:
            body["provider"] = self._routing
        # ensure_ascii: lone surrogates in hostile evidence survive as escapes, never break encoding.
        data = json.dumps(body, ensure_ascii=True).encode("ascii")
        req = urllib.request.Request(self.url, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        timeout = self.timeout_s if timeout_s is None else max(1.0, min(self.timeout_s, timeout_s))
        raw = self._exchange(req, timeout)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ModelError("malformed", "response_too_large")
        try:
            out = well_formed(json.loads(raw))
        except (ValueError, RecursionError):
            raise ModelError("malformed", "invalid_json") from None
        if not isinstance(out, dict):
            raise ModelError("malformed", "response is not an object")
        return out

    def _exchange(self, req: urllib.request.Request, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        box: dict[str, Any] = {}
        stop = threading.Event()

        def work() -> None:
            try:
                with self._opener.open(req, timeout=timeout) as resp:
                    read = getattr(resp, "read1", None) or resp.read
                    buf = bytearray()
                    while not stop.is_set():
                        if time.monotonic() >= deadline:
                            box["late"] = True
                            return
                        chunk = read(65536)
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) > MAX_RESPONSE_BYTES:
                            break
                    box["raw"] = bytes(buf)
            except BaseException as exc:  # handed to the caller below
                box["exc"] = exc

        t = threading.Thread(target=work, name="rea-model-call", daemon=True)
        t.start()
        t.join(max(0.0, deadline - time.monotonic()))
        if t.is_alive() or box.get("late"):
            stop.set()  # the thread exits at its next read; it is a daemon either way
            _log.warning("model call exceeded its %.0fs deadline", timeout)
            raise ModelError("unavailable", "deadline_exceeded")
        exc = box.get("exc")
        if isinstance(exc, urllib.error.HTTPError):
            _log.warning("model endpoint returned HTTP %s", exc.code)
            raise ModelError("unavailable", f"http_{exc.code}") from None
        if isinstance(exc, (urllib.error.URLError, OSError, ValueError, http.client.HTTPException)):
            _log.warning("model endpoint unreachable: %s", type(exc).__name__)
            raise ModelError("unavailable", type(exc).__name__) from None
        if exc is not None:
            raise ModelError("unavailable", type(exc).__name__) from None
        raw: bytes = box["raw"]
        return raw
