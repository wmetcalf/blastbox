"""Minimal MCP client: JSON-RPC 2.0 over a child process's stdio, one JSON message per line.

Only what the rea-agent engine needs: ``initialize``, ``tools/list`` and ``tools/call``, one
request in flight at a time. Every response line is capped while reading (``max_response``,
8 MiB by default; ``tools/list`` gets a larger cap because REA's catalog with output schemas
is ~3.9 MB). An oversized line is drained and dropped, and the waiting call fails with
``response_too_large``; the session stays usable. Requests from the server are answered with
"method not found"; notifications are ignored. stderr is discarded. The child runs in its
own process group, and ``close`` kills the whole group (REA forks a JVM).
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Any

# list_procedures(detail=complete) over a 2167-function Go binary is ~500 KB of text; its response
# line passed 1 MiB live (2026-11-05), was dropped, and left the agent's todo seed empty.
MAX_RESPONSE = 8 * 1024 * 1024
MAX_LIST_RESPONSE = 16 * 1024 * 1024
MAX_LIST_PAGES = 16
PROTOCOL_VERSION = "2025-06-18"
_QUEUE_DEPTH = 64


class McpError(Exception):
    """A failed MCP exchange. ``code`` is a short machine-readable reason."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


class _Oversized:
    """Queue marker: a line longer than the reader cap was received and dropped."""

    def __init__(self, size: int) -> None:
        self.size = size


class _Closed:
    """Queue marker: the server's stdout closed."""


class McpStdioClient:
    def __init__(self, argv: list[str], env: Mapping[str, str], cwd: Path, *,
                 max_response: int = MAX_RESPONSE) -> None:
        self._argv = list(argv)
        self._env = dict(env)
        self._cwd = Path(cwd)
        self._max_response = max_response
        self._proc: subprocess.Popen[bytes] | None = None
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=_QUEUE_DEPTH)
        self._write_lock = threading.Lock()
        self._next_id = 0
        self._closed = False
        self._eof = False

    # ------------------------------------------------------------ lifecycle
    def start(self, timeout_s: float = 60.0) -> dict[str, Any]:
        """Spawn the server and run the ``initialize`` handshake; returns its result."""
        try:
            self._proc = subprocess.Popen(
                self._argv,
                env=self._env,
                cwd=self._cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            raise McpError("start_failed", type(exc).__name__) from exc
        assert self._proc.stdout is not None
        threading.Thread(target=self._reader, args=(self._proc.stdout,), daemon=True).start()
        result = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "blastbox-rea-agent", "version": "1"},
        }, timeout_s, self._max_response)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass

    def __enter__(self) -> McpStdioClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------ API
    def list_tools(self, timeout_s: float = 60.0) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            params: dict[str, Any] = {} if cursor is None else {"cursor": cursor}
            res = self._request("tools/list", params, timeout_s, MAX_LIST_RESPONSE)
            page = res.get("tools")
            if not isinstance(page, list):
                raise McpError("bad_response", "tools/list result has no tools list")
            tools += [t for t in page if isinstance(t, dict) and isinstance(t.get("name"), str)]
            nxt = res.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                break
            cursor = nxt
        return tools

    def call(self, name: str, arguments: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        """``tools/call``; returns the result object (``content``, ``isError``, ...)."""
        return self._request("tools/call", {"name": name, "arguments": arguments}, timeout_s,
                             self._max_response)

    # ------------------------------------------------------------ internals
    def _send(self, msg: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or self._closed:
            raise McpError("not_started")
        data = (json.dumps(msg) + "\n").encode()
        with self._write_lock:
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except (OSError, ValueError) as exc:
                raise McpError("server_exited", type(exc).__name__) from exc

    def _request(self, method: str, params: dict[str, Any], timeout_s: float, cap: int) -> dict[str, Any]:
        if self._eof:
            raise McpError("server_exited")
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.monotonic() + max(0.0, timeout_s)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self._cancel(rid)
                raise McpError("timeout", f"{method} exceeded {timeout_s:.1f}s")
            try:
                item = self._queue.get(timeout=left)
            except queue.Empty:
                continue
            if isinstance(item, _Closed):
                self._eof = True
                raise McpError("server_exited")
            if isinstance(item, _Oversized):
                # One request in flight: an oversized reply is ours (or a stale one, which
                # is equally unusable). Either way this request fails, and the session lives.
                raise McpError("response_too_large", f"{item.size}+ bytes > {cap}")
            raw, msg = item
            mid = msg.get("id")
            if type(mid) is not int or mid != rid:  # `true == 1` must not match
                continue  # a late reply to a request that already timed out
            if len(raw) > cap:
                raise McpError("response_too_large", f"{len(raw)} bytes > {cap}")
            if "error" in msg:
                err = msg.get("error")
                text = err.get("message") if isinstance(err, dict) else None
                raise McpError("rpc_error", str(text)[:500] if text is not None else "")
            result = msg.get("result")
            if not isinstance(result, dict):
                raise McpError("bad_response", "result is not an object")
            return result

    def _cancel(self, rid: int) -> None:
        try:
            self._send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                        "params": {"requestId": rid, "reason": "timeout"}})
        except McpError:
            pass

    def _put(self, item: Any) -> None:
        while not self._closed:
            try:
                self._queue.put(item, timeout=0.5)
                return
            except queue.Full:
                continue

    def _reader(self, stdout: IO[bytes]) -> None:
        limit = max(self._max_response, MAX_LIST_RESPONSE)
        try:
            while True:
                line = stdout.readline(limit + 1)
                if not line:
                    break
                if len(line) > limit and not line.endswith(b"\n"):
                    size = len(line)
                    while True:  # drain the rest of the oversized line without keeping it
                        more = stdout.readline(65536)
                        size += len(more)
                        if not more or more.endswith(b"\n"):
                            break
                    self._put(_Oversized(size))
                    continue
                try:
                    msg = json.loads(line)
                except (ValueError, RecursionError):
                    continue
                if not isinstance(msg, dict):
                    continue
                if "method" in msg:
                    if "id" in msg:  # a server->client request: we offer no client features
                        try:
                            self._send({"jsonrpc": "2.0", "id": msg["id"],
                                        "error": {"code": -32601, "message": "method not found"}})
                        except McpError:
                            pass
                    continue
                self._put((line, msg))
        except (OSError, ValueError):
            pass
        finally:
            self._put(_Closed())
