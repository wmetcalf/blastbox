"""Minimal Firecracker HTTP-over-UDS API client (snapshot/restore tier).

Firecracker's control plane speaks HTTP/1.1 over a Unix domain socket. The cold
tier uses ``firecracker --no-api --config-file`` and never touches the API, but
snapshot/restore is API-only (``PUT /snapshot/create``, ``PUT /snapshot/load``,
``PATCH /vm``, …). This is a tiny stdlib client so the host process pulls in no
third-party HTTP dependency.

Field shapes are valid for Firecracker v1.12.1 through v1.16.0 (the version we run
since the virtio-rng descriptor-chain host-memory DoS was fixed in v1.15.1):
``CreateSnapshotParams{snapshot_type, snapshot_path, mem_file_path}``,
``LoadSnapshotConfig{snapshot_path, mem_backend{backend_type, backend_path},
track_dirty_pages, resume_vm}``, ``Vm{state}``. ``track_dirty_pages`` is the FC
≥1.13 replacement for the deprecated ``enable_diff_snapshots``.
"""
from __future__ import annotations

import http.client
import json
import socket
from typing import Any


class FcApiError(RuntimeError):
    """A Firecracker API request returned a >=400 status."""

    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        super().__init__(f"{method} {path} -> {status}: {body[:300]}")
        self.status = status
        self.body = body


class _UdsHTTPConnection(http.client.HTTPConnection):
    """``HTTPConnection`` that dials a Unix domain socket instead of TCP."""

    def __init__(self, uds_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._uds_path = uds_path

    def connect(self) -> None:  # noqa: D401 - override
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._uds_path)
        self.sock = sock


class FcApiClient:
    """PUT/PATCH/GET against a Firecracker API Unix socket.

    A fresh connection per request — Firecracker's API server is single-threaded
    and short request/response cycles avoid keep-alive edge cases. Raises
    :class:`FcApiError` on any >=400 response so callers fail loudly.
    """

    def __init__(self, uds_path: str, timeout: float = 30.0) -> None:
        self._uds_path = uds_path
        self._timeout = timeout

    def _request(self, method: str, path: str, body: Any = None) -> tuple[int, str]:
        conn = _UdsHTTPConnection(self._uds_path, self._timeout)
        try:
            payload = json.dumps(body) if body is not None else None
            headers = {"Accept": "application/json"}
            if payload is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", "replace")
            if resp.status >= 400:
                raise FcApiError(method, path, resp.status, data)
            return resp.status, data
        finally:
            conn.close()

    def put(self, path: str, body: Any = None) -> int:
        return self._request("PUT", path, body)[0]

    def patch(self, path: str, body: Any = None) -> int:
        return self._request("PATCH", path, body)[0]

    def get(self, path: str) -> tuple[int, str]:
        return self._request("GET", path)
