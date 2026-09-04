"""Test FcApiClient against a real Unix-socket HTTP server."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler
from socketserver import UnixStreamServer

import pytest

from blastbox.host.runtime.fc_api import FcApiClient, FcApiError


def _start_server(sock_path, fail_path=None):
    records = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(n) if n else b""

        def _handle(self, method):
            body = self._body()
            records.append((method, self.path, json.loads(body) if body else None))
            if fail_path is not None and self.path == fail_path:
                self.send_response(400)
                self.send_header("Content-Length", "11")
                self.end_headers()
                self.wfile.write(b"bad request")
            else:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def do_PUT(self):
            self._handle("PUT")

        def do_PATCH(self):
            self._handle("PATCH")

        def log_message(self, *a):
            pass

    server = UnixStreamServer(sock_path, Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, records


def test_put_serializes_json_over_uds(tmp_path):
    sock = str(tmp_path / "fc.sock")
    server, records = _start_server(sock)
    try:
        status = FcApiClient(sock, timeout=5).put("/vm", {"state": "Paused"})
        assert status == 204
        assert records == [("PUT", "/vm", {"state": "Paused"})]
    finally:
        server.shutdown()
        server.server_close()


def test_patch_over_uds(tmp_path):
    sock = str(tmp_path / "fc.sock")
    server, records = _start_server(sock)
    try:
        FcApiClient(sock, timeout=5).patch("/vm", {"state": "Resumed"})
        assert records == [("PATCH", "/vm", {"state": "Resumed"})]
    finally:
        server.shutdown()
        server.server_close()


def test_4xx_raises_fc_api_error(tmp_path):
    sock = str(tmp_path / "fc.sock")
    server, _ = _start_server(sock, fail_path="/snapshot/load")
    try:
        client = FcApiClient(sock, timeout=5)
        with pytest.raises(FcApiError) as ei:
            client.put("/snapshot/load", {"snapshot_path": "/s"})
        assert ei.value.status == 400
        assert "bad request" in ei.value.body
    finally:
        server.shutdown()
        server.server_close()
