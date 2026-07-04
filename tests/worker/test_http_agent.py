"""Tests for the generic HTTP worker agent + an end-to-end round-trip with the host transport.

A real ThreadingHTTPServer is started on 127.0.0.1:0 (loopback, always reachable in-process) serving a
fake engine, then the real ``remote_http.detonate_remote`` client posts a job and verifies the sealed
output dir (metadata.json + the artifact) comes back in the tar. No real AWS / network involved.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from blastbox.contract import ArtifactRef, DeclaredArtifact, Detection, Dimensions, Page
from blastbox.host.runtime.remote_http import detonate_remote
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult
from blastbox.worker.http_agent import serve


class _NoopEngine:
    name = "test-noop"
    formats = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        (outdir / "page-001.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 56)
        return DetonationResult(
            payload=Page(index=0, dims=Dimensions(width=100.0, height=100.0, unit="px"),
                         image=ArtifactRef(id="a0")),
            artifacts=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")],
            detected=Detection(label="docx", mime="application/octet-stream", confidence=0.9, source="test"),
        )


def _running_agent(**kw):
    httpd = serve(_NoopEngine(), bind="127.0.0.1", port=0, **kw)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _post(url: str, body: bytes, headers: dict | None = None):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers or {})
    return urllib.request.urlopen(req, timeout=10)


def test_healthz():
    httpd, port = _running_agent()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10) as r:
            assert r.status == 200
            body = json.loads(r.read())
            assert body["ok"] is True and body["engine"] == "test-noop"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_end_to_end_detonate_roundtrip(tmp_path):
    """Real agent + real client: input bytes -> engine runs + seals -> tar -> extracted into out/."""
    httpd, port = _running_agent()
    try:
        inp = tmp_path / "doc.docx"
        inp.write_bytes(b"hello world")
        out = tmp_path / "out"
        meta = detonate_remote(f"http://127.0.0.1:{port}", inp, out)
        # the sealed output dir came back whole
        assert (out / "metadata.json").is_file()
        assert (out / "page-001.png").is_file()             # the artifact travelled in the tar
        assert (out / "page-001.png").read_bytes().startswith(b"\x89PNG")
        assert isinstance(meta, dict) and meta               # metadata.json parsed
        assert meta.get("status") == "ok"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_auth_required_when_token_set(tmp_path):
    httpd, port = _running_agent(token="s3cr3t")
    try:
        url = f"http://127.0.0.1:{port}/detonate?name=x.bin"
        with pytest.raises(urllib.error.HTTPError) as ei:  # no token -> 401
            _post(url, b"data")
        assert ei.value.code == 401
        # with the token (as the Lambda-style header) -> 200
        r = _post(url, b"data", {"X-aws-proxy-auth": "s3cr3t"})
        assert r.status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_size_cap(tmp_path):
    httpd, port = _running_agent(max_bytes=8)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(f"http://127.0.0.1:{port}/detonate?name=x.bin", b"way too many bytes")
        assert ei.value.code == 413
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_unknown_paths_404():
    httpd, port = _running_agent()
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nope", timeout=10)
        assert ei.value.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


class _EnvEchoEngine:
    """Reflects the TEST_PARAM env var into the detection label -- to prove per-job params reach here."""

    name = "env-echo"
    formats = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        import os
        (outdir / "p.png").write_bytes(b"\x89PNG")
        return DetonationResult(
            payload=Page(index=0, dims=Dimensions(width=1.0, height=1.0, unit="px"),
                         image=ArtifactRef(id="a0")),
            artifacts=[DeclaredArtifact(id="a0", path="p.png", kind="image")],
            detected=Detection(label=os.environ.get("TEST_PARAM", "<unset>"),
                               mime="application/octet-stream", confidence=1.0, source="test"),
        )


def test_forwards_params_and_restores_env(tmp_path):
    import os
    httpd = serve(_EnvEchoEngine(), bind="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"z")
    try:
        meta = detonate_remote(f"http://127.0.0.1:{port}", inp, tmp_path / "o1",
                               params={"TEST_PARAM": "forwarded"})
        assert meta["detected"]["label"] == "forwarded"        # param reached the engine
        meta2 = detonate_remote(f"http://127.0.0.1:{port}", inp, tmp_path / "o2")
        assert meta2["detected"]["label"] == "<unset>"          # no leak between jobs
        assert "TEST_PARAM" not in os.environ                   # env restored on the server side
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_harness_failure_returns_500(tmp_path, monkeypatch):
    # a non-zero run_detonation (e.g. metadata.json couldn't be sealed) must be a job failure, not 200
    monkeypatch.setattr("blastbox.worker.http_agent.run_detonation", lambda *a, **k: 1)
    httpd, port = _running_agent()
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(f"http://127.0.0.1:{port}/detonate?name=x.bin", b"data")
        assert ei.value.code == 500
    finally:
        httpd.shutdown()
        httpd.server_close()
