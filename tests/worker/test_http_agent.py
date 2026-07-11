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


def test_guard_exposure_fails_closed_when_wide_open():
    from blastbox.worker.http_agent import _guard_exposure
    # non-loopback bind with NO mTLS / token / allowlist and no insecure opt-in -> refuse to start
    with pytest.raises(SystemExit, match="refusing to serve"):
        _guard_exposure("0.0.0.0", 8765, token=None, client_ca=None, allow_cidrs=None, allow_insecure=False)


def test_guard_exposure_rejects_empty_cidr_allowlist():
    from blastbox.worker.http_agent import _guard_exposure
    # a whitespace/comma-only ALLOW_CIDRS parses to [] which _caller_allowed treats as allow-ANY -- it is
    # NOT a gate, so the guard must still fail closed (a typo like `" , "` must not open the agent wide).
    for junk in (" , ", "   ", ",,"):
        with pytest.raises(SystemExit, match="refusing to serve"):
            _guard_exposure("0.0.0.0", 8765, token=None, client_ca=None, allow_cidrs=junk,
                            allow_insecure=False)


def test_guard_exposure_allows_gated_or_optin():
    from blastbox.worker.http_agent import _guard_exposure
    # each of these must NOT raise: loopback bind, a token, mTLS, an IP allowlist, or the insecure opt-in.
    _guard_exposure("127.0.0.1", 8765, token=None, client_ca=None, allow_cidrs=None, allow_insecure=False)
    _guard_exposure("::1", 8765, token=None, client_ca=None, allow_cidrs=None, allow_insecure=False)
    _guard_exposure("0.0.0.0", 8765, token="s3cret", client_ca=None, allow_cidrs=None, allow_insecure=False)
    _guard_exposure("0.0.0.0", 8765, token=None, client_ca="/ca.pem", allow_cidrs=None, allow_insecure=False)
    _guard_exposure("0.0.0.0", 8765, token=None, client_ca=None, allow_cidrs="10.0.0.0/8", allow_insecure=False)
    _guard_exposure("0.0.0.0", 8765, token=None, client_ca=None, allow_cidrs=None, allow_insecure=True)


def test_serve_applies_socket_read_timeout():
    # a stalled/slowloris request body would otherwise hold the single-flight job lock forever; serve()
    # must stamp the timeout onto the handler so StreamRequestHandler.setup() enforces it per request.
    httpd, _ = _running_agent(timeout_s=42.0)
    try:
        assert httpd.RequestHandlerClass.timeout == 42.0
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


class _EgressEchoEngine:
    """Reflects limits.net_egress into the detection label -- proves forwarded BLASTBOX_NET_EGRESS
    reaches Limits (built AFTER the params env is installed)."""

    name = "egress-echo"
    formats = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        (outdir / "p.png").write_bytes(b"\x89PNG")
        return DetonationResult(
            payload=Page(index=0, dims=Dimensions(width=1.0, height=1.0, unit="px"),
                         image=ArtifactRef(id="a0")),
            artifacts=[DeclaredArtifact(id="a0", path="p.png", kind="image")],
            detected=Detection(label=("egress" if limits.net_egress else "sealed"),
                               mime="application/octet-stream", confidence=1.0, source="test"),
        )


def test_forwarded_net_egress_reaches_limits(tmp_path):
    # J1: Limits must be built INSIDE the forwarded-params env, so BLASTBOX_NET_EGRESS actually applies.
    httpd = serve(_EgressEchoEngine(), bind="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"z")
    try:
        meta = detonate_remote(f"http://127.0.0.1:{port}", inp, tmp_path / "o1",
                               params={"BLASTBOX_NET_EGRESS": "1"})
        assert meta["detected"]["label"] == "egress"        # forwarded param took effect on Limits
        meta2 = detonate_remote(f"http://127.0.0.1:{port}", inp, tmp_path / "o2")
        assert meta2["detected"]["label"] == "sealed"        # default is fail-closed, no leak
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


def test_tls_env_fails_closed_on_partial_config():
    from blastbox.worker.http_agent import _tls_env
    with pytest.raises(SystemExit):
        _tls_env({"BLASTBOX_WORKER_AGENT_TLS_CERT": "c"}.get)     # cert without key
    with pytest.raises(SystemExit):
        _tls_env({"BLASTBOX_WORKER_AGENT_CLIENT_CA": "ca"}.get)   # mTLS without TLS
    assert _tls_env({}.get) == (None, None, None)


def test_input_named_out_does_not_collide_with_output_dir():
    httpd, port = _running_agent()
    try:
        r = _post(f"http://127.0.0.1:{port}/detonate?name=out", b"data")
        assert r.status == 200        # a client filename of "out" no longer clashes with out_dir
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_healthz_requires_token_when_set():
    httpd, port = _running_agent(token="s3cr3t")
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10)
        assert ei.value.code == 401                       # misconfigured token -> not "healthy"
        req = urllib.request.Request(f"http://127.0.0.1:{port}/healthz", headers={"X-aws-proxy-auth": "s3cr3t"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_zero_byte_input_accepted():
    httpd, port = _running_agent()
    try:
        r = _post(f"http://127.0.0.1:{port}/detonate?name=empty.bin", b"")
        assert r.status == 200        # a zero-byte sample is valid (the local harness runs it too)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_agent_caps_oversized_metadata_before_archiving(monkeypatch):
    # a metadata.json over its OWN cap must fail the job BEFORE it's archived, so a buggy engine can't
    # fill the worker disk (a 2nd copy would land in the spooled tar) before the host rejects it.
    monkeypatch.setenv("BLASTBOX_MAX_METADATA", "50")   # any real sealed metadata.json exceeds 50 bytes
    httpd, port = _running_agent()
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(f"http://127.0.0.1:{port}/detonate?name=x.bin", b"data")
        assert ei.value.code == 500   # over the metadata cap -> job fails, not a huge disk write
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_concurrent_detonate_returns_409_busy():
    """A warm box serves one job at a time: a request landing while another is in flight gets a fast
    409 (so the dispatcher fails+retires that slot) instead of queueing behind the busy job."""
    started = threading.Event()
    release = threading.Event()

    class _BlockingEngine(_NoopEngine):
        def detonate(self, input: Path, outdir: Path, limits):
            started.set()
            release.wait(timeout=10)
            return super().detonate(input, outdir, limits)

    httpd = serve(_BlockingEngine(), bind="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/detonate?name=a.bin"
    r1: dict = {}

    def _job1():
        try:
            r1["r"] = _post(url, b"x")
        except Exception as exc:  # noqa: BLE001
            r1["e"] = exc

    try:
        th = threading.Thread(target=_job1, daemon=True)
        th.start()
        assert started.wait(timeout=10)                 # job 1 is inside the engine, holding the lock
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(url, b"y")                            # job 2 lands while busy
        assert ei.value.code == 409
        release.set()                                   # let job 1 finish
        th.join(timeout=10)
        assert r1.get("r") is not None and r1["r"].status == 200   # job 1 completed cleanly
    finally:
        release.set()
        httpd.shutdown()
        httpd.server_close()


def test_healthz_honors_cidr_allowlist():
    httpd, port = _running_agent(allow_cidrs="10.0.0.0/8")   # 127.0.0.1 excluded
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10)
        assert ei.value.code == 403   # readiness gated same as /detonate -> no false "healthy"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ip_allowlist_blocks_disallowed_peer():
    httpd, port = _running_agent(allow_cidrs="10.0.0.0/8")   # 127.0.0.1 is not in it
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(f"http://127.0.0.1:{port}/detonate?name=x.bin", b"data")
        assert ei.value.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_mtls_end_to_end_and_rejects_uncertified_caller(tmp_path):
    from blastbox.host.pki import ensure_ca
    from blastbox.tls import client_ssl_context

    ca = ensure_ca(tmp_path / "pki")
    scrt, skey = ca.issue_server(["127.0.0.1"]).write(tmp_path, "server")
    (tmp_path / "ca.crt").write_bytes(ca.cert_pem)
    ccrt, ckey = ca.issue_client("dispatcher").write(tmp_path, "client")

    httpd = serve(_NoopEngine(), bind="127.0.0.1", port=0,
                  tls_cert=str(scrt), tls_key=str(skey), client_ca=str(tmp_path / "ca.crt"))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"z")
    try:
        # dispatcher presents its CA-signed client cert -> allowed
        cctx = client_ssl_context(str(tmp_path / "ca.crt"), cert_file=str(ccrt), key_file=str(ckey))
        meta = detonate_remote(f"https://127.0.0.1:{port}", inp, tmp_path / "o", ssl_context=cctx)
        assert meta["detected"]["label"] == "docx"
        # no client cert (server-verify only) -> mTLS gate rejects the caller
        noclient = client_ssl_context(str(tmp_path / "ca.crt"))
        with pytest.raises(Exception):
            detonate_remote(f"https://127.0.0.1:{port}", inp, tmp_path / "o2", ssl_context=noclient)
    finally:
        httpd.shutdown()
        httpd.server_close()
