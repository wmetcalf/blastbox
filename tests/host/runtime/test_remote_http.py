"""Unit tests for the generic remote-HTTP host transport (no network)."""

from __future__ import annotations

import contextlib

import io
import json
import os
import tarfile
from types import SimpleNamespace

import pytest

from blastbox.host.runtime.remote_http import (
    _safe_extract_tar,
    detonate_remote,
    make_remote_validate,
    slot_base_url,
)


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class _Resp:
    def __init__(self, data: bytes) -> None:
        self._bio = io.BytesIO(data)

    def read(self, n: int = -1) -> bytes:
        return self._bio.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(tar_bytes: bytes, capture: list | None = None):
    def op(req, timeout, context=None):
        if capture is not None:
            capture.append(req)
        return _Resp(tar_bytes)
    return op


# --------------------------------------------------------------------- slot_base_url

def test_slot_base_url_lambda_prefers_url():
    slot = SimpleNamespace(url="https://mv.lambda-url.aws/", ip=None, agent_port=8765)
    assert slot_base_url(slot) == "https://mv.lambda-url.aws"


def test_slot_base_url_ec2_ip_port():
    slot = SimpleNamespace(url=None, ip="10.0.1.9", agent_port=8765)
    assert slot_base_url(slot) == "http://10.0.1.9:8765"


def test_slot_base_url_tls_scheme():
    slot = SimpleNamespace(url=None, ip="10.0.0.4", agent_port=8765)
    assert slot_base_url(slot, tls=True) == "https://10.0.0.4:8765"
    assert slot_base_url(slot, tls=False) == "http://10.0.0.4:8765"


def test_slot_base_url_no_endpoint_raises():
    with pytest.raises(ValueError):
        slot_base_url(SimpleNamespace(url=None, ip=None, agent_port=8765))


# --------------------------------------------------------------------- safe extraction

def test_safe_extract_writes_regular_files(tmp_path):
    written = _safe_extract_tar(_tar({"metadata.json": b"{}", "p0.png": b"x"}), tmp_path)
    assert set(written) == {"metadata.json", "p0.png"}
    assert (tmp_path / "p0.png").read_bytes() == b"x"


def test_safe_extract_rejects_traversal(tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    _safe_extract_tar(_tar({"../escape.bin": b"evil", "ok.png": b"good"}), dest)
    assert (dest / "ok.png").exists()
    assert not (tmp_path / "escape.bin").exists()   # traversal dropped


def test_safe_extract_caps_member_count(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    tar = _tar({f"f{i}.bin": b"x" for i in range(10)})
    with pytest.raises(RemoteOutputTooLarge):
        _safe_extract_tar(tar, tmp_path, max_members=5)   # inode-exhaustion guard


def test_safe_extract_refuses_symlink_leaf(tmp_path):
    # a stale symlink at the member's leaf (even one that resolves IN-bounds) must not be written
    # THROUGH: O_NOFOLLOW makes the open fail ELOOP and the member is skipped.
    import os
    dest = tmp_path / "out"
    dest.mkdir()
    inside = dest / "inside.txt"
    inside.write_text("original")
    os.symlink(inside, dest / "p0.png")   # dest/p0.png -> dest/inside.txt (in-bounds, passes bounds check)
    _safe_extract_tar(_tar({"p0.png": b"overwrite"}), dest)
    assert inside.read_text() == "original"   # not written through the symlink


def test_safe_extract_symlink_escape_blocked(tmp_path):
    # a symlink whose target is OUTSIDE dest is dropped by the resolve()+bounds check.
    import os
    dest = tmp_path / "out"
    dest.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("original")
    os.symlink(secret, dest / "p0.png")   # dest/p0.png -> ../secret.txt (out of bounds)
    _safe_extract_tar(_tar({"p0.png": b"overwrite"}), dest)
    assert secret.read_text() == "original"


# --------------------------------------------------------------------- detonate_remote

def test_detonate_remote_extracts_and_returns_meta(tmp_path):
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode(), "page-001.png": b"\x89PNG"})
    cap: list = []
    out = tmp_path / "out"
    inp = tmp_path / "in.docx"
    inp.write_bytes(b"z")
    meta = detonate_remote("http://10.0.0.5:8765", inp, out, http_open=_opener(tar, cap))
    assert meta == {"status": "ok"}
    assert (out / "page-001.png").read_bytes() == b"\x89PNG"
    # posted to /detonate with the sanitized name
    assert cap[0].full_url == "http://10.0.0.5:8765/detonate?name=in.docx"
    assert cap[0].method == "POST"


def test_detonate_remote_sends_jwe_header_when_token(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("https://mv.aws", tmp_path / "in.bin", tmp_path / "o",
                    token="jwe.tok", agent_port=8765, http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert cap[0].headers.get("X-aws-proxy-auth") == "jwe.tok"
    assert cap[0].headers.get("X-aws-proxy-port") == "8765"


def _header_ci(req, name: str):
    return next((v for k, v in req.headers.items() if k.lower() == name.lower()), None)


def test_detonate_remote_forwards_params(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                    params={"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_OCR_ALL": "1"},
                    http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert json.loads(_header_ci(cap[0], "X-Blastbox-Params")) == {"CLIPPYSHOT_OCR": "1", "CLIPPYSHOT_OCR_ALL": "1"}


def test_detonate_remote_no_params_header_when_none(tmp_path):
    (tmp_path / "in.bin").write_bytes(b"z")
    cap: list = []
    detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                    http_open=_opener(_tar({"metadata.json": b"{}"}), cap))
    assert _header_ci(cap[0], "X-Blastbox-Params") is None


def test_dispatch_ssl_context_from_env_none_without_ca():
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    assert dispatch_ssl_context_from_env({}.get) is None


def test_dispatch_ssl_context_from_env_builds(tmp_path):
    import ssl

    from blastbox.host.pki import ensure_ca
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    ensure_ca(tmp_path)     # writes tmp_path/ca.crt
    ctx = dispatch_ssl_context_from_env({"BLASTBOX_DISPATCH_TLS_CA": str(tmp_path / "ca.crt")}.get)
    assert isinstance(ctx, ssl.SSLContext)


def test_dispatch_ssl_context_partial_fails_closed():
    from blastbox.host.runtime.remote_http import dispatch_ssl_context_from_env
    with pytest.raises(RuntimeError):
        dispatch_ssl_context_from_env({"BLASTBOX_DISPATCH_TLS_CERT": "c"}.get)   # cert, no CA -> not plaintext


def test_detonate_remote_caps_output(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    big = _tar({"metadata.json": b"{}", "blob.bin": b"x" * 5000})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(big), max_output_bytes=1000)


def test_detonate_remote_clears_stale_output(tmp_path):
    # a prior/requeued attempt's leftover file must be removed before extraction, so the trust gate
    # re-seals ONLY this attempt's output.
    out = tmp_path / "out"
    out.mkdir()
    (out / "stale.png").write_bytes(b"old")
    (tmp_path / "in.bin").write_bytes(b"z")
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode(), "page-001.png": b"new"})
    detonate_remote("http://h:8765", tmp_path / "in.bin", out, http_open=_opener(tar))
    assert not (out / "stale.png").exists()          # stale file dropped
    assert (out / "page-001.png").read_bytes() == b"new"


def test_extracted_artifacts_are_group_readable(tmp_path):
    # 0644 so a serve process on a different UID can read the artifacts (serve+dispatch split).
    import stat
    _safe_extract_tar(_tar({"p0.png": b"x"}), tmp_path)
    mode = stat.S_IMODE((tmp_path / "p0.png").stat().st_mode)
    assert mode & 0o044   # world/group readable


def test_detonate_remote_caps_member_count(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    many = _tar({"metadata.json": b"{}", **{f"f{i}.bin": b"x" for i in range(20)}})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(many), max_members=5)


def test_extract_excludes_metadata_from_artifact_budget(tmp_path):
    # a job whose ARTIFACTS fit the budget but whose metadata.json would tip the byte total over must
    # NOT be rejected -- metadata is a control file with its own cap (matches the cold trust gate).
    big_meta = b'{"x":"' + b"a" * 900 + b'"}'      # ~910 bytes of metadata
    tar = _tar({"metadata.json": big_meta, "p0.png": b"x" * 200})
    # artifact budget 500: p0.png (200) fits; if metadata counted, 200+910 > 500 would (wrongly) fail.
    written = _safe_extract_tar(tar, tmp_path, max_total_bytes=500)
    assert set(written) == {"metadata.json", "p0.png"}


def test_detonate_remote_stream_cap_covers_metadata_budget(tmp_path):
    # a result whose ARTIFACTS fit max_output_bytes but whose (separately-capped) metadata is large must
    # NOT be rejected by the pre-extraction stream cap -- the stream cap must include the metadata budget.
    (tmp_path / "in.bin").write_bytes(b"z")
    big_meta = b'{"status":"ok","pad":"' + b"a" * 100_000 + b'"}'      # 100KB metadata (within its cap)
    tar = _tar({"metadata.json": big_meta, "p0.png": b"x" * 200})       # tiny artifact (within 1000)
    meta = detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                           http_open=_opener(tar), max_output_bytes=1000, max_metadata_bytes=4_000_000)
    assert meta.get("status") == "ok"   # not rejected: stream cap = artifact + metadata budgets + overhead


def test_detonate_remote_stream_cap_covers_member_headroom(tmp_path):
    # many tiny artifacts whose CONTENT fits max_output_bytes but whose per-member tar headers (512B each)
    # push the raw stream past artifact+metadata budgets. The stream cap must add per-member headroom
    # (~max_members*1KB) or a legitimate many-page result is (wrongly) rejected before extraction.
    (tmp_path / "in.bin").write_bytes(b"z")
    files = {"metadata.json": b'{"status":"ok"}'}
    files.update({f"p{i}.png": b"x" * 10 for i in range(200)})   # 2KB of content across 200 members
    tar = _tar(files)   # ~206KB stream (200 x 1KB tar blocks) -- exceeds 5000*1.1 + 2000 + 64KB naive cap
    meta = detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                           http_open=_opener(tar), max_output_bytes=5000, max_metadata_bytes=2000,
                           max_members=300)
    assert meta.get("status") == "ok"   # not rejected: stream cap includes max_members*1024 header headroom


def test_safe_extract_metadata_cap_applies_to_normalized_path(tmp_path):
    # F7 (security): a worker disguising the control file as "./metadata.json" still lands at
    # output/metadata.json, so it must get the METADATA cap -- not the (much larger) artifact byte budget.
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    tar = _tar({"./metadata.json": b'{"x":"' + b"a" * 5000 + b'"}'})   # ~5KB "metadata"
    with pytest.raises(RemoteOutputTooLarge):
        _safe_extract_tar(tar, tmp_path, max_total_bytes=1_000_000, max_metadata_bytes=1000)


def test_default_open_does_not_follow_worker_redirects():
    # G2 (security): a worker's 3xx must NOT be followed -- urllib would rewrite POST->GET and re-send
    # X-aws-proxy-auth / X-Blastbox-Params to the Location, leaking the token + doing an SSRF GET.
    import http.server
    import threading
    import urllib.error
    import urllib.request
    from blastbox.host.runtime.remote_http import _default_open
    leaked = {}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "/steal")
            self.end_headers()

        def do_GET(self):                       # the redirect target -- must NEVER be reached
            leaked["auth"] = self.headers.get("X-aws-proxy-auth")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/detonate", data=b"x",
                                     method="POST", headers={"X-aws-proxy-auth": "SECRET-JWE"})
        with pytest.raises(urllib.error.HTTPError) as ei:
            _default_open(req, timeout=5)
        assert ei.value.code in (301, 302, 303, 307, 308)   # redirect surfaced (fail-closed), not followed
        assert "auth" not in leaked                          # /steal never hit -> token not leaked
    finally:
        srv.shutdown()


def test_health_probes_do_not_follow_worker_redirects():
    # H1 (security): BOTH health-probe paths (aws_worker._default_http_probe + remote_http.make_tls_probe)
    # must fail closed on a worker's /healthz 3xx, like /detonate -- else they re-send X-aws-proxy-auth
    # (the shared EC2/static agent_token or a Lambda JWE) to the Location and a 2xx there falsely = READY.
    import http.server
    import threading
    from blastbox.host.runtime.aws_worker import _default_http_probe
    from blastbox.host.runtime.remote_http import make_tls_probe
    leaked = {}

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/steal":                       # the redirect target -- must never be reached
                leaked["auth"] = self.headers.get("X-aws-proxy-auth")
                self.send_response(200)
            else:
                self.send_response(302)
                self.send_header("Location", "/steal")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/healthz"
        for probe in (_default_http_probe, make_tls_probe(None)):
            leaked.clear()
            assert probe(url, {"X-aws-proxy-auth": "SECRET"}, 5.0) is False   # redirect -> not ready
            assert "auth" not in leaked                                        # token NOT leaked to /steal
    finally:
        srv.shutdown()


def test_default_open_ignores_ambient_proxy(monkeypatch):
    # J2: worker transport must IGNORE HTTP_PROXY/HTTPS_PROXY -- else the /detonate body + X-aws-proxy-auth
    # route through the proxy (cleartext for http workers). With a DEAD proxy set, a direct request to a
    # live local worker must still SUCCEED, proving the proxy was bypassed.
    import http.server
    import threading
    import urllib.request
    from blastbox.host.runtime.remote_http import _default_open

    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")    # dead proxy port
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/healthz")
        with _default_open(req, timeout=5) as resp:
            assert resp.status == 200        # reached the worker DIRECTLY (a used proxy would refuse:1)
    finally:
        srv.shutdown()


def test_extracted_artifacts_forced_0644_under_restrictive_umask(tmp_path):
    # G5: a restrictive process umask (e.g. 077) must not mask extracted artifacts to 0600 -- the API
    # process (a different UID in a serve+dispatch split) has to read them. fchmod forces the exact mode.
    old = os.umask(0o077)
    try:
        written = _safe_extract_tar(_tar({"metadata.json": b'{"ok":1}', "p0.png": b"x" * 10}), tmp_path)
        for name in written:
            assert (os.stat(tmp_path / name).st_mode & 0o777) == 0o644, name
    finally:
        os.umask(old)


def test_cap_read_timeout_best_effort():
    # #1: _cap_read_timeout shrinks the socket read timeout to the remaining budget (so a chunk-then-stall
    # can't block the full original socket timeout past the deadline), and is a graceful no-op with no sock.
    from blastbox.host.runtime.remote_http import _cap_read_timeout

    class _Sock:
        t = None

        def settimeout(self, v):
            self.t = v

    resp = SimpleNamespace(fp=SimpleNamespace(raw=SimpleNamespace(_sock=_Sock())))
    _cap_read_timeout(resp, 3.5)
    assert resp.fp.raw._sock.t == 3.5            # capped to the remaining budget
    _cap_read_timeout(SimpleNamespace(), 2.0)    # no reachable socket -> no-op, no raise


def test_oversized_params_rejected_before_claim(tmp_path):
    # #2: oversized params (ingress-valid but past the header limit) must be rejected BEFORE claiming a
    # slot -- else a client could quarantine static boxes / burn AWS slots without running a job.
    from blastbox.host.runtime.remote_http import make_remote_validate
    claimed = []
    slot = SimpleNamespace(slot_id="s1", auth_token=None, agent_port=8765)
    big = {f"K{i:03d}": "A" * 4000 for i in range(20)}   # ~80 KB > 65536

    validate = make_remote_validate(
        lambda: (claimed.append(1), slot)[1], lambda s, dirty=False: None,
        output_dir_for=lambda p: tmp_path)
    meta, ok = validate(tmp_path / "in.bin", params=big)
    assert ok is False and "error" in meta
    assert claimed == []   # rejected WITHOUT claiming a slot


def test_make_remote_validate_params_for_raise_fails_before_claim(tmp_path):
    # F2 + #2: a raising params_for is a LOCAL failure -- it must NOT claim a slot at all (deriving params
    # before claim() means no worker is claimed+dirtied), returning the sanitized (error, False) contract.
    from blastbox.host.runtime.remote_http import make_remote_validate
    claimed, released = [], []
    slot = SimpleNamespace(slot_id="s1", auth_token=None, agent_port=8765)

    def boom(_p):
        raise ValueError("bad hook")

    validate = make_remote_validate(
        lambda: (claimed.append(1), slot)[1], lambda s, dirty=False: released.append((s.slot_id, dirty)),
        output_dir_for=lambda p: tmp_path, params_for=boom)
    meta, ok = validate(tmp_path / "in.bin")
    assert ok is False and "error" in meta       # sanitized failure, not a raise
    assert claimed == [] and released == []      # no slot claimed -> none to leak or dirty


def test_detonate_remote_caps_metadata_size(tmp_path):
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    (tmp_path / "in.bin").write_bytes(b"z")
    huge_meta = _tar({"metadata.json": b'{"x":"' + b"a" * 10000 + b'"}'})
    with pytest.raises(RemoteOutputTooLarge):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "o",
                        http_open=_opener(huge_meta), max_metadata_bytes=1000)


def test_make_remote_validate_forwards_input_sha_to_trust(tmp_path):
    # the dispatcher-supplied authoritative ingress SHA reaches output_trust (not a recompute).
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    got = {}

    def trust(_in_path, _out_dir, sha, _owns=None):
        got["sha"] = sha

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=trust,
    )
    validate(tmp_path / "in.docx", input_sha256="deadbeef")
    assert got["sha"] == "deadbeef"


def test_make_remote_validate_forwards_owns_to_trust(tmp_path):
    # the ownership predicate reaches output_trust so it can fence the metadata write.
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    got = {}

    def trust(_in_path, _out_dir, _sha, owns=None):
        got["owns"] = owns() if owns else None

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=trust,
    )
    validate(tmp_path / "in.docx", owns=lambda: True)   # True -> detonate proceeds to the trust gate
    assert got["owns"] is True   # predicate threaded through to output_trust


def test_detonate_remote_fences_destructive_ops_on_lost_claim(tmp_path):
    # L1: if the claim was lost (a peer reclaimed+completed the job), detonate_remote must NOT empty/extract
    # into the SHARED output dir -- that would clobber the new owner's sealed result. It aborts (ClaimLost).
    from blastbox.host.runtime.remote_http import ClaimLost
    out = tmp_path / "out"
    out.mkdir()
    (out / "peer.png").write_bytes(b"peer artifact")   # the peer owner's result already in the shared dir
    (tmp_path / "in.bin").write_bytes(b"z")
    with pytest.raises(ClaimLost):
        detonate_remote("http://h:8765", tmp_path / "in.bin", out,
                        http_open=_opener(_tar({"metadata.json": b"{}"})), owns=lambda: False)
    assert (out / "peer.png").read_bytes() == b"peer artifact"   # NOT wiped / clobbered


def test_detonate_remote_read_deadline_aborts_trickle(tmp_path, monkeypatch):
    # M1: a worker trickling the response past the timeout must ABORT (RemoteReadTimeout), not hang -- else
    # the abandoned validate thread pins the pool slot forever (availability DoS).
    from blastbox.host.runtime.remote_http import RemoteReadTimeout
    (tmp_path / "in.bin").write_bytes(b"z")

    class _Trickle:
        def read(self, n=-1):
            return b"x"                    # never EOFs
        read1 = read

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    clock = {"t": 0.0}
    monkeypatch.setattr("blastbox.host.runtime.remote_http.time.monotonic", lambda: clock["t"])

    def opener(req, timeout, context=None):
        clock["t"] = timeout + 1           # jump past the read deadline before the first chunk check
        return _Trickle()

    with pytest.raises(RemoteReadTimeout):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "out",
                        http_open=opener, timeout=5, max_output_bytes=1000)


def test_detonate_remote_rejects_oversized_params(tmp_path):
    # M3: a params set that serializes past the stdlib header-line limit must fail fast BEFORE the round-trip
    # (else the worker rejects the request opaquely at the HTTP parser).
    from blastbox.host.runtime.remote_http import ParamsTooLargeForRemote
    (tmp_path / "in.bin").write_bytes(b"z")
    big = {f"K{i:03d}": "A" * 4000 for i in range(20)}   # ~80 KB > 65536
    called = {"n": 0}

    def opener(req, timeout, context=None):
        called["n"] += 1
        return _Resp(b"")

    with pytest.raises(ParamsTooLargeForRemote):
        detonate_remote("http://h:8765", tmp_path / "in.bin", tmp_path / "out",
                        http_open=opener, params=big, max_output_bytes=1000)
    assert called["n"] == 0   # rejected before any network round-trip


def test_worker_busy_409_requeues_not_fails(tmp_path):
    # M4: a 409 (worker's single-flight lock held by a stale detonation) is capacity pressure -> WorkerBusy
    # propagates (dispatcher requeues) and the slot is released DIRTY, not treated as a job failure.
    import io
    import urllib.error
    from blastbox.host.runtime.remote_http import WorkerBusy, make_remote_validate
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url="http://x", ip=None, auth_token=None, agent_port=8765)
    released = []

    def opener(req, timeout, context=None):
        raise urllib.error.HTTPError(req.full_url, 409, "busy", {}, io.BytesIO(b'{"error":"busy"}'))

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: released.append(dirty),
        output_dir_for=lambda p: tmp_path / "out", http_open=opener)
    with pytest.raises(WorkerBusy):
        validate(tmp_path / "in.docx")
    assert released == [True]   # busy box released dirty (cooldown); the job requeues


def test_open_bounded_deadline():
    # N2: the opener (connect/send/headers) phase must be bounded by a total wall-clock deadline, not just
    # urllib's per-op socket timeout -- else a worker trickling the request/headers pins the claimed slot.
    import threading
    import time as _time
    from blastbox.host.runtime.remote_http import RemoteReadTimeout, _open_bounded
    blocked = threading.Event()

    def slow_opener(req, timeout, context=None):
        blocked.wait(5)          # blocks well past the deadline
        return "late"

    with pytest.raises(RemoteReadTimeout):
        _open_bounded(slow_opener, object(), timeout=5, context=None, deadline=_time.monotonic() + 0.2)
    blocked.set()
    assert _open_bounded(lambda r, t, context=None: "ok", object(), 5, None,
                         _time.monotonic() + 5) == "ok"   # a fast opener returns its value


def test_open_bounded_timeout_thread_is_daemon():
    # #3: a timed-out opener must run in a DAEMON thread so it never blocks process exit (a non-daemon
    # executor thread abandoned with wait=False would).
    import threading
    import time as _time
    from blastbox.host.runtime.remote_http import RemoteReadTimeout, _open_bounded
    before = set(threading.enumerate())
    ev = threading.Event()

    def slow(req, timeout, context=None):
        ev.wait(2)
        return "late"

    try:
        with pytest.raises(RemoteReadTimeout):
            _open_bounded(slow, object(), 2, None, _time.monotonic() + 0.1)
        leaked = [t for t in threading.enumerate() if t not in before and t.name == "bb-open"]
        assert leaked and all(t.daemon for t in leaked)   # abandoned opener thread is a daemon
    finally:
        ev.set()


def test_validated_engine_error_releases_slot_clean(tmp_path):
    # N3+#2: a VALIDATED engine_error (trust gate verified the envelope/hash -> healthy worker, bad sample)
    # releases the slot CLEAN, so a client feeding malformed samples can't quarantine the static fleet.
    from blastbox.errors import EngineErrorEnvelope
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url="http://x", ip=None, auth_token=None, agent_port=8765)
    released = []

    def trust(_in, _out, _sha, owns=None):
        raise EngineErrorEnvelope("engine_error: sample failed")   # envelope VALIDATED, status engine_error

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: released.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "engine_error"}).encode()})),
        output_trust=trust)
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False and released == [False]   # validated engine_error -> clean release


def test_fake_engine_error_stays_dirty(tmp_path):
    # #2: a worker returning {"status":"engine_error"} that does NOT validate (bad hash / malformed) must
    # stay DIRTY -- a compromised/broken worker can't dodge cooldown by faking engine_error.
    from blastbox.errors import OutputTrustError
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url="http://x", ip=None, auth_token=None, agent_port=8765)
    released = []

    def trust(_in, _out, _sha, owns=None):
        raise OutputTrustError("hash mismatch / malformed envelope")   # NOT a validated engine_error

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: released.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "engine_error"}).encode()})),
        output_trust=trust)
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False and released == [True]    # unvalidatable -> retire the worker dirty


def test_missing_metadata_releases_slot_dirty(tmp_path):
    # ...but genuinely abnormal worker output (no sealed metadata) stays dirty -> retire it.
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url="http://x", ip=None, auth_token=None, agent_port=8765)
    released = []
    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: released.append(dirty),
        output_dir_for=lambda p: tmp_path / "out", http_open=_opener(_tar({})))   # no metadata.json
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False and released == [True]


def test_safe_extract_counts_non_regular_members(tmp_path):
    # N5: a tar dominated by non-regular headers (dirs/symlinks) must still trip max_members -- they were
    # skipped BEFORE counting, so a header-count DoS slipped the cap.
    from blastbox.host.runtime.remote_http import RemoteOutputTooLarge
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i in range(10):
            ti = tarfile.TarInfo(f"d{i}")
            ti.type = tarfile.DIRTYPE
            tf.addfile(ti)
    with pytest.raises(RemoteOutputTooLarge):
        _safe_extract_tar(buf.getvalue(), tmp_path, max_members=5)   # 10 dir headers > 5


def test_detonate_remote_streams_input_with_content_length(tmp_path):
    # the input is streamed (open file handle + Content-Length), not read fully into memory.
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"x" * 1234)
    cap: list = []
    tar = _tar({"metadata.json": json.dumps({"status": "ok"}).encode()})
    detonate_remote("http://h:8765", inp, tmp_path / "out", http_open=_opener(tar, cap))
    req = cap[0]
    assert req.get_header("Content-length") == "1234"      # explicit length -> streamed body
    assert hasattr(req.data, "read")                        # data is a file object, not bytes


def test_make_remote_validate_releases_dirty_on_failure(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []

    def boom(req, timeout, context=None):
        raise OSError("connection refused")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out", http_open=boom,
    )
    validate(tmp_path / "in.docx")
    assert seen == [True]   # transport failure -> retire the slot dirty


def test_make_remote_validate_releases_clean_on_success(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []
    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
    )
    validate(tmp_path / "in.docx")
    assert seen == [False]   # clean success -> reusable


def test_make_remote_validate_fails_on_engine_error(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s: None,
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "engine_error"}).encode()})),
    )
    _, ok = validate(tmp_path / "in.docx")
    assert ok is False   # a sealed engine_error envelope is not a successful job


def test_make_remote_validate_trust_failure_keeps_slot_dirty(tmp_path):
    # host trust gate runs BEFORE the slot is released: a transport-ok job that FAILS host validation
    # must fail AND retire the slot dirty (not re-offer a worker that produced untrusted output).
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    seen = []

    def bad_trust(_in_path, _out_dir, _sha, _owns=None):
        raise RuntimeError("hash mismatch")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: seen.append(dirty),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=bad_trust,
    )
    _, ok = validate(tmp_path / "in.docx")
    assert ok is False and seen == [True]   # trust failed -> job fails, slot retired dirty


def test_make_remote_validate_trust_ok_rereads_sealed_metadata(tmp_path):
    # a passing trust gate re-writes metadata.json (host-sealed) -> validate returns the re-read version.
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    out = tmp_path / "out"

    def reseal(_in_path, out_dir, _sha, _owns=None):
        (out_dir / "metadata.json").write_text(json.dumps({"status": "ok", "sealed": True}))

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s, dirty=False: None,
        output_dir_for=lambda p: out,
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
        output_trust=reseal,
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is True and meta.get("sealed") is True   # returns the host-sealed metadata, not the worker's


# --------------------------------------------------------------------- make_remote_validate

def test_make_remote_validate_happy(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    claimed, released = [], []
    validate = make_remote_validate(
        claim=lambda: (claimed.append(slot) or slot),
        release=lambda s: released.append(s),
        output_dir_for=lambda p: tmp_path / "out",
        http_open=_opener(_tar({"metadata.json": json.dumps({"status": "ok"}).encode()})),
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is True and meta == {"status": "ok"}
    assert claimed == [slot] and released == [slot]   # slot claimed AND released


def test_make_remote_validate_failure_releases_slot(tmp_path):
    (tmp_path / "in.docx").write_bytes(b"z")
    slot = SimpleNamespace(url=None, ip="10.0.1.4", auth_token=None, agent_port=8765)
    released = []

    def boom(req, timeout, context=None):
        raise OSError("connection refused")

    validate = make_remote_validate(
        claim=lambda: slot, release=lambda s: released.append(s),
        output_dir_for=lambda p: tmp_path / "out", http_open=boom,
    )
    meta, ok = validate(tmp_path / "in.docx")
    assert ok is False
    assert meta == {"error": "remote worker transport error"}   # sanitized reason surfaced
    assert released == [slot]   # released even on failure


def test_a_broken_release_is_not_laddered_into_a_clean_release(tmp_path):
    """A TypeError from INSIDE release() must not walk the compatibility ladder.

    The old three-rung `except TypeError` ladder could not tell "this seam predates the kwarg"
    from "release() raised TypeError for a real reason", so one genuine bug released the SAME
    slot three times -- and the final rung dropped `dirty`, returning a worker that had just
    failed a detonation to IDLE with no forced recycle, ready to take the next untrusted sample.
    """
    calls: list[tuple[bool, str | None]] = []
    slot = SimpleNamespace(slot_id="s1", url="http://worker.invalid", ip=None)

    def release(s, *, dirty: bool = False, fault: str | None = None) -> None:
        calls.append((dirty, fault))
        raise TypeError("bug inside release(), NOT an old signature")

    def boom(*a, **kw):
        raise OSError("transport down")

    validate = make_remote_validate(
        lambda: slot, release, output_dir_for=lambda p: tmp_path, http_open=boom,
    )

    (tmp_path / "in.bin").write_bytes(b"sample")
    with contextlib.suppress(TypeError):
        validate(tmp_path / "in.bin")

    assert len(calls) == 1, f"one slot, one release -- got {len(calls)}: {calls}"
    assert calls[0][0] is True, "a failed detonation must stay DIRTY, never fall back to clean"


def test_empty_metadata_is_attributed_to_the_worker(tmp_path):
    """Empty metadata is abnormal worker output — and the attribution must be REACHABLE.

    The first attempt added this as an `elif not meta` placed AFTER the `if not meta: return`
    that already exits, so it could never execute: malformed worker output still never advanced
    burnout or base rebuilding, and a recycle-capable worker could be reset and re-offered
    forever. A test that only asserts the failure result would have passed throughout.
    """
    calls: list[tuple[bool, str | None]] = []

    def release(s, *, dirty: bool = False, fault: str | None = None) -> None:
        calls.append((dirty, fault))

    slot = SimpleNamespace(slot_id="s1", url="http://worker.invalid", ip=None)
    out = tmp_path / "out"
    out.mkdir()
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"sample")
    validate = make_remote_validate(
        lambda: slot, release, output_dir_for=lambda p: out,
        http_open=_opener(_tar({"metadata.json": b"{}"})),
    )

    meta, ok = validate(inp)

    assert ok is False
    # Pin WHICH branch produced the fault. The generic transport handler also sets "worker", so
    # an assertion on the fault alone passes even when this branch is never reached — the first
    # version of this test did exactly that, and the mutant survived because of it.
    assert meta == {"error": "remote worker returned no metadata"}, (
        f"the empty-metadata branch was not reached; got {meta}"
    )
    assert calls and calls[0][1] == "worker", (
        f"empty metadata must advance worker burnout, got fault={calls[0][1] if calls else None}"
    )


def test_local_host_io_is_unattributed_but_transport_still_convicts(tmp_path):
    """The two must be told apart EXPLICITLY, because Python's hierarchy conflates them.

    urllib's URLError/HTTPError and socket.timeout are all OSError subclasses, so an
    `except OSError` written for ENOSPC silently swallows every connection failure too. Fixing
    the reported half (host I/O wrongly convicting) without this guard would have killed wedge
    detection for the transport failures the attribution exists for — so both directions are
    asserted here.
    """
    import socket
    import urllib.error

    out = tmp_path / "out"
    out.mkdir()
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"sample")
    slot = SimpleNamespace(slot_id="s1", url="http://worker.invalid", ip=None)

    def _run(err):
        calls: list[tuple[bool, str | None]] = []

        def release(s, *, dirty: bool = False, fault: str | None = None) -> None:
            calls.append((dirty, fault))

        def boom(*a, **kw):
            raise err

        validate = make_remote_validate(
            lambda: slot, release, output_dir_for=lambda p: out, http_open=boom,
        )
        validate(inp)
        return calls[0][1] if calls else None

    # LOCAL disk failure: the request never went out — not this worker's fault.
    assert _run(OSError(28, "No space left on device")) == "unknown", (
        "a dispatcher-disk failure must not burn out healthy slots"
    )

    # TRANSPORT failures still convict, despite also being OSErrors.
    assert _run(urllib.error.URLError("connection refused")) == "worker"
    assert _run(socket.timeout("timed out")) == "worker"
    assert _run(ConnectionResetError("peer reset")) == "worker"


def test_worker_busy_and_incomplete_validation_are_not_worker_evidence(tmp_path):
    """Two conditions that reach the remote path's generic handler but are not failures.

    409/WorkerBusy means the worker ANSWERED and its single-flight lock is held — capacity
    pressure, and the job is requeued rather than failed. OutputTrustUnknown means the HOST could
    not complete validation; validate_worker_output wraps the OSError, so it is no longer an
    OSError and the generic branch would convict, defeating the type's whole purpose on this path.
    """
    from blastbox.errors import OutputTrustUnknown
    from blastbox.host.runtime.remote_http import WorkerBusy

    out = tmp_path / "out"
    out.mkdir()
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"sample")
    slot = SimpleNamespace(slot_id="s1", url="http://worker.invalid", ip=None)

    def _run(err, expect_raise):
        calls: list[tuple[bool, str | None]] = []

        def release(s, *, dirty: bool = False, fault: str | None = None) -> None:
            calls.append((dirty, fault))

        def boom(*a, **kw):
            raise err

        validate = make_remote_validate(
            lambda: slot, release, output_dir_for=lambda p: out, http_open=boom,
        )
        if expect_raise:
            with contextlib.suppress(Exception):
                validate(inp)
        else:
            validate(inp)
        return calls[0] if calls else (None, None)

    dirty, fault = _run(WorkerBusy("worker busy (409)"), expect_raise=True)
    assert fault == "unknown", f"a 409 is capacity pressure, not failure evidence (got {fault})"
    assert dirty is True, "still quarantine the box so it is not immediately re-offered"

    _, fault = _run(OutputTrustUnknown("EMFILE hashing metadata.json"), expect_raise=False)
    assert fault == "unknown", (
        f"a check the HOST could not complete is not worker evidence (got {fault})"
    )


def test_a_tls_failure_is_transport_not_local_disk(tmp_path):
    """ssl.SSLError is an OSError but none of the other transport types.

    So an HTTPS read failing on a TLS protocol error or a mid-stream disconnect landed in the
    local-filesystem branch: a worker with a broken TLS stack could never be detected, because
    every failure it produced was attributed to this dispatcher's disk.
    """
    import ssl

    out = tmp_path / "out"
    out.mkdir()
    inp = tmp_path / "in.bin"
    inp.write_bytes(b"sample")
    slot = SimpleNamespace(slot_id="s1", url="https://worker.invalid", ip=None)

    calls: list[tuple[bool, str | None]] = []

    def release(s, *, dirty: bool = False, fault: str | None = None) -> None:
        calls.append((dirty, fault))

    def boom(*a, **kw):
        raise ssl.SSLError(1, "[SSL: DECRYPTION_FAILED] protocol error")

    validate = make_remote_validate(
        lambda: slot, release, output_dir_for=lambda p: out, http_open=boom,
    )
    validate(inp)

    assert calls and calls[0][1] == "worker", (
        f"a TLS failure is evidence about the worker, not our disk (got {calls[0][1]})"
    )
