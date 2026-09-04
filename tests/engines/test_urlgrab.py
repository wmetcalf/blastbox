"""UrlGrabEngine: fetch one URL, seal the response. Network fetch is injected (no real I/O)."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from blastbox.engines.urlgrab import (
    FetchError,
    FetchResult,
    UrlGrabEngine,
    _CappedRedirect,
)
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation


def test_redirect_to_non_http_scheme_is_blocked():
    # a 302 to file:// (or ftp:// etc.) must NOT be followed — build_opener's default FileHandler
    # would otherwise read a worker-local file into the sealed body artifact (SSRF / local read).
    h = _CappedRedirect()
    req = urllib.request.Request("http://evil.example/start")
    for bad in ("file:///etc/passwd", "ftp://evil.example/x", "gopher://evil/x"):
        with pytest.raises(urllib.error.URLError) as ei:
            h.redirect_request(req, None, 302, "Found", {}, bad)
        # must be a transport-style URLError, NOT an HTTPError (which _default_fetch would record as
        # a successful 302 response instead of a fetch failure).
        assert not isinstance(ei.value, urllib.error.HTTPError)


def test_redirect_to_http_scheme_is_allowed():
    h = _CappedRedirect()
    req = urllib.request.Request("http://evil.example/start")
    nxt = h.redirect_request(req, None, 302, "Found", {}, "https://ok.example/next")
    assert nxt is not None and nxt.full_url == "https://ok.example/next"


def test_default_fetch_blocked_scheme_redirect_is_a_fetch_failure(monkeypatch):
    # urllib's HTTPRedirectHandler raises HTTPError (before our hook) for schemes it refuses
    # (file://, gopher://); that must surface as a FETCH FAILURE, not a fake fetched 302 response.
    import io
    from blastbox.engines.urlgrab import FetchError, _default_fetch

    def blocked(self, req, timeout=None):
        raise urllib.error.HTTPError("file:///etc/passwd", 302, "Found", {}, None)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", blocked)
    with pytest.raises(FetchError):
        _default_fetch("http://evil/", timeout=5, max_bytes=100, max_redirects=3)

    def http404(
        self, req, timeout=None
    ):  # a genuine 4xx (http url) is still a RESPONSE
        raise urllib.error.HTTPError(
            "http://x/missing", 404, "Not Found", {}, io.BytesIO(b"nope")
        )

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", http404)
    assert (
        _default_fetch("http://x/", timeout=5, max_bytes=100, max_redirects=3).status
        == 404
    )


def _run(
    tmp_path: Path, engine: UrlGrabEngine, url_text: bytes, limits: Limits | None = None
) -> tuple[int, dict, Path]:
    import tempfile

    work = Path(tempfile.mkdtemp(dir=tmp_path))  # unique per call (tests may loop)
    indir = work / "in"
    outdir = work / "out"
    indir.mkdir()
    outdir.mkdir()
    inp = indir / "url.txt"
    inp.write_bytes(url_text)
    rc = run_detonation(
        engine, input_path=inp, output_dir=outdir, limits=limits or Limits()
    )
    meta = json.loads((outdir / "metadata.json").read_text())
    return rc, meta, outdir


def _ok_fetch(
    body=b"<html>evil</html>", status=200, ct="text/html", truncated=False, final=None
):
    def fetch(url, *, timeout, max_bytes, max_redirects, verify_tls=True):
        return FetchResult(
            final_url=final or url,
            status=status,
            content_type=ct,
            server="nginx",
            body=body[:max_bytes],
            truncated=truncated,
        )

    return fetch


def test_verify_tls_passed_to_fetch_and_recorded(tmp_path: Path) -> None:
    seen = {}

    def fetch(url, *, timeout, max_bytes, max_redirects, verify_tls):
        seen["verify_tls"] = verify_tls
        return FetchResult(
            final_url=url,
            status=200,
            content_type="text/html",
            server="FakeNet/1.3",
            body=b"ok",
            truncated=False,
        )

    # default = verify ON
    _run(tmp_path, UrlGrabEngine(fetch_fn=fetch), b"https://x/")
    assert seen["verify_tls"] is True
    # opt out → passed through + recorded in the envelope for provenance
    _, meta, _ = _run(
        tmp_path, UrlGrabEngine(fetch_fn=fetch, verify_tls=False), b"https://x/"
    )
    assert seen["verify_tls"] is False
    assert meta["payload"]["fields"]["tls_verified"] is False


def test_verify_tls_env_default(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BLASTBOX_URLGRAB_VERIFY_TLS", "0")
    seen = {}

    def fetch(url, *, timeout, max_bytes, max_redirects, verify_tls):
        seen["v"] = verify_tls
        return FetchResult(
            final_url=url,
            status=200,
            content_type="t",
            server="s",
            body=b"x",
            truncated=False,
        )

    _run(tmp_path, UrlGrabEngine(fetch_fn=fetch), b"https://x/")
    assert seen["v"] is False


def test_successful_fetch_seals_body_and_metadata(tmp_path: Path) -> None:
    body = b"MZ\x90\x00 fake payload"
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(body=body, ct="application/octet-stream"))
    rc, meta, outdir = _run(tmp_path, eng, b"http://hordlepc.com/payload.bin\n")
    assert rc == 0
    assert meta["status"] == "ok"
    p = meta["payload"]["fields"]
    assert p["url"] == "http://hordlepc.com/payload.bin"
    assert p["fetched"] is True and p["status"] == 200
    assert p["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert p["body_len"] == len(body)
    # body sealed as an artifact + on disk
    assert any(a["id"] == "body" and a["path"] == "body.bin" for a in meta["artifacts"])
    assert (outdir / "body.bin").read_bytes() == body


def test_http_error_status_is_still_a_response(tmp_path: Path) -> None:
    # 404 has a body — it's a real response, not a transport failure.
    eng = UrlGrabEngine(
        fetch_fn=_ok_fetch(body=b"not found", status=404, ct="text/plain")
    )
    rc, meta, _ = _run(tmp_path, eng, b"http://badmakeup.biz/gone")
    assert meta["status"] == "ok"
    assert (
        meta["payload"]["fields"]["status"] == 404
        and meta["payload"]["fields"]["fetched"] is True
    )


def test_dead_url_is_ok_not_engine_error(tmp_path: Path) -> None:
    # DNS NXDOMAIN / connection refused → a normal "dead URL" verdict, NOT engine_error.
    def boom(url, *, timeout, max_bytes, max_redirects, verify_tls=True):
        raise FetchError("Name or service not known")

    rc, meta, outdir = _run(
        tmp_path, UrlGrabEngine(fetch_fn=boom), b"http://sinkholed.example/"
    )
    assert meta["status"] == "ok"  # must not FAIL the job
    assert meta["payload"]["fields"]["fetched"] is False
    assert any(w["code"] == "fetch_failed" for w in meta["warnings"])
    assert not (outdir / "body.bin").exists()


def test_invalid_url_is_rejected_without_fetching(tmp_path: Path) -> None:
    called = []

    def fetch(url, **kw):
        called.append(url)
        return _ok_fetch()(url, timeout=1, max_bytes=1, max_redirects=1)

    for bad in (b"ftp://x/y", b"not a url", b"file:///etc/passwd", b""):
        rc, meta, _ = _run(tmp_path, UrlGrabEngine(fetch_fn=fetch), bad)
        assert meta["status"] == "rejected", bad
    assert called == []  # never reached the network


def test_first_nonempty_line_is_the_url(tmp_path: Path) -> None:
    eng = UrlGrabEngine(fetch_fn=_ok_fetch())
    rc, meta, _ = _run(
        tmp_path, eng, b"\n   \n  https://drive.google.com/open?id=abc  \njunk\n"
    )
    assert meta["payload"]["fields"]["url"] == "https://drive.google.com/open?id=abc"


def test_truncation_warns(tmp_path: Path) -> None:
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(body=b"x" * 10, truncated=True))
    rc, meta, _ = _run(
        tmp_path, eng, b"http://h/big", limits=Limits(max_artifact_bytes=10)
    )
    assert any(w["code"] == "body_truncated" for w in meta["warnings"])
    assert meta["payload"]["fields"]["truncated"] is True


def test_records_final_url_after_redirects(tmp_path: Path) -> None:
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(final="http://hordlepc.com/real-landing"))
    rc, meta, _ = _run(tmp_path, eng, b"http://hordlepc.com/r")
    assert meta["payload"]["fields"]["final_url"] == "http://hordlepc.com/real-landing"
