"""UrlGrabEngine: fetch one URL, seal the response. Network fetch is injected (no real I/O)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from blastbox.engines.urlgrab import FetchError, FetchResult, UrlGrabEngine
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation


def _run(tmp_path: Path, engine: UrlGrabEngine, url_text: bytes,
         limits: Limits | None = None) -> tuple[int, dict, Path]:
    import tempfile
    work = Path(tempfile.mkdtemp(dir=tmp_path))  # unique per call (tests may loop)
    indir = work / "in"
    outdir = work / "out"
    indir.mkdir()
    outdir.mkdir()
    inp = indir / "url.txt"
    inp.write_bytes(url_text)
    rc = run_detonation(engine, input_path=inp, output_dir=outdir, limits=limits or Limits())
    meta = json.loads((outdir / "metadata.json").read_text())
    return rc, meta, outdir


def _ok_fetch(body=b"<html>evil</html>", status=200, ct="text/html", truncated=False, final=None):
    def fetch(url, *, timeout, max_bytes, max_redirects):
        return FetchResult(
            final_url=final or url, status=status, content_type=ct, server="nginx",
            body=body[:max_bytes], truncated=truncated,
        )
    return fetch


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
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(body=b"not found", status=404, ct="text/plain"))
    rc, meta, _ = _run(tmp_path, eng, b"http://badmakeup.biz/gone")
    assert meta["status"] == "ok"
    assert meta["payload"]["fields"]["status"] == 404 and meta["payload"]["fields"]["fetched"] is True


def test_dead_url_is_ok_not_engine_error(tmp_path: Path) -> None:
    # DNS NXDOMAIN / connection refused → a normal "dead URL" verdict, NOT engine_error.
    def boom(url, *, timeout, max_bytes, max_redirects):
        raise FetchError("Name or service not known")
    rc, meta, outdir = _run(tmp_path, UrlGrabEngine(fetch_fn=boom), b"http://sinkholed.example/")
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
    rc, meta, _ = _run(tmp_path, eng, b"\n   \n  https://drive.google.com/open?id=abc  \njunk\n")
    assert meta["payload"]["fields"]["url"] == "https://drive.google.com/open?id=abc"


def test_truncation_warns(tmp_path: Path) -> None:
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(body=b"x" * 10, truncated=True))
    rc, meta, _ = _run(tmp_path, eng, b"http://h/big", limits=Limits(max_artifact_bytes=10))
    assert any(w["code"] == "body_truncated" for w in meta["warnings"])
    assert meta["payload"]["fields"]["truncated"] is True


def test_records_final_url_after_redirects(tmp_path: Path) -> None:
    eng = UrlGrabEngine(fetch_fn=_ok_fetch(final="http://hordlepc.com/real-landing"))
    rc, meta, _ = _run(tmp_path, eng, b"http://hordlepc.com/r")
    assert meta["payload"]["fields"]["final_url"] == "http://hordlepc.com/real-landing"
