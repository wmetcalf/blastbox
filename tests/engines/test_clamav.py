"""The ClamAV engine: warm, parse-only, and honest about what it did not do.

TWO FAILURE MODES ARE INDISTINGUISHABLE FROM SUCCESS unless the engine works to keep them
apart, and both were real here rather than hypothetical.

The first is an unreachable daemon. The Loadout driver this replaces caught
`FileNotFoundError` and sealed an empty successful result, so a deployment with no scanner
reported every sample clean, at confidence 1.0, for as long as it stayed broken.

The second was mine, and it is why these tests run against a live daemon wherever one is
available. The first version sent `ALLMATCHSCAN` before `INSTREAM`; the daemon answers
`UNKNOWN COMMAND` and the connection returns nothing — so EICAR scanned CLEAN and sealed
`status: ok`. Nothing about the code looked wrong. Only asking a real clamd found it.
"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import clamd
import pytest

from blastbox.engines.clamav import ClamAVEngine, ClamdUnavailable, ping, scan_stream
from blastbox.limits import Limits

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

live = pytest.mark.skipif(not ping(1.0), reason="no clamd reachable")


def _run(tmp_path: Path, data: bytes, **kw):
    p = tmp_path / "in.bin"
    p.write_bytes(data)
    return ClamAVEngine(**kw).detonate(p, tmp_path, Limits(timeout_s=60))


# --- the outage must not look like a clean scan -----------------------------------

def test_an_unreachable_daemon_is_an_engine_error_not_a_clean_verdict(tmp_path):
    """THE PROPERTY. A scanner that cannot look must never seal a result that reads as
    'looked, found nothing' — that is a false negative for the length of the outage, and
    it is invisible because the job completes."""
    def dead(data, *, timeout, max_stream=None):
        raise ClamdUnavailable("clamd at ('x', 3310) is not reachable")

    r = _run(tmp_path, EICAR, scan_fn=dead)
    assert r.status == "engine_error", "an outage sealed as a successful scan"
    assert r.payload.fields["scanned"] is False
    # NO `infected` KEY AT ALL on the error path. Not `False` — a reader taking the
    # field at face value would read `infected: false` as "scanned, nothing found",
    # which is the very confusion this test exists to prevent.
    assert "infected" not in r.payload.fields, r.payload.fields
    assert any(w.code == "clamd_unavailable" for w in r.warnings)


def test_an_oversize_sample_is_refused_not_truncated(monkeypatch):
    """A partial scan reporting clean is a false statement about the whole file.

    THE CEILING IS THE DAEMON'S, not this module's. clamd enforces `StreamMaxLength` and
    the library raises `BufferTooLongError`; what has to be true here is that the
    translation keeps it an ERROR — because the failure mode it guards against is a
    size refusal that reads as a transport hiccup and then as a clean verdict about
    bytes nobody looked at."""
    class _TooLong:
        def instream(self, _fh):
            raise clamd.BufferTooLongError("INSTREAM size limit exceeded")

    monkeypatch.setattr("blastbox.engines.clamav._client", lambda _t: _TooLong())
    with pytest.raises(ClamdUnavailable, match="Refused rather than truncated"):
        scan_stream(b"x" * 32, timeout=5)


def test_a_daemon_error_reply_is_not_a_clean_scan(monkeypatch):
    """`ERROR` in the reply means the daemon failed on this sample — a scanner that
    broke mid-file has not established that the file is clean."""
    class _Errs:
        def instream(self, _fh):
            return {"stream": ("ERROR", "Can't allocate memory")}

    monkeypatch.setattr("blastbox.engines.clamav._client", lambda _t: _Errs())
    with pytest.raises(ClamdUnavailable, match="clamd reported an error"):
        scan_stream(b"x", timeout=5)


def test_an_unknown_signature_database_is_a_warning_not_a_silence(tmp_path, monkeypatch):
    """A verdict whose signature age is unknown is worth less than one that states it,
    and omitting the field lets a reader assume it was current."""
    monkeypatch.setattr("blastbox.engines.clamav.db_version", lambda *a, **k: None)
    r = _run(tmp_path, b"harmless", scan_fn=lambda data, **kw: [])
    assert r.status == "ok"
    assert r.payload.fields["db_version"] == "unknown"
    assert any(w.code == "db_version_unknown" for w in r.warnings)


def test_the_result_says_it_stopped_at_the_first_hit(tmp_path):
    """`signature_count: 1` on an archive means AT LEAST one, not exactly one. Sealed so
    the reader is not left to assume the stronger reading."""
    r = _run(tmp_path, b"x", scan_fn=lambda data, **kw: ["Some.Sig"])
    assert r.payload.fields["first_hit_only"] is True


# --- against a real daemon ---------------------------------------------------------

@live
def test_eicar_is_detected_by_a_real_daemon(tmp_path):
    r = _run(tmp_path, EICAR)
    assert r.status == "ok"
    assert r.payload.fields["infected"] is True, r.payload.fields
    assert r.payload.fields["signature_count"] >= 1
    assert "eicar" in r.payload.fields["signatures"].lower()


@live
def test_a_clean_sample_is_clean(tmp_path):
    r = _run(tmp_path, b"nothing interesting in here at all")
    assert r.status == "ok" and r.payload.fields["infected"] is False


@live
def test_an_infected_archive_is_detected(tmp_path):
    """clamd unpacks it. Only the FIRST member is reported — the protocol has no
    all-match — which `first_hit_only` says out loud."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a/one.com", EICAR)
        z.writestr("b/two.com", EICAR)
        z.writestr("c/clean.txt", b"fine")
    r = _run(tmp_path, buf.getvalue())
    assert r.payload.fields["infected"] is True
    assert r.payload.fields["first_hit_only"] is True


@live
def test_all_match_is_not_reachable_over_the_socket():
    """PINNED so nobody re-adds it. `ALLMATCHSCAN` is a libclamav scan option, not a
    daemon command — and the version of this engine that sent it anyway made EICAR scan
    clean, because the rejected command left the connection returning nothing."""
    import socket

    host = os.environ.get("BLASTBOX_CLAMD_HOST", "127.0.0.1")
    port = int(os.environ.get("BLASTBOX_CLAMD_PORT", "3310"))
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(b"zALLMATCHSCAN\0")
        assert b"UNKNOWN COMMAND" in s.recv(200)


@live
def test_the_database_version_is_sealed_with_the_verdict(tmp_path):
    r = _run(tmp_path, b"harmless")
    assert r.payload.fields["db_version"].startswith("ClamAV"), r.payload.fields
