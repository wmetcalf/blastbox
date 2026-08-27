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

AND THE FIX CARRIED A SECOND ERROR THAT LIVED HERE. From that `UNKNOWN COMMAND` I
concluded all-match was unreachable over the socket, wrote it into the engine as a design
rationale, and pinned it with a test named
`test_all_match_is_not_reachable_over_the_socket`. It was false — the probe had sent
`ALLMATCHSCAN` with no path argument, and the daemon rejected a malformed command, not the
feature. `ALLMATCHSCAN <path>` returned 344 signatures across 40 LNK samples where `SCAN`
returned 36. A test pinning a wrong belief is worse than no test: it makes the belief look
verified and stops the next person from checking.
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


def _daemon_sees_our_paths() -> bool:
    """PING IS NOT ENOUGH FOR THE PATH TESTS. A clamd whose socket is bind-mounted out
    of a container answers every command and can read none of this process's files — the
    exact shape `_shares_filesystem()` cannot tell from a local daemon, and the reason
    the engine degrades instead of failing. All-match cannot be exercised there."""
    if not ping(1.0):
        return False
    import tempfile
    from blastbox.engines.clamav import ClamdCannotSeePath, scan_path

    with tempfile.NamedTemporaryFile(suffix=".txt") as fh:
        fh.write(b"harmless"); fh.flush()
        try:
            scan_path(Path(fh.name), timeout=10)
            return True
        except ClamdCannotSeePath:
            return False
        except ClamdUnavailable:
            return False


shared_fs = pytest.mark.skipif(
    not _daemon_sees_our_paths(),
    reason="the daemon cannot read this process's paths (socket bind-mounted from a "
           "container) — all-match needs a shared filesystem")


def _run(tmp_path: Path, data: bytes, *, stream=True, monkeypatch=None, **kw):
    """Runs the engine. `stream=True` forces the INSTREAM fallback so a unit test can
    drive `scan_fn`; the engine otherwise prefers all-match by path whenever the daemon
    shares its filesystem, which in the worker guest it always does."""
    p = tmp_path / "in.bin"
    p.write_bytes(data)
    if stream:
        os.environ["BLASTBOX_CLAMD_FORCE_STREAM"] = "1"
    try:
        return ClamAVEngine(**kw).detonate(p, tmp_path, Limits(timeout_s=60))
    finally:
        if stream:
            os.environ.pop("BLASTBOX_CLAMD_FORCE_STREAM", None)


# --- the outage must not look like a clean scan -----------------------------------

def test_an_unreachable_daemon_is_an_engine_error_not_a_clean_verdict(tmp_path):
    """THE PROPERTY. A scanner that cannot look must never seal a result that reads as
    'looked, found nothing' — that is a false negative for the length of the outage, and
    it is invisible because the job completes."""
    def dead(data, *, timeout, max_stream=None):
        raise ClamdUnavailable("clamd at ('x', 3310) is not reachable")

    r = _run(tmp_path, EICAR, scan_fn=dead)
    assert r.status == "engine_error", "an outage sealed as a successful scan"
    # A DIFFERENT NODE TYPE, not a scan with holes in it. There is no `infected` field
    # to misread — `infected: false` from a scanner that never ran is indistinguishable
    # from a real clean verdict, which is the confusion this test exists to prevent.
    assert r.payload.type == "signature_scan_unavailable", r.payload
    assert not hasattr(r.payload, "infected"), r.payload
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
    assert r.payload.db_version == "unknown"
    assert any(w.code == "db_version_unknown" for w in r.warnings)


def test_the_result_says_it_stopped_at_the_first_hit(tmp_path):
    """`signature_count: 1` on an archive means AT LEAST one, not exactly one. Sealed so
    the reader is not left to assume the stronger reading."""
    r = _run(tmp_path, b"x", scan_fn=lambda data, **kw: ["Some.Sig"])
    assert r.payload.first_hit_only is True


# --- against a real daemon ---------------------------------------------------------

@live
def test_eicar_is_detected_by_a_real_daemon(tmp_path):
    r = _run(tmp_path, EICAR)
    assert r.status == "ok"
    assert r.payload.infected is True, r.payload.fields
    assert r.payload.signature_count >= 1
    assert any("eicar" in sig.lower() for sig in r.payload.signatures), r.payload.signatures


@live
def test_a_clean_sample_is_clean(tmp_path):
    r = _run(tmp_path, b"nothing interesting in here at all")
    assert r.status == "ok" and r.payload.infected is False


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
    assert r.payload.infected is True
    assert r.payload.first_hit_only is True


@shared_fs
def test_all_match_by_path_returns_more_than_the_first_hit(tmp_path):
    """THE TEST THAT REPLACES A WRONG ONE. Its predecessor,
    `test_all_match_is_not_reachable_over_the_socket`, asserted `ALLMATCHSCAN` answers
    `UNKNOWN COMMAND` — true only of the malformed, argument-less form the broken engine
    sent. With a path it works, and it is the difference between one label and the whole
    set the database has.

    Built rather than sampled: a zip holding EICAR twice under different names matches
    at least once per member, so all-match must report at least as many signatures as a
    first-hit scan, and the engine must mark the result as complete."""
    from blastbox.engines.clamav import scan_path, scan_stream

    z = tmp_path / "two.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.com", EICAR)
        zf.writestr("b.com", EICAR)

    streamed = scan_stream(z.read_bytes(), timeout=60)
    matched = scan_path(z, timeout=60)
    assert streamed, "the control found nothing, so this comparison proves nothing"
    assert len(matched) >= len(streamed), (
        f"all-match returned fewer signatures than first-hit: {matched} vs {streamed}")

    r = _run(tmp_path, z.read_bytes(), stream=False)
    assert r.status == "ok"
    assert r.payload.first_hit_only is False, (
        "an all-match result still claims it stopped at the first hit")


@live
def test_the_stream_fallback_still_declares_itself_incomplete(tmp_path):
    """The fallback is correct to exist — a remote daemon cannot read a local path — but
    a reader must be able to tell its `signature_count` is a floor, not a total."""
    r = _run(tmp_path, EICAR, stream=True)
    assert r.status == "ok"
    assert r.payload.first_hit_only is True


@shared_fs
def test_duplicate_signature_names_are_collapsed(tmp_path):
    """The daemon reports a signature once per object it matched inside, so an archive
    echoes the same name repeatedly. That is a fact about structure, not about which
    signatures fired, and an uncollapsed list reads as many separate findings."""
    from blastbox.engines.clamav import scan_path

    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(6):
            zf.writestr(f"m{i}.com", EICAR)
    hits = scan_path(z, timeout=60)
    assert len(hits) == len(set(hits)), f"duplicate signature names survived: {hits}"


@live
def test_the_database_version_is_sealed_with_the_verdict(tmp_path):
    r = _run(tmp_path, b"harmless")
    assert r.payload.db_version.startswith("ClamAV"), r.payload


# --- the contract itself ----------------------------------------------------

def test_the_payload_round_trips_through_the_node_parser(tmp_path):
    """Registration is what makes `parse_node()` accept the discriminator. Without it
    the type exists but every consumer round-tripping an envelope rejects the payload it
    was just sent."""
    from blastbox.contract import parse_node

    r = _run(tmp_path, b"x", scan_fn=lambda data, **kw: ["Eicar-Test-Signature"])
    node = parse_node(r.payload.model_dump(by_alias=True))
    assert node.type == "signature_scan"
    assert node.signatures == ["Eicar-Test-Signature"] and node.first_hit_only is True


def test_a_missing_database_version_cannot_be_omitted():
    """THE FIELD A READER FILLS IN OPTIMISTICALLY. A verdict with no stated signature
    age reads as one from a current database; the engine must say "unknown" out loud
    rather than leave the field off."""
    import pydantic
    from blastbox.engines.clamav import SignatureScan

    with pytest.raises(pydantic.ValidationError):
        SignatureScan(infected=False, signatures=[], signature_count=0,
                      first_hit_only=True, bytes_scanned=1)      # no db_version


def test_a_renamed_field_is_a_parse_error_not_a_silent_none():
    """THE WHOLE REASON THIS IS NOT A `Record`. Rename `first_hit_only` in a field bag
    and every reader gets `None` — which is falsy, so `signature_count: 1` silently
    starts reading as "exactly one" instead of "at least one"."""
    import pydantic
    from blastbox.engines.clamav import SignatureScan

    ok = dict(infected=True, signatures=["X"], signature_count=1, db_version="1.5.3/1",
              first_hit_only=True, bytes_scanned=1)
    SignatureScan(**ok)                                   # control: the shape is valid

    drifted = {**ok, "only_first_hit": ok.pop("first_hit_only")}
    with pytest.raises(pydantic.ValidationError):
        SignatureScan(**drifted)
