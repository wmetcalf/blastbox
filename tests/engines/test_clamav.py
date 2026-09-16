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
        fh.write(b"harmless")
        fh.flush()
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
    assert r.payload.fields["schema"] == "signature_scan_unavailable", r.payload.fields
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
    assert any("eicar" in sig.lower() for sig in r.payload.fields["signatures"]), r.payload.fields["signatures"]


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
    assert r.payload.fields["first_hit_only"] is False, (
        "an all-match result still claims it stopped at the first hit")


@live
def test_the_stream_fallback_still_declares_itself_incomplete(tmp_path):
    """The fallback is correct to exist — a remote daemon cannot read a local path — but
    a reader must be able to tell its `signature_count` is a floor, not a total."""
    r = _run(tmp_path, EICAR, stream=True)
    assert r.status == "ok"
    assert r.payload.fields["first_hit_only"] is True


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
    assert r.payload.fields["db_version"].startswith("ClamAV"), r.payload


# --- the contract itself ----------------------------------------------------

def test_the_payload_round_trips_through_the_node_parser(tmp_path):
    """Registration is what makes `parse_node()` accept the discriminator. Without it
    the type exists but every consumer round-tripping an envelope rejects the payload it
    was just sent."""
    from blastbox.contract import parse_node

    r = _run(tmp_path, b"x", scan_fn=lambda data, **kw: ["Eicar-Test-Signature"])
    node = parse_node(r.payload.model_dump(by_alias=True))
    # GENERIC ON THE WIRE. An engine runs in a container and the host validating its
    # envelope does not import it, so an engine-registered tag is rejected host-side
    # (observed live). The typed model still validated the fields on the way out.
    assert node.type == "record"
    assert node.fields["schema"] == "signature_scan"
    assert node.fields["signatures"] == ["Eicar-Test-Signature"]
    assert node.fields["first_hit_only"] is True


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


# ------------------------------------------------ unscanned is not clean

def _stub_engine(**kw):
    """A driver with both scan paths stubbed, so these exercise the decision logic."""
    from blastbox.engines.clamav import ClamAVEngine

    return ClamAVEngine(scan_fn=kw.get("scan_fn", lambda data, timeout=None: []),
                        path_scan_fn=kw.get("path_scan_fn", lambda p, timeout=None: []))


def _detonate(engine, tmp_path, size):
    from blastbox.limits import Limits

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\0" * size)
    return engine.detonate(sample, tmp_path / "out", Limits(timeout_s=30))


def test_a_file_over_the_scanner_limit_is_not_reported_clean(tmp_path, monkeypatch):
    """clamd DECLINES a file over MaxFileSize and returns no hits. Sealing that as
    `infected: false` is a false negative manufactured by configuration — and the shipped
    clamd.conf's own comment says the driver reads these limits back and says so. It
    didn't.
    """
    from blastbox.engines import clamav

    monkeypatch.setattr(clamav, "MAX_SCANNABLE_BYTES", 1024)
    res = _detonate(_stub_engine(), tmp_path, 4096)

    assert res.status == "engine_error"
    assert res.detected.label != "clean"
    assert res.detected.confidence == 0.0
    # The payload type has no `infected` field to misread — that is the whole design.
    # _sealed() puts the model on the wire as a generic Record whose `schema` field
    # names the real type — a consumer discriminates on that, and it has no `infected`.
    assert res.payload.fields["schema"] == "signature_scan_unavailable"
    assert "infected" not in res.payload.fields
    assert any(w.code == "sample_exceeds_scanner_limit" for w in res.warnings)


def test_a_file_within_the_limit_still_scans_normally(tmp_path, monkeypatch):
    from blastbox.engines import clamav

    monkeypatch.setattr(clamav, "MAX_SCANNABLE_BYTES", 1024 * 1024)
    res = _detonate(_stub_engine(), tmp_path, 4096)
    assert res.status == "ok"
    assert res.detected.label == "clean"


def test_a_scanner_outage_does_not_emit_a_high_confidence_clean_label(tmp_path):
    """The typed payload was already careful; the Detection beside it was not. The
    generic job summary surfaces that label independently, so every list view showed a
    confident CLEAN for a sample nothing had looked at."""
    from blastbox.engines.clamav import ClamdUnavailable

    def dead(*a, **kw):
        raise ClamdUnavailable("connection refused")

    res = _detonate(_stub_engine(scan_fn=dead, path_scan_fn=dead), tmp_path, 16)
    assert res.status == "engine_error"
    assert res.detected.label == "unknown" and res.detected.confidence == 0.0


def test_a_truncated_scan_that_found_nothing_is_not_clean(tmp_path):
    """`Heuristics.Limits.Exceeded` means clamd stopped early. Counting it as a
    signature reports every big archive as malware; dropping it silently reports the
    same archive as clean. It is neither."""
    from blastbox.engines.clamav import _LIMIT_HEURISTIC

    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: [_LIMIT_HEURISTIC],
                       scan_fn=lambda d, timeout=None: [_LIMIT_HEURISTIC]),
               tmp_path, 16)
    assert res.detected.label != "clean"
    assert any(w.code == "scan_truncated_by_limits" for w in res.warnings)


def test_a_truncated_scan_that_found_something_still_reports_the_signature(tmp_path):
    """The truncation must not mask a real hit that was found before the limit."""
    from blastbox.engines.clamav import _LIMIT_HEURISTIC

    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: ["Eicar-Test-Signature",
                                                             _LIMIT_HEURISTIC],
                       scan_fn=lambda d, timeout=None: ["Eicar-Test-Signature",
                                                        _LIMIT_HEURISTIC]),
               tmp_path, 16)
    assert res.detected.label == "Eicar-Test-Signature"
    assert any(w.code == "scan_truncated_by_limits" for w in res.warnings)
    # ...and the limit notice is not itself reported as a signature.
    assert _LIMIT_HEURISTIC not in (res.payload.fields.get("signatures") or [])


def test_the_config_and_the_driver_agree_on_the_limit():
    """They must, and disagreeing in the permissive direction re-opens the hole."""
    import re
    from pathlib import Path

    from blastbox.engines.clamav import MAX_SCANNABLE_BYTES

    conf = (Path(__file__).resolve().parents[2] / "deploy/clamav/clamd.conf").read_text()
    m = re.search(r"^MaxFileSize\s+(\d+)M", conf, re.M)
    assert m, "clamd.conf must state MaxFileSize"
    assert MAX_SCANNABLE_BYTES <= int(m.group(1)) * 1024 * 1024
    assert re.search(r"^AlertExceedsMax\s+true", conf, re.M), \
        "without AlertExceedsMax, 'declined' and 'clean' are identical on the wire"


def test_clamd_conf_has_no_malformed_directives():
    """A REGRESSION GUARD FOR A SELF-INFLICTED OUTAGE.

    An edit that replaced `MaxFileSize 25M` also hit `PCREMaxFileSize 25M` — the former
    is a SUBSTRING of the latter — destroying the PCRE limit and leaving a literal
    `PCRE# ...` line. clamd refuses a config with an unknown option, so every ClamAV
    worker would have failed to start, and nothing in the test suite looked at this file.
    """
    from pathlib import Path

    conf = (Path(__file__).resolve().parents[2] / "deploy/clamav/clamd.conf").read_text()
    directives = []
    for raw in conf.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        assert "#" not in line.split()[0], f"malformed directive: {raw!r}"
        assert len(line.split()) >= 2, f"directive with no value: {raw!r}"
        directives.append(line.split()[0])

    dupes = {d for d in directives if directives.count(d) > 1}
    assert not dupes, f"duplicated directives (a bad edit usually): {sorted(dupes)}"

    # The settings the driver's correctness actually depends on.
    for required in ("AlertExceedsMax", "MaxFileSize", "StreamMaxLength", "PCREMaxFileSize"):
        assert required in directives, f"{required} is missing from clamd.conf"


def test_an_empty_or_unrecognised_clamd_reply_is_not_a_clean_scan(monkeypatch):
    """Silence used to fall through the parse loop and return [] — indistinguishable
    from "scanned, nothing matched", which is then sealed `infected: false, status: ok`.
    A clean verdict manufactured by silence is the failure this engine exists to prevent."""
    from pathlib import Path

    from blastbox.engines import clamav

    for reply in ([], ["UNKNOWN COMMAND"], ["garbage without a terminator"]):
        monkeypatch.setattr(clamav, "_raw_command", lambda c, t, r=reply: r)
        with pytest.raises(clamav.ClamdUnavailable, match="no recognisable scan result"):
            clamav.scan_path(Path("/x"))

    # ...and a genuine clean reply still works.
    monkeypatch.setattr(clamav, "_raw_command", lambda c, t: ["/x: OK"])
    assert clamav.scan_path(Path("/x")) == []


def test_a_path_containing_a_colon_space_does_not_corrupt_the_signature(monkeypatch):
    """clamd echoes the path before the signature; splitting at the FIRST ": " landed
    inside filenames like "sample: copy.zip"."""
    from pathlib import Path

    from blastbox.engines import clamav

    monkeypatch.setattr(clamav, "_raw_command",
                        lambda c, t: ["/s/sample: copy.zip: Win.Trojan.Foo-1 FOUND"])
    assert clamav.scan_path(Path("/x")) == ["Win.Trojan.Foo-1"]


def test_a_truncated_scan_with_no_hits_is_not_sealed_as_clean(tmp_path):
    """The detection was downgraded to "unknown", but the PAYLOAD still said
    `infected: false` with `status="ok"` — and the payload is the thing the design says
    consumers discriminate on."""
    from blastbox.engines.clamav import _LIMIT_HEURISTIC

    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: [_LIMIT_HEURISTIC],
                                 scan_fn=lambda d, timeout=None: [_LIMIT_HEURISTIC]),
                    tmp_path, 16)
    assert res.status == "engine_error"
    assert res.payload.fields["schema"] == "signature_scan_unavailable"
    assert "infected" not in res.payload.fields
    assert res.detected.confidence == 0.0


def test_an_encrypted_archive_is_reported_unscannable(tmp_path):
    """clamd.conf has promised exactly this since it was written — "reported as
    unscannable rather than clean by the driver" — and nothing implemented it."""
    from blastbox.engines.clamav import _ENCRYPTED_HEURISTIC

    enc = f"{_ENCRYPTED_HEURISTIC}.Zip"
    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: [enc],
                                 scan_fn=lambda d, timeout=None: [enc]),
                    tmp_path, 16)
    assert res.status == "engine_error"
    assert res.payload.fields["schema"] == "signature_scan_unavailable"
    assert any(w.code == "encrypted_archive_not_scanned" for w in res.warnings)


def test_a_real_signature_alongside_an_encrypted_member_is_still_reported(tmp_path):
    from blastbox.engines.clamav import _ENCRYPTED_HEURISTIC

    hits = ["Eicar-Test-Signature", f"{_ENCRYPTED_HEURISTIC}.Zip"]
    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: hits,
                                 scan_fn=lambda d, timeout=None: hits), tmp_path, 16)
    assert res.detected.label == "Eicar-Test-Signature"
    assert _ENCRYPTED_HEURISTIC not in (res.payload.fields.get("signatures") or [])


def test_the_conf_enables_the_encrypted_alert_the_driver_depends_on():
    from pathlib import Path

    conf = (Path(__file__).resolve().parents[2] / "deploy/clamav/clamd.conf").read_text()
    assert "ArchiveBlockEncrypted true" in conf


# --------------------------------------------------------------------------------------
# The limits the conf declares and the limits the driver enforces must be one thing.
# --------------------------------------------------------------------------------------

def _conf_text() -> str:
    from pathlib import Path as _P

    return (_P(__file__).resolve().parents[2] / "deploy/clamav/clamd.conf").read_text()


def test_the_driver_reads_the_conf_limits_rather_than_a_hardcoded_copy(tmp_path, monkeypatch):
    """The conf has claimed "The driver reads them back and says so" since it was
    written. For two commits it did not: a module constant, evaluated once at import,
    with a comment asking operators to keep the two in sync by hand."""
    from blastbox.engines import clamav

    conf = tmp_path / "clamd.conf"
    conf.write_text("MaxFileSize 7M\nStreamMaxLength 9M\nPCREMaxFileSize 1M\n")
    monkeypatch.setenv(clamav.CLAMD_CONF_ENV, str(conf))
    monkeypatch.delenv("BLASTBOX_CLAMD_MAX_FILE_BYTES", raising=False)
    # The SMALLER of the two: whichever bounds the transport actually used is the point
    # past which a verdict cannot be trusted, and PCREMaxFileSize must not be mistaken
    # for MaxFileSize (that exact substring confusion corrupted this conf once already).
    assert clamav.max_scannable_bytes() == 7 * 1024 * 1024


def test_the_env_override_can_lower_the_limit_but_never_raise_it(tmp_path, monkeypatch):
    """"Set BLASTBOX_CLAMD_MAX_FILE_BYTES to match blastbox's input limit" is the
    natural operator move and it is the dangerous one: files between the conf's limit
    and the raised one are declined by clamd, come back with no hits, and seal as clean
    at confidence 1.0. An env var on the worker cannot make a daemon read more."""
    from blastbox.engines import clamav

    conf = tmp_path / "clamd.conf"
    conf.write_text("MaxFileSize 25M\nStreamMaxLength 25M\n")
    monkeypatch.setenv(clamav.CLAMD_CONF_ENV, str(conf))

    monkeypatch.setenv("BLASTBOX_CLAMD_MAX_FILE_BYTES", str(100 * 1024 * 1024))
    assert clamav.max_scannable_bytes() == 25 * 1024 * 1024, "the raise must be ignored"

    monkeypatch.setenv("BLASTBOX_CLAMD_MAX_FILE_BYTES", str(5 * 1024 * 1024))
    assert clamav.max_scannable_bytes() == 5 * 1024 * 1024, "lowering is always allowed"


def test_an_unreadable_conf_falls_back_rather_than_scanning_without_a_limit(monkeypatch):
    """A remote TCP daemon's config is not ours to read. Losing the limit entirely would
    turn every oversized file back into a silent clean."""
    from blastbox.engines import clamav

    monkeypatch.setenv(clamav.CLAMD_CONF_ENV, "/nonexistent/clamd.conf")
    monkeypatch.delenv("BLASTBOX_CLAMD_MAX_FILE_BYTES", raising=False)
    assert clamav.max_scannable_bytes() == clamav.MAX_SCANNABLE_BYTES > 0


def test_stream_max_length_is_cross_checked_too_not_only_max_file_size():
    """Only MaxFileSize was ever compared against the driver; StreamMaxLength bounds the
    INSTREAM fallback, which is the transport every remote-daemon deployment uses."""
    import re

    from blastbox.engines.clamav import _conf_size

    conf = _conf_text()
    for directive in ("MaxFileSize", "StreamMaxLength"):
        assert re.search(rf"^{directive}\s+\d+[KMG]?$", conf, re.M), f"{directive} missing"
        assert _conf_size(conf, directive), f"{directive} unparseable by the driver"
    assert _conf_size(conf, "MaxFileSize") == _conf_size(conf, "StreamMaxLength"), (
        "the path scan and the stream fallback must decline the same files, or the "
        "ClamdCannotSeePath downgrade silently changes what 'clean' means"
    )


def test_pcre_max_file_size_is_not_mistaken_for_max_file_size():
    """Anchored name matching. A substring match here is exactly how this file was
    corrupted into something clamd refuses to parse."""
    from blastbox.engines.clamav import _conf_size

    conf = "PCREMaxFileSize 1M\nMaxFileSize 25M\n"
    assert _conf_size(conf, "MaxFileSize") == 25 * 1024 * 1024
    assert _conf_size(conf, "PCREMaxFileSize") == 1024 * 1024


def test_a_commented_out_directive_is_not_read_as_set():
    from blastbox.engines.clamav import _conf_size

    assert _conf_size("# MaxFileSize 400M\nMaxFileSize 25M\n", "MaxFileSize") == 25 * 1024 * 1024


def test_the_sealed_signature_cap_matches_the_model_and_is_announced():
    """`signatures` was documented as "EVERY signature reported" and silently truncated
    to 64 with no warning, in a module whose thesis is that a result must never quietly
    say less than it knows. A count/list mismatch is inferable; inferable is not said."""
    from blastbox.engines.clamav import MAX_SEALED_SIGNATURES, SignatureScan

    field = SignatureScan.model_fields["signatures"]
    limits = [m for m in field.metadata if hasattr(m, "max_length")]
    assert limits and limits[0].max_length == MAX_SEALED_SIGNATURES, (
        "a model stricter than the slice turns a heavily-flagged sample into a sealing "
        "failure instead of a truncated result"
    )


def test_a_truncated_signature_list_carries_a_warning(tmp_path):
    from blastbox.engines.clamav import MAX_SEALED_SIGNATURES

    hits = [f"Win.Trojan.Fam{i}-1" for i in range(MAX_SEALED_SIGNATURES + 16)]
    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: hits,
                                 scan_fn=lambda d, timeout=None: hits), tmp_path, 16)
    assert res.payload.fields["signature_count"] == len(hits)
    assert len(res.payload.fields["signatures"]) == MAX_SEALED_SIGNATURES
    w = [x for x in res.warnings if x.code == "signatures_truncated"]
    assert w, "the dropped names may be the distinguishing ones; say so"
    assert str(len(hits)) in w[0].message


def test_an_unreachable_daemon_does_not_escape_detonate_as_a_raw_oserror(tmp_path, monkeypatch):
    """socket.connect() sat above the try, so a dead or not-yet-bound clamd raised
    FileNotFoundError straight out of detonate(). The harness's blanket except kept it
    from becoming a false CLEAN, but it bypassed the typed payload, db_version, the
    clamd_unavailable warning, and — for bind-mounted-socket deployments — the
    ClamdCannotSeePath downgrade to INSTREAM, so those nodes failed every job."""
    from blastbox.engines import clamav

    monkeypatch.setenv("BLASTBOX_CLAMD_SOCKET", str(tmp_path / "nope.ctl"))
    monkeypatch.delenv("BLASTBOX_CLAMD_HOST", raising=False)
    with pytest.raises(clamav.ClamdUnavailable):
        clamav._raw_command("PING", 2.0)


# --------------------------------------------------------------------------------------
# The DEFAULT scan path, offline. Every test exercising `scan_path` was gated behind
# @live/@shared_fs, so in CI (40 skipped) nothing covered it — and the offline helper
# forces BLASTBOX_CLAMD_FORCE_STREAM, so `first_hit_only` was only ever asserted True,
# which is the value the env var produces. Mutation-tested against the real suite: three
# separate reverts of this parser left every offline test green.
# --------------------------------------------------------------------------------------

def _reply(monkeypatch, lines):
    from blastbox.engines import clamav

    monkeypatch.setattr(clamav, "_raw_command", lambda c, t: list(lines))


def test_all_match_returns_every_signature_not_only_the_first(monkeypatch):
    """The whole reason ALLMATCHSCAN exists here: 344 signatures across 40 LNK samples
    where SCAN returned 36."""
    from blastbox.engines.clamav import scan_path

    _reply(monkeypatch, ["/s: Win.A-1 FOUND", "/s: Win.B-2 FOUND", "/s: Win.C-3 FOUND", "/s: OK"])
    assert scan_path(Path("/s")) == ["Win.A-1", "Win.B-2", "Win.C-3"]


def test_the_first_hit_stays_first(monkeypatch):
    """Order is the one thing a consumer can rely on to reconstruct what a first-hit
    scan would have said."""
    from blastbox.engines.clamav import scan_path

    _reply(monkeypatch, ["/s: Zzz-1 FOUND", "/s: Aaa-2 FOUND"])
    assert scan_path(Path("/s"))[0] == "Zzz-1"


def test_duplicate_signature_names_are_collapsed(monkeypatch):
    """An archive whose members all match the same family reports it once per member."""
    from blastbox.engines.clamav import scan_path

    _reply(monkeypatch, ["/a.zip: Win.X-1 FOUND", "/a.zip: Win.X-1 FOUND",
                         "/a.zip: Win.Y-2 FOUND", "/a.zip: Win.X-1 FOUND"])
    assert scan_path(Path("/a.zip")) == ["Win.X-1", "Win.Y-2"]


def test_an_error_line_in_the_reply_is_an_outage_not_a_finding(monkeypatch):
    """Deleting this branch makes a daemon that broke mid-file report a clean scan, and
    every offline test still passed."""
    from blastbox.engines import clamav

    _reply(monkeypatch, ["/s: Can't allocate memory ERROR"])
    with pytest.raises(clamav.ClamdUnavailable, match="clamd reported an error"):
        clamav.scan_path(Path("/s"))


@pytest.mark.parametrize("line", [
    "/s: File path check failure: No such file or directory. ERROR",
    "/s: lstat() failed: No such file or directory. ERROR",
    "/s: Can't access file /s ERROR",
])
def test_a_path_the_daemon_cannot_see_is_classified_for_the_stream_downgrade(monkeypatch, line):
    """Misclassifying this as a generic outage fails every job on a bind-mounted-socket
    deployment instead of degrading it to INSTREAM. Nothing pinned these strings."""
    from blastbox.engines import clamav

    _reply(monkeypatch, [line])
    with pytest.raises(clamav.ClamdCannotSeePath):
        clamav.scan_path(Path("/s"))


def test_first_hit_only_is_false_on_the_all_match_path(tmp_path, monkeypatch):
    """The offline helper forces the stream fallback, so `first_hit_only` was only ever
    asserted True — the value that env var produces, which proves nothing. Replacing
    `first_hit_only=not all_match` with a literal True passed the whole offline suite.

    It matters because `first_hit_only` is how a consumer knows whether
    `signature_count` is the whole story.
    """
    monkeypatch.delenv("BLASTBOX_CLAMD_FORCE_STREAM", raising=False)
    monkeypatch.setattr("blastbox.engines.clamav._shares_filesystem", lambda: True)
    res = _detonate(_stub_engine(path_scan_fn=lambda p, timeout=None: ["Win.A-1", "Win.B-2"]),
                    tmp_path, 16)
    assert res.payload.fields["first_hit_only"] is False
    assert res.payload.fields["signatures"] == ["Win.A-1", "Win.B-2"]


def test_first_hit_only_is_true_when_the_stream_fallback_was_used(tmp_path, monkeypatch):
    """The other half, so the field is pinned in both directions rather than to one
    constant."""
    monkeypatch.setenv("BLASTBOX_CLAMD_FORCE_STREAM", "1")
    res = _detonate(_stub_engine(scan_fn=lambda d, timeout=None: ["Win.A-1"]), tmp_path, 16)
    assert res.payload.fields["first_hit_only"] is True


def test_the_clamav_engine_warms_by_proving_the_daemon_answers(monkeypatch):
    """serve_warm signals READY only after warmup(), and the gVisor checkpoint is taken
    there. A slot that reached READY without ever speaking to clamd restores into the
    same ignorance on every job."""
    from blastbox.engines import clamav

    calls = []
    monkeypatch.setattr(clamav, "ping", lambda t=1.0: calls.append(t) or True)
    clamav.ClamAVEngine().warmup()
    assert calls, "warmup() must actually probe the daemon"


def test_a_dead_daemon_does_not_kill_the_slot_at_warmup(monkeypatch):
    """A reaped slot cannot seal a signature_scan_unavailable payload saying why."""
    from blastbox.engines import clamav

    monkeypatch.setattr(clamav, "ping", lambda t=1.0: False)
    clamav.ClamAVEngine().warmup()  # must not raise
