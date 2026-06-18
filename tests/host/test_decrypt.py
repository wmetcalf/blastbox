"""TDD tests for blastbox.host.decrypt — GoGoRoboCap TLS-decrypt command builders + orchestration.

GoGoRoboCap (github.com/wmetcalf/GoGoRoboCap) replays a captured pcap's TLS flows into cleartext
given the session keys. CLI grounded in CAPE's decryptpcap.py + a live toolz2 run
(curl+SSLKEYLOGFILE → keylog → decrypted.pcap). This module holds the pure argv builders + a
seam-injected orchestration (no subprocess in tests).
"""
from __future__ import annotations

import pytest

from blastbox.host.decrypt import (
    DecryptResult,
    decrypt_capture,
    gogorobocap_keylog_argv,
    gogorobocap_sslproxy_clean_argv,
)


# --------------------------------------------------------------------------- argv builders
def test_keylog_argv_matches_cape_cli():
    argv = gogorobocap_keylog_argv("/bin/ggrc", "/j/dump.pcap", "/j/keys.log", "decrypted", "/j/out.pcap")
    assert argv == [
        "/bin/ggrc",
        "-i", "/j/dump.pcap",
        "-keylog", "/j/keys.log",
        "-tlsmode", "decrypted",
        "-o", "/j/out.pcap",
    ]


def test_keylog_argv_rejects_bad_mode():
    with pytest.raises(ValueError):
        gogorobocap_keylog_argv("/bin/ggrc", "p", "k", "plaintext", "o")


@pytest.mark.parametrize("mode", ["decrypted", "mixed"])
def test_keylog_argv_accepts_valid_modes(mode):
    assert gogorobocap_keylog_argv("b", "p", "k", mode, "o")[-3] == mode


def test_sslproxy_clean_argv():
    argv = gogorobocap_sslproxy_clean_argv("/bin/ggrc", "/j/sslproxy.pcap", "/j/clean.pcap")
    assert argv == ["/bin/ggrc", "-sslproxy-clean", "-i", "/j/sslproxy.pcap", "-o", "/j/clean.pcap"]


# --------------------------------------------------------------------------- decrypt_capture
def _seam(produced, *, rc=0, make_output=True):
    """A run_fn that records argv and (optionally) creates a non-trivial output pcap."""
    def run_fn(argv):
        produced.append(argv)
        if make_output:
            out = argv[argv.index("-o") + 1]
            with open(out, "wb") as fh:
                fh.write(b"\xd4\xc3\xb2\xa1" + b"x" * 200)  # > pcap header
        return rc
    return run_fn


def test_decrypt_capture_runs_decrypted_and_mixed(tmp_path):
    pcap = tmp_path / "dump.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"y" * 200)
    keylog = tmp_path / "sslkeys.log"
    keylog.write_text("SERVER_HANDSHAKE_TRAFFIC_SECRET abc def\n")
    produced: list = []

    res = decrypt_capture(
        binary="/bin/ggrc", pcap_path=str(pcap), keylog_path=str(keylog),
        out_dir=str(tmp_path), run_fn=_seam(produced),
    )

    assert isinstance(res, DecryptResult)
    # Both modes invoked, in value position.
    modes = [a[a.index("-tlsmode") + 1] for a in produced]
    assert set(modes) == {"decrypted", "mixed"}
    assert res.decrypted_path == str(tmp_path / "decrypted.pcap")
    assert res.mixed_path == str(tmp_path / "mixed.pcap")


def test_decrypt_capture_skips_when_no_keylog(tmp_path):
    pcap = tmp_path / "dump.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"y" * 200)
    produced: list = []
    res = decrypt_capture(
        binary="/bin/ggrc", pcap_path=str(pcap), keylog_path=str(tmp_path / "missing.log"),
        out_dir=str(tmp_path), run_fn=_seam(produced),
    )
    assert res is None
    assert produced == []  # nothing run without keys


def test_decrypt_capture_none_when_output_empty(tmp_path):
    # GoGoRoboCap ran but produced no usable output (no TLS flows) → no artifact.
    pcap = tmp_path / "dump.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"y" * 200)
    keylog = tmp_path / "sslkeys.log"
    keylog.write_text("x\n")
    res = decrypt_capture(
        binary="/bin/ggrc", pcap_path=str(pcap), keylog_path=str(keylog),
        out_dir=str(tmp_path), run_fn=_seam([], make_output=False),
    )
    assert res is None


def test_decrypt_capture_swallows_runner_errors(tmp_path):
    pcap = tmp_path / "dump.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"y" * 200)
    keylog = tmp_path / "sslkeys.log"
    keylog.write_text("x\n")

    def boom(argv):
        raise RuntimeError("ggrc crashed")

    # Best-effort: a decryptor crash must not raise (the job's capture is still sealed).
    res = decrypt_capture(
        binary="/bin/ggrc", pcap_path=str(pcap), keylog_path=str(keylog),
        out_dir=str(tmp_path), run_fn=boom,
    )
    assert res is None
