"""`worker-link status --check`: exit 2 on a stale or never-made handshake."""
from __future__ import annotations

import subprocess

from blastbox.host import worker_link_apply as wla
from blastbox.worker import link

NOW = 1_800_000_000.0
PRIV = "PRIVATEKEYPRIVATEKEYPRIVATEKEYPRIVATEKEY0="
PSK = "PRESHAREDPRESHAREDPRESHAREDPRESHAREDPSK0="


def _dump(*peers: tuple[str, int]) -> str:
    lines = [f"{PRIV}\tPUBIFACE=\t51820\toff"]
    for key, hs in peers:
        lines.append(f"{key}\t{PSK}\t1.2.3.4:5\t10.0.0.2/32\t{hs}\t10\t20\toff")
    return "\n".join(lines) + "\n"


def _runner(out: str, rc: int = 0):
    def run(argv, **_kw):
        assert argv == ["wg", "show", "wg-test", "dump"]
        return subprocess.CompletedProcess(argv, rc, out, "")
    return run


def test_all_fresh_exits_0():
    code, lines = wla.check_handshakes(
        "wg-test", 180, now=NOW,
        run=_runner(_dump(("AAAAAAAAAAAA=", int(NOW) - 10), ("BBBBBBBBBBBB=", int(NOW) - 179))))
    assert code == 0 and "2 peer" in lines[0]


def test_stale_peer_exits_2_and_names_it_truncated():
    code, lines = wla.check_handshakes(
        "wg-test", 180, now=NOW,
        run=_runner(_dump(("AAAAAAAAAAAA=", int(NOW) - 10), ("BBBBBBBBBBBB=", int(NOW) - 181))))
    text = "\n".join(lines)
    assert code == 2
    assert "BBBBBBBB:" in text and "181s" in text and "AAAAAAAA" not in text
    assert "BBBBBBBBBBBB" not in text


def test_never_handshaked_exits_2():
    code, lines = wla.check_handshakes(
        "wg-test", 180, now=NOW, run=_runner(_dump(("CCCCCCCCCCCC=", 0))))
    assert code == 2 and "never handshaked" in "\n".join(lines)


def test_no_secret_is_ever_printed():
    _, lines = wla.check_handshakes(
        "wg-test", 180, now=NOW, run=_runner(_dump(("CCCCCCCCCCCC=", 0), ("DDDDDDDDDDDD=", 5))))
    text = "\n".join(lines)
    assert PRIV not in text and PSK not in text and "PRIVATEKEY" not in text


def test_read_error_exits_1():
    assert wla.check_handshakes("wg-test", 180, now=NOW, run=_runner("", rc=1))[0] == 1
    assert wla.check_handshakes("wg-test", 180, now=NOW, run=_runner(_dump()))[0] == 1


def test_missing_binary_exits_1():
    def run(argv, **_kw):
        raise FileNotFoundError("wg")
    assert wla.check_handshakes("wg-test", 180, now=NOW, run=run)[0] == 1


def test_cli_check_exit_codes(monkeypatch, capsys):
    import argparse
    p = argparse.ArgumentParser()
    link.add_parser(p.add_subparsers())
    args = p.parse_args(["worker-link", "status", "--check", "--iface", "wg-test",
                         "--max-handshake-age", "60"])
    monkeypatch.setattr(wla, "check_handshakes",
                        lambda iface, age, **_: (2, [f"STALE {iface} {age}"]))
    assert args.func(args) == 2
    assert "STALE wg-test 60.0" in capsys.readouterr().out
