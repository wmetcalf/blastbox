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


def test_nan_max_age_is_refused_not_silently_ok():
    code, _ = wla.check_handshakes(
        "wg-test", float("nan"), now=NOW, run=_runner(_dump(("AAAAAAAAAAAA=", 1))))
    assert code == 1


def test_an_unparseable_peer_line_is_an_error_not_an_ok():
    out = _dump(("AAAAAAAAAAAA=", int(NOW) - 10)) + f"BBBBBBBBBBBB=\t{PSK}\te\t10.0.0.3/32\tX\t1\t1\toff\n"
    code, lines = wla.check_handshakes("wg-test", 180, now=NOW, run=_runner(out))
    assert code == 1
    assert PSK not in "\n".join(lines) and PRIV not in "\n".join(lines)


def test_a_handshake_far_in_the_future_is_stale():
    """After a backward clock step a dead peer's last handshake sits ahead of now."""
    code, _ = wla.check_handshakes(
        "wg-test", 180, now=NOW, run=_runner(_dump(("AAAAAAAAAAAA=", int(NOW) + 3600))))
    assert code == 2
    code, _ = wla.check_handshakes(
        "wg-test", 180, now=NOW, run=_runner(_dump(("AAAAAAAAAAAA=", int(NOW) + 5))))
    assert code == 0


def test_cli_check_on_a_host_reads_the_configured_interface(monkeypatch):
    import argparse

    from blastbox.host.worker_link import WorkerLinkConfig
    p = argparse.ArgumentParser()
    link.add_parser(p.add_subparsers())
    args = p.parse_args(["worker-link", "status", "--check", "--role", "host"])
    monkeypatch.setattr(wla, "load_config", lambda **_: WorkerLinkConfig(wg_iface="customwg0"))
    seen = []
    monkeypatch.setattr(wla, "check_handshakes",
                        lambda iface, age, **_: seen.append(iface) or (0, ["ok"]))
    assert args.func(args) == 0
    assert seen == ["customwg0"]


def _worker_check_args(*extra: str):
    import argparse
    p = argparse.ArgumentParser()
    link.add_parser(p.add_subparsers())
    return p.parse_args(["worker-link", "status", "--check", "--role", "worker", *extra])


def test_cli_check_on_a_macos_worker_reads_the_real_utun(monkeypatch):
    """macOS wg-quick runs the link on a utunN; `wg show wtwg0` would fail on a healthy link."""
    monkeypatch.setattr(link, "_platform", lambda: "darwin")
    monkeypatch.setattr(link, "_which", lambda name: f"/opt/homebrew/bin/{name}")
    resolved = []
    monkeypatch.setattr(link, "_our_real_iface_darwin",
                        lambda wg, iface: resolved.append((wg, iface)) or "utun7")
    seen, wgs = [], []
    monkeypatch.setattr(wla, "check_handshakes",
                        lambda iface, age, wg="wg", **_: seen.append(iface) or wgs.append(wg)
                        or (0, ["ok"]))
    args = _worker_check_args()
    assert args.func(args) == 0
    assert seen == ["utun7"]
    assert resolved == [("/opt/homebrew/bin/wg", link.DEFAULT_IFACE)]
    assert wgs == ["/opt/homebrew/bin/wg"]      # the dump runs the SAME resolved binary


def test_cli_check_on_a_macos_worker_with_no_verified_utun_is_an_error(monkeypatch, capsys):
    monkeypatch.setattr(link, "_platform", lambda: "darwin")
    monkeypatch.setattr(link, "_which", lambda name: f"/opt/homebrew/bin/{name}")
    monkeypatch.setattr(link, "_our_real_iface_darwin", lambda wg, iface: None)
    monkeypatch.setattr(wla, "check_handshakes",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("not reached")))
    args = _worker_check_args("--iface", "wtwg0")
    assert args.func(args) == 1
    assert "wtwg0" in capsys.readouterr().err


def test_cli_check_on_a_linux_worker_keeps_the_logical_name(monkeypatch):
    monkeypatch.setattr(link, "_platform", lambda: "linux")
    seen = []
    monkeypatch.setattr(wla, "check_handshakes",
                        lambda iface, age, **_: seen.append(iface) or (0, ["ok"]))
    args = _worker_check_args("--iface", "wtwg0")
    assert args.func(args) == 0
    assert seen == ["wtwg0"]


def test_check_handshakes_runs_the_given_wg_binary():
    """Under sudo or a launchd timer PATH may lack Homebrew: run the resolved binary."""
    argvs = []

    def run(argv, **_kw):
        argvs.append(argv)
        return subprocess.CompletedProcess(argv, 0, _dump(("AAAAAAAAAAAA=", int(NOW) - 10)), "")
    code, _ = wla.check_handshakes("utun7", 180, now=NOW, run=run, wg="/opt/homebrew/bin/wg")
    assert code == 0
    assert argvs == [["/opt/homebrew/bin/wg", "show", "utun7", "dump"]]
