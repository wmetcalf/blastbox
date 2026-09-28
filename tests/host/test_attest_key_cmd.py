"""`blastbox attest-key`: print the public half of the host attestation key for pinning."""
from __future__ import annotations

import stat

from blastbox.host import attest, cli


def _run(monkeypatch, capsys, env):
    for k in ("BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    rc = cli.main(["attest-key"])
    return rc, capsys.readouterr()


def test_generates_and_prints_pem_and_key_id(monkeypatch, capsys, tmp_path):
    rc, cap = _run(monkeypatch, capsys, {"BLASTBOX_PKI_DIR": str(tmp_path / "pki")})
    assert rc == 0
    path = tmp_path / "pki" / "attest.key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    key = attest.load_or_create_key(path)
    assert key.public_key_pem in cap.out
    assert f"key_id: {key.key_id}" in cap.out
    assert "PRIVATE" not in cap.out


def test_is_stable_across_runs(monkeypatch, capsys, tmp_path):
    env = {"BLASTBOX_ATTEST_KEY": str(tmp_path / "k.pem")}
    _, first = _run(monkeypatch, capsys, env)
    _, second = _run(monkeypatch, capsys, env)
    assert first.out == second.out


def test_unconfigured_says_how_to_enable_and_creates_nothing(monkeypatch, capsys, tmp_path):
    monkeypatch.chdir(tmp_path)
    rc, cap = _run(monkeypatch, capsys, {})
    assert rc == 2
    assert "BLASTBOX_ATTEST_KEY" in cap.err and "BLASTBOX_PKI_DIR" in cap.err
    assert list(tmp_path.iterdir()) == []
