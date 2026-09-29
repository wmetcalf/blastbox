"""`blastbox attest-key`: print the public half of the host attestation key for pinning."""
from __future__ import annotations

import stat

from blastbox.host import attest, cli


def _run(monkeypatch, capsys, env, *extra):
    for k in ("BLASTBOX_ATTEST_KEY", "BLASTBOX_PKI_DIR"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    rc = cli.main(["attest-key", *extra])
    return rc, capsys.readouterr()


def test_generates_and_prints_pem_and_key_id(monkeypatch, capsys, tmp_path):
    rc, cap = _run(monkeypatch, capsys,
                   {"BLASTBOX_ATTEST_KEY": str(tmp_path / "pki" / "attest.key")})
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
    assert "BLASTBOX_ATTEST_KEY" in cap.err
    assert list(tmp_path.iterdir()) == []


def test_pki_dir_alone_does_not_enable_it(monkeypatch, capsys, tmp_path):
    rc, cap = _run(monkeypatch, capsys, {"BLASTBOX_PKI_DIR": str(tmp_path / "pki")})
    assert rc == 2 and "BLASTBOX_ATTEST_KEY" in cap.err
    assert not (tmp_path / "pki").exists()


def test_refuses_a_key_owned_by_another_user_and_says_who_to_run_as(monkeypatch, capsys,
                                                                    tmp_path):
    import os

    path = tmp_path / "attest.key"
    attest.load_or_create_key(path)
    owner = os.stat(path).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
    rc, cap = _run(monkeypatch, capsys, {"BLASTBOX_ATTEST_KEY": str(path)})
    assert rc == 1
    assert "sudo -u" in cap.err and "service user" in cap.err
    assert "BEGIN PUBLIC KEY" not in cap.out


def test_root_on_a_fresh_host_refuses_to_mint(monkeypatch, capsys, tmp_path):
    """Minting as root makes a root-owned key a non-root dispatcher then refuses."""
    import os

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    path = tmp_path / "attest.key"
    rc, cap = _run(monkeypatch, capsys, {"BLASTBOX_ATTEST_KEY": str(path)})
    assert rc == 1
    assert "sudo -u" in cap.err and "--allow-root" in cap.err
    assert not path.exists()


def test_help_says_to_run_as_the_dispatchers_user(capsys):
    import pytest

    with pytest.raises(SystemExit):
        cli.main(["attest-key", "--help"])
    out = capsys.readouterr().out
    assert "service user" in out and "BLASTBOX_ATTEST_KEY" in out
