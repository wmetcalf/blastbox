"""`blastbox claim-key show|reset`, which had no test at all (#178, round five).

It is the documented diagnostic for the one multi-host fault that reads like a certificate
problem -- two ingress hosts deriving different signing keys -- so a regression in it does not
report a failure, it reports false agreement. Seven distinct outcomes, none of them asserted
until now; a reviewer's mutation pass found the whole command unguarded.
"""
from __future__ import annotations

import argparse

import pytest

from blastbox.host import cli
from blastbox.host.node_auth import SECRET_FILE_ENV


def run(monkeypatch, capsys, *, sub="show", yes=False, env=None):
    for k in ("BLASTBOX_DATABASE_URL", "BLASTBOX_API_KEY", SECRET_FILE_ENV):
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    rc = cli._claim_key_cmd(argparse.Namespace(claim_key_cmd=sub, yes=yes))
    return rc, capsys.readouterr().out


def test_the_file_override_wins_and_says_so(monkeypatch, capsys, tmp_path):
    """`resolve_claim_secret` returns the file before it ever looks at the store, so reporting
    the queue's row on such a host answers a different question than the operator asked."""
    rc, out = run(monkeypatch, capsys, env={SECRET_FILE_ENV: str(tmp_path / "k"),
                                            "BLASTBOX_DATABASE_URL": "sqlite:///x"})
    assert rc == 1 and "FILE" in out


def test_without_a_dsn_it_refuses_rather_than_reporting_on_a_throwaway(monkeypatch, capsys):
    """The factory hands back an in-memory store with no DSN -- which satisfies the registry, so
    `reset --yes` printed success while mutating a throwaway object. An operator rotating a
    suspected-compromised key would restart the fleet onto the same key, told it had changed."""
    rc, out = run(monkeypatch, capsys, sub="reset", yes=True)
    assert rc == 2 and "BLASTBOX_DATABASE_URL" in out


def test_reset_without_yes_refuses_and_explains_the_stopped_fleet_rule(monkeypatch, capsys,
                                                                       tmp_path):
    rc, out = run(monkeypatch, capsys, sub="reset",
                  env={"BLASTBOX_DATABASE_URL": f"sqlite:///{tmp_path/'q.db'}"})
    assert rc == 2 and "STOPPED fleet" in out


def test_show_reports_absence_then_presence(monkeypatch, capsys, tmp_path):
    dsn = f"sqlite:///{tmp_path/'q.db'}"
    rc, out = run(monkeypatch, capsys, env={"BLASTBOX_DATABASE_URL": dsn})
    assert rc == 0 and "no node signing key recorded" in out

    from blastbox.host.jobs.factory import build_job_store_from_env

    monkeypatch.setenv("BLASTBOX_DATABASE_URL", dsn)
    build_job_store_from_env().claim_signing_key("ab" * 32)
    rc, out = run(monkeypatch, capsys, env={"BLASTBOX_DATABASE_URL": dsn})
    assert rc == 0 and "recorded" in out
    assert "ab" * 32 not in out, "the command printed the key itself"


def test_the_fingerprint_is_of_the_EFFECTIVE_key_so_two_hosts_can_differ(monkeypatch, capsys,
                                                                         tmp_path):
    """BLASTBOX_API_KEY is the pepper, so the STORED value is identical on every host by
    construction: fingerprinting it meant the command whose whole purpose is "confirm two hosts
    agree" could never report a difference, and would actively confirm agreement between a
    keyed and a keyless ingress -- exactly the split that breaks node sessions."""
    dsn = f"sqlite:///{tmp_path/'q.db'}"
    monkeypatch.setenv("BLASTBOX_DATABASE_URL", dsn)
    from blastbox.host.jobs.factory import build_job_store_from_env

    build_job_store_from_env().claim_signing_key("cd" * 32)

    _rc, unkeyed = run(monkeypatch, capsys, env={"BLASTBOX_DATABASE_URL": dsn})
    _rc, keyed = run(monkeypatch, capsys, env={"BLASTBOX_DATABASE_URL": dsn,
                                               "BLASTBOX_API_KEY": "s3cret"})
    _rc, other = run(monkeypatch, capsys, env={"BLASTBOX_DATABASE_URL": dsn,
                                               "BLASTBOX_API_KEY": "different"})

    def fp(text):
        return text.split("fingerprint ")[1].split(")")[0].strip()

    assert fp(unkeyed) != fp(keyed), (
        "a keyed and an unkeyed ingress fingerprinted the same, so the diagnostic confirms an "
        "agreement that does not exist")
    assert fp(keyed) != fp(other), "two different API keys fingerprinted the same"
    assert "s3cret" not in keyed


@pytest.mark.parametrize("sub", ["show", "reset"])
def test_a_store_that_cannot_record_a_key_says_which(monkeypatch, capsys, sub, tmp_path):
    class NoRegistry:
        pass

    monkeypatch.setattr("blastbox.host.jobs.factory.build_job_store_from_env",
                        lambda *a, **k: NoRegistry())
    rc, out = run(monkeypatch, capsys, sub=sub, yes=True,
                  env={"BLASTBOX_DATABASE_URL": f"sqlite:///{tmp_path/'q.db'}"})
    assert rc == 1 and "NoRegistry" in out
