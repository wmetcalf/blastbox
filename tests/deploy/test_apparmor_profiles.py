"""Every AppArmor profile this repo ships must COMPILE.

A profile is data until a parser reads it, and the parser only runs on a host during
deployment -- so a syntax error here is discovered by an operator, at the moment they are
trying to fix something else. `apparmor_parser -Q` preprocesses and compiles without loading
(no root, no kernel change), which is exactly the half that can be wrong in a text file.

`blastbox-sandbox` is the child profile the backends attach to the detonated workload. Until
#160 the code demanded it by default and this directory did not contain it, so every host
reported `apparmor_missing` -- and once that became a real insecurity reason, a bare-metal
host had no selectable inner backend at all.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_PROFILE_DIR = Path(__file__).resolve().parents[2] / "deploy" / "apparmor"
_PROFILES = sorted(p for p in _PROFILE_DIR.glob("blastbox-*") if p.is_file())


def test_the_directory_is_not_empty() -> None:
    """Guards the glob itself: a rename that stops matching would otherwise turn every
    parametrised test below into zero tests, silently."""
    assert _PROFILES, f"no blastbox-* profiles found in {_PROFILE_DIR}"


def test_the_child_profile_is_shipped() -> None:
    """The one the code asks for BY DEFAULT (apparmor.DEFAULT_PROFILE)."""
    from blastbox.worker.sandbox.apparmor import DEFAULT_PROFILE

    assert (_PROFILE_DIR / DEFAULT_PROFILE).is_file(), (
        f"the backends attach {DEFAULT_PROFILE!r} by default and this repo does not ship it"
    )


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser not installed on this host")
@pytest.mark.parametrize("profile", _PROFILES, ids=lambda p: p.name)
def test_the_profile_compiles(profile: Path, tmp_path: Path) -> None:
    res = subprocess.run(
        ["apparmor_parser", "-Q", f"--cache-loc={tmp_path}", str(profile)],
        capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, f"{profile.name} does not compile:\n{res.stderr}"


@pytest.mark.parametrize("profile", _PROFILES, ids=lambda p: p.name)
def test_the_profile_declares_its_own_name(profile: Path) -> None:
    """`aa-exec -p <name>` and `profile_loaded(<name>)` both key on the NAME, so a file whose
    profile is declared under a different one loads fine and is then never found."""
    text = profile.read_text()
    assert f"profile {profile.name} " in text, (
        f"{profile.name} does not declare `profile {profile.name}`"
    )


def test_the_child_profile_closes_the_proc_surface_that_proc_rw_opens() -> None:
    """The reason this profile is not optional hardening.

    Attaching it is what makes the nsjail backend pass `--proc_rw`, and that flag makes
    /proc/self/mem (among others) writable for the child -- a payload rewriting its own
    executable mappings without mprotect. The profile is the mitigation for the flag it
    enables, so the deny rules travel with it or the trade does not close.
    """
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    for needed in ("/proc/*/mem", "/proc/*/clear_refs", "/proc/*/oom_score_adj",
                   "change_profile", "ptrace"):
        assert f"deny {needed}" in text or f"audit deny {needed}" in text, (
            f"blastbox-sandbox does not deny {needed}"
        )


def test_the_child_profile_permits_the_selector_probe() -> None:
    """`select_sandbox` smoketests each backend by running /usr/bin/true through it, with the
    profile attached. A child profile that denies the probe takes the backend down -- which is
    a real failure mode, diagnosed in detect.py, and not one the SHIPPED profile may have."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    assert "/** rwlkmix," in text, (
        "the shipped profile no longer permits the workload (and the selector probe) to exec"
    )
