"""Differential test: the lock checker against the tool it predicts.

`missing_from_locks` reasons statically about what `pip install
--require-hashes` will accept -- markers, extras, hashes, closures. Everything
it knows is a MODEL of pip, and a model drifts.

It already drifted once. The checker was built on "a missing dependency makes
the install fail", and against real pip that is only true for base requirements
and for packages something else in the file needs. Removing `fastapi` from a
lock whose line reads `blastbox==...` installs perfectly well; removing it from
one reading `blastbox[host]==...` does not. Thirteen of sixteen single-package
removals from RedTusk's own lock were accepted by pip while the checker called
them gaps, because the extras a repository DECLARES are not the extras a lock
LINE binds.

So this asks pip directly, on the same inputs, and requires the two to agree
about install failures. It is slow and needs docker and the network, which is
why it is marked -- but a unit test cannot catch this class at all, because the
thing being tested is whether our idea of pip matches pip.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from blastbox.host.cli import _requirements_of
from blastbox.host.pins import missing_from_locks

pytestmark = pytest.mark.docker

_IMAGE = "python:3.12-slim-bookworm"
_HERE = Path(__file__).parent
# A REAL compiled closure for `blastbox==0.1.39`, hashes and all, produced by
# `uv pip compile --generate-hashes --python-version 3.12`. Small on purpose:
# seven packages is enough to exercise the invariant and small enough to read.
_BASE_LOCK = _HERE / "pip_agreement_base.lock"
_REQUIRES = _HERE / "pip_agreement_requires.json"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, check=False).returncode
        == 0
    )


def _without(text: str, package: str) -> str:
    """``text`` with one package's entry and its hash lines removed."""
    return re.sub(
        rf"^{re.escape(package)}==.*?(?=^[a-zA-Z0-9]|\Z)", "", text, flags=re.S | re.M
    )


def _pip_accepts(lock: Path) -> bool:
    """Whether real pip resolves this file under --require-hashes."""
    proc = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{lock.parent}:/w:ro",
            _IMAGE,
            "pip",
            "install",
            "-q",
            "--no-cache-dir",
            "--dry-run",
            "--require-hashes",
            "-r",
            f"/w/{lock.name}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="needs a working docker")
def test_the_checker_and_pip_agree_about_install_failures(tmp_path):
    """For every variant, our INSTALL-failure verdict must match pip's.

    Gaps the checker marks runtime-only are excluded on purpose: those are the
    ones pip accepts by design, and that distinction is what this protects.
    """
    base = _BASE_LOCK.read_text()
    requires = json.loads(_REQUIRES.read_text())
    packages = sorted(
        set(re.findall(r"^([a-zA-Z0-9_.-]+)==", base, re.M)) - {"blastbox"}
    )
    assert packages, "the fixture lock pins nothing but blastbox"

    disagreements = []
    for package in [None, *packages]:
        body = base if package is None else _without(base, package)
        lock = tmp_path / "requirements.lock"
        lock.write_text(body)
        ours = missing_from_locks(tmp_path, requires, requirements_of=_requirements_of)
        claimed = [
            gap
            for entries in ours.values()
            for gap in entries
            if "not an install failure" not in gap
        ]
        accepted = _pip_accepts(lock)
        if bool(claimed) != (not accepted):
            disagreements.append(
                {"removed": package, "we_claim": claimed, "pip_accepts": accepted}
            )
    assert not disagreements, f"checker and pip disagree: {disagreements}"
