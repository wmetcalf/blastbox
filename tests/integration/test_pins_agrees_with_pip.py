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


_PULL_TIMEOUT = 600
_RUN_TIMEOUT = 300

# What a REJECTION by pip looks like when pip is answering the question we
# asked. Anything else that fails -- an unreachable registry, a broken index, a
# stalled pull -- is infrastructure, and calling it "pip rejected the lock"
# turns an offline CI host into a checker disagreement it cannot reproduce.
_VERDICT_MARKERS = (
    "--require-hashes",
    "hashes are required",
    "do not match the hashes",
    "resolutionimpossible",
    "dependency resolution failed",
    "cannot install",
)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(["docker", "info"], capture_output=True, check=False).returncode
        == 0
    )


class _Unavailable(Exception):
    """The environment could not answer the question. Not a verdict."""


def _pull() -> None:
    """Fetch the image up front, so a pull failure is not read as a rejection."""
    try:
        proc = subprocess.run(
            ["docker", "pull", "-q", _IMAGE],
            capture_output=True,
            text=True,
            check=False,
            timeout=_PULL_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise _Unavailable(f"docker pull timed out after {_PULL_TIMEOUT}s") from exc
    if proc.returncode != 0:
        raise _Unavailable(f"cannot pull {_IMAGE}: {proc.stderr.strip()[-400:]}")


def _without(text: str, package: str) -> str:
    """``text`` with one package's entry and its hash lines removed."""
    return re.sub(
        rf"^{re.escape(package)}==.*?(?=^[a-zA-Z0-9]|\Z)", "", text, flags=re.S | re.M
    )


def _pip_accepts(lock: Path) -> bool:
    """Whether real pip resolves this file under --require-hashes.

    Raises `_Unavailable` when the run did not produce a resolver verdict at
    all: `docker run` failing, the process being killed, or pip failing for a
    reason that is about the network rather than about the file.
    """
    try:
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
            timeout=_RUN_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise _Unavailable(f"pip run timed out after {_RUN_TIMEOUT}s") from exc
    if proc.returncode == 0:
        return True
    output = f"{proc.stdout}\n{proc.stderr}".lower()
    if any(marker in output for marker in _VERDICT_MARKERS):
        return False
    raise _Unavailable(
        f"pip exited {proc.returncode} without a resolver verdict: "
        f"{proc.stderr.strip()[-400:]}"
    )


@pytest.mark.skipif(not _docker_available(), reason="needs a working docker")
def test_the_checker_and_pip_agree_about_install_failures(tmp_path):
    """For every variant, our INSTALL-failure verdict must match pip's.

    Gaps the checker marks runtime-only are excluded on purpose: those are the
    ones pip accepts by design, and that distinction is what this protects.
    """
    try:
        _pull()
    except _Unavailable as exc:
        pytest.skip(str(exc))
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
        try:
            accepted = _pip_accepts(lock)
        except _Unavailable as exc:
            pytest.skip(f"cannot ask pip (removed={package}): {exc}")
        if bool(claimed) != (not accepted):
            disagreements.append(
                {"removed": package, "we_claim": claimed, "pip_accepts": accepted}
            )
    assert not disagreements, f"checker and pip disagree: {disagreements}"


@pytest.mark.skipif(not _docker_available(), reason="needs a working docker")
def test_a_broken_environment_is_not_read_as_a_pip_verdict(tmp_path, monkeypatch):
    """The two failure kinds are distinguished by RUNNING them, not by reading.

    Both cases below exit non-zero. Treating that alone as "pip rejected the
    lock" reported an unreachable registry as a checker disagreement.
    """
    lock = tmp_path / "requirements.lock"
    lock.write_text(_BASE_LOCK.read_text())

    # 1. A real pip verdict: a lock with an unhashed entry cannot resolve under
    #    --require-hashes, and pip says so in terms this classifies.
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "requirements.lock").write_text("packaging==26.3\n")
    assert _pip_accepts(broken / "requirements.lock") is False

    # 2. Infrastructure: the image cannot be obtained. Same non-zero exit, and
    #    it must NOT come back as "pip rejected the lock".
    monkeypatch.setattr(
        "tests.integration.test_pins_agrees_with_pip._IMAGE",
        "blastbox.invalid/nonexistent:0",
    )
    with pytest.raises(_Unavailable):
        _pip_accepts(lock)
