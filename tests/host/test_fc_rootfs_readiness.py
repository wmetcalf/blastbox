"""A stamped rootfs that disagrees with its host must not be booted.

The failure this replaces: the microVM boots, the guest never sends READY, and
every warm job dies on the 300s timeout while the tier reports itself available.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from blastbox.host import rootfs_stamp as rfs
from blastbox.host.runtime import firecracker as fc


def _write(tree: Path, version: str) -> Path:
    rfs.write_into_tree(tree, rfs.RootfsStamp(blastbox_version=version, image="e:1"))
    return tree


def test_matching_guest_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fc, "__name__", fc.__name__)  # no-op, keeps mypy honest
    tree = _write(tmp_path, "0.1.40")
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.1.40")
    assert fc.rootfs_guest_problem(str(tree)) == ""


def test_mismatched_guest_is_refused_with_a_remedy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _write(tmp_path, "0.1.26")
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.1.40")
    problem = fc.rootfs_guest_problem(str(tree))
    assert "0.1.26" in problem and "0.1.40" in problem
    assert "build-images" in problem


def test_a_dev_wheel_is_the_same_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _write(tmp_path, "0.1.40+gdeadbee")
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.1.40")
    assert fc.rootfs_guest_problem(str(tree)) == ""


def test_unstamped_rootfs_warns_but_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Every rootfs exported before stamping existed is unstamped.

    Refusing those would take the whole fleet offline on upgrade, which is a
    worse failure than the one being prevented.
    """
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.1.40")
    with caplog.at_level(logging.WARNING):
        assert fc.rootfs_guest_problem(str(tmp_path)) == ""
    assert "no readable blastbox stamp" in caplog.text
    assert "build-images" in caplog.text


def test_an_unreadable_rootfs_is_not_a_wrong_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """"I could not look" must never be reported as "it is wrong"."""
    monkeypatch.setattr("importlib.metadata.version", lambda _n: "0.1.40")
    assert fc.rootfs_guest_problem(str(tmp_path / "does-not-exist")) == ""
