"""The rootfs stamp: the record that survives `docker export` into the guest."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from blastbox.host import rootfs_stamp as rfs


def _stamp(**kw: str) -> rfs.RootfsStamp:
    base = dict(
        blastbox_version="0.1.40",
        image="clippyshot-fc-worker:0140",
        image_id="sha256:abc",
        revision="deadbeef",
        exported_at="2026-09-18T20:00:00Z",
    )
    base.update(kw)
    return rfs.RootfsStamp(**base)  # type: ignore[arg-type]


def test_roundtrip_through_json() -> None:
    s = _stamp()
    assert rfs.RootfsStamp.from_json(s.to_json()) == s


def test_from_json_ignores_unknown_keys_and_nulls() -> None:
    body = json.dumps({"blastbox_version": "0.1.40", "future_field": 1, "image": None})
    got = rfs.RootfsStamp.from_json(body)
    assert got.blastbox_version == "0.1.40"
    assert got.image == ""


def test_from_json_rejects_non_objects() -> None:
    with pytest.raises(rfs.RootfsStampError):
        rfs.RootfsStamp.from_json("[1, 2]")
    with pytest.raises(rfs.RootfsStampError):
        rfs.RootfsStamp.from_json("not json")


def test_write_into_tree_then_read_from_dir(tmp_path: Path) -> None:
    written = rfs.write_into_tree(tmp_path, _stamp())
    assert written == tmp_path / rfs.STAMP_PATH
    assert rfs.read(tmp_path) == _stamp()


def test_read_from_dir_says_unstamped_not_missing_file(tmp_path: Path) -> None:
    with pytest.raises(rfs.RootfsStampError, match="unstamped"):
        rfs.read_from_dir(tmp_path)


def test_privileged_write_uses_the_runner_at_that_privilege(tmp_path: Path) -> None:
    """A root-extracted tree is written through the same privilege, not directly."""
    calls: list[list[str]] = []

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    rfs.write_into_tree(tmp_path, _stamp(), priv=["sudo", "-n"], run=run)
    assert len(calls) == 1, "one command, one privilege level"
    argv = calls[0]
    assert argv[:3] == ["sudo", "-n", "install"]
    assert argv[-1] == str(tmp_path / rfs.STAMP_PATH)
    assert "-D" in argv and "root" in argv


def test_privileged_write_takes_no_kwargs_the_runner_lacks(tmp_path: Path) -> None:
    """The export runner accepts argv/cwd/capture_output/stdout and nothing else.

    A `text=`/`input=` kwarg here is a TypeError deep inside a real export, long
    after every image has been built.
    """
    seen: list[dict] = []

    def run(argv, *, cwd=None, capture_output=False, stdout=None):  # type: ignore[no-untyped-def]
        seen.append({"cwd": cwd, "capture_output": capture_output, "stdout": stdout})
        return subprocess.CompletedProcess(argv, 0, "", "")

    rfs.write_into_tree(tmp_path, _stamp(), priv=["sudo"], run=run)
    assert seen == [{"cwd": None, "capture_output": True, "stdout": None}]


def test_privileged_write_surfaces_failure(tmp_path: Path) -> None:
    def run(argv, **kw):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(argv, 1, "", "denied")

    with pytest.raises(rfs.RootfsStampError, match="denied"):
        rfs.write_into_tree(tmp_path, _stamp(), priv=["sudo"], run=run)


def test_read_from_ext4_parses_debugfs_output(tmp_path: Path) -> None:
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")
    body = _stamp().to_json()

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        assert argv[0] == "debugfs"
        assert argv[1] == "-R"
        assert argv[2] == f"cat /{rfs.STAMP_PATH}"
        return subprocess.CompletedProcess(argv, 0, body, "")

    assert rfs.read_from_ext4(img, run=run) == _stamp()


def test_read_from_ext4_empty_output_is_unstamped_even_on_exit_zero(
    tmp_path: Path,
) -> None:
    """debugfs reports a missing file on stderr and STILL exits 0."""
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(argv, 0, "", "File not found by ext2_lookup")

    with pytest.raises(rfs.RootfsStampError, match="carries no"):
        rfs.read_from_ext4(img, run=run)


def test_read_from_ext4_missing_image(tmp_path: Path) -> None:
    with pytest.raises(rfs.RootfsStampError, match="does not exist"):
        rfs.read_from_ext4(tmp_path / "nope.ext4")


@pytest.mark.parametrize(
    ("guest", "host", "agrees"),
    [
        ("0.1.40", "0.1.40", True),
        ("0.1.40+gdeadbee", "0.1.40", True),  # dev wheel, same release
        ("0.1.40", "0.1.40+gdeadbee", True),
        ("0.1.35", "0.1.40", False),
        ("0.1.40", "0.1.26", False),
    ],
)
def test_compare_to_host(guest: str, host: str, agrees: bool) -> None:
    complaint = rfs.compare_to_host(_stamp(blastbox_version=guest), host)
    assert (complaint == "") is agrees
    if not agrees:
        assert guest in complaint and host in complaint


def test_compare_to_host_flags_a_stamp_with_no_version() -> None:
    assert rfs.compare_to_host(_stamp(blastbox_version=""), "0.1.40")
