"""Stamp the artifact a warm tier BOOTS, and read it back without mounting.

`stamp.py` records what an image was built from, in OCI labels, and `doctor.py`
compares the versions running inside containers. Neither reaches the one
artifact a warm tier actually boots: the exported rootfs. ``docker export``
writes a filesystem and drops the image config, so every label goes with it --
which is why the engine name is already written to a FILE (`/opt/blastbox/engine`)
rather than carried in ENV.

The cost of that gap, measured on toolz2 2026-09-18: clippyshot's FC rootfs had
been exported by hand in July from an image generation that no longer matched the
host tier. The microVM booted, the guest never sent READY, and every warm job
died on the 300s timeout -- for two months, while the API answered 200 and the
fleet's own health check reported the engine live. Three separate engines were in
that state. Nothing compared the rootfs to anything, because nothing could.

So the stamp is written INTO the tree before the filesystem is made, and read
back out of the finished ext4 with `debugfs -R cat` -- no mount, no loop device,
the same discipline the host side uses for disks it did not create.

What it carries is what makes a mismatch diagnosable rather than mysterious:
the blastbox version the GUEST has, the image and its ID, the source revision,
and when it was exported.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

#: Inside the rootfs. Kept next to `/opt/blastbox/engine`, which exists for the
#: same reason -- image config does not survive `docker export`.
STAMP_PATH = "opt/blastbox/rootfs-stamp.json"


class RootfsStampError(RuntimeError):
    """The rootfs stamp could not be written, read, or trusted."""


@dataclass(frozen=True)
class RootfsStamp:
    """What a booted rootfs says about itself."""

    blastbox_version: str = ""
    image: str = ""
    image_id: str = ""
    revision: str = ""
    exported_at: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> "RootfsStamp":
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise RootfsStampError(f"rootfs stamp is not JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise RootfsStampError("rootfs stamp is not a JSON object")
        known = {f: raw.get(f, "") for f in cls.__dataclass_fields__}
        return cls(**{k: ("" if v is None else str(v)) for k, v in known.items()})


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_into_tree(
    tree: Path | str,
    stamp: RootfsStamp,
    *,
    priv: Sequence[str] = (),
    run: Runner | None = None,
) -> Path:
    """Write the stamp into an extracted tree, before the filesystem is made.

    Placed through the SAME privilege the extraction used. The tree is extracted
    as root so ownership and setuid bits survive, so an unprivileged write into
    it fails -- after every image has been built and verified, which is the worst
    possible moment to find out.

    The content is staged to a caller-owned temp file and moved in with a single
    `install`, because the runner this module is handed takes an argv and nothing
    else: there is no stdin to pipe a heredoc through.
    """
    tree = Path(tree)
    target = tree / STAMP_PATH
    body = stamp.to_json()
    if not priv:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        return target
    if run is None:  # pragma: no cover - defensive
        raise RootfsStampError("a privileged write needs a runner")
    with tempfile.NamedTemporaryFile(
        "w", suffix=".rootfs-stamp.json", delete=False
    ) as fh:
        fh.write(body)
        staged = fh.name
    try:
        # -D makes the parent, -o/-g give it the ownership the rest of the tree
        # has. One command, one privilege level: the export's invariant.
        proc = run(
            [
                *priv,
                "install",
                "-D",
                "-m",
                "0644",
                "-o",
                "root",
                "-g",
                "root",
                staged,
                str(target),
            ],
            capture_output=True,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip() or f"exit {proc.returncode}"
            raise RootfsStampError(f"could not write {target}: {detail}")
    finally:
        Path(staged).unlink(missing_ok=True)
    return target


def read_from_dir(tree: Path | str) -> RootfsStamp:
    """Read the stamp from an exported directory rootfs (the gVisor kind)."""
    path = Path(tree) / STAMP_PATH
    try:
        return RootfsStamp.from_json(path.read_text())
    except FileNotFoundError as exc:
        raise RootfsStampError(f"{path} is missing: this rootfs is unstamped") from exc


def read_from_ext4(image: Path | str, *, run: Runner | None = None) -> RootfsStamp:
    """Read the stamp out of an ext4 WITHOUT mounting it.

    `debugfs` reads the filesystem as a file. Mounting would need root, a loop
    device, and would attach a filesystem this host did not create -- which the
    export side already refuses to do, and the read side has no better reason to.
    """
    image = Path(image)
    if not image.is_file():
        raise RootfsStampError(f"{image} does not exist")
    if shutil.which("debugfs") is None:
        raise RootfsStampError(
            "debugfs (e2fsprogs) is not installed, so the rootfs stamp cannot be "
            "read without mounting the image; install e2fsprogs"
        )
    runner = run or _default_runner
    proc = runner(
        ["debugfs", "-R", f"cat /{STAMP_PATH}", str(image)],
        capture_output=True,
        text=True,
    )
    # debugfs reports a missing file on stderr and still exits 0, so the exit
    # code alone cannot be trusted here.
    body = (proc.stdout or "").strip()
    if not body:
        raise RootfsStampError(
            f"{image} carries no {STAMP_PATH}: it was exported by something that "
            "did not stamp it (a hand-run `docker export`, or a blastbox older "
            "than this check). Rebuild it with `blastbox build-images`."
        )
    return RootfsStamp.from_json(body)


def read(path: Path | str, *, run: Runner | None = None) -> RootfsStamp:
    """Read a stamp from either rootfs shape: a directory or an ext4 file."""
    p = Path(path)
    return read_from_dir(p) if p.is_dir() else read_from_ext4(p, run=run)


def compare_to_host(stamp: RootfsStamp, host_version: str) -> str:
    """Return a human-readable complaint, or "" when guest and host agree.

    Compared as plain strings after stripping a PEP 440 local suffix: a dev
    wheel stamps `0.1.40+g<sha>` and that is the same release as `0.1.40`.
    """
    guest = _release_of(stamp.blastbox_version)
    host = _release_of(host_version)
    if not guest:
        return "the rootfs stamp records no blastbox version"
    if guest != host:
        return (
            f"the rootfs guest is blastbox {stamp.blastbox_version} but this host "
            f"runs {host_version}. A guest that does not match its host is how a "
            f"warm tier boots, never signals READY, and times out every job."
        )
    return ""


def _release_of(version: str) -> str:
    return (version or "").split("+", 1)[0].strip()


def _default_runner(
    argv: Sequence[str], **kwargs: object
) -> "subprocess.CompletedProcess[str]":  # pragma: no cover - thin wrapper
    return subprocess.run(list(argv), check=False, **kwargs)  # type: ignore[call-overload,no-any-return]


__all__ = [
    "STAMP_PATH",
    "RootfsStamp",
    "RootfsStampError",
    "compare_to_host",
    "now_iso",
    "read",
    "read_from_dir",
    "read_from_ext4",
    "write_into_tree",
]
