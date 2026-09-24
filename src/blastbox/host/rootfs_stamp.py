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
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blastbox.host.platform_id import HostPlatform

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

#: Inside the rootfs. Kept next to `/opt/blastbox/engine`, which exists for the
#: same reason -- image config does not survive `docker export`.
STAMP_PATH = "opt/blastbox/rootfs-stamp.json"

#: A stamp is a few hundred bytes. It is read out of an artifact this host did not
#: create, so the read is capped: a huge (or /dev/zero-backed) stamp must not
#: exhaust the memory of `doctor` or of a tier's availability probe.
MAX_STAMP_BYTES = 64 * 1024

#: debugfs on a malformed filesystem can spin; the probe must not.
DEBUGFS_TIMEOUT_S = 30.0


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
    #: The machine this artifact was baked on. Empty for artifacts exported
    #: before platform capture existed; see platform_id.compare for why that is
    #: a warning and not a refusal.
    platform: dict = field(default_factory=dict)

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
        plat = raw.get("platform")
        # Named `fields`, not `text`: `text` is this method's own parameter, and
        # shadowing it here hid the JSON body behind the parsed result.
        fields: dict[str, str] = {
            name: ("" if raw.get(name) is None else str(raw.get(name)))
            for name in cls.__dataclass_fields__
            if name != "platform"
        }
        return cls(**fields, platform=plat if isinstance(plat, dict) else {})


def platform_of(stamp: "RootfsStamp") -> "HostPlatform":
    """What a ROOTFS is bound to: its architecture and the runtime tier it is for.

    Only those two. A rootfs carries no CPU state -- the snapshot is taken later, on the
    DEPLOYING host, by SnapshotManager.build -- so the CPU vendor, model, kernel and runtime
    version of the machine that ran mkfs.ext4 say nothing about where it can boot. Stamps
    exported before this recorded them; they are ignored here rather than refusing a correct
    rootfs moved between an AMD build host and an Intel fleet.
    """
    from blastbox.host.platform_id import HostPlatform

    full = HostPlatform.from_dict(stamp.platform)
    return HostPlatform(arch=full.arch, runtime=full.runtime)


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
    # The TREE is the image's, and this write runs as root: a symlink anywhere on the stamp
    # path would let the image create or truncate a file on the HOST (a final link to
    # /etc/sudoers, an `opt` pointing at /etc). The extracted tree is static while we write,
    # so checking every component first is sufficient; nothing below then follows a link.
    _refuse_links(tree, STAMP_PATH)
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


def _refuse_links(tree: Path, rel: str) -> None:
    """Raise if any component of ``tree/rel`` that exists is a symlink."""
    cur = tree
    for part in Path(rel).parts:
        cur = cur / part
        try:
            if cur.is_symlink():
                raise RootfsStampError(
                    f"{cur} is a symlink inside the image; refusing to follow it -- the "
                    "stamp is written as root and must stay inside the tree"
                )
        except OSError as exc:
            raise RootfsStampError(f"cannot inspect {cur}: {exc}") from exc


def read_from_dir(tree: Path | str) -> RootfsStamp:
    """Read the stamp from an exported directory rootfs (the gVisor kind).

    Bounded, and without following links: the tree is an image's, not ours.
    """
    tree = Path(tree)
    path = tree / STAMP_PATH
    _refuse_links(tree, STAMP_PATH)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as exc:
        raise RootfsStampError(f"{path} is missing: this rootfs is unstamped") from exc
    except OSError as exc:
        raise RootfsStampError(f"cannot read {path}: {exc}") from exc
    with os.fdopen(fd, "rb") as fh:
        raw = fh.read(MAX_STAMP_BYTES + 1)
    return RootfsStamp.from_json(_bounded(raw, path))


def _bounded(raw: bytes | str, where: object) -> str:
    if len(raw) > MAX_STAMP_BYTES:
        raise RootfsStampError(
            f"the stamp in {where} is larger than {MAX_STAMP_BYTES} bytes; refusing it"
        )
    return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw


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
    argv = ["debugfs", "-R", f"cat /{STAMP_PATH}", str(image)]
    if run is not None:
        proc = run(argv, capture_output=True, text=True)
        out = proc.stdout or ""
    else:
        out = _bounded_debugfs(argv)
    # debugfs reports a missing file on stderr and still exits 0, so the exit
    # code alone cannot be trusted here.
    body = _bounded(out, image).strip()
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


def _bounded_debugfs(argv: Sequence[str]) -> str:
    """Run debugfs with a deadline, keeping at most MAX_STAMP_BYTES + 1 of its output."""
    proc = subprocess.Popen(  # noqa: S603 -- fixed argv, no shell
        list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    try:
        out, _ = proc.communicate(timeout=DEBUGFS_TIMEOUT_S)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        raise RootfsStampError(
            f"debugfs timed out after {DEBUGFS_TIMEOUT_S:.0f}s reading {argv[-1]}"
        ) from exc
    return (out or b"")[: MAX_STAMP_BYTES + 1].decode("utf-8", "replace")


def guest_problem(rootfs: str, runtime: str) -> str:
    """Why this host must not boot ``rootfs`` on ``runtime``, or "" when it may.

    Shared by both warm tiers. An unstamped or unreadable rootfs WARNS and returns "" --
    "I could not look" is not "it is wrong", and refusing it would strand every deployment
    exported before stamping existed.
    """
    import logging
    from importlib.metadata import PackageNotFoundError, version

    from blastbox.host import platform_id as _plat

    log = logging.getLogger("blastbox.host.rootfs_stamp")
    try:
        stamp = read(rootfs)
    except RootfsStampError as exc:
        log.warning(
            "rootfs %s carries no readable blastbox stamp (%s); booting it anyway. "
            "Rebuild it with `blastbox build-images` so guest/host drift is caught "
            "here instead of as a timeout on every warm job.",
            rootfs, exc,
        )
        return ""
    except Exception as exc:  # noqa: BLE001 - never fail the tier on a diagnostic
        log.warning("could not read the rootfs stamp on %s: %s", rootfs, exc)
        return ""
    try:
        host = version("blastbox")
    except PackageNotFoundError:  # pragma: no cover
        return ""
    # The MACHINE, before the software: saying "wrong blastbox" about an aarch64 rootfs
    # on an x86_64 host sends the operator after the wrong thing.
    findings = _plat.compare(platform_of(stamp), _plat.host_platform(runtime=runtime))
    fatal = _plat.refusals(findings)
    if fatal:
        return f"{rootfs}: {_plat.summarise(fatal)}"
    complaint = compare_to_host(stamp, host)
    if complaint:
        return (
            f"{rootfs}: {complaint} Rebuild the rootfs with `blastbox build-images` "
            f"(the stamp says image={stamp.image or '?'} "
            f"exported_at={stamp.exported_at or '?'})."
        )
    log.info("rootfs %s guest blastbox %s matches this host", rootfs, stamp.blastbox_version)
    return ""


def _default_runner(
    argv: Sequence[str], **kwargs: object
) -> "subprocess.CompletedProcess[str]":  # pragma: no cover - thin wrapper
    return subprocess.run(list(argv), check=False, **kwargs)  # type: ignore[call-overload,no-any-return]


__all__ = [
    "DEBUGFS_TIMEOUT_S",
    "MAX_STAMP_BYTES",
    "STAMP_PATH",
    "guest_problem",
    "platform_of",
    "RootfsStamp",
    "RootfsStampError",
    "compare_to_host",
    "now_iso",
    "read",
    "read_from_dir",
    "read_from_ext4",
    "write_into_tree",
]
