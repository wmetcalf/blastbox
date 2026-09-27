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

import contextlib
import errno
import json
import os
import re
import shutil
import stat as _stat
import subprocess
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

#: How long GuestGate trusts an UNDECIDABLE verdict (the stamp could not be read) for an
#: unchanged file before reading again. Such failures rarely heal by themselves -- debugfs not
#: installed, a bad-magic image -- and prepare() runs every pool tick.
UNDECIDED_RETRY_S = 60.0

#: Each docker call stamp_tree makes (inspect, and the in-image version probe).
STAMP_TREE_TIMEOUT_S = 120.0


class RootfsStampError(RuntimeError):
    """The rootfs stamp could not be written, read, or trusted."""


class RootfsUnstamped(RootfsStampError):
    """The rootfs carries no stamp at all -- a definitive answer, unlike a failed read."""


class RootfsStampInvalid(RootfsStampError):
    """A stamp is PRESENT but malformed, oversized, linked, or not a regular file.

    Definitive, and a refusal: only an absent stamp is legacy. Treating a damaged stamp like
    a missing one let an untrusted guest past the gate by corrupting its own stamp.
    """


class RootfsStale(RootfsStampError):
    """The rootfs changed since a snapshot was checkpointed against it."""


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
            raise RootfsStampInvalid(f"rootfs stamp is not JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise RootfsStampInvalid("rootfs stamp is not a JSON object")
        plat = raw.get("platform")
        # Named `fields`, not `text`: `text` is this method's own parameter, and
        # shadowing it here hid the JSON body behind the parsed result.
        # SANITISED HERE, once, for every consumer: the stamp is written by an image, and
        # its fields reach the dispatcher's log and exception messages (guest_problem), not
        # only doctor's output -- a newline or escape sequence there forges log lines.
        # REQUIRED, and a string: the writer always emits it (possibly "", a verified guest
        # without blastbox). `{}` or a null defaulted to "" and read as that verified state --
        # an incomplete stamp from an untrusted artifact skipping every version comparison.
        if not isinstance(raw.get("blastbox_version"), str):
            raise RootfsStampInvalid(
                "rootfs stamp has no string blastbox_version; refusing an incomplete stamp"
            )
        fields: dict[str, str] = {
            name: _clean(raw.get(name))
            for name in cls.__dataclass_fields__
            if name != "platform"
        }
        clean_plat = (
            {_clean(k): _clean(v) for k, v in plat.items()} if isinstance(plat, dict) else {}
        )
        return cls(**fields, platform=clean_plat)


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: object) -> str:
    """A stamp field as display-safe text: no control characters, bounded length.

    Beyond C0/C1: Unicode line and paragraph separators (which splitlines() and log viewers
    break on) and every format character -- bidi overrides, zero-widths, BOM -- which can
    forge or reorder what an operator reads.
    """
    if value is None:
        return ""
    text = _CONTROL.sub("", str(value))
    return "".join(
        ch for ch in text if unicodedata.category(ch) not in ("Cf", "Zl", "Zp")
    )[:200]


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
    # ...and nothing but a regular file may already sit AT the path. As root the plain branch
    # below would open whatever is there: a FIFO hangs the build, and a block device node the
    # image planted would have the stamp written into a HOST disk. A directory makes
    # `install -D` write INSIDE it and report success -- a rootfs that claims to be stamped
    # and then boots unchecked.
    _require_regular_or_absent(target)
    if not priv:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.unlink(missing_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as fh:
                fh.write(body)
        except OSError as exc:
            raise RootfsStampError(f"could not write {target}: {exc}") from exc
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
                "-T",   # the target is a FILE: never "copy into" a directory
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
                raise RootfsStampInvalid(
                    f"{cur} is a symlink inside the image; refusing to follow it -- the "
                    "stamp is written as root and must stay inside the tree"
                )
        except OSError as exc:
            raise RootfsStampError(f"cannot inspect {cur}: {exc}") from exc


def _require_regular_or_absent(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RootfsStampError(f"cannot inspect {path}: {exc}") from exc
    if not _stat.S_ISREG(st.st_mode):
        raise RootfsStampInvalid(
            f"{path} exists and is not a regular file (mode {st.st_mode:o}); refusing it -- "
            "the image put something else at the stamp path"
        )


def read_from_dir(tree: Path | str) -> RootfsStamp:
    """Read the stamp from an exported directory rootfs (the gVisor kind).

    Bounded, and without following links: the tree is an image's, not ours.
    """
    tree = Path(tree)
    path = tree / STAMP_PATH
    _refuse_links(tree, STAMP_PATH)
    if not path.exists() and not path.is_symlink():
        raise RootfsUnstamped(f"{path} is missing: this rootfs is unstamped")
    # Regular files only, and opened so that nothing else can block or act: a FIFO blocks
    # open() forever (gVisor tier selection never returns), and opening a device node can
    # have side effects on the HOST. lstat first, O_NONBLOCK so a swapped-in FIFO cannot
    # block, then fstat the descriptor to be sure it is the file we checked.
    _require_regular_or_absent(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise RootfsUnstamped(f"{path} is missing: this rootfs is unstamped") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RootfsStampInvalid(f"{path} is a symlink; refusing it") from exc
        raise RootfsStampError(f"cannot read {path}: {exc}") from exc
    with os.fdopen(fd, "rb") as fh:
        if not _stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise RootfsStampInvalid(f"{path} is not a regular file; refusing it")
        raw = fh.read(MAX_STAMP_BYTES + 1)
    return RootfsStamp.from_json(_bounded(raw, path))


def _bounded(raw: bytes | str, where: object) -> str:
    if len(raw) > MAX_STAMP_BYTES:
        raise RootfsStampInvalid(
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
    # `--`: an image path starting with "-" must never be parsed as a debugfs option.
    argv = ["debugfs", "-R", f"cat /{STAMP_PATH}", "--", str(image)]
    if run is not None:
        proc = run(argv, capture_output=True, text=True)
        out = proc.stdout or ""
    else:
        out = _bounded_debugfs(argv)
    # debugfs reports a missing file on stderr and still exits 0, so the exit
    # code alone cannot be trusted here.
    body = _bounded(out, image).strip()
    if not body:
        raise RootfsUnstamped(
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
    # As RELEASES, not strings: the guest version is the image's label, spelled as the repo
    # pinned it (`0.2.0-rc1`, `0.2`), while the host's comes normalised from installed
    # metadata (`0.2.0rc1`, `0.2.0`). A string compare refused a correct guest forever --
    # rebuilding re-stamps the same label.
    from blastbox.host.stamp import _same_release

    if not _same_release(guest, host):
        return (
            f"the rootfs guest is blastbox {stamp.blastbox_version} but this host "
            f"runs {host_version}. A guest that does not match its host is how a "
            f"warm tier boots, never signals READY, and times out every job."
        )
    return ""


def _release_of(version: str) -> str:
    return (version or "").split("+", 1)[0].strip()


_DEBUGFS_BANNER = re.compile(r"^debugfs \d[^\n]*$", re.MULTILINE)


#: debugfs probes that ignored SIGKILL (uninterruptible I/O on a hung image) and are still
#: alive, with their reader threads. Capped: an undecidable verdict is retried every
#: UNDECIDED_RETRY_S, and each retry against the same hung image would otherwise leave one
#: more unreapable process, two threads and two pipes behind, until the dispatcher runs out.
MAX_ABANDONED_DEBUGFS = 4
_ABANDONED_DEBUGFS: list[tuple[Any, threading.Thread, threading.Thread]] = []
_ABANDONED_LOCK = threading.Lock()
#: Probes started and not yet finished. Counted against the cap WITH the abandoned ones: a hung
#: probe joins the ledger only after its timeout, so N concurrent checks all passed admission.
_DEBUGFS_IN_FLIGHT = 0
#: How long to wait for a killed debugfs, and then for each reader thread, to finish.
_DEBUGFS_REAP_S = 1.0


def _close_idle(proc: Any, t: threading.Thread, te: threading.Thread) -> None:
    # Close the pipes once nothing reads them, or every probe leaks two fds until GC. A
    # reader still blocked keeps its pipe: closing a buffered stream under a blocked reader
    # can deadlock on its lock.
    for stream, reader_thread in ((proc.stdout, t), (proc.stderr, te)):
        if stream is not None and not reader_thread.is_alive():
            with contextlib.suppress(Exception):
                stream.close()


def _admit_debugfs() -> None:
    """Reclaim abandoned probes that have finally exited; reserve a slot or refuse at the cap."""
    global _DEBUGFS_IN_FLIGHT
    with _ABANDONED_LOCK:
        live = []
        for proc, t, te in _ABANDONED_DEBUGFS:
            if proc.poll() is None or t.is_alive() or te.is_alive():
                live.append((proc, t, te))
            else:
                _close_idle(proc, t, te)
        _ABANDONED_DEBUGFS[:] = live
        if len(live) + _DEBUGFS_IN_FLIGHT >= MAX_ABANDONED_DEBUGFS:
            raise RootfsStampError(
                f"{len(live)} earlier debugfs probes are still hung (ignoring SIGKILL) and "
                f"{_DEBUGFS_IN_FLIGHT} are in flight; not starting another until they exit -- "
                "is the rootfs on a stuck mount?"
            )
        _DEBUGFS_IN_FLIGHT += 1


def _release_debugfs(entry: tuple[Any, threading.Thread, threading.Thread] | None) -> None:
    """Give back the slot _admit_debugfs reserved; a probe that survived SIGKILL keeps it."""
    global _DEBUGFS_IN_FLIGHT
    with _ABANDONED_LOCK:
        _DEBUGFS_IN_FLIGHT -= 1
        if entry is not None:
            _ABANDONED_DEBUGFS.append(entry)


def _bounded_debugfs(argv: Sequence[str]) -> str:
    """Run debugfs, keeping at most MAX_STAMP_BYTES + 1 of its output, within a deadline.

    READ INCREMENTALLY. communicate() buffered the whole output before anything could be
    sliced, so a sparse multi-GiB stamp in a small ext4 streamed gigabytes of zeros into the
    reading process -- the dispatcher, in-process -- and an OOM kill is not an exception any
    caller can catch. stderr is drained the same way (first 4 KiB kept, the rest discarded)
    so a real debugfs error (bad magic, permission denied) can be told apart from "no
    stamp" without an unbounded buffer.
    """
    _admit_debugfs()
    abandoned: tuple[Any, threading.Thread, threading.Thread] | None = None
    try:
        proc = subprocess.Popen(  # noqa: S603 -- fixed argv, no shell
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        got: list[bytes] = []
        err: list[bytes] = []

        def reader() -> None:
            assert proc.stdout is not None
            got.append(proc.stdout.read(MAX_STAMP_BYTES + 1))

        def err_reader() -> None:
            assert proc.stderr is not None
            err.append(proc.stderr.read(4096))
            while proc.stderr.read(65536):
                pass

        t = threading.Thread(target=reader, daemon=True, name="rootfs-stamp-debugfs")
        te = threading.Thread(target=err_reader, daemon=True, name="rootfs-stamp-debugfs-err")
        t.start()
        te.start()
        t.join(DEBUGFS_TIMEOUT_S)
        timed_out = t.is_alive()
        # Always stop it: past the cap there is nothing we will read, and a blocked writer must
        # not linger. The wait is bounded too -- a debugfs in uninterruptible sleep (a hung NFS
        # image) ignores SIGKILL, and the probe must not hang with it.
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=_DEBUGFS_REAP_S * 5)
        t.join(_DEBUGFS_REAP_S)
        te.join(_DEBUGFS_REAP_S)
        _close_idle(proc, t, te)
        if proc.poll() is None or t.is_alive() or te.is_alive():
            # Survived SIGKILL: remembered, so the next probe can reclaim it or refuse to add one.
            abandoned = (proc, t, te)
    finally:
        # The reserved slot is released on EVERY path (a Popen that raises included), or moved
        # to the abandoned ledger when the probe could not be reaped.
        _release_debugfs(abandoned)
    if timed_out:
        raise RootfsStampError(
            f"debugfs timed out after {DEBUGFS_TIMEOUT_S:.0f}s reading {argv[-1]}"
        )
    out = got[0] if got else b""
    if not out.strip():
        # debugfs ALWAYS prints its version banner on stderr; only what follows is an error.
        detail = _clean(_DEBUGFS_BANNER.sub("", (err[0] if err else b"").decode(
            "utf-8", "replace")).strip())
        if detail and "not found" not in detail.lower():
            raise RootfsStampError(f"debugfs could not read {argv[-1]}: {detail}")
    return out.decode("utf-8", "replace")


def guest_problem(rootfs: str, runtime: str) -> str:
    """Why this host must not boot ``rootfs`` on ``runtime``, or "" when it may."""
    return guest_verdict(rootfs, runtime)[0]


def guest_verdict(rootfs: str, runtime: str) -> tuple[str, bool]:
    """Why this host must not boot ``rootfs`` on ``runtime``, or "" when it may.

    Shared by both warm tiers. An UNSTAMPED rootfs (no stamp at all) or one that could not
    be read WARNS and returns "" -- "I could not look" is not "it is wrong", and refusing it
    would strand every deployment exported before stamping existed. A stamp that is PRESENT
    but malformed is refused: only absence earns the legacy exception.
    """
    import logging
    from blastbox.host import platform_id as _plat

    log = logging.getLogger("blastbox.host.rootfs_stamp")
    try:
        stamp = read(rootfs)
    except RootfsUnstamped as exc:
        log.warning(
            "rootfs %s carries no blastbox stamp (%s); booting it anyway. "
            "Rebuild it with `blastbox build-images` so guest/host drift is caught "
            "here instead of as a timeout on every warm job.",
            rootfs, exc,
        )
        return "", True        # definitively unstamped: nothing to re-read until it changes
    except RootfsStampInvalid as exc:
        # PRESENT but unusable: refused. The image wrote it, and a damaged stamp must not
        # buy the unchecked boot that only a genuinely absent one gets.
        return f"{rootfs}: its blastbox stamp is unusable ({exc}); rebuild it with " \
            "`blastbox build-images`", True
    except RootfsStampError as exc:
        log.warning(
            "rootfs %s carries no readable blastbox stamp (%s); booting it anyway. "
            "Rebuild it with `blastbox build-images` so guest/host drift is caught "
            "here instead of as a timeout on every warm job.",
            rootfs, exc,
        )
        return "", False       # could NOT look: allowed, but must be looked at again
    except Exception as exc:  # noqa: BLE001 - never fail the tier on a diagnostic
        log.warning("could not read the rootfs stamp on %s: %s", rootfs, exc)
        return "", False
    # The version as this PROCESS loaded it (blastbox.__version__, read from metadata once at
    # import) -- not importlib.metadata now, which re-reads dist-info from disk: a pip upgrade
    # under a live dispatcher would otherwise admit a guest newer than the code serving it.
    import blastbox

    host = str(getattr(blastbox, "__version__", "") or "")
    if not host:  # pragma: no cover
        return "", False
    # The MACHINE, before the software: saying "wrong blastbox" about an aarch64 rootfs
    # on an x86_64 host sends the operator after the wrong thing.
    findings = _plat.compare(platform_of(stamp), _plat.host_platform(runtime=runtime))
    # The non-fatal findings are what permit an UNCHECKED boot (a stamp that predates platform
    # capture, say): say so, rather than log only that the guest matches.
    for warn in (f for f in findings if not f.fatal):
        log.warning("rootfs %s: %s: %s", rootfs, warn.field, warn.message)
    fatal = _plat.refusals(findings)
    if fatal:
        return f"{rootfs}: {_plat.summarise(fatal)}", True
    if not (stamp.blastbox_version or "").strip():
        # A guest with no blastbox installed (a pure-JVM worker) is valid -- verify_built()
        # accepts it -- so its VERSION is unchecked, said loudly; arch/runtime still applied.
        log.warning("rootfs %s records no blastbox version, so its guest version is not "
                    "checked against this host", rootfs)
        return "", True
    complaint = compare_to_host(stamp, host)
    if complaint:
        return (
            f"{rootfs}: {complaint} Rebuild the rootfs with `blastbox build-images` "
            f"(the stamp says image={stamp.image or '?'} "
            f"exported_at={stamp.exported_at or '?'})."
        ), True
    log.info("rootfs %s guest blastbox %s matches this host", rootfs, stamp.blastbox_version)
    return "", True


def file_identity(path: Path | str) -> "tuple[int, ...] | None":
    """What changes when a rootfs is republished: device, inode, size, mtime -- or None.

    `build-images` publishes by renaming a new artifact over the old one, so the inode moves;
    an in-place rewrite moves size or mtime. For a directory rootfs the stamp file's own
    identity is folded in, since a tree can be refreshed without replacing its top directory.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    if _stat.S_ISDIR(st.st_mode):
        # A directory's own size/mtime move when anything inside is created -- `runsc run`
        # makes /in, /out and /ctrl in a bare tree -- so only its inode (a republish moves a
        # new tree into place) and the stamp file's own identity count.
        key: tuple[int, ...] = (st.st_dev, st.st_ino)
        try:
            sst = os.lstat(Path(path) / STAMP_PATH)
            key += (sst.st_ino, sst.st_size, sst.st_mtime_ns)
        except OSError:
            key += (-1,)
        return key
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def opened_matches(
    pid: int, path: str, key: "tuple[int, ...] | None", *, strict: bool = False
) -> "bool | None":
    """Whether process ``pid`` holds the PINNED file open -- by the file, not by the path.

    True: it holds the pinned (dev, inode) AND that file still has the pinned size/mtime -- a
    `cp` over the same inode rewrites it in place, and (dev, inode) alone blessed the rewrite.
    False: it holds the pinned inode rewritten, or a DIFFERENT file at ``path`` (including one
    since unlinked, "(deleted)"), or -- ``strict`` -- anything but the pinned file.
    None: /proc could not answer (or, not strict, nothing identifiable at all).

    ``strict`` is for callers that KNOW the runtime has the disk open (a restore after the
    snapshot load, a base after READY): the pinned inode must then be positively present. A
    symlinked rootfs rolled back A->B->A leaves the runtime holding B under a name that is
    neither the link nor its current target, which the lenient check cannot see.
    """
    if key is None:
        return None
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        fds = list(fd_dir.iterdir())
    except OSError:
        return None
    want = (key[0], key[1])
    real = os.path.realpath(path)
    other = False
    for fd in fds:
        try:
            st = os.stat(fd)
        except OSError:
            continue
        if (st.st_dev, st.st_ino) == want:
            if len(key) >= 4 and (st.st_size, st.st_mtime_ns) != (key[2], key[3]):
                return False                      # the pinned inode, rewritten in place
            return True
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target in (path, real) or target in (f"{path} (deleted)", f"{real} (deleted)"):
            other = True
    if other or strict:
        return False
    return None


class GuestGate:
    """guest_problem() for one rootfs, re-read only when the file changes.

    Tier selection checks the guest once, at dispatcher start -- but `build-images` publishes
    in place, and the dispatcher keeps booting from the same path. Called where the rootfs is
    actually BOOTED (a plain FC spawn, a snapshot base build), this catches a republished
    guest the moment it would be used, at the cost of one stat() per boot.
    """

    def __init__(self, rootfs: str, runtime: str) -> None:
        self.rootfs = rootfs
        self.runtime = runtime
        self._lock = threading.Lock()
        self._key: "tuple[int, ...] | None" = None
        self._problem = ""
        #: None for a definitive verdict (kept until the file changes); otherwise when an
        #: undecidable one may be re-read.
        self._retry_at: "float | None" = None

    def problem(self) -> str:
        return self.checked()[0]

    def checked(self) -> "tuple[str, tuple[int, ...] | None]":
        """(problem, the identity that verdict is for). Only a DEFINITIVE verdict -- a stamp
        read, or genuinely absent -- is cached: a failed read (a debugfs timeout on a cold,
        freshly published image) cached as "" switched the check off for that file for good."""
        if not self.rootfs:
            return "", None    # no rootfs configured: nothing to check
        key = file_identity(self.rootfs)
        if key is None:
            # MISSING -- e.g. mid-publish, between the old file's removal and the new one's
            # install. Not a pass: a spawn finishing after the new file appeared would boot it
            # unchecked, and a snapshot would be pinned to no disk at all.
            return f"{self.rootfs} is missing (possibly mid-publish); not booting it", None
        with self._lock:
            if key == self._key and (self._retry_at is None
                                     or time.monotonic() < self._retry_at):
                return self._problem, key
        found, definitive = guest_verdict(self.rootfs, self.runtime)
        # Cached only if the file did not change DURING the read: otherwise this verdict may
        # describe a different file than the identity it would be stored under. A definitive
        # verdict holds until the file changes; an undecidable one (the stamp could not be
        # read) only for UNDECIDED_RETRY_S -- re-reading it every tick re-ran debugfs and a
        # WARNING ten times a second, and caching it forever switched the check off.
        after = file_identity(self.rootfs)
        if after == key:
            with self._lock:
                self._key, self._problem = key, found
                self._retry_at = None if definitive else time.monotonic() + UNDECIDED_RETRY_S
        return found, key          # the identity the check STARTED from; callers re-stat


PENDING = "pending"
"""GuestGate.problem_nowait(): the verdict for the current file is still being established."""


def _gate_problem_nowait(self: "GuestGate") -> str:
    """The cached verdict for the current file, or PENDING while a background check runs.

    For callers on the pool tick: a debugfs stalled on a malformed image held prepare() for the
    full read deadline, freezing promotion, health checks and reaping. The check runs on its own
    thread; the tick only ever reads a result.
    """
    if not self.rootfs:
        return ""
    key = file_identity(self.rootfs)
    if key is None:
        return f"{self.rootfs} is missing (possibly mid-publish); not booting it"
    with self._lock:
        fresh = key == self._key and (self._retry_at is None or time.monotonic() < self._retry_at)
        if fresh:
            return self._problem
        running = self.__dict__.get("_check_thread")
        if running is None or not running.is_alive():
            t = threading.Thread(target=self.checked, daemon=True, name="rootfs-guest-check")
            self.__dict__["_check_thread"] = t
            t.start()
        if key == self._key:
            # The SAME file, whose undecidable verdict is merely due a re-read: keep serving it
            # while the re-read runs. PENDING here made a policy-allowed tier flap not-ready for
            # the whole re-read, every interval, forever, on slow storage.
            return self._problem
    return PENDING


GuestGate.problem_nowait = _gate_problem_nowait  # type: ignore[attr-defined]


class RootfsPin:
    """Bind each snapshot checkpoint to the rootfs it was taken against.

    A snapshot restore attaches the rootfs by PATH, under a memory image whose page cache and
    ext4 metadata describe the file that was there at checkpoint. Republished in place, the
    restore pairs old memory with a new disk -- the corruption class generation-stamping the
    outdisk already prevents, left open for the shared rootfs. Backends call:

    * ``before_boot()`` -- the guest gate, then the identity this build boots;
    * ``wrap(boot, key)`` -- records that identity against the artifact checkpoint() returns;
    * ``check_restore(artifact)`` -- refuses a restore if the file changed since;
    * ``forget(artifact)`` -- when the generation is discarded.
    """

    def __init__(self, rootfs: str, runtime: str) -> None:
        self.gate = GuestGate(rootfs, runtime)
        self._lock = threading.Lock()
        self._keys: "dict[str, tuple[int, ...] | None]" = {}

    @staticmethod
    def _akey(artifact: object) -> str:
        return str(getattr(artifact, "snapshot_path", artifact))

    def before_boot(self) -> "tuple[int, ...] | None":
        problem, key = self.gate.checked()
        if problem:
            raise RootfsStampError(problem)
        # The identity pinned must be the one that was CHECKED. A republish landing between
        # the check and a second stat would pin a file the gate never looked at.
        if file_identity(self.gate.rootfs) != key:
            raise RootfsStampError(
                f"{self.gate.rootfs} changed while it was being checked; the next build "
                "checks the new one"
            )
        return key

    def wrap(self, boot: object, key: "tuple[int, ...] | None") -> object:
        return _PinnedBoot(boot, key, self)

    def record(self, artifact: object, key: "tuple[int, ...] | None") -> None:
        with self._lock:
            self._keys[self._akey(artifact)] = key

    def check_restore(self, artifact: object) -> None:
        with self._lock:
            if self._akey(artifact) not in self._keys:
                return         # not built by this process (or before pinning): nothing to compare
            key = self._keys[self._akey(artifact)]
        if key is not None and file_identity(self.gate.rootfs) != key:
            raise RootfsStale(
                f"{self.gate.rootfs} changed since this snapshot was checkpointed; restoring "
                "it would pair the old memory image with a different disk. The base must be "
                "rebuilt from the current rootfs."
            )

    def check_opened(self, artifact: object, pid: "int | None") -> None:
        """After the runtime opened the rootfs: refuse unless it holds the PINNED inode.

        Falls back to the path check when /proc cannot answer.
        """
        with self._lock:
            key = self._keys.get(self._akey(artifact))
        if key is None:
            return
        # STRICT: after the snapshot load the drive is certainly open, so the pinned file must
        # be positively held -- not merely "nothing wrong seen".
        verdict = opened_matches(pid, self.gate.rootfs, key, strict=True) if pid else None
        if verdict is False:
            raise RootfsStale(
                f"{self.gate.rootfs}: the runtime opened a different file than the one this "
                "snapshot was checkpointed against (a republish landed during the restore)"
            )
        if verdict is None:
            self.check_restore(artifact)

    def forget(self, artifact: object) -> None:
        with self._lock:
            self._keys.pop(self._akey(artifact), None)


class _PinnedBoot:
    """A base boot handle whose checkpoint() records the rootfs identity it booted."""

    def __init__(self, inner: object, key: "tuple[int, ...] | None", pin: RootfsPin) -> None:
        self._inner = inner
        self._key = key
        self._pin = pin

    def checkpoint(self, dest_dir: Path) -> object:
        # The BASE, like a restore: a publish rolled back between before_boot() and here leaves
        # the path at the checked file while the base opened another -- and the pin would then
        # bless every restore of memory captured against the wrong disk.
        pid = getattr(getattr(self._inner, "proc", None), "pid", None)
        if pid and opened_matches(pid, self._pin.gate.rootfs, self._key, strict=True) is False:
            raise RootfsStale(
                f"{self._pin.gate.rootfs}: the base opened a different file than the one that "
                "was checked (a republish landed during the base boot); not checkpointing it"
            )
        artifact = self._inner.checkpoint(dest_dir)  # type: ignore[attr-defined]
        self._pin.record(artifact, self._key)
        return artifact

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def stamp_tree(
    tree: Path | str,
    image: str,
    runtime: str,
    *,
    run: Runner | None = None,
    revision: str = "",
    docker: str = "docker",
) -> Path:
    """Stamp an extracted tree from what IMAGE records about itself -- for exports made
    outside `build-images` (the legacy `deploy/` scripts).

    Those scripts used to publish unstamped rootfs, which the tiers only warn about and boot:
    exactly the hotfix path where a guest/host mismatch is most likely. The same provenance
    `build-images` stamps -- the image's own blastbox label, revision and architecture -- and
    the same hardened write.
    """
    from blastbox.host.imagerun import _DOCKER_ARCH  # noqa: PLC0415
    from blastbox.host.stamp import UNKNOWN  # noqa: PLC0415

    def runner(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
        # The SAME docker the export used (`DOCKER=podman` is supported by the scripts): the
        # literal `docker` could fail, or describe an image in a different daemon.
        argv = [docker, *argv[1:]] if argv and argv[0] == "docker" else list(argv)
        # BOUNDED: the probe runs the image being stamped, and a hung image or daemon must not
        # hang a deploy script forever.
        if run is not None:
            return run(list(argv), capture_output=True, text=True, timeout=STAMP_TREE_TIMEOUT_S)
        return subprocess.run(list(argv), capture_output=True, text=True, check=False,
                              timeout=STAMP_TREE_TIMEOUT_S)

    from blastbox.host.doctor import version_in_image  # noqa: PLC0415

    try:
        installed, detail = version_in_image(image, runner)
    except subprocess.TimeoutExpired:
        installed, detail = UNKNOWN, f"probe timed out after {STAMP_TREE_TIMEOUT_S:.0f}s"
    # Only a real VERSION counts: the probe answers sentinels (NOPKG, UNKNOWN), and stamping one
    # makes every host refuse the rootfs while the deploy script reports success.
    # The INSTALLED version, and nothing else. These exports derive images from a shipped
    # image, so a label is usually inherited from the base and says nothing about the wheel
    # this build installed.
    #   a version -> stamp it
    #   NOPKG     -> DEFINITIVE: no blastbox in the guest (a pure-JVM worker); stamp none
    #   otherwise -> the probe could not look (timeout, inspect failure): refuse, rather than
    #                let an inherited label vouch for an unverified guest
    from blastbox.host.doctor import NOPKG  # noqa: PLC0415

    if _is_version(installed):
        version = installed
    elif installed == NOPKG:
        version = ""
    else:
        raise RootfsStampError(
            f"{image}: its installed blastbox version could not be verified "
            f"({detail or installed or 'unreadable'}); refusing to stamp a version nobody "
            "checked"
        )

    def inspect(fmt: str) -> str:
        proc = runner(["docker", "inspect", "--type", "image", image, "--format", fmt])
        return (proc.stdout or "").strip() if proc.returncode == 0 else ""

    arch_raw = inspect("{{.Architecture}}")
    if not arch_raw:
        # As stage_rootfs: an empty arch is not compared at boot, so this rootfs would skip the
        # arch check entirely. Refuse rather than publish it.
        raise RootfsStampError(
            f"cannot read the architecture of {image}; refusing to stamp a rootfs the boot "
            "gate could not check"
        )
    stamp = RootfsStamp(
        blastbox_version=version,
        image=image,
        image_id=inspect("{{.Id}}"),
        # NEVER from the labels: these exports derive images FROM a shipped image, inheriting its
        # labels (revision included), and a hotfix wheel carries the same static version -- so
        # nothing here can tell whose revision a label names. The caller says it explicitly.
        revision=revision,
        exported_at=now_iso(),
        platform={"arch": _DOCKER_ARCH.get(arch_raw, arch_raw), "runtime": runtime},
    )
    return write_into_tree(tree, stamp)


def _is_version(value: str) -> bool:
    from packaging.version import InvalidVersion, Version  # noqa: PLC0415

    try:
        Version((value or "").split("+", 1)[0])
    except InvalidVersion:
        return False
    return bool(value)


def clear_stamp(tree: Path | str) -> None:
    """Remove a stamp baked into an extracted tree -- without following the image's links.

    `rm tree/opt/blastbox/rootfs-stamp.json` (run as root for a gVisor tree) follows an
    image-controlled `opt/blastbox` symlink and deletes a stamp in a HOST directory -- the
    deployed rootfs's, say, sending it down the unchecked legacy path. Same confinement as the
    write: no link on the path, and only a regular file is removed.
    """
    tree = Path(tree)
    _refuse_links(tree, STAMP_PATH)
    target = tree / STAMP_PATH
    _require_regular_or_absent(target)
    try:
        target.unlink(missing_ok=True)
    except OSError as exc:
        raise RootfsStampError(f"could not remove {target}: {exc}") from exc


def main(argv: Sequence[str]) -> int:
    """`python -m blastbox.host.rootfs_stamp write TREE IMAGE {firecracker|gvisor}`."""
    if len(argv) == 2 and argv[0] == "clear":
        try:
            clear_stamp(argv[1])
        except RootfsStampError as exc:
            print(f"rootfs stamp: {exc}")
            return 1
        return 0
    if (len(argv) not in (4, 5) or argv[0] != "write"
            or argv[3] not in ("firecracker", "gvisor")):
        print("usage: python -m blastbox.host.rootfs_stamp write TREE IMAGE "
              "{firecracker|gvisor} [REVISION]")
        return 2
    try:
        stamp_tree(argv[1], argv[2], argv[3], revision=argv[4] if len(argv) == 5 else "",
                   docker=os.environ.get("DOCKER") or "docker")
    except RootfsStampError as exc:
        print(f"rootfs stamp: {exc}")
        return 1
    return 0


def _default_runner(
    argv: Sequence[str], **kwargs: object
) -> "subprocess.CompletedProcess[str]":  # pragma: no cover - thin wrapper
    return subprocess.run(list(argv), check=False, **kwargs)  # type: ignore[call-overload,no-any-return]


__all__ = [
    "DEBUGFS_TIMEOUT_S",
    "GuestGate",
    "PENDING",
    "RootfsStale",
    "RootfsUnstamped",
    "guest_verdict",
    "RootfsPin",
    "file_identity",
    "opened_matches",
    "MAX_STAMP_BYTES",
    "STAMP_PATH",
    "guest_problem",
    "platform_of",
    "RootfsStamp",
    "RootfsStampError",
    "RootfsStampInvalid",
    "compare_to_host",
    "now_iso",
    "read",
    "read_from_dir",
    "read_from_ext4",
    "stamp_tree",
    "clear_stamp",
    "write_into_tree",
]


if __name__ == "__main__":  # pragma: no cover - thin CLI
    import sys

    sys.exit(main(sys.argv[1:]))
