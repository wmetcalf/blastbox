"""Execute a declared image plan: build stamped, verify, then export.

Split from :mod:`blastbox.host.images`, which is pure declaration and
validation. Everything here touches docker, the filesystem and sometimes sudo,
so it cannot be exercised by reading a spec — and keeping the two apart means
the validation a dry run performs is the same code, not a second copy of it.

Every guard below is a failure that has actually happened on this fleet:

* a build that ran with no stamp because a ``$(...)`` status was discarded, so
  the image took its Dockerfile's mutable default base and the run still
  printed success;
* an upstream tag resolved twice — once for the label, once by the build — so
  the stamp named a different image than the one built;
* a warm rootfs exported from the wrong image, which booted with no ``/init``
  and took the Firecracker tier down until it was restored from a ``.bak``;
* ``docker export | tar -x`` over a live tree, which leaves files the new image
  deleted and boots a mixture of two builds.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

from blastbox.host import images as _images
from blastbox.host.images import Plan, RootfsSpec
from blastbox.host.stamp import StampError
from blastbox.host.stamp import build_args as _stamp_flags
from blastbox.host.stamp import read as _read_stamp

__all__ = ["BuildError", "build_plan", "export_rootfs", "run_plan"]


class BuildError(RuntimeError):
    """A step failed. Nothing after it in the plan should run."""


Runner = Callable[..., "subprocess.CompletedProcess[str]"]
Log = Callable[[str], None]


def _log(message: str) -> None:
    """Print, FLUSHED.

    Python block-buffers stdout when it is redirected to a file, while the
    docker child writes straight to the same descriptor. Unflushed, every
    progress line lands after all the build output it was meant to introduce:
    an operator tailing the log sees pages of docker with nothing saying which
    image is being built, and on a failure the last line printed is not the
    step that failed.
    """
    print(message, flush=True)


def _default_runner(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    capture_output: bool = False,
    stdout: object | None = None,
) -> subprocess.CompletedProcess[str]:
    """The real runner. Kept to the exact keywords this module uses, so a test
    double has a small, stated surface to implement rather than all of
    ``subprocess.run``."""
    return subprocess.run(  # noqa: S603
        list(argv),
        text=True,
        check=False,
        cwd=cwd,
        capture_output=capture_output,
        stdout=stdout,  # type: ignore[arg-type]
    )


def _must(
    argv: Sequence[str], what: str, run: Runner, *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` and abort the plan unless it succeeded.

    Checked EVERY time. The bash this replaces put one of these inside a
    command substitution in docker's argument list, where ``set -e`` discards
    the status: the stamp refused, the build ran anyway on a mutable default,
    and the script reported that everything was stamped.
    """
    proc = run(argv, cwd=str(cwd) if cwd else None)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise BuildError(f"{what} failed ({' '.join(argv)}){': ' + detail if detail else ''}")
    return proc


def build_plan(
    plan: Plan,
    tag: str,
    *,
    blastbox_version: str,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    pull: bool = True,
) -> list[str]:
    """Build every image in the chain, each stamped with what it was built from.

    Returns the tags built, in chain order. Raises :class:`BuildError` on the
    first failure rather than continuing: a chain whose second image failed
    would otherwise have its third built on a stale tag of the same name, which
    is how a "rebuild" ships a mixture of two builds under one tag.
    """
    run = run or _default_runner
    env = dict(os.environ) if env is None else env

    problems = _images.missing_dockerfiles(plan, env) + _images.arg_problems(plan, env)
    if problems:
        raise BuildError(
            "the plan cannot be built as declared:\n  " + "\n  ".join(problems)
        )

    built: list[str] = []
    for spec, base_ref in _images.resolve_chain(plan, tag):
        if pull and not spec.internal:
            # Present locally BEFORE it is inspected for a digest. Otherwise the
            # build pulls it itself and can get a different push of the same
            # mutable tag than the one recorded a moment earlier.
            log(f">> pull {base_ref}")
            _must(["docker", "pull", "-q", base_ref], f"pull {base_ref}", run)

        source = _images.source_repo_path(plan, spec, env)
        try:
            flags = _stamp_flags(
                blastbox_version=blastbox_version,
                repo=source,
                base=base_ref,
                base_arg=spec.base_arg,
                dockerfile=_images.dockerfile_path(plan, spec, env),
            )
        except StampError as exc:
            # Refusing here is the point. An unstamped image is one nobody can
            # rebuild, and a stamp naming an ARG the Dockerfile does not declare
            # is worse: docker discards the pin and the label lies.
            raise BuildError(f"{spec.name}: refusing to build unstamped — {exc}") from exc

        argv = _images.build_command(spec, tag, flags, base_ref, env, plan)
        log(f">> build {spec.tagged(tag)}  <- {base_ref}")
        _must(argv, f"build {spec.tagged(tag)}", run, cwd=plan.root)
        built.append(spec.tagged(tag))

    return built


def verify_built(images: Sequence[str], *, run: Runner | None = None, log: Log = print) -> None:
    """Every image must read back a stamp naming what produced it.

    Read from the ARTIFACT, not from what the build was told to do: the two
    disagreeing is exactly the state worth finding, and the only way to see it
    is to ask the image.
    """
    runner = None if run is None else (lambda argv: run(argv))
    bad: list[str] = []
    for image in images:
        log(f"-- {image}")
        try:
            stamp = _read_stamp(image, runner)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001 - reported per image, not fatal here
            bad.append(f"{image}: {exc}")
            continue
        if not stamp.revision:
            bad.append(f"{image}: stamped with no source revision")
    if bad:
        raise BuildError(
            "one or more images are not reproducible from what they record:\n  "
            + "\n  ".join(bad)
        )


def _remove_tree(path: Path, priv: list[str], run: Runner) -> None:
    """Remove a staging tree at the privilege it was WRITTEN with.

    `os.access` on the directory is not the test: mkdtemp makes it owned by this
    user, while everything root extracted inside it is not, so an ordinary
    rmtree walks in and fails partway. A failed export then leaves a whole
    root-owned rootfs behind — observed on toolz2 after the mkfs failure above.
    """
    if priv:
        run([*priv, "rm", "-rf", str(path)], capture_output=True)
    else:
        shutil.rmtree(path, ignore_errors=True)


def _extract_image(image: str, dest: Path, run: Runner, log: Log, *, as_root: bool) -> None:
    """Extract ``image``'s filesystem into an EMPTY ``dest``.

    A container is created and removed rather than ``docker save``: export gives
    the flattened filesystem the tiers actually boot, where a save gives layers.
    """
    # Extracted as ROOT when possible. A rootfs unpacked by an ordinary user
    # has every file reassigned to that user, drops setuid bits and cannot
    # create device nodes -- so the guest boots a tree that differs from the
    # image in ways nothing downstream reports. The bash this replaces did this
    # for the gVisor tree and not for the Firecracker one; the inconsistency was
    # not deliberate.
    proc = run(["docker", "create", image], capture_output=True)
    if proc.returncode != 0:
        raise BuildError(f"docker create {image} failed: {(proc.stderr or '').strip()}")
    cid = (proc.stdout or "").strip()
    try:
        tar_argv = [*(_root_prefix() if as_root else []), "tar", "-x", "-C", str(dest)]
        tar = subprocess.Popen(tar_argv, stdin=subprocess.PIPE)  # noqa: S603
        export = run(["docker", "export", cid], stdout=tar.stdin)
        if tar.stdin:
            tar.stdin.close()
        if tar.wait() != 0 or export.returncode != 0:
            raise BuildError(f"exporting {image} failed")
    finally:
        run(["docker", "rm", "-f", cid], capture_output=True)
    log(f"   extracted {image}")


def _check_requires(tree: Path, spec: RootfsSpec, image: str) -> None:
    """Refuse to publish a rootfs missing something the plan says it needs.

    This is the titanarum outage encoded. A cold worker image was exported as a
    Firecracker rootfs; it had no ``/init``, so every warm guest hung until the
    boot timeout and the tier was dead until the previous file was restored.
    Nothing checked, because nothing had written down what the artifact needed.
    Checked BEFORE the live artifact is replaced, so a bad export cannot take
    the tier down at all.
    """
    # lexists, not exists: `/init` is very often a symlink into /opt, and a
    # symlink whose target is absent from the HOST is present in the guest.
    # Resolving it here would reject a correct rootfs.
    missing = [r for r in spec.requires if not os.path.lexists(tree / r.lstrip("/"))]
    if missing:
        raise BuildError(
            f"{image} is missing {missing}, which {spec.dest} declares it requires; "
            "not replacing the live artifact"
        )


def _root_prefix() -> list[str]:
    """How to run a command as root, or an empty list if this cannot.

    Returns `[]` when the process IS root — prepending sudo there needs sudo to
    be installed, which it is not on a minimal image, and would turn a working
    build into a "command not found".
    """
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo") is None:
        return []
    probe = subprocess.run(  # noqa: S603
        ["sudo", "-n", "true"], capture_output=True, text=True, check=False
    )
    return ["sudo"] if probe.returncode == 0 else []


def _can_be_root() -> bool:
    return os.geteuid() == 0 or bool(_root_prefix())


def _sudo_needed(path: Path) -> bool:
    """Whether writing ``path`` needs root.

    Decided by trying the directory rather than by a flag: the gVisor tree lives
    under /var/lib and the Firecracker file usually under $HOME, and an operator
    who has to remember which is which will eventually run the wrong one. An
    unnecessary sudo prompt is a worse default than a check.
    """
    probe = path if path.exists() else path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return not os.access(probe, os.W_OK)


def export_rootfs(
    plan: Plan,
    spec: RootfsSpec,
    tag: str,
    *,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    extract: Callable[[str, Path], None] | None = None,
) -> Path:
    """Produce the artifact a warm tier boots, from the image already verified.

    Never rebuilt from a Dockerfile here. Building one produces an artifact on
    that file's DEFAULT base — unstamped, and not the thing that was verified a
    moment earlier — which reads like a rebuild and is not one.

    Extract, CHECK, then swap. The previous artifact is kept alongside as
    ``.bak``: it is what a rollback needs, and it is the only reason the
    Firecracker outage was minutes rather than a rebuild.
    """
    run = run or _default_runner
    env = dict(os.environ) if env is None else env
    image = f"{spec.image}:{tag}"
    dest = Path(spec.resolved_dest(env))
    if "$" in str(dest):
        raise BuildError(
            f"{spec.dest} still contains an unset variable ({dest}); refusing to "
            "write to a path nobody chose"
        )
    # ONE privilege level for the whole export. The tree is extracted as root
    # so ownership and setuid bits survive, which means everything that then
    # READS it -- mkfs.ext4 above all -- has to be root as well. Splitting the
    # two is not a style question: measured on toolz2, a root-extracted tree
    # consumed by a user-run mkfs.ext4 dies on `.pwd.lock` (mode 600, root) with
    # "Permission denied while populating file system", after every image has
    # already been built and verified.
    #
    # `need_sudo` is the separate question of whether the DESTINATION needs
    # root; when it does, the same prefix covers that too.
    need_sudo = _sudo_needed(dest)
    as_root = _can_be_root()
    priv = _root_prefix() if (as_root or need_sudo) else []

    staging = Path(
        tempfile.mkdtemp(
            prefix="bb-rootfs-",
            dir=str(dest.parent) if dest.parent.exists() and not need_sudo else None,
        )
    )
    # Tracked as a FLAG rather than by clearing `staging` to a sentinel path:
    # `Path("")` stringifies to "." -- truthy, and it exists -- so a falsy check
    # followed by rmtree would delete the working directory.
    published = False
    try:
        if extract is not None:
            extract(image, staging)
        else:
            _extract_image(image, staging, run, log, as_root=as_root)
        _check_requires(staging, spec, image)

        if spec.kind == "dir":
            # Extract-and-swap, never tar over the live tree: an overlay leaves
            # every file the new image DELETED, and the guest boots a mixture.
            if dest.exists():
                _must([*priv, "rm", "-rf", f"{dest}.bak"], "clear .bak", run)
                _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
            _must([*priv, "mkdir", "-p", str(dest.parent)], "mkdir", run)
            _must([*priv, "mv", str(staging), str(dest)], "publish rootfs", run)
            published = True  # moved into place; there is nothing left to remove
        else:
            size = spec.size_mib or _existing_mib(dest) or 1536
            tmp_img = dest.with_suffix(dest.suffix + ".new")
            _must([*priv, "mkdir", "-p", str(dest.parent)], "mkdir", run)
            _must([*priv, "truncate", "-s", f"{size}M", str(tmp_img)], "truncate", run)
            # `mke2fs -d` populates the image directly: no mount, no loop device
            # and no root beyond writing the file — the same discipline the host
            # side uses for never mounting a disk it did not create.
            _must(
                [*priv, "mkfs.ext4", "-F", "-q", "-d", str(staging), str(tmp_img)],
                "mkfs.ext4",
                run,
            )
            if dest.exists():
                _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
            _must([*priv, "mv", str(tmp_img), str(dest)], "publish rootfs", run)
        log(f"   {dest}  (previous kept as {dest.name}.bak)")
        return dest
    finally:
        if not published:
            _remove_tree(staging, priv, run)


def _existing_mib(path: Path) -> int:
    """Match the size of the artifact being replaced when the plan omits one.

    A rootfs that silently shrinks fills up in the guest, and the failure shows
    as whatever the workload was doing at the time rather than as a size.
    """
    try:
        return path.stat().st_size // 1024 // 1024
    except OSError:
        return 0


def run_plan(
    plan: Plan,
    tag: str,
    *,
    blastbox_version: str,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    extract: Callable[[str, Path], None] | None = None,
) -> list[str]:
    """Build, verify, then export — in that order, and only ever in that order.

    Verification sits BETWEEN the two halves deliberately. Exporting first would
    publish an artifact from an image that has not been shown to record what
    built it, which is precisely the state the whole module exists to make
    impossible.
    """
    built = build_plan(plan, tag, blastbox_version=blastbox_version, env=env, run=run, log=log)
    log("\n>> verify: every image must record what it was built from")
    verify_built(built, run=run, log=log)
    for spec in plan.rootfs:
        log(f"\n>> {spec.kind} rootfs <- {spec.image}:{tag}")
        export_rootfs(plan, spec, tag, env=env, run=run, log=log, extract=extract)
    return built
