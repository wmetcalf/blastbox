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

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from blastbox.host import images as _images
from blastbox.host.images import ImageSpec, Plan, RootfsSpec
from blastbox.host.stamp import StampError
from blastbox.host.stamp import repo_digest_ref as _repo_digest_ref
from blastbox.host.stamp import build_args as _stamp_flags
from blastbox.host.stamp import read as _read_stamp
from blastbox.host.stamp import verify_contents as _verify_contents

__all__ = [
    "BuildError",
    "build_plan",
    "export_rootfs",
    "publish_staged",
    "run_plan",
    "stage_rootfs",
    "verify_built",
]


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


_IMAGE_ARG_RE = re.compile(r"^[a-z0-9][\w./-]*(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?$")


def _looks_like_an_image(value: str) -> bool:
    """Whether a build-arg value is plausibly an image reference.

    Deliberately narrow: it must carry a TAG or a digest. A bare word is far
    more likely to be a version, a path or a flag, and pinning something that is
    not an image would fail the build for a reason that has nothing to do with
    provenance.
    """
    if "@sha256:" in value:
        return True
    if ":" not in value:
        return False
    return bool(_IMAGE_ARG_RE.match(value))


def _pin_builder_images(
    spec: ImageSpec,
    env: dict[str, str],
    run: Runner,
    log: Log,
    *,
    pull: bool,
) -> dict[str, str]:
    """Resolve image-valued build args to digests, or {} if there are none.

    Already-digested references are left alone. Anything that cannot be resolved
    is left alone too and reported rather than failing the build: a build arg
    that merely LOOKS like an image is not worth refusing over, and the cost of
    guessing wrong here is a confusing failure a long way from the cause.
    """
    out: dict[str, str] = {}
    for key, raw in sorted(spec.build_args.items()):
        value = _images._expand(raw, env)  # noqa: SLF001 - same package
        if not _looks_like_an_image(value) or "@sha256:" in value:
            continue
        if pull:
            run(["docker", "pull", "-q", value], capture_output=True)
        proc = run(
            ["docker", "inspect", "--type", "image", value, "--format", "{{json .RepoDigests}}"],
            capture_output=True,
        )
        if proc.returncode != 0:
            log(f"   note: could not resolve {key}={value} to a digest; left as the tag")
            continue
        # The FULL `repo@sha256:...`, not the bare digest. A bare one handed to
        # docker as a base resolves as `docker.io/library/sha256:...` and fails
        # with an authorization error naming a repository nobody wrote --
        # measured on toolz2, on titanarum's very first real build.
        digest = _repo_digest_ref(value, (proc.stdout or "").strip())
        if digest:
            out[key] = digest
            log(f"   pinned {key} -> {digest}")
        else:
            log(f"   note: {value} has no registry digest; left as the tag")
    return out


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
    # The resolved version is put in the environment the plan expands against,
    # so a spec can write `BLASTBOX_VERSION = "$BLASTBOX_VERSION"` and keep one
    # source of truth instead of a literal that drifts from the pin.
    env = {**(dict(os.environ) if env is None else env),
           "BLASTBOX_VERSION": blastbox_version}

    problems = (
        _images.missing_dockerfiles(plan, env)
        + _images.arg_problems(plan, env)
        + _images.unresolved_build_args(plan, env)
        + _size_problems(plan, env)
    )
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

        # Builder-stage images are pinned too. `JDK_BUILD_IMAGE
        # = "eclipse-temurin:25-jdk"` is a mutable tag that a multi-stage
        # Dockerfile COPIES artifacts out of, and only the primary base was ever
        # pulled, resolved and recorded -- so an upstream push could change what
        # lands in the image while every label stayed identical. Resolving them
        # to digests makes the build reproducible in the same sense the base is.
        pinned_args = _pin_builder_images(spec, env, run, log, pull=pull)
        to_build = (
            replace(spec, build_args={**spec.build_args, **pinned_args})
            if pinned_args
            else spec
        )
        argv = _images.build_command(to_build, tag, flags, base_ref, env, plan)
        log(f">> build {spec.tagged(tag)}  <- {base_ref}")
        before = _source_state(source)
        _must(argv, f"build {spec.tagged(tag)}", run, cwd=plan.root)
        after = _source_state(source)
        if before != after:
            # The label records the revision read BEFORE the build, while docker
            # read the context during it. A concurrent deploy or an editor save
            # in between produces an image whose contents are not the commit it
            # names -- and it passes every stamp check, because the stamp is
            # self-consistent. Cannot be prevented from here; it can be noticed.
            raise BuildError(
                f"{spec.name}: {source} changed while it was being built "
                f"({before} -> {after}). The stamp would name a revision this "
                "image does not contain; rebuild from a checkout nothing is "
                "writing to."
            )
        built.append(spec.tagged(tag))

    return built


def verify_built(
    images: Sequence[str], *, run: Runner | None = None, log: Log = _log
) -> dict[str, str]:
    """Every image must record enough to be rebuilt, and record it TRUTHFULLY.

    Read from the ARTIFACT, not from what the build was told to do: the two
    disagreeing is exactly the state worth finding, and the only way to see it
    is to ask the image.

    Three separate questions, because an image can pass one and fail another:

    * ``Stamp.reproducible`` -- are the labels complete and usable? Truthiness
      of ``revision`` is not that test: an unstamped image reads back as the
      sentinel ``"unknown"``, which is truthy, so a completely unstamped image
      passed and was exported.
    * ``Stamp.base_moved`` -- did the tag the stamp names still point at the
      recorded image? A local base is pinned by a mutable reference, so a
      concurrent build can retarget it between the inspection and the build and
      leave a child of image B carrying image A's digest.
    * ``verify_contents`` -- is the recorded blastbox version the one actually
      installed? A stale Dockerfile default or a wrong --blastbox-version is
      syntactically perfect and still false, which is the precise thing
      provenance is for.
    """
    runner = None if run is None else (lambda argv: run(argv))
    resolved: dict[str, str] = {}
    bad: list[str] = []
    for image in images:
        log(f"-- {image}")
        try:
            stamp = _read_stamp(image, runner)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001 - collected per image, not fatal here
            bad.append(f"{image}: {exc}")
            continue
        if not stamp.reproducible:
            bad.append(f"{image}: {_why_unusable(stamp)}")
            continue
        try:
            # Returns the base's CURRENT id when it differs from the record, and
            # "" when there is nothing to report. It RAISES when the question
            # cannot be asked, which is not the same as agreement.
            moved = stamp.base_moved(runner)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{image}: could not confirm its base did not move ({exc})")
            continue
        if moved:
            bad.append(
                f"{image}: {stamp.base_name} now resolves to {moved[:19]}…, not the "
                f"{(stamp.base_image_id or '')[:19]}… it records — it was built on "
                "an image its stamp does not name"
            )
            continue
        agrees, detail = _verify_contents(image, runner)  # type: ignore[arg-type]
        if agrees is False:
            bad.append(f"{image}: {detail}")
            continue
        # The ID this tag resolved to WHILE it was being verified. Exporting by
        # tag reopens the question: another build can retag between here and
        # `docker create`, and the rootfs would then come from an image nothing
        # checked.
        ident = _image_id(image, run or _default_runner)
        if not ident:
            bad.append(f"{image}: could not resolve it to an image id")
            continue
        resolved[image] = ident
    if bad:
        raise BuildError(
            "one or more images are not reproducible from what they record:\n  "
            + "\n  ".join(bad)
        )
    return resolved


def _ensure_dir(path: Path, priv: list[str], run: Runner) -> None:
    """Create ``path`` and its parents, shelling out only when root is needed."""
    if priv:
        _must([*priv, "mkdir", "-p", str(path)], "mkdir", run)
    else:
        path.mkdir(parents=True, exist_ok=True)


def _stage_dir(parent: Path, priv: list[str], run: Runner) -> Path:
    """A fresh staging directory beside ``parent``, created with ``priv``.

    ``tempfile.mkdtemp`` cannot do this when the parent needs root, so the name
    is generated here and the directory made through the same runner as
    everything else. ``mktemp -d`` picks the name, so two concurrent runs do not
    collide.
    """
    if not priv:
        return Path(tempfile.mkdtemp(prefix="bb-rootfs-", dir=str(parent)))
    proc = run([*priv, "mktemp", "-d", str(parent / "bb-rootfs-XXXXXXXX")], capture_output=True)
    if proc.returncode != 0:
        raise BuildError(
            f"could not create a staging directory in {parent}: "
            f"{(proc.stderr or '').strip()}"
        )
    # An empty stdout with a zero exit is not a directory. `Path("")` is `.`,
    # which EXISTS and is writable, so the whole export would then extract an
    # image over the working directory and later try to move it into place.
    # This is not hypothetical: a stubbed runner returning "" did exactly that
    # and left a `usr/bin/true` in the repo.
    name = (proc.stdout or "").strip()
    if not name:
        raise BuildError(
            f"mktemp reported success but named no directory in {parent}; "
            "refusing to stage into the working directory"
        )
    return Path(name)


def _size_problems(plan: Plan, env: dict[str, str]) -> list[str]:
    """Declared sizes that do not resolve to a positive whole number.

    Checked in the PREFLIGHT. `resolved_size_mib` raises PlanError, which is not
    a BuildError -- so left to surface from the export it escaped the CLI's
    handler and ended the command in a traceback, after every image had been
    built and verified.
    """
    out: list[str] = []
    for rf in plan.rootfs:
        try:
            rf.resolved_size_mib(env)
        except _images.PlanError as exc:
            out.append(str(exc))
    return out


def _source_state(repo: Path) -> str:
    """A cheap fingerprint of a source tree: its HEAD plus its dirty status.

    Enough to catch the case that matters -- the tree moving or being edited
    across a build -- without hashing a whole checkout on every image.
    """
    head = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    status = subprocess.run(  # noqa: S603
        # --untracked-files=normal explicitly, exactly as stamp.git_revision
        # does: a repo or global config carrying status.showUntrackedFiles=no
        # otherwise hides a new build input created while docker was reading
        # the context, and the before/after comparison sees no change at all.
        ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=normal"],
        capture_output=True, text=True, check=False,
    )
    if head.returncode != 0:
        return ""  # not a git tree; `git_revision` handles that case separately
    # A stable digest, not hash(): PYTHONHASHSEED randomises that per process,
    # so a value built here would be meaningless to compare anywhere else and
    # unreadable in the error message.
    dirt = hashlib.sha256(status.stdout.encode()).hexdigest()[:12]
    return f"{head.stdout.strip()}:{dirt}"


def _image_id(image: str, run: Runner) -> str:
    """``image``'s current image ID, or "" if it cannot be resolved."""
    proc = run(
        ["docker", "inspect", "--type", "image", image, "--format", "{{.Id}}"],
        capture_output=True,
    )
    return (proc.stdout or "").strip() if proc.returncode == 0 else ""


def _why_unusable(stamp: object) -> str:
    """Which condition of ``Stamp.reproducible`` this stamp fails.

    "stamp is incomplete" plus a dump of four fields is not actionable. The
    common case by far is a DIRTY tree, and the fix for that is `git commit`,
    which the operator will not infer from a field list.
    """
    revision = str(getattr(stamp, "revision", "") or "")
    base_name = str(getattr(stamp, "base_name", "") or "")
    blastbox = str(getattr(stamp, "blastbox", "") or "")
    pin = str(getattr(stamp, "base_digest", "") or getattr(stamp, "base_image_id", "") or "")
    if revision.endswith("-dirty"):
        return (
            f"built from a DIRTY tree ({revision}). The uncommitted changes are "
            "recorded nowhere, so that revision cannot rebuild this image — "
            "commit them, or build from a clean checkout"
        )
    if revision in ("", "unknown"):
        return "records no source revision; it was built without a stamp"
    if not pin or pin == "unknown":
        return f"records no base digest for {base_name or 'its base'}; a tag can move or be deleted"
    if base_name in ("", "unknown"):
        return "records a base digest but not which repository to pull it from"
    if blastbox in ("", "unknown"):
        return "records no blastbox version"
    return f"stamp is unusable (revision={revision!r} base={base_name!r} blastbox={blastbox!r})"


def _remove_tree(path: Path, priv: list[str], run: Runner) -> None:
    """Remove a staging tree at the privilege it was WRITTEN with.

    `os.access` on the directory is not the test: mkdtemp makes it owned by this
    user, while everything root extracted inside it is not, so an ordinary
    rmtree walks in and fails partway. A failed export then leaves a whole
    root-owned rootfs behind — observed on toolz2.
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


def _refuse_shrink(dest: Path, size_mib: int, priv: list[str], run: Runner) -> None:
    """Refuse to replace an artifact with a smaller one.

    Not silently obeyed: the exporter this replaces matched the artifact already
    in place, so a smaller declaration is either a mistake or a deliberate
    shrink -- and the deliberate one is rare enough to be worth confirming.
    Shrinking either fails inside mkfs.ext4 once the extracted tree no longer
    fits, or fills up in the guest and surfaces as whatever the workload was
    doing at the time. Neither points at the size.

    Fails CLOSED when the size cannot be read. "I could not look" is not
    "there is nothing there", and reading it as the latter is what lets a
    smaller image through.
    """
    existing = _existing_bytes(dest, priv, run)
    if existing is None:
        raise BuildError(
            f"could not read the size of {dest}; refusing to replace an artifact "
            "that could not be measured"
        )
    want = size_mib * 1024 * 1024
    if existing and want < existing:
        raise BuildError(
            f"{dest} is {existing} bytes and the plan asks for {want} "
            f"({size_mib} MiB). Refusing to shrink a rootfs that is already in "
            "place; set the size explicitly (ROOTFS_MIB, or size_mib in the "
            "plan) if that is intended."
        )


def _normalize_root(tree: Path, priv: list[str], run: Runner) -> None:
    """Give the staging tree the mode and owner a filesystem ROOT has.

    ``mkdtemp`` creates it 0700 and owned by the invoking user, and moving it
    into place publishes it exactly like that -- so the gVisor tree came out
    `drwx------ coz coz` where the one it replaced was `drwxr-xr-x root root`.
    Every file INSIDE is already root's, because extraction runs as root; it is
    only the top directory, which nothing extracts, that keeps mkdtemp's.

    A rootfs whose own root a runtime cannot traverse is a boot failure that
    looks like anything but a permissions problem.
    """
    # Checked, not fired and forgotten. On a filesystem that permits rename but
    # rejects metadata changes, an unchecked pair publishes a tree still at
    # mkdtemp's 0700 and the invoking user -- and reports success.
    if priv:
        _must([*priv, "chown", "root:root", str(tree)], "chown rootfs root", run)
    _must([*priv, "chmod", "0755", str(tree)], "chmod rootfs root", run)


class _Unreadable(Exception):
    """The tree could not be inspected, which is distinct from a missing file."""


def _present_in(tree: Path, requirement: str) -> bool:
    """Whether ``requirement`` exists INSIDE ``tree``, on the image's own terms.

    Walked component by component, refusing to follow a symlink in any parent.
    The tree is attacker-controlled in the only sense that matters here -- it is
    whatever the image happens to contain -- and `os.path.lexists` on a joined
    path follows intermediate links, so an image with `usr -> /usr` would make
    the check find a HOST file and approve a rootfs where the guest path is
    absent. That defeats the guard in the direction that publishes.

    The final component is checked with lstat, not stat: `/init` is very often a
    symlink whose target only resolves inside the guest, and resolving it would
    reject a correct rootfs.
    """
    current = tree
    parts = [p for p in PurePosixPath(requirement).parts if p != "/"]
    for i, part in enumerate(parts):
        candidate = current / part
        try:
            st = candidate.lstat()
        except PermissionError as exc:
            # Not being able to look is not an answer. Reporting "absent" here
            # sends an operator hunting for a file that is present, which is
            # exactly what a root-owned 0700 staging directory did.
            raise _Unreadable(f"{requirement}: {exc}") from exc
        except OSError:
            return False
        last = i == len(parts) - 1
        if last:
            return True
        if stat.S_ISLNK(st.st_mode):
            # A link in a PARENT position would take the walk out of the tree.
            return False
        current = candidate
    return False


def _requirement_problem(requirement: str) -> str:
    """Why ``requirement`` cannot be checked, or "".

    A requirement is a path in the GUEST. Anything relative, or containing `..`,
    either does not describe a guest path or describes one outside the rootfs,
    and in both cases the honest answer is to refuse rather than to check
    something else and report on that.
    """
    if not requirement.startswith("/"):
        return f"{requirement!r} is not an absolute guest path"
    if ".." in PurePosixPath(requirement).parts:
        return f"{requirement!r} contains '..', which would leave the rootfs"
    return ""


def _check_no_setuid(
    tree: Path, spec: RootfsSpec, image: str, priv: list[str], run: Runner
) -> None:
    """Refuse a sandbox rootfs carrying setuid/setgid binaries.

    `deploy/firecracker/build-rootfs.sh` has always refused these, and replacing
    that flow with this module must not silently drop the gate. Audited on the
    EXTRACTED tree rather than by running `find` inside the image: this is what
    actually gets published, and it needs no container.

    Run through `find` at the SAME privilege as the extraction, not with
    `Path.rglob`. rglob skips a directory it cannot read and raises nothing, so
    an unprivileged walk over a root-extracted tree scans almost none of it and
    reports clean -- a gate that always passes is worse than no gate, because it
    reads as evidence. A non-zero find is treated as a refusal for the same
    reason: not being able to look is not a clean result.

    Extraction preserves mode bits on purpose -- that is the fidelity the guest
    needs -- so the audit and the preservation belong together.
    """
    if not spec.forbid_setuid:
        return
    proc = run(
        [*priv, "find", str(tree), "-xdev", "-type", "f", "-perm", "/6000"],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise BuildError(
            f"could not audit {image} for setuid binaries "
            f"({(proc.stderr or '').strip()[:200]}); refusing to publish a rootfs "
            "that has not been checked"
        )
    found = sorted(
        "/" + line.strip()[len(str(tree)) :].lstrip("/")
        for line in (proc.stdout or "").splitlines()
        if line.strip()
    )
    if found:
        raise BuildError(
            f"{image} carries setuid/setgid binaries, which a sandbox rootfs must "
            f"not: {found[:20]}. Strip them in the Dockerfile "
            "(`find / -xdev -type f -perm /6000 -exec chmod a-s {} +`), or set "
            "`forbid_setuid = false` on this [[rootfs]] to accept them deliberately."
        )


def _check_requires(tree: Path, spec: RootfsSpec, image: str) -> None:
    """Refuse to publish a rootfs missing something the plan says it needs.

    This is the titanarum outage encoded. A cold worker image was exported as a
    Firecracker rootfs; it had no ``/init``, so every warm guest hung until the
    boot timeout and the tier was dead until the previous file was restored.
    Nothing checked, because nothing had written down what the artifact needed.
    Checked BEFORE the live artifact is replaced, so a bad export cannot take
    the tier down at all.
    """
    malformed = [p for p in (_requirement_problem(r) for r in spec.requires) if p]
    if malformed:
        raise BuildError(
            f"{spec.dest} declares a requirement that cannot be checked: "
            + "; ".join(malformed)
        )
    try:
        missing = [r for r in spec.requires if not _present_in(tree, r)]
    except _Unreadable as exc:
        raise BuildError(
            f"could not check what {image} contains ({exc}); refusing to publish "
            "a rootfs that has not been checked"
        ) from exc
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
    # The PARENT, never the destination itself. Every write this module does --
    # the staging directory, the `.new` image, the `.bak` rename -- is a
    # SIBLING of the destination. A directory rootfs published through sudo can
    # stay owned and writable by the invoking user under a /var/lib parent that
    # is not, so probing the destination says "no sudo needed" and the next run
    # dies in mkdtemp before it starts.
    probe = path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return not os.access(probe, os.W_OK)


@dataclass
class _Staged:
    """A rootfs prepared but not yet published."""

    spec: RootfsSpec
    image: str
    dest: Path
    priv: list[str]
    staging: Path
    ready: Path  # what gets renamed onto `dest`: the tree, or the .new image
    size_mib: int = 0  # ext4 only; 0 for a directory tree


def stage_rootfs(
    plan: Plan,
    spec: RootfsSpec,
    tag: str,
    *,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    extract: Callable[[str, Path], None] | None = None,
    verified_id: str = "",
) -> _Staged:
    """Prepare the artifact a warm tier boots, WITHOUT replacing anything.

    Never rebuilt from a Dockerfile here. Building one produces an artifact on
    that file's DEFAULT base -- unstamped, and not the thing that was verified a
    moment earlier -- which reads like a rebuild and is not one.
    """
    run = run or _default_runner
    env = dict(os.environ) if env is None else env
    image = f"{spec.image}:{tag}"
    # Extracted by the ID verification resolved, when there is one: a tag is
    # mutable, and re-resolving it here can hand us an image nothing checked.
    source = verified_id or image
    dest = Path(spec.resolved_dest(env))
    if "$" in str(dest):
        raise BuildError(
            f"{spec.dest} still contains an unset variable ({dest}); refusing to "
            "write to a path nobody chose"
        )
    # ONE privilege level for the whole export. The tree is extracted as root so
    # ownership and setuid bits survive, which means everything that then READS
    # it -- mkfs.ext4 above all -- has to be root as well. Measured on toolz2: a
    # root-extracted tree consumed by a user-run mkfs.ext4 dies on `.pwd.lock`
    # (mode 600, root) after every image has already been built and verified.
    need_sudo = _sudo_needed(dest)
    as_root = _can_be_root()
    priv = _root_prefix() if (as_root or need_sudo) else []

    _ensure_dir(dest.parent, priv, run)
    staging = _stage_dir(dest.parent, priv, run)
    try:
        if extract is not None:
            extract(source, staging)
        else:
            if not as_root:
                # An unprivileged tar reassigns every file to the invoking UID
                # and drops setuid bits and device nodes, and the tree is then
                # audited, formatted and published as if it faithfully
                # represented the image. Refusing is the honest outcome: the
                # artifact would not be the one that was verified.
                raise BuildError(
                    f"cannot extract {image} with ownership preserved: this "
                    "process is not root and has no passwordless sudo. An "
                    "unprivileged extraction reassigns every file to the "
                    "invoking user and drops setuid bits, so the published "
                    "rootfs would not be the image that was verified."
                )
            _extract_image(source, staging, run, log, as_root=as_root)
        # BEFORE the checks, not after. `mktemp -d` makes the staging root
        # 0700, and under privilege it is owned by ROOT -- so the in-process
        # requirement walk could not traverse into it and reported /init
        # missing on a rootfs that contained it. The root's mode is ours to
        # set; the contents are the image's.
        _normalize_root(staging, priv, run)
        _check_requires(staging, spec, image)
        _check_no_setuid(staging, spec, image, priv, run)

        staged_size = 0
        if spec.kind == "dir":
            ready = staging
        else:
            declared = spec.resolved_size_mib(env) or 1536
            # Compared in BYTES and rounded UP. Flooring made an artifact of
            # 64 MiB plus one block read as 64, so the preservation below did
            # not trigger and the shrink guard aborted the rebuild -- on an
            # enlarged artifact with no override, which is the exact case this
            # is here to keep working.
            existing_b = _existing_bytes(dest, priv, run) or 0
            existing = -(-existing_b // (1024 * 1024))  # ceil to whole MiB
            if spec.size_is_defaulted(env) and existing > declared:
                # No override given, and the artifact in place is bigger: KEEP
                # its size. The exporter this replaces derived the default from
                # `stat` on the existing file, so a deployment that had grown
                # its rootfs kept it across rebuilds without anyone
                # remembering. Taking the literal instead makes every such
                # rebuild fail the shrink guard -- correct, and useless.
                log(f"   keeping the existing {existing} MiB (declared {declared}, no override)")
                size = existing
            else:
                size = declared
            _refuse_shrink(dest, size, priv, run)
            staged_size = size
            # Unique per run, not a fixed `<dest>.new`. Two concurrent exports
            # to one destination would otherwise truncate and format the SAME
            # file, and one can rename it live while the other is still writing
            # into it -- publication being a rename does not help.
            ready = Path(f"{staging}.img")
            _must([*priv, "truncate", "-s", f"{size}M", str(ready)], "truncate", run)
            # `mke2fs -d` populates the image directly: no mount, no loop device
            # and no root beyond writing the file -- the same discipline the host
            # side uses for never mounting a disk it did not create.
            _must(
                [*priv, "mkfs.ext4", "-F", "-q", "-d", str(staging), str(ready)],
                "mkfs.ext4",
                run,
            )
    except BaseException:
        _remove_tree(staging, priv, run)
        raise
    return _Staged(
        spec=spec, image=image, dest=dest, priv=priv, staging=staging, ready=ready,
        size_mib=staged_size,
    )


def publish_staged(staged: _Staged, *, run: Runner | None = None, log: Log = _log) -> Path:
    """Swap a staged artifact into place, keeping the previous one as ``.bak``.

    Extract, CHECK, then swap -- and the swap is a rename within one filesystem,
    because the staging directory is created beside the destination. The
    previous artifact is what a rollback needs, and it is the only reason the
    Firecracker outage was minutes rather than a rebuild.
    """
    run = run or _default_runner
    dest, priv = staged.dest, staged.priv
    if staged.spec.kind == "dir":
        # Extract-and-swap, never tar over the live tree: an overlay leaves
        # every file the new image DELETED, and the guest boots a mixture.
        if dest.exists():
            _must([*priv, "rm", "-rf", f"{dest}.bak"], "clear .bak", run)
            _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
        _must([*priv, "mv", str(staged.ready), str(dest)], "publish rootfs", run)
    else:
        # RE-CHECKED here, not only at staging. The two are separated in time and
        # this module deliberately supports concurrent exports to one
        # destination, so a larger run can publish in between -- and the check
        # made against the old smaller artifact would then let this one shrink
        # it back.
        _refuse_shrink(dest, staged.size_mib, priv, run)
        if dest.exists():
            _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
        _must([*priv, "mv", str(staged.ready), str(dest)], "publish rootfs", run)
        _remove_tree(staged.staging, priv, run)
    log(f"   {dest}  (previous kept as {dest.name}.bak)")
    return dest


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
    """Stage one artifact and publish it. Convenience for a single export."""
    staged = stage_rootfs(plan, spec, tag, env=env, run=run, log=log, extract=extract)
    return publish_staged(staged, run=run, log=log)


def _existing_bytes(path: Path, priv: list[str], run: Runner) -> int | None:
    """Size of the artifact already in place, in BYTES. None = cannot tell.

    Measured through the privileged runner when the destination needs it: an
    unprivileged `Path.stat()` on a root-only directory raises EACCES, and
    reading that as "absent" would let a smaller image replace a larger one --
    the exact thing the shrink guard exists to prevent.

    BYTES, not MiB: flooring the existing size makes an image of 64 MiB plus one
    block read as 64, so a 64 MiB replacement passes the guard and `truncate`
    removes that block from a filesystem somebody deliberately extended.
    """
    if not priv:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return 0
        except OSError:
            return None
    proc = run([*priv, "stat", "-c", "%s", str(path)], capture_output=True)
    if proc.returncode != 0:
        # Distinguish "not there" from "cannot look". Only the former is a zero.
        missing = run([*priv, "test", "-e", str(path)], capture_output=True)
        return 0 if missing.returncode != 0 else None
    try:
        return int((proc.stdout or "").strip())
    except ValueError:
        return None


def _existing_mib(path: Path, priv: list[str], run: Runner) -> int:
    """The existing size in whole MiB, for defaulting. 0 when absent/unknown."""
    b = _existing_bytes(path, priv, run)
    return (b // 1024 // 1024) if b else 0


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
    verified = verify_built(built, run=run, log=log)
    # Staged FIRST, all of them, then published. Publishing each as it is built
    # leaves the earlier destinations on the new release and the later ones on
    # the old when a later export fails -- the warm tiers then run a mixed
    # release even though the command reported failure, which is worse than not
    # having run it.
    staged: list[_Staged] = []
    try:
        for spec in plan.rootfs:
            log(f"\n>> stage {spec.kind} rootfs <- {spec.image}:{tag}")
            staged.append(
                stage_rootfs(
                    plan, spec, tag, env=env, run=run, log=log, extract=extract,
                    verified_id=verified.get(f"{spec.image}:{tag}", ""),
                )
            )
    except BaseException:
        for s in staged:
            _remove_tree(s.staging, s.priv, run or _default_runner)
        raise
    for s in staged:
        log(f"\n>> publish {s.dest}")
        publish_staged(s, run=run, log=log)
    return built
