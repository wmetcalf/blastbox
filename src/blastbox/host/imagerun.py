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

import contextlib
import fcntl
import hashlib
import time
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
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
    "PublishedTags",
    "build_plan",
    "export_rootfs",
    "publish_staged",
    "publish_tags",
    "sweep_stale_staging_tags",
    "restore_tags",
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
        # Never the VALUE for an argument whose name reads as a credential.
        # `REGISTRY_PASS=hunter:2` looks exactly like an image reference, so it
        # reaches the pull below and its failure message carried the expanded
        # credential into terminal and CI logs -- a leak reached through the
        # very heuristic that exists to be permissive.
        shown = f"{key}=<redacted>" if _images._is_secret(key) else f"{key}={value}"  # noqa: SLF001
        if not _looks_like_an_image(value):
            continue
        if "@sha256:" in value:
            # Already immutable, so nothing to resolve -- but it still supplies
            # files to the image, so it belongs in the provenance record.
            # Omitting it made a multi-stage build read back with the same empty
            # `org.blastbox.builders` as an image that has no builder at all.
            out[key] = value
            continue
        if pull:
            # NOT fatal, because reaching here is a HEURISTIC: `CACHE_ENDPOINT
            # = "cache:6379"` looks exactly like an image reference, and
            # aborting a valid build over a value docker was only ever going to
            # receive as a string is worse than the drift.
            #
            # A failure is reported and the value left alone, so a stale local
            # image cannot be silently resolved to a digest and recorded as
            # though it were fresh: the inspect below is skipped too.
            pulled = run(["docker", "pull", "-q", value], capture_output=True)
            if pulled.returncode != 0:
                # docker echoes the reference it was given, so a secret-bearing
                # stderr is a leak too. Redacted arguments get the reason
                # withheld, not the whole note: the operator still learns which
                # argument was skipped and why to look at it.
                why = (
                    "the value is withheld because the argument name reads as a "
                    "credential"
                    if _images._is_secret(key)  # noqa: SLF001
                    else (pulled.stderr or "").strip()[:120]
                )
                log(f"   note: could not pull {shown} ({why}); left as the tag")
                continue
        proc = run(
            [
                "docker",
                "inspect",
                "--type",
                "image",
                value,
                "--format",
                "{{json .RepoDigests}}",
            ],
            capture_output=True,
        )
        if proc.returncode != 0:
            log(f"   note: could not resolve {shown} to a digest; left as the tag")
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
            log(f"   note: {shown} has no registry digest; left as the tag")
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


def _redact_argv(argv: Sequence[str]) -> list[str]:
    """``argv`` with secret --build-arg VALUES masked.

    describe() redacting them is not enough: a real build passes the EXPANDED
    value here, and this failure message is printed by the CLI -- so any routine
    docker failure put the token in terminal history and CI logs, right after a
    description that showed it redacted.
    """
    from blastbox.host.images import _is_secret  # noqa: PLC0415

    out: list[str] = []
    for arg in argv:
        name, sep, _value = arg.partition("=")
        out.append(f"{name}=<redacted>" if sep and _is_secret(name) else arg)
    return out


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
        raise BuildError(
            f"{what} failed ({' '.join(_redact_argv(argv))})"
            f"{': ' + detail if detail else ''}"
        )
    return proc


def _staging_tag(tag: str) -> str:
    """A private tag to build under, distinct from the one being published.

    `docker build -t` moves the tag the moment the build succeeds. When that is
    a tag the fleet dispatches on, a worker can pull an image before anything
    has verified it, and a later failure in the chain leaves the live tags on a
    mixture of two builds. So the chain is built under this name and only
    retagged once every image has passed verification.

    Includes the pid because two runs of the same tag on one host would
    otherwise share a staging name and each would see the other's images.
    Bounded to docker's 128 characters, keeping the SUFFIX -- the part that
    makes it private -- when a long tag has to be trimmed.
    """
    # The pid alone is not unique: two `run_plan` calls for the same requested
    # tag inside one process -- a fleet tool building several engines, a test
    # suite -- would share a staging name, retag each other's images mid-build,
    # and the first to publish would delete tags the second still needs.
    # The pid is kept anyway: it says which process to look at when a refused
    # build leaves its images behind.
    # The tag carries its OWN creation time. docker's `.CreatedAt` is when the
    # IMAGE was created, not when the tag was attached, so a cache hit gives a
    # brand-new staging tag an old timestamp -- and a concurrent run's sweep
    # would then delete a tag the live build still needs.
    suffix = (
        f"-blastbox-staging-{os.getpid()}-{uuid.uuid4().hex[:8]}-{int(time.time())}"
    )
    return tag[: 128 - len(suffix)] + suffix


@dataclass(frozen=True)
class PublishedTags:
    """Which tags a run moved, what each pointed at, and what it now holds.

    All three are needed to roll back correctly. "What it pointed at" is where
    the tag goes back to -- and a tag that pointed at NOTHING has to be removed
    rather than left on a half-published chain. "What it now holds" is how a
    rollback tells its own publication from a newer run's: putting our previous
    image back over somebody else's newer one is the same silent downgrade the
    artifact rollback already guards against.
    """

    tags: tuple[str, ...]
    previous: dict[str, str]
    published: dict[str, str]


# The COMPLETE generated shape, anchored at the end of the tag component.
# `demo-blastbox-staging-cache:prod` is a legal image name, and a substring
# check would have handed it to `docker rmi`.
_STAGING_RE = re.compile(r"-blastbox-staging-\d+-[0-9a-f]{8}-(\d{10,})$")


def sweep_stale_staging_tags(
    older_than_hours: int = 24, *, run: Runner | None = None, log: Log = _log
) -> list[str]:
    """Drop private build tags left behind by runs that finished long ago.

    A refused build deliberately KEEPS its staging tags: they are the only names
    those images have, and an operator diagnosing why verification rejected one
    needs to inspect it. That is only defensible if they do not accumulate --
    repeated failures would otherwise pin every rejected chain on disk forever.

    Age, not liveness. Deciding by pid means guessing whether a pid belongs to a
    concurrent run or was recycled, and guessing wrong deletes a tag a live run
    still needs. Anything this old belongs to a run nobody is still reading.
    """
    runner = run or _default_runner
    proc = runner(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.CreatedAt}}"],
        capture_output=True,
    )
    if proc.returncode != 0:
        return []  # not worth failing a build over; the next run tries again
    cutoff = time.time() - older_than_hours * 3600
    dropped: list[str] = []
    for line in (proc.stdout or "").splitlines():
        ref, _, _created = line.partition("\t")
        # The TAG component only. With the end anchor above this is currently
        # equivalent to searching the whole reference -- a mutation check says
        # so -- but it states the rule the anchor happens to enforce: only the
        # part this module generates is ours to delete.
        match = _STAGING_RE.search(ref.rsplit(":", 1)[-1])
        if match is None:
            continue
        stamp = float(match.group(1))
        if stamp > cutoff:
            continue
        if (
            runner(["docker", "rmi", "--no-prune", ref], capture_output=True).returncode
            == 0
        ):
            dropped.append(ref)
    if dropped:
        log(f"   swept {len(dropped)} staging tag(s) from earlier runs")
    return dropped


def publish_tags(
    staged: Sequence[str], tag: str, *, run: Runner | None = None, log: Log = _log
) -> PublishedTags:
    """Point the requested tags at the images that were built and verified.

    Refuses before moving ANYTHING if the previous state of a tag cannot be
    read. A rollback decides between "restore the old image" and "remove the
    tag" from that reading, so guessing turns a transient daemon error into a
    deleted production tag with no recorded reference to restore.
    """
    runner = run or _default_runner
    finals = [f"{s.rsplit(':', 1)[0]}:{tag}" for s in staged]
    previous: dict[str, str] = {}
    published: dict[str, str] = {}
    order: list[str] = []
    with contextlib.ExitStack() as locks:
        # EVERY tag, held across the whole snapshot-and-publish sequence. Taken
        # one at a time, two runs could interleave a chain: A publishes the
        # base, B publishes base and worker, A then publishes the worker -- a
        # mixed chain although both runs reported success. Sorted, so two runs
        # acquiring overlapping sets cannot deadlock against each other.
        for ref in sorted(set(finals)):
            locks.enter_context(_tag_lock(ref))
        for final in finals:
            state = _image_state(final, runner)
            if state is None:
                raise BuildError(
                    f"refusing to publish: cannot determine what {final} points "
                    "at now. Rollback depends on knowing whether it existed, so "
                    "moving it without that reading risks losing the image it "
                    "names."
                )
            previous[final] = state
        try:
            for staged_tag, final in zip(staged, finals, strict=True):
                log(f"   {final} <- {staged_tag}")
                _must(["docker", "tag", staged_tag, final], f"tag {final}", runner)
                # Read back while the lock is still held: a rollback restores
                # only while the tag still holds this.
                published[final] = _image_id(final, runner)
                order.append(final)
        except BaseException:
            _restore_tags_locked(
                PublishedTags(tuple(order), previous, published), runner, log
            )
            _drop_staging_tags(staged, runner)
            raise
    _drop_staging_tags(staged, runner)
    return PublishedTags(tuple(order), previous, published)


def restore_tags(
    published: PublishedTags,
    staged: Sequence[str] = (),
    *,
    run: Runner | None = None,
    log: Log = _log,
) -> None:
    """Put every tag in ``published`` back where it was before the run.

    Best effort in that it does not raise -- it usually runs while another
    failure is propagating -- but never SILENT: a tag it could not restore is
    reported, because the state it leaves behind is a live tag on a new release
    beside a rootfs from the old one, which is the mixed release this path
    exists to prevent.
    """
    runner = run or _default_runner
    with contextlib.ExitStack() as locks:
        for ref in sorted(set(published.tags)):
            locks.enter_context(_tag_lock(ref))
        _restore_tags_locked(published, runner, log)
    _drop_staging_tags(staged, runner)


def _restore_tags_locked(published: PublishedTags, runner: Runner, log: Log) -> None:
    """The restore itself, with every affected tag already locked."""
    failed: list[str] = []
    if True:  # keeps the body's indentation stable for review
        for final in reversed(published.tags):
            now = _image_state(final, runner)
            ours = published.published.get(final, "")
            if now is None:
                failed.append(f"{final} (cannot read what it points at now)")
                continue
            if ours and now and now != ours:
                log(
                    f"   NOT restoring {final}: another run has published there "
                    "since; leaving it alone"
                )
                continue
            was = published.previous.get(final, "")
            if was:
                proc = runner(["docker", "tag", was, final], capture_output=True)
            else:
                # It did not exist before this run. Leaving it on a
                # half-published chain is worse than leaving it absent, which is
                # what a consumer of a brand-new tag is already prepared for.
                proc = runner(
                    ["docker", "rmi", "--no-prune", final], capture_output=True
                )
            if proc.returncode != 0:
                failed.append(f"{final} ({(proc.stderr or '').strip()[:80]})")
                continue
            log(f"   {final} restored")
    if failed:
        log(
            "   TAG ROLLBACK INCOMPLETE — these still point at the new release "
            "while the artifacts do not: " + ", ".join(failed)
        )


def _drop_staging_tags(staged: Sequence[str], run: Runner) -> None:
    """Drop the private build tags; the images live on under their real ones.

    Best effort: a leftover staging tag is untidy, not unsafe, and failing the
    run over one would turn a successful publication into a reported failure.
    """
    for staged_tag in staged:
        run(["docker", "rmi", "--no-prune", staged_tag], capture_output=True)


def build_plan(
    plan: Plan,
    tag: str,
    *,
    blastbox_version: str,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    pull: bool = True,
    staging: str | None = None,
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
    env = {
        **(dict(os.environ) if env is None else env),
        "BLASTBOX_VERSION": blastbox_version,
    }

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

    # After validation, before the first build. A run that is REFUSED keeps its
    # own staging tags for inspection, so the bound on accumulation has to come
    # from somewhere, and this is the point where it costs nothing -- the plan
    # is known good and no docker command has run yet, which is a property the
    # "nothing runs until the size is known" test enforces.
    sweep_stale_staging_tags(run=run, log=log)

    built: list[str] = []
    # The chain is built and linked under a PRIVATE tag. `resolve_chain` is
    # given that name too, so an internal base still resolves to the image from
    # this run rather than to a stale tag of the same name.
    #
    # Computed ONCE per run and shared with the caller: it carries a random
    # component so two invocations cannot collide, so recomputing it anywhere
    # else names images nothing built.
    staging = staging or _staging_tag(tag)
    # Two views of the same chain: what each image is BUILT against (the private
    # staging tags of this run) and what its stamp should NAME (the tags this
    # run will publish). They differ only for internal bases, and conflating
    # them is what left every child stamped with a reference that gets removed
    # at the end of the very run that created it.
    # Paired by position, not keyed on the spec: `ImageSpec` carries a dict of
    # build args and is not hashable.
    published_chain = [ref for _spec, ref in _images.resolve_chain(plan, tag)]
    for index, (spec, base_ref) in enumerate(_images.resolve_chain(plan, staging)):
        record_as = published_chain[index] if spec.internal else None
        if pull and not spec.internal:
            # Present locally BEFORE it is inspected for a digest. Otherwise the
            # build pulls it itself and can get a different push of the same
            # mutable tag than the one recorded a moment earlier.
            log(f">> pull {base_ref}")
            _must(["docker", "pull", "-q", base_ref], f"pull {base_ref}", run)

        source = _images.source_repo_path(plan, spec, env)
        # Resolved BEFORE the stamp, so the digests land in the labels. While
        # this ran after `_stamp_flags` the pins existed only in the build argv:
        # the same plan, revision and base could produce a different image once
        # a builder tag moved, and every label stayed identical -- the drift
        # this pinning exists to prevent, left with nothing recording it.
        pinned_args = _pin_builder_images(spec, env, run, log, pull=pull)
        try:
            flags = _stamp_flags(
                record_base_as=record_as,
                builders=pinned_args,
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
            raise BuildError(
                f"{spec.name}: refusing to build unstamped — {exc}"
            ) from exc

        # Builder-stage images are pinned too. `JDK_BUILD_IMAGE
        # = "eclipse-temurin:25-jdk"` is a mutable tag that a multi-stage
        # Dockerfile COPIES artifacts out of, and only the primary base was ever
        # pulled, resolved and recorded -- so an upstream push could change what
        # lands in the image while every label stayed identical. Resolving them
        # to digests makes the build reproducible in the same sense the base is.
        to_build = (
            replace(spec, build_args={**spec.build_args, **pinned_args})
            if pinned_args
            else spec
        )
        argv = _images.build_command(to_build, staging, flags, base_ref, env, plan)
        log(f">> build {spec.tagged(staging)}  <- {base_ref}")
        before = _source_state(source)
        _must(argv, f"build {spec.tagged(staging)}", run, cwd=plan.root)
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
        built.append(spec.tagged(staging))

    return built


def verify_built(
    images: Sequence[str],
    *,
    aliases: Mapping[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
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
        # FIRST, before anything is asked of the tag. Every check below used to
        # re-resolve the mutable tag independently, so a concurrent retag between
        # them let verification read image A's stamp and export image B. One
        # resolution, and every question afterwards is asked of that ID.
        ident = _image_id(image, run or _default_runner)
        if not ident:
            bad.append(f"{image}: could not resolve it to an image id")
            continue
        try:
            stamp = _read_stamp(ident, runner)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001 - collected per image, not fatal here
            bad.append(f"{image}: {exc}")
            continue
        if not stamp.reproducible:
            bad.append(f"{image}: {_why_unusable(stamp)}")
            continue
        # The stamp names the tag that WILL be published; during verification
        # that tag does not exist yet and the same image is reachable under the
        # staging alias this run built it as. Only the lookup is redirected --
        # what the image records is unchanged, and after publication the
        # recorded name resolves on its own.
        alias = (aliases or {}).get(stamp.base_name or "")
        try:
            # Returns the base's CURRENT id when it differs from the record, and
            # "" when there is nothing to report. It RAISES when the question
            # cannot be asked, which is not the same as agreement.
            moved = stamp.base_moved(runner, alias)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{image}: could not confirm its base did not move ({exc})")
            continue
        # `base_moved` deliberately answers "" when the recorded base is GONE --
        # absence is `resolvable`'s question, and nothing here was asking it. A
        # perfectly stamped image whose base has been deleted cannot be rebuilt
        # from what it records, which is the original failure this all exists for.
        try:
            still_there = stamp.resolvable(runner, alias)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            bad.append(f"{image}: could not confirm its base is still present ({exc})")
            continue
        if not still_there:
            where = f" (looked for it as {alias})" if alias else ""
            bad.append(
                f"{image}: the base it records ({stamp.base_name}) is no longer "
                f"present on this host{where} — it cannot be rebuilt from what "
                "it names"
            )
            continue
        if moved:
            bad.append(
                f"{image}: {stamp.base_name} now resolves to {moved[:19]}…, not the "
                f"{(stamp.base_image_id or '')[:19]}… it records — it was built on "
                "an image its stamp does not name"
            )
            continue
        agrees, detail = _verify_contents(ident, runner)  # type: ignore[arg-type]
        if agrees is False:
            bad.append(f"{image}: {detail}")
            continue
        # The ID every check above was asked of. Callers export THIS, not the
        # tag: another build can retag between here and `docker create`, and the
        # rootfs would then come from an image nothing checked.
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
    proc = run(
        [*priv, "mktemp", "-d", str(parent / "bb-rootfs-XXXXXXXX")], capture_output=True
    )
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
        capture_output=True,
        text=True,
        check=False,
    )
    status = subprocess.run(  # noqa: S603
        # --untracked-files=all explicitly. `stamp.git_revision` forces
        # `normal` for the same reason -- a repo or global config carrying
        # status.showUntrackedFiles=no
        # otherwise hides a new build input created while docker was reading
        # the context, and the before/after comparison sees no change at all.
        # `all`, not `normal`: normal lists an untracked DIRECTORY as one entry,
        # so adding or removing a file inside an already-untracked `generated/`
        # leaves both snapshots reading `?? generated/` and a changing context
        # passes the check unchanged.
        ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
        capture_output=True,
        text=True,
        check=False,
    )
    if head.returncode != 0:
        return ""  # not a git tree; `git_revision` handles that case separately
    # A stable digest, not hash(): PYTHONHASHSEED randomises that per process,
    # so a value built here would be meaningless to compare anywhere else and
    # unreadable in the error message.
    dirt = hashlib.sha256(status.stdout.encode()).hexdigest()[:12]
    return f"{head.stdout.strip()}:{dirt}"


def _image_state(image: str, run: Runner) -> str | None:
    """``image``'s id, "" if it is confirmed ABSENT, or None if unknowable.

    `_image_id` collapses every failure to "", which reads as "there was
    nothing here". Publication uses that to decide whether a rollback should
    restore the previous image or REMOVE the tag -- so one transient daemon
    error made a rollback delete the live tag and lose its only reference.
    """
    proc = run(
        ["docker", "inspect", "--type", "image", image, "--format", "{{.Id}}"],
        capture_output=True,
    )
    if proc.returncode == 0:
        return (proc.stdout or "").strip()
    stderr = (proc.stderr or "").lower()
    if "no such" in stderr or "not found" in stderr:
        return ""
    return None


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
    pin = str(
        getattr(stamp, "base_digest", "") or getattr(stamp, "base_image_id", "") or ""
    )
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


def _extract_image(
    image: str, dest: Path, run: Runner, log: Log, *, as_root: bool
) -> None:
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


@contextlib.contextmanager
def _destination_lock(dest: Path) -> Iterator[None]:
    """Serialise publication AND rollback for one destination.

    This module deliberately supports concurrent exports to a single
    destination, which makes every check-then-swap a race: two runs can both
    pass the shrink check against the old artifact, and a rollback can delete a
    newer run's successful publication and restore a backup that is not its own.
    Re-checking narrows those windows; only a lock closes them.

    Held on a file keyed by the destination in /tmp rather than beside the
    artifact: the destination's directory is often root-only, and needing
    privilege to take a lock would mean the unprivileged path silently skipped
    it. The key is the full path, so two destinations never share a lock.
    """
    # CANONICAL identity, not the spelling. Two invocations naming one artifact
    # through a symlinked parent, a `..` component, or relative vs absolute
    # would otherwise take different locks and concurrently replace the same
    # destination and .bak -- the lock would exist and serialise nothing.
    # realpath on the parent, keeping the name: the final component is what we
    # replace and may itself be a symlink we must not follow.
    canonical = Path(os.path.realpath(dest.parent)) / dest.name
    yield from _locked_on(str(canonical))


@contextlib.contextmanager
def _tag_lock(ref: str) -> Iterator[None]:
    """Serialise publication AND rollback for one image tag.

    The same argument as `_destination_lock`, for the other half of a
    publication: two runs moving one tag is a check-and-swap, and a rollback
    that does not hold the lock races the ownership check it just made.
    """
    yield from _locked_on(f"tag:{ref}")


def _locked_on(key_source: str) -> Iterator[None]:
    """The lock itself, keyed by an already-canonical identity."""
    key = hashlib.sha256(key_source.encode()).hexdigest()[:16]
    path = Path(tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"
    # O_RDONLY: flock needs a descriptor, not write access. The file PERSISTS,
    # so an operator who runs once as root leaves it 0644 root-owned under the
    # usual umask -- and every later run as the deployment user would then get
    # EACCES on O_RDWR and be unable to publish at all, for a lock it only
    # wanted to read.
    # O_NOFOLLOW, because this path is PREDICTABLE and lives in a
    # world-writable directory: without it an unprivileged user can pre-create
    # it as a symlink to a root-owned file, and a root run would then follow
    # the link and fchmod that file to 0666.
    # O_NONBLOCK as well as O_NOFOLLOW: a local user can plant a FIFO rather
    # than a symlink at this predictable path, and opening an existing FIFO
    # O_RDONLY blocks until a writer appears -- so execution never reaches the
    # regular-file check below and every publication for this destination hangs
    # forever. O_NOFOLLOW does not cover that.
    fd = os.open(path, os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o666)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BuildError(f"{path} is not a regular file; refusing to lock on it")
        # Widened only when we own it AND it is a plain file, so the chmod can
        # never land on something we were pointed at.
        with contextlib.suppress(OSError):
            if st.st_uid == os.geteuid():
                os.fchmod(fd, 0o666)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _restore_backup(staged: _Staged, run: Runner, log: Log) -> None:
    """Put the previous artifact back at ``dest``, best effort.

    Best effort on purpose: this runs while another failure is already
    propagating, and raising here would replace the real error with a worse
    one. What it cannot restore, it SAYS -- a silent half-rollback is the
    thing that makes an incident hard to read afterwards.
    """
    dest, priv = staged.dest, staged.priv
    # The SAME lock publication takes. Without it this check-and-swap races the
    # very thing it is checking for: a second run can publish between the
    # comparison below and the exchange that follows it.
    with _destination_lock(dest):
        _restore_locked(staged, dest, priv, run, log)


def _restore_locked(
    staged: _Staged, dest: Path, priv: list[str], run: Runner, log: Log
) -> None:
    """The rollback itself, under the destination's lock."""
    # Ours, or somebody else's? `publish_staged` releases the lock when it
    # returns, so another run can publish here before this one fails on a LATER
    # artifact. Restoring then would replace its artifact with the release we
    # are rolling back FROM -- a silent downgrade of a live tier, done by a
    # recovery path.
    now = _artifact_identity(dest, priv, run)
    if not staged.published_identity or not now:
        # Failing OPEN here defeats the guard entirely: a destination that has
        # vanished, or a stat that failed, is exactly when we cannot tell our
        # artifact from a newer run's -- and restoring over a newer one is the
        # silent downgrade this check exists to prevent. Unknown means leave it.
        log(
            f"   NOT rolling back {dest}: cannot establish whether it still "
            "holds this run's artifact; leaving it alone"
        )
        return
    if now != staged.published_identity:
        log(
            f"   NOT rolling back {dest}: another run has published there since "
            "(it no longer holds this run's artifact); leaving it alone"
        )
        return
    bak = staged.restore_from or Path(f"{staged.dest}.bak")
    # What this run FOUND, not what happens to be on disk now: a stale backup
    # from an earlier run would otherwise be resurrected as if it were ours.
    if staged.had_previous is False:
        # Nothing was there before this run, so the inverse of publishing is
        # REMOVING what we put down -- that restores the prior state exactly.
        # Leaving it would be a partial publish of the release that just failed.
        proc = run([*priv, "rm", "-rf", str(dest)], capture_output=True)
        if proc.returncode == 0:
            log(f"   removed {dest} (nothing was there before this run)")
        else:
            log(f"   ROLLBACK FAILED for {dest}: {(proc.stderr or '').strip()}")
        return
    # EXCHANGE, then delete the failed artifact. `rm -rf dest` followed by
    # `mv bak dest` leaves the live path absent for as long as the removal
    # takes -- reintroducing, during recovery, the exact outage window the
    # atomic publish exists to avoid.
    if not _exists(bak, priv, run):
        # Removing the live artifact with nothing to put back is worse than
        # leaving the new one in place. Say what happened instead.
        log(
            f"   CANNOT roll back {dest}: no restorable copy at {bak}; "
            "the new artifact is still live"
        )
        return
    if _exchange(bak, dest, priv, run):
        run([*priv, "rm", "-rf", str(bak)], capture_output=True)
        return
    proc = run([*priv, "rm", "-rf", str(dest)], capture_output=True)
    if proc.returncode != 0:
        log(f"   cannot roll back {dest}: {(proc.stderr or '').strip()}")
        return
    proc = run([*priv, "mv", str(bak), str(dest)], capture_output=True)
    if proc.returncode != 0:
        log(f"   ROLLBACK FAILED for {dest}: {(proc.stderr or '').strip()}")


def _exists(path: Path, priv: list[str], run: Runner) -> bool:
    """Whether ``path`` exists, asked at the privilege that can see it."""
    if not priv:
        return path.exists()
    return run([*priv, "test", "-e", str(path)], capture_output=True).returncode == 0


def _exchange(a: Path, b: Path, priv: list[str], run: Runner) -> bool:
    """Atomically swap two paths; False when the platform cannot.

    `mv old aside` followed by `mv new in` leaves the live path ABSENT in
    between, and a worker that starts in that window fails for a reason nothing
    records. `renameat2(RENAME_EXCHANGE)` has no such window.

    Reported rather than assumed: the syscall needs Linux >= 3.15 and
    filesystem support, so the caller falls back and says the window exists.
    """
    script = (
        "import ctypes, sys;"
        "libc = ctypes.CDLL(None, use_errno=True);"
        "AT_FDCWD = -100; RENAME_EXCHANGE = 2;"
        "r = libc.renameat2(AT_FDCWD, sys.argv[1].encode(), AT_FDCWD,"
        " sys.argv[2].encode(), RENAME_EXCHANGE);"
        "sys.exit(0 if r == 0 else 1)"
    )
    proc = run(
        [*priv, sys.executable, "-c", script, str(a), str(b)], capture_output=True
    )
    return proc.returncode == 0


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
    # Recorded at publication, never inferred from `.bak` afterwards: a stale
    # backup can outlive an absent destination, and `Path.exists()` answers
    # False for a real one under a root-only parent. Both readings make rollback
    # do the wrong thing -- resurrect a stale artifact, or delete the new one
    # without restoring anything.
    had_previous: bool | None = None
    # WHERE the replaceable original ended up. Normally `<dest>.bak`, but when
    # the exchange succeeded and saving the backup then failed, the original is
    # still sitting at `ready`. Rollback must be told, not left to assume.
    restore_from: Path | None = None
    # WHAT this run put at `dest`, as device:inode. Rollback restores only when
    # the destination is still that object: a concurrent run can publish in
    # between, and putting our backup over its artifact would silently downgrade
    # a tier to the release we were rolling back FROM.
    published_identity: str = ""


def stage_rootfs(
    plan: Plan,
    spec: RootfsSpec,
    tag: str,
    *,
    env: dict[str, str] | None = None,
    run: Runner | None = None,
    log: Log = _log,
    extract: Callable[[str, Path], None] | None = None,
    extract_preserves_ownership: bool = False,
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
    # Asked of the TEMPLATE, like the dry run and the plan validator. This is
    # the last of the three and the one that actually guards the write, so
    # leaving it result-based meant a destination whose expansion legitimately
    # contains a dollar was built and verified and only then refused.
    if _images.unresolved_names(
        spec.dest, env if env is not None else dict(os.environ)
    ):
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

    # BEFORE any directory is created. `_ensure_dir`/`_stage_dir` raise a bare
    # PermissionError under a protected destination, and the CLI catches only
    # BuildError -- so the very environment this refusal exists for got a
    # traceback instead of the actionable message.
    if extract is not None and not extract_preserves_ownership:
        # The presence of a hook is not evidence about what it does. An
        # ordinary shutil/tar callback produces an all-caller-owned tree with
        # setuid bits dropped, and `_normalize_root` only fixes the staging
        # ROOT -- so the remaining checks would pass and publish an altered
        # filesystem. Callers who preserve ownership say so; the default is the
        # safe answer for a callback this module cannot inspect.
        raise BuildError(
            f"cannot extract {image} through a caller-supplied hook without "
            "extract_preserves_ownership=True. An extraction that reassigns "
            "ownership or drops setuid bits publishes a rootfs that is not the "
            "image that was verified, and the hook's presence alone does not "
            "say which kind it is."
        )
    if extract is None and not as_root:
        raise BuildError(
            f"cannot extract {image} with ownership preserved: this process is "
            "not root and has no passwordless sudo. An unprivileged extraction "
            "reassigns every file to the invoking user and drops setuid bits, "
            "so the published rootfs would not be the image that was verified."
        )
    _ensure_dir(dest.parent, priv, run)
    staging = _stage_dir(dest.parent, priv, run)
    # Bound BEFORE the try: the cleanup handler reads it, and an exception from
    # the audit -- which runs before the artifact is named -- would otherwise
    # raise NameError and mask the real failure.
    staged_ready: Path | None = None
    try:
        if extract is not None:
            extract(source, staging)
        else:
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
            ready = staged_ready = staging
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
                log(
                    f"   keeping the existing {existing} MiB (declared {declared}, no override)"
                )
                size = existing
            else:
                size = declared
            _refuse_shrink(dest, size, priv, run)
            staged_size = size
            # Unique per run, not a fixed `<dest>.new`. Two concurrent exports
            # to one destination would otherwise truncate and format the SAME
            # file, and one can rename it live while the other is still writing
            # into it -- publication being a rename does not help.
            ready = staged_ready = Path(f"{staging}.img")
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
        # `ready` is a sibling FILE for ext4, not inside the staging tree, so
        # removing the tree alone left a partly-formatted image of the declared
        # size beside the destination after every failed attempt.
        if staged_ready is not None and staged_ready != staging:
            run([*priv, "rm", "-f", str(staged_ready)], capture_output=True)
        raise
    return _Staged(
        spec=spec,
        image=image,
        dest=dest,
        priv=priv,
        staging=staging,
        ready=ready,
        size_mib=staged_size,
    )


def publish_staged(
    staged: _Staged, *, run: Runner | None = None, log: Log = _log
) -> Path:
    """Swap a staged artifact into place, keeping the previous one as ``.bak``.

    Extract, CHECK, then swap -- and the swap is a rename within one filesystem,
    because the staging directory is created beside the destination. The
    previous artifact is what a rollback needs, and it is the only reason the
    Firecracker outage was minutes rather than a rebuild.
    """
    run = run or _default_runner
    dest, priv = staged.dest, staged.priv
    with _destination_lock(dest):
        return _publish_locked(staged, dest, priv, run, log)


def _publish_locked(
    staged: _Staged, dest: Path, priv: list[str], run: Runner, log: Log
) -> Path:
    """The swap itself, under the destination's lock."""
    # Through the privileged runner, because `Path.exists()` answers False for a
    # real artifact under a root-only parent -- and rollback would then delete
    # what it just published instead of restoring anything.
    staged.had_previous = _exists(dest, priv, run)
    if staged.spec.kind == "dir":
        # Extract-and-swap, never tar over the live tree: an overlay leaves
        # every file the new image DELETED, and the guest boots a mixture.
        # `mv old aside` then `mv new in` leaves a window with NO rootfs at the
        # live path, and a worker starting in that window fails. Swap the
        # DIRECTORY ENTRY instead: renameat2(RENAME_EXCHANGE) is atomic, so the
        # path is never absent. Falls back to the two-step form only where the
        # kernel or filesystem lacks it, and says so.
        if staged.had_previous:
            _must([*priv, "rm", "-rf", f"{dest}.bak"], "clear .bak", run)
            if _exchange(staged.ready, dest, priv, run):
                # The new tree is LIVE from here on. Keeping the old one is
                # best-effort: failing now and letting the caller roll back
                # would undo a publication that already succeeded, so the
                # inability to save a backup is reported, not raised.
                keep = run(
                    [*priv, "mv", str(staged.ready), f"{dest}.bak"], capture_output=True
                )
                if keep.returncode == 0:
                    staged.restore_from = Path(f"{dest}.bak")
                else:
                    # The exchange already happened, so the ORIGINAL is at
                    # `ready`. Recording that is the difference between a
                    # rollback that works and one that deletes the live
                    # artifact and finds nothing to put back.
                    staged.restore_from = staged.ready
                    log(
                        f"   published, but could not keep a backup of {dest}: "
                        f"{(keep.stderr or '').strip()}; the previous tree is at "
                        f"{staged.ready}"
                    )
            else:
                log(
                    "   note: atomic exchange unavailable; the live path is "
                    "briefly absent during this swap"
                )
                _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
                staged.restore_from = Path(f"{dest}.bak")
                _must(
                    [*priv, "mv", str(staged.ready), str(dest)], "publish rootfs", run
                )
        else:
            _must([*priv, "mv", str(staged.ready), str(dest)], "publish rootfs", run)
    else:
        # RE-CHECKED here, not only at staging. The two are separated in time and
        # this module deliberately supports concurrent exports to one
        # destination, so a larger run can publish in between -- and the check
        # made against the old smaller artifact would then let this one shrink
        # it back.
        _refuse_shrink(dest, staged.size_mib, priv, run)
        if staged.had_previous:
            _must([*priv, "mv", str(dest), f"{dest}.bak"], "keep .bak", run)
            staged.restore_from = Path(f"{dest}.bak")
        _must([*priv, "mv", str(staged.ready), str(dest)], "publish rootfs", run)
        _remove_tree(staged.staging, priv, run)
    # Recorded while the lock is still held, so it names what THIS run
    # published rather than whatever wins a later race.
    staged.published_identity = _artifact_identity(dest, priv, run)
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
    extract_preserves_ownership: bool = False,
) -> Path:
    """Stage one artifact and publish it. Convenience for a single export."""
    staged = stage_rootfs(
        plan,
        spec,
        tag,
        env=env,
        run=run,
        log=log,
        extract=extract,
        extract_preserves_ownership=extract_preserves_ownership,
    )
    return publish_staged(staged, run=run, log=log)


def _artifact_identity(path: Path, priv: list[str], run: Runner) -> str:
    """`device:inode` of ``path``, or "" when it cannot be read.

    Publication replaces the destination with a DIFFERENT object, so this is
    what distinguishes "the artifact this run put here" from "whatever is here
    now". Rollback needs that distinction: another run can publish between our
    publication and our failure, and restoring our backup over its artifact is
    the concurrent-clobber this module already takes a lock to prevent.

    Read through the privileged runner for the same reason sizes are: an
    unprivileged stat under a root-only parent raises, and reading that as
    "no identity" would make every rollback skip itself.
    """
    proc = run([*priv, "stat", "-c", "%d:%i", str(path)], capture_output=True)
    return (proc.stdout or "").strip() if proc.returncode == 0 else ""


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
    extract_preserves_ownership: bool = False,
) -> list[str]:
    """Build, verify, then export — in that order, and only ever in that order.

    Verification sits BETWEEN the two halves deliberately. Exporting first would
    publish an artifact from an image that has not been shown to record what
    built it, which is precisely the state the whole module exists to make
    impossible.

    The requested TAGS are part of the export, not part of the build. `docker
    build -t` moves a tag the instant one image succeeds, so building straight
    into a tag the fleet dispatches on let a worker pull an unverified image,
    and a failure later in the chain left the live tags on a mixture of two
    builds. The chain is built under a private name and the real tags are moved
    once, at the end, alongside the rootfs.
    """
    # ONCE per run, then shared: the private tag carries a random component so
    # two invocations cannot collide, so recomputing it here would name images
    # nothing built.
    staging = _staging_tag(tag)
    staged_tags = build_plan(
        plan,
        tag,
        blastbox_version=blastbox_version,
        env=env,
        run=run,
        log=log,
        staging=staging,
    )
    log("\n>> verify: every image must record what it was built from")
    aliases = {
        f"{spec.base}:{tag}": f"{spec.base}:{staging}"
        for spec in plan.images
        if spec.internal
    }
    try:
        verified = verify_built(staged_tags, aliases=aliases, run=run, log=log)
    except BaseException:
        # Deliberately NOT cleaned up. The staging tags are the only names these
        # images have, and an operator diagnosing why verification refused one
        # needs to be able to `docker inspect` it. They are clearly marked and
        # scoped to this pid; dropping them here would leave dangling images and
        # a question nobody can answer.
        log(f"   images left tagged :{staging} for inspection")
        raise
    # Staged FIRST, all of them, then published. Publishing each as it is built
    # leaves the earlier destinations on the new release and the later ones on
    # the old when a later export fails -- the warm tiers then run a mixed
    # release even though the command reported failure, which is worse than not
    # having run it.
    staged: list[_Staged] = []
    try:
        for spec in plan.rootfs:
            log(f"\n>> stage {spec.kind} rootfs <- {spec.image}:{tag}")
            # Keyed on the tag it was BUILT under. Exporting resolves the
            # verified id anyway, but an empty id here would silently fall back
            # to the mutable tag -- the exact substitution verification exists
            # to prevent.
            staged.append(
                stage_rootfs(
                    plan,
                    spec,
                    tag,
                    env=env,
                    run=run,
                    log=log,
                    extract=extract,
                    extract_preserves_ownership=extract_preserves_ownership,
                    verified_id=verified[f"{spec.image}:{staging}"],
                )
            )
    except BaseException:
        for s in staged:
            _remove_tree(s.staging, s.priv, run or _default_runner)
        raise
    # Publication is rolled back too, not just staging. A later artifact
    # failing on I/O, permissions or a concurrent publish would otherwise leave
    # the earlier destinations on the NEW release and the rest on the old --
    # the mixed release the staging phase was written to prevent, arriving one
    # step later.
    # ROOTFS FIRST, TAGS LAST.
    #
    # These are two different atomicity domains -- filesystem renames and the
    # docker tag table -- so a reader can always observe one updated and the
    # other not. That window cannot be closed here; it can only be made as
    # small as possible and put where it does least harm. A versioned pointer
    # the dispatcher resolves once per job is the real fix, and it belongs in
    # the dispatcher rather than in this module.
    #
    # Rootfs publication is the half that actually fails -- disk, permissions,
    # a concurrent publish -- so doing it first means the common failure never
    # touches a tag at all. Moving the tags first meant every such failure had
    # to unwind live production tags, which is more moving parts in exactly the
    # situation with the least margin.
    done: list[_Staged] = []
    published: list[str] = []
    pub = PublishedTags((), {}, {})
    try:
        for s in staged:
            log(f"\n>> publish {s.dest}")
            publish_staged(s, run=run, log=log)
            done.append(s)
        log(f"\n>> publish tags -> :{tag}")
        pub = publish_tags(staged_tags, tag, run=run, log=log)
        published = list(pub.tags)
    except BaseException:
        if pub.tags:
            # Reached only when tag publication PARTLY succeeded: `publish_tags`
            # unwinds its own failures, so anything left here is a later
            # failure with tags already moved.
            log("   rolling back published tags")
            restore_tags(pub, staged_tags, run=run, log=log)
        for s in reversed(done):
            log(f"   rolling back {s.dest}")
            _restore_backup(s, run or _default_runner, log)
        raise
    return published
