"""Record what an image was built FROM, so it can be rebuilt.

The gap this closes, measured on toolz2 2026-09-02: the base image that built
the running `redtusk-cold-worker:rows` no longer existed. Its worker jar
(`10f6ccf292a0aefa...`) matched none of the fourteen `redtusk-worker:*` tags on
the box and no dangling image. Rebuilding the worker on any available base would
have swapped the Java engine for a different build while looking like a routine
blastbox version bump. Nothing recorded the base, so "rebuild this image" was
not a reproducible operation.

Three facts make it one, and they are cheap to carry:

* which blastbox went in,
* which source revision built it,
* the **digest** of the base it was built on -- not the tag, which moves.

Standard OCI annotation keys are used rather than a private namespace, so other
tooling can read them:
``org.opencontainers.image.base.digest``, ``.base.name``, ``.revision``,
plus ``org.blastbox.version`` for the framework version, which OCI has no key for.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]

LABEL_BLASTBOX = "org.blastbox.version"
LABEL_REVISION = "org.opencontainers.image.revision"
LABEL_BASE_NAME = "org.opencontainers.image.base.name"
LABEL_BASE_DIGEST = "org.opencontainers.image.base.digest"

UNKNOWN = "unknown"
DIRTY_SUFFIX = "-dirty"


class StampError(RuntimeError):
    """A stamp could not be produced or read truthfully.

    Raised rather than degraded: a stamp that says `unknown` where a real value
    was expected looks stamped and is not, which is worse than no stamp.
    """


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=60)


@dataclass(frozen=True)
class Stamp:
    """What an image records about its own construction."""

    blastbox: str = UNKNOWN
    revision: str = UNKNOWN
    base_name: str = UNKNOWN
    base_digest: str = UNKNOWN

    @property
    def reproducible(self) -> bool:
        """Whether this image records enough to be rebuilt deliberately.

        Requires a base DIGEST -- a tag can be re-pointed or deleted, which is
        exactly what happened to the worker base -- AND a CLEAN revision. A
        `<sha>-dirty` build cannot be reproduced from that sha by definition:
        the uncommitted changes are not recorded anywhere.
        """
        return (
            self.base_digest not in (UNKNOWN, "")
            and self.revision not in (UNKNOWN, "")
            and not self.revision.endswith(DIRTY_SUFFIX)
        )


REVISION_FILE = ".blastbox-revision"


def git_revision(repo: Path | str, runner: Runner | None = None) -> str:
    """The source revision, marked dirty when the tree has uncommitted changes.

    A stamp that claims a clean sha for a dirty tree is worse than no stamp: it
    names a commit that never produced this artifact.

    Deployed trees are frequently NOT git checkouts -- they are rsync'd copies,
    which is how a host ends up with source of unknown provenance. Measured:
    stamping a real build on toolz2 reported revision=unknown for exactly that
    reason. So a ``.blastbox-revision`` file is honoured as a fallback, letting
    the deploy that copies the tree record where it came from.
    """
    run = runner or _run
    marker = Path(repo) / REVISION_FILE
    try:
        recorded = marker.read_text(encoding="utf-8").strip()
    except OSError:
        recorded = ""
    head = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    if head.returncode != 0:
        # Not a checkout: use what the deploy recorded, if anything.
        return recorded or UNKNOWN
    sha = head.stdout.strip()
    dirty = run(["git", "-C", str(repo), "status", "--porcelain"])
    if dirty.returncode == 0 and dirty.stdout.strip():
        return f"{sha}-dirty"
    return sha


def repo_of(image: str) -> str:
    """The repository part of an image reference, without tag or digest.

    Registry ports make this fiddly: in ``host:5000/img`` the colon is a PORT,
    not a tag, so a naive rsplit(":") would mangle it. Only a colon in the LAST
    path segment introduces a tag.
    """
    ref = image.split("@", 1)[0]
    head, slash, last = ref.rpartition("/")
    if ":" in last:
        last = last.rsplit(":", 1)[0]
    return f"{head}{slash}{last}"


def base_digest(image: str, runner: Runner | None = None) -> str:
    """The repo digest of ``image``, or its local image ID if never pushed.

    A local-only base has no repo digest; its content-addressed image ID is
    still a precise identifier on this host, which is where rebuilds happen.

    Raises StampError when neither can be read -- stamping `unknown` there
    produces an image that looks recorded and cannot be rebuilt.
    """
    run = runner or _run
    repo = repo_of(image)
    proc = run(["docker", "inspect", image, "--format", "{{json .RepoDigests}}"])
    if proc.returncode == 0:
        try:
            digests = [str(d) for d in json.loads(proc.stdout.strip() or "[]")]
        except json.JSONDecodeError:
            digests = []
        # One image can carry digests from several repositories; take the one
        # for the repo actually requested, or the sole entry when unambiguous.
        matching = [d for d in digests if d.split("@", 1)[0] == repo]
        if matching:
            return matching[0].split("@", 1)[-1]
        if len(digests) == 1:
            return digests[0].split("@", 1)[-1]
        if digests:
            raise StampError(
                f"{image}: {len(digests)} repo digests and none for {repo!r}; "
                "cannot tell which base this is"
            )
    proc = run(["docker", "inspect", image, "--format", "{{.Id}}"])
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    raise StampError(
        f"{image}: cannot resolve a digest (image absent, or docker unavailable). "
        "Pull or build the base first; stamping 'unknown' would look recorded "
        "while being unreproducible."
    )


def build_args(
    *, blastbox_version: str, repo: Path | str, base: str | None = None,
    base_arg: str = "BASE_IMAGE", runner: Runner | None = None,
) -> list[str]:
    """`docker build` flags that stamp the image, shell-quoted.

    When ``base`` is given, the returned flags ALSO pin the build to the digest
    being recorded (``--build-arg <base_arg>=name@sha256:...``). Resolving a
    digest and then letting the build resolve the mutable tag independently --
    especially with ``--pull`` -- can stamp one image while building on another.
    Pinning makes the stamp true by construction.

    The base labels are emitted even with no base, as empty values. Docker
    inherits LABELs from the parent image, so an unset base label would silently
    carry the PARENT's base digest and claim a grandparent as this image's base.
    """
    revision = git_revision(repo, runner)
    labels = {
        LABEL_BLASTBOX: blastbox_version,
        LABEL_REVISION: revision,
        LABEL_BASE_NAME: base or "",
        LABEL_BASE_DIGEST: base_digest(base, runner) if base else "",
    }
    args: list[str] = []
    for key, value in labels.items():
        args += ["--label", shlex.quote(f"{key}={value}")]
    if base:
        pinned = f"{repo_of(base)}@{labels[LABEL_BASE_DIGEST]}"
        args += ["--build-arg", shlex.quote(f"{base_arg}={pinned}")]
    return args


def read(image: str, runner: Runner | None = None) -> Stamp:
    """The stamp an image carries, if any.

    Raises StampError when the image cannot be inspected at all: a mistyped
    name or a stopped daemon must not read as "this image is unstamped".
    """
    run = runner or _run
    proc = run(["docker", "inspect", image, "--format", "{{json .Config.Labels}}"])
    if proc.returncode != 0:
        raise StampError(
            f"{image}: cannot inspect ({(proc.stderr or '').strip()[:120]})"
        )
    try:
        labels = json.loads(proc.stdout.strip() or "{}") or {}
    except json.JSONDecodeError:
        return Stamp()
    return Stamp(
        blastbox=labels.get(LABEL_BLASTBOX, UNKNOWN),
        revision=labels.get(LABEL_REVISION, UNKNOWN),
        base_name=labels.get(LABEL_BASE_NAME, UNKNOWN),
        base_digest=labels.get(LABEL_BASE_DIGEST, UNKNOWN),
    )
