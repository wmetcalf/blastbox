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

        The base DIGEST is the load-bearing part: a tag can be re-pointed or
        deleted, and that is exactly what happened to the worker base.
        """
        return self.base_digest != UNKNOWN and self.revision != UNKNOWN


REVISION_FILE = ".blastbox-revision"


def git_revision(repo: Path, runner: Runner | None = None) -> str:
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


def base_digest(image: str, runner: Runner | None = None) -> str:
    """The repo digest of ``image``, or its local image ID if never pushed.

    A local-only base has no repo digest; its content-addressed image ID is
    still a precise identifier on this host, which is where rebuilds happen.
    """
    run = runner or _run
    proc = run(["docker", "inspect", image, "--format", "{{json .RepoDigests}}"])
    if proc.returncode == 0:
        try:
            digests = json.loads(proc.stdout.strip() or "[]")
        except json.JSONDecodeError:
            digests = []
        if digests:
            return str(digests[0]).split("@", 1)[-1]
    proc = run(["docker", "inspect", image, "--format", "{{.Id}}"])
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    return UNKNOWN


def build_args(
    *, blastbox_version: str, repo: Path, base: str | None = None,
    runner: Runner | None = None,
) -> list[str]:
    """`docker build` flags that stamp the image. Splice into a build command."""
    revision = git_revision(repo, runner)
    args = [
        "--label", f"{LABEL_BLASTBOX}={blastbox_version}",
        "--label", f"{LABEL_REVISION}={revision}",
    ]
    if base:
        args += [
            "--label", f"{LABEL_BASE_NAME}={base}",
            "--label", f"{LABEL_BASE_DIGEST}={base_digest(base, runner)}",
        ]
    return args


def read(image: str, runner: Runner | None = None) -> Stamp:
    """The stamp an image carries, if any."""
    run = runner or _run
    proc = run(["docker", "inspect", image, "--format", "{{json .Config.Labels}}"])
    if proc.returncode != 0:
        return Stamp()
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
