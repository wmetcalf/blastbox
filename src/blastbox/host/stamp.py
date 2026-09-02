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
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]

LABEL_BLASTBOX = "org.blastbox.version"
LABEL_REVISION = "org.opencontainers.image.revision"
LABEL_BASE_NAME = "org.opencontainers.image.base.name"
LABEL_BASE_DIGEST = "org.opencontainers.image.base.digest"
# A local-only base has no manifest digest. Its content-addressed image ID pins
# it exactly on this host, but it is NOT a repo digest and must not be written
# into the OCI key as if it were.
LABEL_BASE_IMAGE_ID = "org.blastbox.base.image_id"

# Emitted flags are consumed with `$(blastbox stamp ...)`. Command substitution
# word-splits its output but does NOT remove quotes, so a quoted value arrives
# with literal quote characters attached. Rather than emit something that breaks,
# refuse values that would need quoting.
_SHELL_SAFE = re.compile(r"^[\w@%+=:,./-]*$")

UNKNOWN = "unknown"
DIRTY_SUFFIX = "-dirty"
# A recorded identifier must look like one. An externally built or hand-edited
# image can carry anything in these labels, and "present" is not "valid".
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{7,40}(-dirty)?$")


class StampError(RuntimeError):
    """A stamp could not be produced or read truthfully.

    Raised rather than degraded: a stamp that says `unknown` where a real value
    was expected looks stamped and is not, which is worse than no stamp.
    """


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run a helper, turning "could not run it at all" into StampError.

    A missing binary or a timeout must not surface as a raw OSError from deep
    inside a build script; and it must never be mistaken for "the value is
    absent". git is handled separately -- its absence is a legitimate state on
    a deployed tree.
    """
    try:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        raise StampError(f"{argv[0]} timed out: {' '.join(map(str, argv))[:120]}") from exc
    except FileNotFoundError as exc:
        if argv and argv[0] == "git":
            raise
        raise StampError(f"{argv[0]} is not installed") from exc


@dataclass(frozen=True)
class Stamp:
    """What an image records about its own construction."""

    blastbox: str = UNKNOWN
    revision: str = UNKNOWN
    base_name: str = UNKNOWN
    base_digest: str = UNKNOWN
    base_image_id: str = UNKNOWN

    @property
    def reproducible(self) -> bool:
        """Whether this image records enough to be rebuilt deliberately.

        Requires a base DIGEST -- a tag can be re-pointed or deleted, which is
        exactly what happened to the worker base -- AND a CLEAN revision. A
        `<sha>-dirty` build cannot be reproduced from that sha by definition:
        the uncommitted changes are not recorded anywhere.
        """
        # The NAME is required alongside the digest: a bare `sha256:...` does
        # not say which repository to pull it from, so it cannot be resolved
        # back to an image on its own.
        pinned = _DIGEST_RE.match(self.base_digest or "") or _DIGEST_RE.match(
            self.base_image_id or ""
        )
        return bool(
            pinned
            and self.blastbox not in (UNKNOWN, "")
            and self.base_name not in (UNKNOWN, "")
            and _REVISION_RE.match(self.revision or "")
            and not self.revision.endswith(DIRTY_SUFFIX)
        )

    def resolvable(self, runner: Runner | None = None) -> bool:
        """Whether the recorded base is STILL present on this host.

        `reproducible` says the image recorded enough; this says the recorded
        base can actually be found. They differ exactly in the case that
        started this work: a perfectly stamped image whose base has since been
        deleted is not rebuildable, and reporting OK for it would repeat the
        original failure.
        """
        if not self.reproducible:
            return False
        run = runner or _run
        ref = (
            f"{repo_of(self.base_name)}@{self.base_digest}"
            if _DIGEST_RE.match(self.base_digest or "")
            else self.base_image_id
        )
        # A failure to ASK is not an answer. Callers state "the base is gone"
        # on a False, so an unreachable daemon must raise rather than be
        # reported as absence -- the same rule read() and doctor already follow.
        proc = run(["docker", "inspect", "--type", "image", ref,
                    "--format", "{{.Id}}"])
        if proc.returncode == 0:
            return True
        stderr = (proc.stderr or "").lower()
        if "no such" in stderr or "not found" in stderr:
            return False
        raise StampError(
            f"cannot determine whether {ref} is present: "
            f"{(proc.stderr or '').strip()[:120]}"
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
    try:
        head = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    except (FileNotFoundError, OSError):
        # git is not installed. A deployed rsynced tree often has no git at all,
        # which is exactly where the recorded revision matters most.
        return recorded or UNKNOWN
    if head.returncode != 0:
        # Not a checkout: use what the deploy recorded, if anything.
        return recorded or UNKNOWN
    sha = head.stdout.strip()
    try:
        # --untracked-files=normal overrides a repo/global
        # status.showUntrackedFiles=no. Untracked files are build inputs -- a
        # COPY picks them up -- so hiding them would stamp a dirty tree clean.
        dirty = run([
            "git", "-C", str(repo), "status", "--porcelain",
            "--untracked-files=normal",
        ])
    except (FileNotFoundError, OSError):
        # git vanished between the two calls; we cannot claim the tree is clean.
        return f"{sha}{DIRTY_SUFFIX}"
    if dirty.returncode != 0:
        # Cannot tell whether the tree is clean, so do not claim that it is:
        # a clean sha for a dirty tree names a commit that never built this.
        return f"{sha}{DIRTY_SUFFIX}"
    if dirty.stdout.strip():
        return f"{sha}{DIRTY_SUFFIX}"
    return sha


# Docker reports RepoDigests for Hub images in SHORT form ("minio/minio@sha256:…")
# even when inspected by a fully-qualified reference. Verified against a real
# daemon: `docker inspect docker.io/minio/minio:latest` returns `minio/minio@…`.
# Without normalising, stamping a fully-qualified base raises "1 repo digests and
# none for 'docker.io/minio/minio'".
_HUB_PREFIXES = ("docker.io/library/", "index.docker.io/library/",
                 "docker.io/", "index.docker.io/")


def _canonical_repo(repo: str) -> str:
    """Strip Docker Hub's implicit registry/namespace so references compare equal."""
    for prefix in _HUB_PREFIXES:
        if repo.startswith(prefix):
            return repo[len(prefix):]
    return repo


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


def base_image_id(image: str, runner: Runner | None = None) -> str:
    """The content-addressed image ID of ``image``.

    Not a repo digest: this is the config digest, exact on THIS host but not a
    manifest reference. It is recorded under its own label so it cannot be
    mistaken for one.
    """
    run = runner or _run
    proc = run(["docker", "inspect", "--type", "image", image, "--format", "{{.Id}}"])
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    raise StampError(f"{image}: cannot resolve an image ID (absent, or docker unavailable)")


def base_digest(image: str, runner: Runner | None = None) -> str:
    """The REPO digest of ``image``, or "" when it has none (never pushed).

    Deliberately does not fall back to the image ID: that is a different kind of
    identifier and belongs in its own label.
    """
    run = runner or _run
    repo = repo_of(image)
    proc = run(["docker", "inspect", "--type", "image", image,
                "--format", "{{json .RepoDigests}}"])
    if proc.returncode == 0:
        try:
            # Docker reports a nil RepoDigests field as JSON `null`, which
            # decodes to None and is not iterable.
            raw = json.loads(proc.stdout.strip() or "[]")
        except json.JSONDecodeError:
            raw = []
        digests = [str(d) for d in (raw or [])]
        # One image can carry digests from several repositories; take the one
        # for the repo actually requested. A sole entry that does NOT match is
        # still the wrong repository, so it is refused rather than assumed.
        want = _canonical_repo(repo)
        matching = [d for d in digests if _canonical_repo(d.split("@", 1)[0]) == want]
        if matching:
            return matching[0].split("@", 1)[-1]
        if digests:
            raise StampError(
                f"{image}: {len(digests)} repo digests and none for {repo!r}; "
                "cannot tell which base this is"
            )
        return ""
    raise StampError(
        f"{image}: cannot resolve a digest (image absent, or docker unavailable). "
        "Pull or build the base first; stamping 'unknown' would look recorded "
        "while being unreproducible."
    )


def build_args(
    *, blastbox_version: str, repo: Path | str, base: str | None = None,
    base_arg: str = "BASE_IMAGE", runner: Runner | None = None,
) -> list[str]:
    """`docker build` flags that stamp the image.

    When ``base`` is given, the returned flags ALSO pin the build to what is
    being recorded (``--build-arg <base_arg>=repo@sha256:...``, or the image ID
    for a local-only base). Resolving a reference and then letting the build
    resolve the mutable tag independently -- especially with ``--pull`` -- can
    stamp one image while building on another. Pinning makes the stamp true by
    construction.

    Base labels are emitted even with no base, as empty values: docker inherits
    LABELs from the parent, so an unset base label would silently carry the
    PARENT's base and claim a grandparent as this image's base.

    Values that would need shell quoting are REFUSED. The output is consumed via
    ``$(blastbox stamp ...)``, and command substitution word-splits without
    removing quotes, so a quoted value arrives with literal quote characters.
    Failing loudly beats emitting something that silently mis-parses.
    """
    revision = git_revision(repo, runner)
    if revision != UNKNOWN and not _REVISION_RE.match(revision):
        raise StampError(
            f"{repo}: recorded revision {revision!r} is not a commit id. "
            f"`{REVISION_FILE}` must hold the sha the tree came from -- a branch "
            "or release name looks recorded exactly as much as 'unknown' does, "
            "and the image would read back as UNSTAMPED."
        )
    if revision == UNKNOWN:
        raise StampError(
            f"{repo}: no source revision (not a git checkout and no "
            f"{REVISION_FILE}). Stamping 'unknown' produces an image that looks "
            "recorded and cannot be rebuilt; write the revision the tree came "
            "from into that file as part of the deploy."
        )
    digest = base_digest(base, runner) if base else ""
    image_id = base_image_id(base, runner) if base and not digest else ""
    labels = {
        LABEL_BLASTBOX: blastbox_version,
        LABEL_REVISION: revision,
        LABEL_BASE_NAME: base or "",
        LABEL_BASE_DIGEST: digest,
        LABEL_BASE_IMAGE_ID: image_id,
    }
    args: list[str] = []
    for key, value in labels.items():
        _require_shell_safe(key, value)
        args += ["--label", f"{key}={value}"]
    if base:
        pinned = f"{repo_of(base)}@{digest}" if digest else image_id
        _require_shell_safe(base_arg, pinned)
        args += ["--build-arg", f"{base_arg}={pinned}"]
    return args


def _require_shell_safe(key: str, value: str) -> None:
    if not _SHELL_SAFE.match(value):
        raise StampError(
            f"{key}={value!r} contains characters that would need shell quoting. "
            "These flags are consumed with $(...), which word-splits without "
            "removing quotes, so a quoted value would arrive corrupted."
        )


def verify_contents(image: str, runner: Runner | None = None) -> tuple[bool, str]:
    """Check the recorded blastbox version against what the image ACTUALLY has.

    The `org.blastbox.version` label is a self-report: `build_args` writes
    whatever it was told, defaulting to the version of the CLI on the build
    host, which is not necessarily what the image installs. Nothing verified it,
    and `doctor` deliberately reads only running containers -- so a stamp
    claiming 0.1.27 on an image containing 0.1.17 was unrepresentable in either
    module, and `pins`, `stamp --read` and `doctor` could all exit 0 on a fleet
    running a version nobody declared.

    This is the join: it runs the same probe `doctor` uses, inside the image.

    Returns (agrees, detail).
    """
    from blastbox.host.doctor import UNKNOWN as D_UNKNOWN  # noqa: PLC0415 -- cycle
    from blastbox.host.doctor import version_in_image  # noqa: PLC0415

    stamped = read(image, runner).blastbox
    if stamped in (UNKNOWN, ""):
        return False, "image records no blastbox version"
    actual, detail = version_in_image(image, runner)
    if actual == D_UNKNOWN:
        return False, f"cannot read the image's blastbox: {detail}"
    if actual != stamped:
        return False, f"label says {stamped}, image contains {actual}"
    return True, actual


def read(image: str, runner: Runner | None = None) -> Stamp:
    """The stamp an image carries, if any.

    Raises StampError when the image cannot be inspected at all: a mistyped
    name or a stopped daemon must not read as "this image is unstamped".
    """
    run = runner or _run
    proc = run(["docker", "inspect", "--type", "image", image,
                "--format", "{{json .Config.Labels}}"])
    if proc.returncode != 0:
        raise StampError(
            f"{image}: cannot inspect ({(proc.stderr or '').strip()[:120]})"
        )
    try:
        labels = json.loads(proc.stdout.strip() or "{}") or {}
    except json.JSONDecodeError as exc:
        # Unparseable output is "could not read", not "carries no stamp".
        # Every other error path here raises; this one used to contradict the
        # docstring by returning an all-unknown Stamp.
        raise StampError(f"{image}: unparseable inspect output ({exc})") from exc
    return Stamp(
        blastbox=labels.get(LABEL_BLASTBOX, UNKNOWN),
        revision=labels.get(LABEL_REVISION, UNKNOWN),
        base_name=labels.get(LABEL_BASE_NAME, UNKNOWN),
        base_digest=labels.get(LABEL_BASE_DIGEST, UNKNOWN),
        base_image_id=labels.get(LABEL_BASE_IMAGE_ID, UNKNOWN),
    )
