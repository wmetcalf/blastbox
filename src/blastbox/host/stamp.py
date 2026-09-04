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
from collections.abc import Callable, Mapping, Sequence
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
# The BUILDER stages, which are as much a part of what an image contains as its
# base is: a multi-stage Dockerfile COPIES artifacts out of them. Recorded as
# `ARG=ref` pairs joined by commas -- one label rather than one per argument,
# because the set is declared per image and varies between them.
LABEL_BUILDERS = "org.blastbox.builders"

# Emitted flags are consumed with `$(blastbox stamp ...)`. Command substitution
# word-splits its output but does NOT remove quotes, so a quoted value arrives
# with literal quote characters attached. Rather than emit something that breaks,
# refuse values that would need quoting.
# `!` is included for PEP 440 EPOCHS (`1!0.2.0`). It is not special to any
# shell in an unquoted word -- only interactive bash history expansion treats
# it that way, and these values go through an argv list, never a shell line.
# Excluding it made every epoch-bearing version impossible to build.
_SHELL_SAFE = re.compile(r"^[\w@%+=:,./!-]*$")

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
        raise StampError(
            f"{argv[0]} timed out: {' '.join(map(str, argv))[:120]}"
        ) from exc
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
    # `ARG=ref` pairs, comma-joined. Empty when the image declares no builder
    # stages, which is the common case and not a defect.
    builders: str = ""

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

    def base_state(
        self, runner: Runner | None = None, ref: str | None = None
    ) -> tuple[bool, str]:
        """``(present, current_image_id)`` for the recorded base, from ONE look.

        Presence and identity are the same question asked of the same moment.
        Answered separately -- `resolvable()` then `base_moved()` -- a base that
        is absent for the first call and recreated before the second reports
        "present, and nothing moved", and the newly present image's ID is never
        compared with the record at all. That is precisely the concurrent-tag
        case these checks exist for.

        ``ref`` overrides WHICH reference to inspect, for the window in which
        the recorded name is not yet published. The chain builds under private
        staging tags while the stamps name the tags that WILL be published, so
        during verification the recorded name does not exist yet and the same
        image is reachable under its staging alias. The record is unchanged;
        only the lookup is redirected.

        Raises rather than answering when the question cannot be ASKED: callers
        state "the base is gone" on a False, so an unreachable daemon must not
        be reported as absence.
        """
        run = runner or _run
        # Check the reference a REBUILD would actually use. build_args pins to
        # exactly the base it was given, and that is what base_name records, so
        # there is nothing to reconstruct here. Inspecting the image ID instead
        # reported OK for a base whose tag had been deleted -- the ID is still
        # in docker's store, but the tag is what gets handed to the builder.
        name = ref or self.base_name
        proc = run(
            ["docker", "inspect", "--type", "image", name, "--format", "{{.Id}}"]
        )
        if proc.returncode == 0:
            return True, (proc.stdout or "").strip()
        stderr = (proc.stderr or "").lower()
        if "no such" in stderr or "not found" in stderr:
            return False, ""
        raise StampError(
            f"cannot determine whether {name} is present: "
            f"{(proc.stderr or '').strip()[:120]}"
        )

    def resolvable(self, runner: Runner | None = None, ref: str | None = None) -> bool:
        """Whether the recorded base is STILL present on this host.

        `reproducible` says the image recorded enough; this says the recorded
        base can actually be found. They differ exactly in the case that started
        this work: a perfectly stamped image whose base has since been deleted
        is not rebuildable, and reporting OK for it would repeat the original
        failure.
        """
        if not self.reproducible:
            return False
        return self.base_state(runner, ref)[0]

    def base_moved(self, runner: Runner | None = None, ref: str | None = None) -> str:
        """The base reference's CURRENT image ID, when it differs from the record.

        Empty string means "no disagreement to report": either the base was
        pinned by a registry digest (immutable, nothing to check), nothing was
        recorded, the reference is gone entirely -- which is `resolvable`'s
        finding, and reporting it here too would double-count one problem as
        two -- or it still resolves to the image that was stamped.

        This is the check that makes an ID-only stamp trustworthy after the
        fact. A local tag can move between the inspection that produced the
        label and the build that consumed it -- concurrent builds do exactly
        this -- and the result is a child built from B while claiming A.
        """
        if "@sha256:" in (self.base_name or ""):
            return ""  # pinned by digest in the reference itself; it cannot move
        recorded = self.base_image_id or ""
        name = self.base_name or ""
        if not _DIGEST_RE.match(recorded) or name in (UNKNOWN, ""):
            return ""
        present, current = self.base_state(runner, ref)
        if not present:
            return ""
        return "" if current == recorded else current


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
        # `normal` is enough HERE: this only needs the boolean "is the tree
        # dirty", and an untracked directory already answers it. `_source_state`
        # in imagerun needs `all`, because it fingerprints WHAT changed.
        # --untracked-files=normal overrides a repo/global
        # status.showUntrackedFiles=no. Untracked files are build inputs -- a
        # COPY picks them up -- so hiding them would stamp a dirty tree clean.
        dirty = run(
            [
                "git",
                "-C",
                str(repo),
                "status",
                "--porcelain",
                "--untracked-files=normal",
            ]
        )
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
_HUB_PREFIXES = (
    "docker.io/library/",
    "index.docker.io/library/",
    "docker.io/",
    "index.docker.io/",
)


def _canonical_repo(repo: str) -> str:
    """Strip Docker Hub's implicit registry/namespace so references compare equal."""
    for prefix in _HUB_PREFIXES:
        if repo.startswith(prefix):
            return repo[len(prefix) :]
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
    raise StampError(
        f"{image}: cannot resolve an image ID (absent, or docker unavailable)"
    )


def repo_digest_ref(image: str, digests_json: str) -> str:
    """The full ``repo@sha256:...`` reference for ``image``'s repository, or "".

    The full reference, not the bare digest: a bare `sha256:...` handed to
    docker as a base resolves as `docker.io/library/sha256:...` and fails with
    an authorization error naming a repository nobody wrote. That is fine for a
    LABEL, which is what `_digest_from` returns, and wrong for anything the
    build has to resolve.
    """
    try:
        raw = json.loads(digests_json or "[]")
    except json.JSONDecodeError:
        raw = []
    digests = [str(d) for d in (raw or [])]
    repo = repo_of(image)
    want = _canonical_repo(repo)
    matching = [d for d in digests if _canonical_repo(d.split("@", 1)[0]) == want]
    if matching:
        return matching[0]
    if digests:
        raise StampError(
            f"{image}: {len(digests)} repo digests and none for {repo!r}; "
            "cannot tell which base this is"
        )
    return ""


def _digest_from(image: str, digests_json: str) -> str:
    """The bare ``sha256:...`` for ``image``'s repository, or "".

    For LABELS. Anything the build must resolve wants `repo_digest_ref`.

    Shared by the single-fact and the one-snapshot readers so both apply the
    same rule: one image can carry digests from several repositories, and a
    sole entry for the WRONG repository is refused rather than assumed.
    """
    ref = repo_digest_ref(image, digests_json)
    return ref.split("@", 1)[-1] if ref else ""


def _inspect_base(image: str, runner: Runner | None = None) -> tuple[str, str]:
    """``(repo_digest, image_id)`` for ``image``, read from ONE inspect.

    Both facts describe the same image only if they were read at the same
    moment. Asking twice lets a mutable tag move in between and produces a
    stamp pairing one image's digest with another's ID.
    """
    run = runner or _run
    proc = run(
        [
            "docker",
            "inspect",
            "--type",
            "image",
            image,
            "--format",
            "{{json .RepoDigests}}\t{{.Id}}",
        ]
    )
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        raise StampError(
            f"{image}: cannot resolve a digest (image absent, or docker "
            "unavailable). Pull or build the base first; stamping 'unknown' "
            "would look recorded while being unreproducible."
        )
    raw = proc.stdout.strip().split("\t")
    digests_json, image_id = raw[0], (raw[1].strip() if len(raw) > 1 else "")
    if not image_id:
        raise StampError(
            f"{image}: cannot resolve an image ID (absent, or docker unavailable)"
        )
    return _digest_from(image, digests_json), image_id


def base_digest(image: str, runner: Runner | None = None) -> str:
    """The REPO digest of ``image``, or "" when it has none (never pushed).

    Deliberately does not fall back to the image ID: that is a different kind of
    identifier and belongs in its own label.
    """
    run = runner or _run
    proc = run(
        [
            "docker",
            "inspect",
            "--type",
            "image",
            image,
            "--format",
            "{{json .RepoDigests}}",
        ]
    )
    if proc.returncode == 0:
        return _digest_from(image, proc.stdout.strip())
    raise StampError(
        f"{image}: cannot resolve a digest (image absent, or docker unavailable). "
        "Pull or build the base first; stamping 'unknown' would look recorded "
        "while being unreproducible."
    )


def _logical_lines(text: str) -> list[str]:
    """Dockerfile instructions, comments dropped and continuations joined.

    A `FROM` split across lines with a trailing backslash is one instruction to
    docker; treating it as two makes the base look like a bare `FROM` with no
    reference, so the check would pass a file it never actually read.
    """
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        if not pending and re.match(r"^\s*#", raw):
            continue
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append((pending + stripped).strip())
        pending = ""
    if pending:
        lines.append(pending.strip())
    return [ln for ln in lines if ln]


def _uses(ref: str, name: str) -> bool:
    """Does ``ref`` interpolate the build arg ``name``?

    Both `$NAME` and `${NAME...}` (including `${NAME:-default}`) count. Arg
    NAMES are case-sensitive even though instruction keywords are not.
    """
    return bool(
        re.search(rf"\$\{{{re.escape(name)}[}}:]", ref)
        or re.search(rf"\${re.escape(name)}(?![A-Za-z0-9_])", ref)
    )


def assert_arg_selects_base(dockerfile: Path | str, base_arg: str) -> None:
    """Fail unless ``base_arg`` actually chooses the image's base.

    Three distinct ways a `--build-arg <base_arg>=<digest>` silently fails to
    pin anything, all of which leave a label claiming a base the build did not
    use -- the one kind of wrong stamp that matters:

    * The ARG is not declared. Docker WARNS and IGNORES the build-arg.
    * The ARG is declared, but only INSIDE a stage. Only an ARG before the
      first FROM can parameterize a FROM, so an in-stage declaration leaves
      the base a constant.
    * The ARG is declared globally and never interpolated into the base at
      all. `FROM alpine` + `ARG BASE_IMAGE` accepts the flag and ignores it.

    Multi-stage builds resolve through their stage graph: the final stage's
    base may name an earlier stage, and it is that chain's terminal reference
    that has to be the parameterized one.
    """
    path = Path(dockerfile)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StampError(f"{path}: cannot read ({exc})") from exc

    lines = _logical_lines(text)
    # Instruction keywords are case-insensitive ("arg x" is valid); arg and
    # stage NAMES are not (stage names docker lowercases, arg names it does not).
    global_args: list[str] = []
    all_args: list[str] = []
    stages: list[tuple[str, str | None]] = []  # (base ref, stage name)
    for ln in lines:
        if m := re.match(r"(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)", ln):
            all_args.append(m.group(1))
            if not stages:
                global_args.append(m.group(1))
        elif m := re.match(r"(?i)^FROM\s+(.*)$", ln):
            rest = re.sub(r"(?i)^(--\S+\s+)*", "", m.group(1)).strip()
            parts = rest.split()
            if not parts:
                continue
            name = None
            if len(parts) >= 3 and parts[-2].lower() == "as":
                name = parts[-1].lower()
            stages.append((parts[0], name))

    if not stages:
        raise StampError(f"{path}: no FROM instruction; nothing to pin.")

    if base_arg not in all_args:
        raise StampError(
            f"{path} declares no `ARG {base_arg}`, so docker would ignore the "
            f"--build-arg that pins the base and the stamp would claim a digest "
            f"the build did not use. Declared ARGs: "
            f"{', '.join(sorted(set(all_args))) or 'none'}. "
            f"Pass --base-arg with the right name, or add the ARG."
        )

    # Follow the final stage back through any stage-to-stage references: the
    # base of `FROM builder` is whatever `builder` was built FROM.
    named = {n: ref for ref, n in stages if n}
    ref = stages[-1][0]
    seen: set[str] = set()
    while (key := ref.lower()) in named and key not in seen:
        seen.add(key)
        ref = named[key]

    if not _uses(ref, base_arg):
        raise StampError(
            f"{path} declares `ARG {base_arg}` but its base is {ref!r}, which "
            f"does not interpolate it. docker would accept the --build-arg and "
            f"build on {ref!r} anyway, while the label claimed the pinned "
            f"digest. Write the base as `FROM ${{{base_arg}}}`, or stamp "
            f"without --base."
        )

    if base_arg not in global_args:
        raise StampError(
            f"{path} declares `ARG {base_arg}` only inside a build stage. Docker "
            f"honours an ARG in a FROM only when it is declared BEFORE the first "
            f"FROM, so the base would not be pinned while the label said it was. "
            f"Move `ARG {base_arg}` above the first FROM."
        )


def build_args(
    *,
    blastbox_version: str,
    repo: Path | str,
    base: str | None = None,
    base_arg: str = "BASE_IMAGE",
    dockerfile: Path | str | None = None,
    record_base_as: str | None = None,
    builders: Mapping[str, str] | None = None,
    runner: Runner | None = None,
) -> list[str]:
    """`docker build` flags that stamp the image.

    When ``base`` is given, the returned flags ALSO pin the build to what is
    being recorded (``--build-arg <base_arg>=repo@sha256:...``, or the caller's
    reference for a local-only base, which buildkit can resolve where an image
    ID cannot). Resolving a reference and then letting the build resolve the
    mutable tag independently -- especially with ``--pull`` -- can stamp one
    image while building on another.

    A REGISTRY DIGEST makes the stamp true by construction. A local-only base
    does not: the reference is mutable, so if the tag moves between the
    inspection here and the build, the label names the image that was inspected
    while the build used the one the tag points at now. What that buys is
    DETECTION rather than prevention -- ``Stamp.base_moved`` compares the
    recorded ID against what the reference resolves to today, and ``--read``
    reports the disagreement. Push the base to a registry for prevention.

    Base labels are emitted even with no base, as empty values: docker inherits
    LABELs from the parent, so an unset base label would silently carry the
    PARENT's base and claim a grandparent as this image's base.

    Values that would need shell quoting are REFUSED. The output is consumed via
    ``$(blastbox stamp ...)``, and command substitution word-splits without
    removing quotes, so a quoted value arrives with literal quote characters.
    Failing loudly beats emitting something that silently mis-parses.
    """
    if base and _DIGEST_RE.fullmatch(base.strip()):
        # docker inspect ACCEPTS a bare image ID, and no repo digest is found
        # for it, so it would fall through to being passed as the build-arg --
        # recreating exactly the buildkit failure this fallback exists to fix,
        # since buildkit reads `sha256:...` as a repository and tries to pull.
        raise StampError(
            f"--base {base} is a bare image ID, which is not a reference any "
            "builder can resolve as a FROM. Pass the name the image is tagged "
            "with (`docker image inspect <id> --format '{{.RepoTags}}'`), or "
            "push it and pass repo@sha256:... to pin by digest."
        )
    if base and dockerfile is not None:
        assert_arg_selects_base(dockerfile, base_arg)
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
    # ONE inspect for both facts. Two separate lookups let a tag change between
    # them and label image A's digest next to image B's ID -- a stamp that is
    # internally inconsistent and would send anyone checking it to the wrong
    # image. The pair is only meaningful read from the same snapshot.
    digest, snapshot_id = _inspect_base(base, runner) if base else ("", "")
    # ALWAYS record the ID when the pin is by reference. It used to be skipped
    # whenever a repo digest was found, which was harmless while a digest also
    # became the pin -- but the pin is now the caller's reference, and with the
    # containerd image store a local image HAS a repo digest, so skipping the ID
    # left exactly the mutable-tag case with nothing for `base_moved` to compare
    # against. The check that makes a reference pin trustworthy would have been
    # silently disabled on the hosts that need it.
    pinned_by_digest = "@sha256:" in (base or "")
    image_id = snapshot_id if base and not pinned_by_digest else ""
    labels = {
        LABEL_BLASTBOX: blastbox_version,
        LABEL_REVISION: revision,
        # What a REBUILD should name, which is not always what this build was
        # given. A chain builds against private staging tags that are removed
        # once the run publishes; recording those would leave every child of an
        # internal base stamped with a reference that no longer exists -- the
        # image reads back as STAMPED BUT UNBUILDABLE the moment it succeeds.
        # The digest and ID below still come from inspecting what was actually
        # built on, and publication points this name at exactly that image.
        LABEL_BASE_NAME: record_base_as or base or "",
        LABEL_BASE_DIGEST: digest,
        LABEL_BASE_IMAGE_ID: image_id,
        # Provenance, not a pin: the pins themselves go through as build args.
        # Without this, the same plan, revision and base could produce a
        # different image after a builder tag moved, and every label would be
        # identical -- the builder-stage drift this pinning exists to prevent,
        # left unrecorded and so undetectable afterwards.
        LABEL_BUILDERS: ",".join(
            f"{k}={v}" for k, v in sorted((builders or {}).items())
        ),
    }
    args: list[str] = []
    for key, value in labels.items():
        _require_shell_safe(key, value)
        args += ["--label", f"{key}={value}"]
    if base:
        # ONE RULE: pin to exactly the reference the caller named.
        #
        # Deriving a "better" reference from `docker inspect` produces one the
        # builder cannot resolve, in two different ways, both measured:
        #
        #   * An image ID is not a FROM at all. buildkit reads `sha256:...` as
        #     the repository `docker.io/library/sha256:...` and tries to pull.
        #   * A RepoDigest is not proof of a registry. With the containerd image
        #     store, buildkit assigns a locally built image a manifest digest
        #     that was never pushed anywhere, so `repo@sha256:...` sends the
        #     build to Docker Hub for a digest that only exists on this host.
        #     That killed a real build of redtusk-cold-worker on a fleet node
        #     while every unit test passed -- the laptop's image store reported
        #     no RepoDigests at all, so the branch was never taken there.
        #
        # If a caller wants a digest pin they pass `repo@sha256:...` as the
        # base, and they get it verbatim. Anything else is pinned by the name
        # they gave, with the digest and image ID still RECORDED in the labels.
        # For a name, the guarantee is "the build used whatever this reference
        # meant at build time, and the label says which image that was" --
        # checkable afterwards via `Stamp.base_moved` rather than guaranteed by
        # construction. Push the base and pass repo@digest for the strong form.
        pinned = base
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


def canonical_version(version: str) -> str:
    """``version`` as an installer would record it, or unchanged if unparseable.

    `0.2.0-rc1`, `0.2.0_rev_3` and `0.2.0+linux-x86` are all valid PEP 440 and
    all normalise to something else once installed (`0.2.0rc1`, `0.2.0.post3`,
    `0.2.0+linux.x86`). Comparing the source spelling against
    `importlib.metadata.version()` therefore fails for pins that are perfectly
    correct.

    Unparseable input is returned as it came: this is used to COMPARE, and a
    value nobody can parse should fall back to comparing what was actually
    written rather than raise inside a verification path.
    """
    from packaging.version import InvalidVersion, Version  # noqa: PLC0415

    try:
        return str(Version(version))
    except InvalidVersion:
        return version


def _same_release(left: str, right: str) -> bool:
    """Whether two spellings name the same release under PEP 440.

    Compared as VERSIONS, not as canonical strings. `0.2` and `0.2.0` are equal
    to pip and to any installer, and `str(Version(...))` preserves the
    release-segment spelling it was given -- so a consumer pinning
    `blastbox>=0.2` got an image whose metadata reads `0.2.0` and failed its own
    verification over a trailing zero.

    Falls back to comparing what was written when either side cannot be parsed:
    this runs inside a verification path and must not raise.
    """
    from packaging.version import InvalidVersion, Version  # noqa: PLC0415

    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return left == right


def verify_contents(
    image: str, runner: Runner | None = None
) -> tuple[bool | None, str]:
    """Check the recorded blastbox version against what the image ACTUALLY has.

    The `org.blastbox.version` label is a self-report: `build_args` writes
    whatever it was told, defaulting to the version of the CLI on the build
    host, which is not necessarily what the image installs. Nothing verified it,
    and `doctor` deliberately reads only running containers -- so a stamp
    claiming 0.1.27 on an image containing 0.1.17 was unrepresentable in either
    module, and `pins`, `stamp --read` and `doctor` could all exit 0 on a fleet
    running a version nobody declared.

    This is the join: it runs the same probe `doctor` uses, inside the image.

    Returns (agrees, detail), where agrees is None when there is nothing to
    join -- the image contains no blastbox at all. That is not a disagreement:
    RedTusk's worker base is a pure JVM/Tika image, deliberately without
    python, and calling its stamp a lie because the join found nothing failed
    a build that was entirely correct.
    """
    from blastbox.host.doctor import NOPKG, UNKNOWN as D_UNKNOWN  # noqa: PLC0415 -- cycle
    from blastbox.host.doctor import version_in_image  # noqa: PLC0415

    stamped = read(image, runner).blastbox
    if stamped in (UNKNOWN, ""):
        return False, "image records no blastbox version"
    actual, detail = version_in_image(image, runner)
    if actual == NOPKG:
        return None, detail or "the image contains no blastbox"
    if actual == D_UNKNOWN:
        return False, f"cannot read the image's blastbox: {detail}"
    # Compared CANONICALLY. The label carries the spelling the repo declared and
    # the probe reports the spelling the installer recorded; `0.2.0-rc1` and
    # `0.2.0rc1` are the same release, and failing a build over the punctuation
    # would reject exactly the valid pins this tooling accepts.
    if not _same_release(actual, stamped):
        return False, f"label says {stamped}, image contains {actual}"
    return True, actual


def read(image: str, runner: Runner | None = None) -> Stamp:
    """The stamp an image carries, if any.

    Raises StampError when the image cannot be inspected at all: a mistyped
    name or a stopped daemon must not read as "this image is unstamped".
    """
    run = runner or _run
    proc = run(
        [
            "docker",
            "inspect",
            "--type",
            "image",
            image,
            "--format",
            "{{json .Config.Labels}}",
        ]
    )
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
        builders=labels.get(LABEL_BUILDERS, ""),
    )
