"""Declarative image chains: build them stamped, export their rootfs artifacts.

Every engine on this fleet builds the same shape -- a chain of images where each
is built FROM the previous, ending in artifacts some tiers boot as a rootfs
rather than run as a container. Each product had grown its own shell script for
that, by copying the last one, and every copy drifted:

* a `--build-arg` the Dockerfile never declared, silently discarded, so an
  "override" pinned nothing (measured on titanarum: BLASTBOX_VERSION and
  BLASTBOX_WHEEL both ignored)
* the ARG NAME differing per Dockerfile -- BASE for blastbox's gvisor file,
  BASE_IMAGE for everything else -- with docker ignoring the wrong one
* a Firecracker rootfs exported from the wrong image, producing an ext4 that
  boots and never signals READY
* builder-stage bases left mutable, so the fat jar copied into the shipped
  image changed while the runtime base looked identical

So the chain is DECLARED, in `blastbox-images.toml` beside the Dockerfiles, and
this module is the one implementation. A new engine writes the declaration; it
does not write the fourth copy of the script.

    [engine]
    name = "titanarum"

    [[image]]
    name       = "titanarum-base"
    dockerfile = "deploy/docker/Dockerfile.titanarum-base"
    base       = "eclipse-temurin:25-jre"          # upstream: pulled, then pinned
    build_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk" }

    [[image]]
    name       = "titanarum-cold-worker"
    dockerfile = "deploy/docker/Dockerfile.titanarum-cold-worker"
    base       = "titanarum-base"                  # a name from this chain

    [[rootfs]]
    kind     = "ext4"
    image    = "titanarum-fc-worker"
    dest     = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"
    requires = ["/init"]                           # refuse an image that cannot boot
"""

from __future__ import annotations

import os
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "ImageSpec",
    "RootfsSpec",
    "Plan",
    "PlanError",
    "load_plan",
    "resolve_chain",
]

SPEC_NAME = "blastbox-images.toml"

# A rootfs is either an exported directory tree (gVisor reads it in place) or an
# ext4 file populated with `mke2fs -d` (Firecracker boots it). Nothing else.
ROOTFS_KINDS = frozenset({"dir", "ext4"})

# Lowercase only: docker repository names are, so `MyImage` would pass here and
# fail at tag time instead.
# Docker's own repository-name grammar, not a stricter guess: separators sit
# BETWEEN alphanumerics, and `__` and repeated dashes ARE valid
# (`my__worker`, `a--b`). Rejecting those would refuse names docker accepts,
# which is its own kind of wrong; `worker-`, `worker.` and `worker..base` are
# still refused, because accepting them just moves the failure to `docker tag`.
_NAME_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")

# A tag names one build. A colon or slash would make `name:tag` parse as
# something else entirely.
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")


class PlanError(RuntimeError):
    """The declaration cannot be trusted to build what it claims.

    Raised rather than skipped: a plan that silently drops an image builds a
    chain missing a link, and the tag still appears.
    """


@dataclass(frozen=True)
class ImageSpec:
    """One image in the chain."""

    name: str
    dockerfile: str
    base: str
    base_arg: str = "BASE_IMAGE"
    context: str = "."
    build_args: dict[str, str] = field(default_factory=dict)
    # True when `base` names another image in this chain rather than an upstream
    # reference. Chain bases are built here; upstream ones are pulled first so
    # the digest recorded is the one the build used.
    internal: bool = False

    def tagged(self, tag: str) -> str:
        return f"{self.name}:{tag}"


@dataclass(frozen=True)
class RootfsSpec:
    """An artifact a warm tier boots, exported from a built image."""

    kind: str
    image: str
    dest: str
    size_mib: int | None = None
    requires: tuple[str, ...] = ()

    def resolved_dest(self, env: dict[str, str] | None = None) -> str:
        """`dest` with $VARS expanded from the environment.

        Destinations are per-host (a FC dir under $HOME on one node, /var/lib on
        another), so they are written as variables rather than baked in.
        """
        # Always the SAME expander: os.path.expandvars does not understand
        # `${VAR:-default}`, so falling back to it made default handling depend
        # on whether the caller happened to pass an env.
        return _expand(self.dest, dict(os.environ) if env is None else env)


def _expand(text: str, env: dict[str, str]) -> str:
    """`$VAR`, `${VAR}` and `${VAR:-default}`.

    The default form matters: these destinations are copied from compose files
    that already use it, and a spec that silently dropped the default would
    resolve to a path with a hole in it.

    An unset variable with NO default is left VISIBLE rather than emptied --
    `/redtusk-rootfs.ext4` is a plausible-looking path at the filesystem root,
    and writing a rootfs there is worse than failing to resolve.
    """

    def sub(m: re.Match[str]) -> str:
        braced, default, bare = m.group(1), m.group(2), m.group(3)
        name = braced or bare
        if name is None:
            return m.group(0)
        value = env.get(name)
        if value:
            return value
        if value == "" and default is None:
            # `$X/file` with X empty gives `/file` -- a plausible-looking path
            # at the filesystem root. Leave the variable visible so the caller
            # refuses instead of writing there.
            return m.group(0)
        # An EMPTY variable takes the default, as `${VAR:-x}` does in the shell.
        # A compose env routinely carries `TITANARUM_FC_DIR=` for an unset knob,
        # and treating that as "set" resolves the path to a hole.
        if default is not None:
            return default
        return value if value is not None else m.group(0)

    return re.sub(r"\$\{(\w+)(?::-([^}]*))?\}|\$(\w+)", sub, text)


@dataclass(frozen=True)
class Plan:
    """A whole engine's build, in declaration order."""

    engine: str
    images: tuple[ImageSpec, ...]
    rootfs: tuple[RootfsSpec, ...] = ()
    root: Path = Path(".")

    def image(self, name: str) -> ImageSpec:
        for spec in self.images:
            if spec.name == name:
                return spec
        raise PlanError(f"{name!r} is not an image in this plan")


def load_plan(root: Path | str) -> Plan:
    """Parse and VALIDATE ``blastbox-images.toml`` under ``root``.

    Validation is the point. A declaration that names a Dockerfile which does
    not exist, or a base that is neither upstream nor earlier in the chain,
    would otherwise fail deep inside a docker build with a message about
    something else entirely.
    """
    root = Path(root)
    path = root / SPEC_NAME
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PlanError(f"{path} not found; the engine declares no image chain") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PlanError(f"{path}: {exc}") from exc

    engine = str((data.get("engine") or {}).get("name") or "").strip()
    if not _NAME_RE.match(engine):
        raise PlanError(f"{path}: [engine].name must be a plain name, got {engine!r}")

    raw_images = data.get("image") or []
    if isinstance(raw_images, dict):
        raise PlanError(
            f"{path}: [image] must be an ARRAY of tables -- write [[image]], "
            "once per image. A single [image] table declares one image and "
            "silently drops any others."
        )
    if not isinstance(raw_images, list) or any(
        not isinstance(x, dict) for x in raw_images
    ):
        raise PlanError(f"{path}: [[image]] entries must be tables")
    if not raw_images:
        raise PlanError(f"{path}: declares no [[image]]; there is nothing to build")

    seen: dict[str, ImageSpec] = {}
    images: list[ImageSpec] = []
    for i, item in enumerate(raw_images):
        name = str(item.get("name") or "").strip()
        if not _NAME_RE.match(name):
            raise PlanError(f"{path}: [[image]] #{i + 1} has no usable name ({name!r})")
        if name in seen:
            raise PlanError(f"{path}: two images are named {name!r}")
        dockerfile = str(item.get("dockerfile") or "").strip()
        if not dockerfile:
            raise PlanError(f"{path}: image {name!r} declares no dockerfile")
        base = str(item.get("base") or "").strip()
        if not base:
            raise PlanError(
                f"{path}: image {name!r} declares no base. An unpinned base is how "
                "a rebuild silently changes what it was built on."
            )
        raw_args = item.get("build_args") or {}
        if not isinstance(raw_args, dict):
            raise PlanError(
                f"{path}: image {name!r} build_args must be a table of "
                f"NAME = \"value\" pairs, got {type(raw_args).__name__}"
            )
        args = {}
        for k, v in raw_args.items():
            if isinstance(v, (dict, list)):
                raise PlanError(
                    f"{path}: image {name!r} build_arg {k!r} must be a scalar; "
                    "docker takes NAME=VALUE strings"
                )
            args[str(k)] = str(v)
        spec = ImageSpec(
            name=name,
            dockerfile=dockerfile,
            base=base,
            base_arg=str(item.get("base_arg") or "BASE_IMAGE").strip(),
            context=str(item.get("context") or ".").strip(),
            build_args=args,
            internal=base in seen,
        )
        # A base naming an image declared LATER is almost certainly a mistake,
        # and treating it as upstream means docker tries to pull it from a
        # registry -- failing with "pull access denied" for an image this very
        # plan builds. Refuse and say so.
        forward = {str(x.get("name") or "").strip() for x in raw_images[i + 1:]}
        if base in forward:
            raise PlanError(
                f"{path}: image {name!r} is based on {base!r}, which this plan "
                "declares LATER. A base must be built before it is used; "
                "reorder them."
            )
        if spec.base_arg in args:
            raise PlanError(
                f"{path}: image {name!r} sets {spec.base_arg!r} in build_args, "
                "which is the argument that pins its base. Whichever won, the "
                "stamp would record a base the build may not have used. Change "
                "`base` instead."
            )
        seen[name] = spec
        images.append(spec)

    rootfs: list[RootfsSpec] = []
    for i, item in enumerate(data.get("rootfs") or []):
        kind = str(item.get("kind") or "").strip()
        if kind not in ROOTFS_KINDS:
            raise PlanError(
                f"{path}: [[rootfs]] #{i + 1} kind must be one of "
                f"{sorted(ROOTFS_KINDS)}, got {kind!r}"
            )
        image = str(item.get("image") or "").strip()
        if image not in seen:
            raise PlanError(
                f"{path}: [[rootfs]] #{i + 1} exports {image!r}, which this plan "
                "never builds. Exporting an image the chain does not produce is "
                "how a rootfs ends up made from something nobody verified."
            )
        dest = str(item.get("dest") or "").strip()
        if not dest:
            raise PlanError(f"{path}: [[rootfs]] #{i + 1} declares no dest")
        size = item.get("size_mib")
        if size is not None:
            if isinstance(size, float) and not size.is_integer():
                raise PlanError(
                    f"{path}: [[rootfs]] #{i + 1} size_mib is {size!r}; truncating "
                    "it would silently build a smaller filesystem than declared"
                )
            try:
                size = int(size)
            except (TypeError, ValueError) as exc:
                raise PlanError(
                    f"{path}: [[rootfs]] #{i + 1} size_mib must be a whole number of "
                    f"MiB, got {item.get('size_mib')!r}"
                ) from exc
            if size <= 0:
                raise PlanError(f"{path}: [[rootfs]] #{i + 1} size_mib must be positive")
        if kind == "ext4" and size is None:
            raise PlanError(
                f"{path}: [[rootfs]] #{i + 1} is ext4 but declares no size_mib. "
                "The filesystem has to be created at some size, and guessing one "
                "either wastes the difference or fails to fit the image."
            )
        rootfs.append(
            RootfsSpec(
                kind=kind,
                image=image,
                dest=dest,
                size_mib=size,
                requires=_requires(path, i, item.get("requires")),
            )
        )

    dests: dict[str, str] = {}
    for rf in rootfs:
        # Compared as DECLARED: two entries resolving to one path means the
        # second silently overwrites the first, and which one survives depends
        # on declaration order.
        if rf.dest in dests:
            raise PlanError(
                f"{path}: {rf.image!r} and {dests[rf.dest]!r} both export to "
                f"{rf.dest!r}; the second would overwrite the first"
            )
        dests[rf.dest] = rf.image

    return Plan(engine=engine, images=tuple(images), rootfs=tuple(rootfs), root=root)


def _requires(path: Path, index: int, value: object) -> tuple[str, ...]:
    """`requires` as a tuple of paths.

    A bare string is the natural typo (`requires = "/init"`) and iterating it
    yields one requirement per CHARACTER -- so the check would look for a file
    named `/`, then `i`, then `n`. Refused.
    """
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise PlanError(
            f"{path}: [[rootfs]] #{index + 1} requires must be an ARRAY of paths, "
            f'got {value!r}. Write requires = ["/init"].'
        )
    return tuple(str(r) for r in value)


def check_tag(tag: str) -> None:
    """Refuse a tag that would not name one build.

    A colon or slash makes `name:tag` parse as something else entirely, and an
    empty tag silently becomes `name:` -- which docker reads as `latest`.
    """
    if not _TAG_RE.match(tag or ""):
        raise PlanError(
            f"{tag!r} is not a usable tag: letters, digits, dot, dash and "
            "underscore only, and it may not start with a separator."
        )


def resolve_chain(plan: Plan, tag: str) -> list[tuple[ImageSpec, str]]:
    """Each image paired with the reference its build should be pinned to.

    An internal base resolves to the tag being built now, so a chain always
    builds on the images from THIS run -- never on a stale tag of the same name
    left over from a previous one, which is how a "rebuild" quietly ships a
    mixture of two builds.
    """
    out: list[tuple[ImageSpec, str]] = []
    for spec in plan.images:
        base_ref = f"{spec.base}:{tag}" if spec.internal else spec.base
        out.append((spec, base_ref))
    return out


def dockerfile_path(plan: Plan, spec: ImageSpec, env: dict[str, str] | None = None) -> Path:
    """Where ``spec``'s Dockerfile actually lives.

    Relative to its CONTEXT, not the plan root. An engine legitimately builds
    some images from Dockerfiles in another tree -- redtusk's warm images come
    from blastbox's own deploy/, with `context = "$BLASTBOX_SRC"` -- and
    resolving those against the consumer repo reports every one of them missing.
    """
    ctx = _expand(spec.context, env if env is not None else dict(os.environ))
    base = Path(ctx) if Path(ctx).is_absolute() else plan.root / ctx
    return base / spec.dockerfile


def missing_dockerfiles(plan: Plan, env: dict[str, str] | None = None) -> list[str]:
    """Declared Dockerfiles that are not present, each shown with its context."""
    out: list[str] = []
    for spec in plan.images:
        path = dockerfile_path(plan, spec, env)
        if not path.is_file():
            where = spec.context if spec.context != "." else "this repo"
            out.append(f"{spec.dockerfile} (context {where})")
    return out


def unresolved_destinations(plan: Plan, env: dict[str, str] | None = None) -> list[str]:
    """Rootfs destinations still containing an unexpanded variable.

    A hard failure rather than a note: the export would either write to a
    literal `$VAR` directory or, worse, to a path that merely looks plausible.
    Printing a warning and continuing invites running it anyway.
    """
    out: list[str] = []
    for rf in plan.rootfs:
        dest = rf.resolved_dest(env)
        if "$" in dest:
            out.append(f"{rf.image} -> {dest}")
    return out


def arg_problems(plan: Plan, env: dict[str, str] | None = None) -> list[str]:
    """Images whose declared ``base_arg`` does not actually select their base.

    Checked in the DRY RUN, because this is the failure the whole module exists
    for: docker silently ignores a --build-arg the Dockerfile does not declare,
    so the build resolves its own default while the stamp claims the pinned
    base. Reporting it before a build beats discovering it in the artifact.
    """
    from blastbox.host.stamp import StampError, assert_arg_selects_base  # noqa: PLC0415

    out: list[str] = []
    for spec in plan.images:
        path = dockerfile_path(plan, spec, env)
        if not path.is_file():
            continue
        try:
            assert_arg_selects_base(path, spec.base_arg)
        except StampError as exc:
            out.append(f"{spec.name}: {exc}")
        # Every OTHER build_arg too. A misspelled builder pin
        # (`JDK_BUILD_IMGE`) is discarded by docker, so the stage keeps its
        # mutable default while the plan reads as if it were pinned -- the same
        # silent failure as a wrong base_arg, one level down.
        declared = set(
            re.findall(
                r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        for key in sorted(spec.build_args):
            if key not in declared:
                out.append(
                    f"{spec.name}: {path} declares no `ARG {key}`, so docker "
                    f"would ignore that --build-arg. Declared: "
                    f"{', '.join(sorted(declared)) or 'none'}"
                )
    return out


def build_command(
    spec: ImageSpec,
    tag: str,
    stamp_flags: list[str],
    base_ref: str | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    """The `docker build` argv for one image.

    Passes the base through ``spec.base_arg`` when ``base_ref`` is given, unless
    ``stamp_flags`` already carries it -- `blastbox stamp` emits that build-arg
    itself, and passing it twice lets the two disagree. Without either, the plan
    would claim a pinned base while the Dockerfile fell back to its own default.

    The context is EXPANDED: `$BLASTBOX_SRC` handed to docker literally is a
    directory named `$BLASTBOX_SRC`, which does not exist.

    Returned as a LIST, never a string: a label value containing a space would
    word-split into loose docker arguments, and the failure surfaces as docker's
    usage message rather than anything about the stamp.
    """
    argv = ["docker", "build", "-f", spec.dockerfile, *stamp_flags]
    already = any(f.startswith(f"{spec.base_arg}=") for f in stamp_flags)
    if base_ref and not already:
        argv += ["--build-arg", f"{spec.base_arg}={base_ref}"]
    for key, value in sorted(spec.build_args.items()):
        argv += ["--build-arg", f"{key}={value}"]
    context = _expand(spec.context, dict(os.environ) if env is None else env)
    argv += ["-t", spec.tagged(tag), context]
    return argv


def describe(plan: Plan, tag: str, env: dict[str, str] | None = None) -> str:
    """What a run would do, for --dry-run.

    Destinations are shown RESOLVED. A dry-run that prints `$REDTUSK_FC_DIR`
    has not told the operator where it writes, which is the one question a
    dry-run exists to answer -- and an unset variable shows as itself, so the
    hole is visible rather than rendered as a path at the filesystem root.
    """
    env = dict(os.environ) if env is None else env
    lines = [f"engine {plan.engine}, tag {tag}"]
    for spec, base_ref in resolve_chain(plan, tag):
        kind = "chain" if spec.internal else "upstream"
        ctx = _expand(spec.context, env)
        where = "" if ctx == "." else f" [context {ctx}]"
        lines.append(
            f"  build {spec.tagged(tag)}  <- {base_ref} ({kind}) "
            f"via {spec.dockerfile} --base-arg {spec.base_arg}{where}"
        )
    for rf in plan.rootfs:
        need = f" requires {list(rf.requires)}" if rf.requires else ""
        size = f" {rf.size_mib} MiB" if rf.size_mib else ""
        dest = rf.resolved_dest(env)
        unresolved = " [UNRESOLVED]" if "$" in dest else ""
        lines.append(
            f"  export {rf.kind}{size} from {rf.image}:{tag} -> {dest}{need}{unresolved}"
        )
    return "\n".join(lines)


def shell_quote(argv: list[str]) -> str:
    """The argv as a copy-pasteable command, for logs and --dry-run."""
    return " ".join(shlex.quote(a) for a in argv)
