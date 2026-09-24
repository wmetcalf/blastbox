"""Report the blastbox version every running container is actually on.

Answering "what is deployed?" today means exec'ing into each container by hand.
Done that way on 2026-09-01 the fleet turned out to be running host 0.1.26,
cold-worker 0.1.25 and warm/guest images 0.1.17 simultaneously, none of which
matched the published release. Nothing surfaced it because nothing compared
them.

Two traps this encodes, both hit by hand first:

* **A restarting container cannot be exec'd.** ``docker exec`` fails with
  "container is restarting", and reading that as "the variable is unset" is
  how a crash-looping dispatcher was misread as a configuration difference.
  A container that cannot be inspected reports UNKNOWN, never a value.
* **An image label is not the running version.** A container keeps running the
  image it started from, so the label on ``:latest`` today says nothing about a
  container started last week. The version is read from inside the container;
  labels are only a fallback for images that are not running.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]

# Read the INSTALLED distribution, not a source literal: a dev wheel stamps a
# PEP 440 local version (0.1.26+g<sha>) and that suffix is the whole point.
# Prints the version, or the NOPKG sentinel when python works but blastbox is
# not installed. The distinction matters: "this is not a blastbox container" and
# "I could not read this container" must not collapse into one answer.
_PROBE = (
    "import importlib.metadata as m\n"
    "try:\n"
    "    print(m.version('blastbox'))\n"
    "except m.PackageNotFoundError:\n"
    "    print('NOPKG')\n"          # genuinely not installed
    "except Exception as e:\n"
    "    print('PROBEFAIL', type(e).__name__)\n"   # metadata unreadable: NOT the same
)

UNKNOWN = "unknown"
NOPKG = "NOPKG"
_PROBEFAIL = "PROBEFAIL"
# Probe output is attacker-influenced (a compromised worker controls stdout), so
# it is never printed raw.
_SAFE = re.compile(r"[^A-Za-z0-9._+:!~<>= -]")
# docker itself refused (container restarting, paused, gone) as opposed to the
# command simply not existing inside a running container.
_DAEMON_ERR = "error response from daemon"
# "the command is not in this image" -- the only exec failure that legitimately
# means "not a blastbox container" rather than "could not look".
_NO_INTERPRETER = ("not found", "no such file or directory", "executable file not found")

# Flags for running an image whose provenance is exactly what is in question.
_CONFINE = (
    "--network", "none",
    "--read-only",
    "--pids-limit", "64",
    "--memory", "256m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", "65534:65534",
)


def _looks_like_missing_interpreter(err: str) -> bool:
    low = err.lower()
    return any(marker in low for marker in _NO_INTERPRETER)


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=60)


@dataclass(frozen=True)
class Container:
    """One running container and the blastbox it is actually running."""

    name: str
    image: str
    project: str
    status: str
    version: str          # or UNKNOWN
    detail: str = ""      # why it is UNKNOWN

    @property
    def known(self) -> bool:
        return self.version != UNKNOWN


def _sanitise(text: str) -> str:
    """Strip control characters from container-controlled output before display."""
    return _SAFE.sub("", text)[:200]


class DockerUnavailable(RuntimeError):
    """`docker ps` itself failed: the survey saw nothing, which is not "nothing runs"."""


def _ps(runner: Runner) -> list[dict[str, str]]:
    fmt = '{"name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}"}'
    try:
        proc = runner(["docker", "ps", "--format", fmt])
    except subprocess.TimeoutExpired as exc:
        raise DockerUnavailable("docker ps timed out") from exc
    if proc.returncode != 0:
        # Returning [] here makes "the daemon is down" indistinguishable from
        # "nothing is running", so --expect would pass having verified nothing.
        raise DockerUnavailable((proc.stderr or "docker ps failed").strip()[:200])
    out: list[dict[str, str]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _project_of(runner: Runner, name: str, image: str = "") -> str:
    try:
        proc = runner([
            "docker", "inspect", name,
            "--format", '{{index .Config.Labels "com.docker.compose.project"}}',
        ])
    except subprocess.TimeoutExpired:
        # One hung inspect must not abort the whole survey. But do not pretend
        # this container has no project: if it IS in a compose stack, filing it
        # under an image/name key would split it from its siblings and hide
        # drift. A distinct key says "we could not tell".
        return f"(unknown-project:{name})"
    value = proc.stdout.strip() if proc.returncode == 0 else ""
    # Go templates render a missing key as "<no value>" on some docker builds
    # (this one emits an empty line). Treat both as absent.
    if value == "<no value>":
        value = ""
    if value:
        return value
    # No compose label. Group by IMAGE, not by container name: blastbox starts
    # its own workers with `docker run`, so a name-unique key would make every
    # worker its own group and drift() -- which compares WITHIN a group -- could
    # never flag them. Two containers from one image must agree; two unrelated
    # `docker run` boxes still do not share a group.
    return f"(image:{image})" if image else f"(none:{name})"


def _version_in(runner: Runner, name: str, status: str) -> tuple[str, str]:
    """The blastbox version running inside ``name``.

    Returns ``(version, detail)`` where version is a version string, ``NOPKG``
    (ran fine, blastbox not installed -- not a blastbox container) or
    ``UNKNOWN`` (could not be read at all).

    Keeping those apart is the point. A container that is restarting cannot be
    exec'd, and reading that failure as "the value is absent" is exactly how a
    crash-looping dispatcher got misdiagnosed as a config difference.
    """
    low = status.lower()
    if "restarting" in low or "created" in low or "paused" in low:
        return UNKNOWN, f"container is {status.strip()}, cannot exec"

    attempts = [
        ["docker", "exec", name, "python3", "-c", _PROBE],
        ["docker", "exec", name, "python", "-c", _PROBE],
        # Consumer images install into a venv that is not on exec's PATH.
        # Stop at the FIRST venv interpreter that reports a version. Running
        # them all and reading the last line drops a container whose blastbox
        # lives in an earlier venv when a later one lacks it.
        ["docker", "exec", name, "sh", "-lc",
         'for p in /opt/*/bin/python; do [ -x "$p" ] || continue; '
         # The pipe belongs on the COMMAND line, before the heredoc body --
         # after the EOF terminator it is a syntax error, not a pipeline.
         # tail -n1 because an interpreter may print a banner before the answer.
         'v=$("$p" - <<\'EOF\' | tail -n1\n' + _PROBE + "EOF\n" + '); '
         'case "$v" in ""|NOPKG*|PROBEFAIL*) continue;; *) printf %s "$v"; exit 0;; esac; '
         'done; printf NOPKG'],
    ]
    last_err = ""
    saw_nopkg = False
    for argv in attempts:
        try:
            proc = runner(argv)
        except subprocess.TimeoutExpired:
            # A hung docker or interpreter is precisely "we do not know".
            return UNKNOWN, "probe timed out"
        # Take the last line FIRST, then sanitise it. Sanitising the whole
        # stream truncates at 200 chars, so any interpreter that prints a
        # banner or warning first would have the version cut off entirely.
        raw_lines = (proc.stdout or "").strip().splitlines()
        line = _sanitise(raw_lines[-1]) if raw_lines else ""
        if proc.returncode == 0 and line:
            if line == NOPKG:
                # This interpreter lacks blastbox, but a venv one may have it.
                # Returning here would DROP a container that does run blastbox.
                saw_nopkg = True
                continue
            if line.startswith(_PROBEFAIL):
                return UNKNOWN, f"metadata unreadable: {line}"
            return line, ""
        err = _sanitise((proc.stderr or "").strip())
        if err:
            last_err = err.splitlines()[-1]
        if _DAEMON_ERR in err.lower():
            # docker refused; retrying another interpreter cannot help.
            return UNKNOWN, last_err[:140]
    if saw_nopkg:
        return NOPKG, ""
    if last_err and not _looks_like_missing_interpreter(last_err):
        # An exec that failed for a reason OTHER than "no such command" --
        # OCI runtime errors, permission/seccomp/AppArmor denials, a read-only
        # rootfs -- means we could not look, not that blastbox is absent.
        # Returning NOPKG here dropped the container from the report entirely,
        # so nothing told the operator a box had been skipped.
        return UNKNOWN, last_err[:140]
    # Every attempt failed because there is no interpreter: for a redis or
    # postgres container that is simply the truth.
    return NOPKG, last_err[:140]


def version_in_image(image: str, runner: Runner | None = None) -> tuple[str, str]:
    """The blastbox version installed in an IMAGE (not a running container).

    Runs the same probe used for containers, in a throwaway container, so a
    stamp's self-reported version can be checked against reality. Returns
    (version, detail); version is UNKNOWN when it could not be read.
    """
    run = runner or _run
    # Pin to one immutable ID: a concurrent pull or rebuild can repoint a tag
    # between the stamp read and this probe, so the two would describe different
    # images while appearing to describe one.
    pinned = run(["docker", "inspect", "--type", "image", image, "--format", "{{.Id}}"])
    if pinned.returncode == 0 and pinned.stdout.strip():
        image = pinned.stdout.strip()
    for interp in ("python3", "python"):
        try:
            proc = run([
                "docker", "run", "--rm",
                # This EXECUTES an image whose provenance is the thing in
                # question -- unlike survey(), which execs into a container the
                # operator already chose to run. Give it as close to nothing as
                # docker allows. (Routing this through blastbox's own gVisor/FC
                # runtime would be stronger still; that is a larger change and
                # is noted in the module docstring.)
                *_CONFINE,
                "--entrypoint", interp, image, "-c", _PROBE,
            ])
        except subprocess.TimeoutExpired:
            return UNKNOWN, "probe timed out"
        raw = (proc.stdout or "").strip().splitlines()
        line = _sanitise(raw[-1]) if raw else ""
        if proc.returncode == 0 and line.startswith(_PROBEFAIL):
            # "metadata unreadable" must not collapse into "no blastbox here".
            return UNKNOWN, f"metadata unreadable: {line}"
        if proc.returncode == 0 and line and line != NOPKG:
            return line, ""
    try:
        proc = run([
            "docker", "run", "--rm",
            *_CONFINE,
            "--entrypoint", "sh", image, "-lc",
            # `tried` distinguishes "there was no interpreter to run" from
            # "an interpreter was there and did not answer" -- the confined UID
            # cannot execute a root-only python, and reporting that as NOPKG
            # says "not a blastbox image" about an image nobody could look
            # inside. Absence and failure are different answers.
            # Three outcomes, kept apart. `nopkg` remembers that an
            # interpreter ANSWERED "not installed" -- without it, a venv python
            # correctly reporting NOPKG fell through to the found-but-failed
            # branch and came back as PROBEFAIL, turning a definite answer into
            # "could not look". No interpreter at all is NOPKG too: an image
            # with no python is not a blastbox image, which is precisely
            # RedTusk's pure-JVM worker base.
            'tried=; nopkg=; for p in /opt/*/bin/python; do [ -x "$p" ] || continue; '
            'tried=1; v=$("$p" - <<\'EOF\'\n' + _PROBE + "EOF\n" + '); '
            'case "$v" in NOPKG*) nopkg=1; continue;; '
            '""|PROBEFAIL*) continue;; '
            '*) printf %s "$v"; exit 0;; esac; '
            'done; '
            'if [ -n "$nopkg" ]; then printf NOPKG; '
            'elif [ -n "$tried" ]; then printf PROBEFAIL; '
            'else printf NOPKG; fi',
        ])
    except subprocess.TimeoutExpired:
        return UNKNOWN, "probe timed out"
    raw = (proc.stdout or "").strip().splitlines()
    line = _sanitise(raw[-1]) if raw else ""
    # The sentinels are checked BEFORE the "looks like a version" branch: they
    # are not versions, and matching that branch first returned the literal
    # string PROBEFAIL to callers as though it were one.
    if proc.returncode == 0 and line.startswith(_PROBEFAIL):
        return UNKNOWN, "an interpreter was present but did not answer"
    if proc.returncode == 0 and line and line != NOPKG:
        return line, ""
    if proc.returncode == 0 and line == NOPKG:
        # The probe RAN and found no blastbox. That is an answer -- "this is not
        # a blastbox image" -- and it is not the same as "the probe failed",
        # which is what returning UNKNOWN here used to say. The distinction is
        # the whole point of the NOPKG sentinel, and collapsing it made
        # verify_contents call a pure-JVM worker base a stamp DISAGREEMENT: the
        # image is not supposed to contain blastbox, so there is nothing to
        # disagree with.
        return NOPKG, "the image contains no blastbox"
    return UNKNOWN, (_sanitise((proc.stderr or "").strip())[:140] or "probe produced no output")


def survey(runner: Runner | None = None) -> list[Container]:
    """Every running container that has blastbox installed."""
    run = runner or _run
    if runner is None and shutil.which("docker") is None:
        # Returning [] here is the vacuous pass this module exists to prevent:
        # "docker is not installed" would read as "nothing is running".
        raise DockerUnavailable("docker is not installed or not on PATH")
    found: list[Container] = []
    for row in _ps(run):
        name = row.get("name", "")
        if not name:
            continue
        version, detail = _version_in(run, name, row.get("status", ""))
        if version == NOPKG:
            continue  # ran fine, no blastbox -- not ours
        found.append(Container(
            name=name,
            image=row.get("image", "?"),
            project=_project_of(run, name, row.get("image", "")),
            status=row.get("status", "?"),
            version=version,
            detail=detail,
        ))
    return found


def drift(containers: list[Container]) -> dict[str, set[str]]:
    """Per compose project, the distinct blastbox versions running in it.

    A project with more than one is running mixed builds -- the shape that had
    an api on 0.1.17 beside dispatchers on 0.1.24 for weeks.
    """
    by_project: dict[str, set[str]] = {}
    for c in containers:
        if c.known:
            by_project.setdefault(c.project, set()).add(c.version)
    return by_project

@dataclass
class Artifact:
    """One warm rootfs and what it says about itself.

    `Container` answers "what blastbox is this process running". This answers the
    question `Container` structurally cannot: a rootfs is a FILE (or a directory
    tree), not a process, and `docker export` drops the image config on the way
    out -- so the labels `stamp.py` attaches never reach it. Three engines drifted
    for two months inside exactly that blind spot.
    """

    path: str
    version: str                      # or UNKNOWN
    runtime: str = ""                 # firecracker | gvisor, from the stamp
    arch: str = ""
    cpu_vendor: str = ""
    image: str = ""
    exported_at: str = ""
    #: The compose project this rootfs serves, when given as `--rootfs PROJECT=PATH`. Paired,
    #: it is checked against THAT project's containers; unpaired, only against the host's
    #: versions as a whole -- where a stale rootfs passes if any product runs its version.
    project: str = ""
    detail: str = ""                  # why it is UNKNOWN, or what disagrees

    @property
    def known(self) -> bool:
        return self.version != UNKNOWN


def survey_rootfs(paths: Sequence[str]) -> list[Artifact]:
    """Read the stamp on each warm artifact. Never raises on a bad path.

    An artifact that cannot be read reports UNKNOWN with the reason, never a
    version -- the same rule `_version_in` applies to a container that cannot be
    exec'd: "I could not look" and "it is absent" must not collapse together.
    """
    from blastbox.host import rootfs_stamp as _rfs

    out: list[Artifact] = []
    for spec in paths:
        project, path = _pairing(spec)
        try:
            stamp = _rfs.read(path)
        except Exception as exc:  # noqa: BLE001 - a survey never dies on one row
            out.append(Artifact(path=path, version=UNKNOWN, detail=str(exc).strip(),
                                project=project))
            continue
        plat = _rfs.platform_of(stamp)
        # Every field below comes from an artifact this host did not create: stripped of
        # control characters, as container output is, so a stamp cannot forge the lines
        # after it or drive the operator's terminal. `path` is the operator's own argument.
        version = _sanitise(stamp.blastbox_version)
        out.append(
            Artifact(
                path=path,
                version=version or UNKNOWN,
                runtime=_sanitise(plat.runtime),
                arch=_sanitise(plat.arch),
                cpu_vendor=_sanitise(plat.cpu_vendor),
                image=_sanitise(stamp.image),
                exported_at=_sanitise(stamp.exported_at),
                detail="" if version else "stamp records no version",
                project=project,
            )
        )
    return out


def _pairing(spec: str) -> tuple[str, str]:
    """`PROJECT=PATH` -> (project, path); a bare path is unpaired.

    Only a leading `name=` with no path separator in `name` counts, so a path that merely
    contains `=` is never split.
    """
    head, sep, tail = spec.partition("=")
    if sep and head and "/" not in head and tail:
        return head, tail
    return "", spec


def _release(version: str) -> object:
    """A version as a comparable RELEASE: `+local` dropped, PEP 440 equality.

    The tier's own guest check (rootfs_stamp.compare_to_host) compares releases, so doctor
    must too -- or the two contradict each other about the same artifact (`0.1.42+gabc`
    boots, and doctor calls it a guest that never signals READY).
    """
    base = (version or "").split("+", 1)[0].strip()
    try:
        from packaging.version import InvalidVersion, Version  # noqa: PLC0415

        return Version(base)
    except (ImportError, InvalidVersion):
        return base


def artifact_problems(artifacts: Sequence[Artifact]) -> list[tuple[Artifact, str]]:
    """Each artifact that will not run on THIS host, with the reason.

    Asked of the live machine rather than of the other artifacts: two rootfs
    agreeing with each other and both disagreeing with the host is the fleet
    state that reads as healthy and serves nothing.
    """
    from blastbox.host import platform_id as _plat

    problems: list[tuple[Artifact, str]] = []
    for art in artifacts:
        if not art.known:
            continue
        recorded = _plat.HostPlatform(
            arch=art.arch, cpu_vendor=art.cpu_vendor, runtime=art.runtime
        )
        live = _plat.host_platform(runtime=art.runtime)
        fatal = _plat.refusals(_plat.compare(recorded, live))
        if fatal:
            problems.append((art, _plat.summarise(fatal)))
    return problems


def verdict(
    containers: Sequence[Container],
    artifacts: Sequence[Artifact] = (),
    *,
    expect: str | None = None,
    allow_mixed: bool = False,
    docker_error: str = "",
) -> list[str]:
    """Every reason the fleet is NOT ok under the given policy; empty means ok.

    The ONE place `--expect` and `--allow-mixed` are applied. The command used to decide
    through a chain of early returns, each seeing part of the policy: JSON mode ignored both
    flags, `--allow-mixed` returned before an unreadable artifact was judged, and a
    rootfs-only fleet was never checked for versions at all. Versions are compared as
    releases (see _release), the same way the tier's own guest check does.
    """
    problems: list[str] = []
    if docker_error:
        # "Could not look" is never "nothing is wrong": artifacts alone cannot vouch for
        # containers nobody inspected.
        problems.append(f"containers could not be inspected: {docker_error}")
    unknown_c = [c.name for c in containers if not c.known]
    unknown_a = [a.path for a in artifacts if not a.known]
    if unknown_c:
        problems.append(f"{len(unknown_c)} container(s) could not be inspected: "
                        + ", ".join(unknown_c))
    if unknown_a:
        problems.append(f"{len(unknown_a)} artifact(s) could not be read: "
                        + ", ".join(unknown_a))
    for art, why in artifact_problems(artifacts):
        problems.append(f"unbootable here: {art.path}: {why}")
    for project, versions in sorted(drift(list(containers)).items()):
        if len({_release(v) for v in versions}) > 1:
            # Within ONE compose project there is no legitimate mix; --allow-mixed is for
            # separate products on one host.
            problems.append(f"compose project {project} runs {', '.join(sorted(versions))}")
    if not containers and not artifacts:
        if expect:
            problems.append(f"expected {expect}, but found nothing to verify")
        return problems
    known_c = [c for c in containers if c.known]
    known_a = [a for a in artifacts if a.known]
    if expect:
        want = _release(expect)
        wrong = sorted({c.name for c in known_c if _release(c.version) != want}
                       | {a.path for a in known_a if _release(a.version) != want})
        if wrong:
            problems.append(f"expected {expect}, but: " + ", ".join(wrong))
    host_releases = {_release(c.version) for c in known_c}
    # The GUEST CHECK applies whatever --allow-mixed says: that flag is exactly what a
    # multi-product host passes, so it cannot also be what switches this off.
    for art in known_a:
        if art.project:
            mine = {_release(c.version) for c in known_c if c.project == art.project}
            if mine and _release(art.version) not in mine:
                problems.append(
                    f"{art.path} records {art.version} but project {art.project} runs "
                    f"{', '.join(sorted(str(v) for v in mine))} -- a guest that does not "
                    "match its host boots and never signals READY")
        elif host_releases and _release(art.version) not in host_releases:
            problems.append(
                f"{art.path} records {art.version} but no container here runs it "
                f"({', '.join(sorted(str(v) for v in host_releases))}) -- a guest that does "
                "not match its host boots and never signals READY")
    if not allow_mixed:
        if len(host_releases) > 1:
            problems.append(f"containers run {len(host_releases)} versions: "
                            + ", ".join(sorted(str(v) for v in host_releases)))
        a_releases = {_release(a.version) for a in known_a}
        if not host_releases and len(a_releases) > 1:
            problems.append(f"artifacts record {len(a_releases)} versions: "
                            + ", ".join(sorted(str(v) for v in a_releases)))
    return problems


def fleet_report(
    containers: Sequence[Container], artifacts: Sequence[Artifact] = ()
) -> dict:
    """The whole fleet as one JSON-able object, for monitoring.

    Everything a check needs without parsing the human output: per-container and
    per-artifact versions, the drift buckets, and the artifacts this host cannot
    boot. `ok` is false when anything is unknown, drifted, or unbootable --
    deliberately strict, because the failure this exists for looked fine.
    """
    versions = sorted({c.version for c in containers if c.known} |
                      {a.version for a in artifacts if a.known})
    unknown = [c.name for c in containers if not c.known] + [
        a.path for a in artifacts if not a.known
    ]
    mixed = {p: sorted(v) for p, v in drift(list(containers)).items() if len(v) > 1}
    unbootable = [
        {"path": a.path, "reason": why} for a, why in artifact_problems(artifacts)
    ]
    return {
        "versions": versions,
        "containers": [asdict(c) for c in containers],
        "artifacts": [asdict(a) for a in artifacts],
        "drift": mixed,
        "unknown": unknown,
        "unbootable": unbootable,
        "ok": not (mixed or unknown or unbootable) and len(versions) <= 1,
    }

