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
from dataclasses import dataclass

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
         # tail -n1: an interpreter may print a banner or warning before the
         # answer, and the answer is the LAST line, not the whole stream.
         'v=$("$p" - <<\'EOF\'\n' + _PROBE + "EOF\n" + ' | tail -n1); '
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
            'for p in /opt/*/bin/python; do [ -x "$p" ] || continue; '
            'v=$("$p" - <<\'EOF\'\n' + _PROBE + "EOF\n" + '); '
            'case "$v" in ""|NOPKG*) continue;; *) printf %s "$v"; exit 0;; esac; '
            'done; printf NOPKG',
        ])
    except subprocess.TimeoutExpired:
        return UNKNOWN, "probe timed out"
    raw = (proc.stdout or "").strip().splitlines()
    line = _sanitise(raw[-1]) if raw else ""
    if proc.returncode == 0 and line and line != NOPKG:
        return line, ""
    return UNKNOWN, (_sanitise((proc.stderr or "").strip())[:140] or "no blastbox in image")


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
