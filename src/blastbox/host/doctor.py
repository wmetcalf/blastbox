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
    "except Exception:\n"
    "    print('NOPKG')\n"
)

UNKNOWN = "unknown"
NOPKG = "NOPKG"
# docker itself refused (container restarting, paused, gone) as opposed to the
# command simply not existing inside a running container.
_DAEMON_ERR = "error response from daemon"


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


def _ps(runner: Runner) -> list[dict[str, str]]:
    fmt = '{"name":"{{.Names}}","image":"{{.Image}}","status":"{{.Status}}"}'
    proc = runner(["docker", "ps", "--format", fmt])
    if proc.returncode != 0:
        return []
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


def _project_of(runner: Runner, name: str) -> str:
    proc = runner([
        "docker", "inspect", name,
        "--format", '{{index .Config.Labels "com.docker.compose.project"}}',
    ])
    value = proc.stdout.strip() if proc.returncode == 0 else ""
    return value or "-"


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
        ["docker", "exec", name, "sh", "-lc",
         'for p in /opt/*/bin/python; do "$p" - <<\'EOF\'\n' + _PROBE + "EOF\ndone"],
    ]
    last_err = ""
    for argv in attempts:
        proc = runner(argv)
        text = (proc.stdout or "").strip()
        if proc.returncode == 0 and text:
            return text.splitlines()[-1], ""
        err = (proc.stderr or "").strip()
        if err:
            last_err = err.splitlines()[-1]
        if _DAEMON_ERR in err.lower():
            # docker refused; retrying another interpreter cannot help.
            return UNKNOWN, err.splitlines()[-1][:140]
    # Every interpreter attempt failed at the shell level: nothing to inspect,
    # which for a redis or postgres container is simply the truth.
    return NOPKG, last_err[:140]


def survey(runner: Runner | None = None) -> list[Container]:
    """Every running container that has blastbox installed."""
    run = runner or _run
    if runner is None and shutil.which("docker") is None:
        return []
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
            project=_project_of(run, name),
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
