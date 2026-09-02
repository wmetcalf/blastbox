"""doctor answers "what is actually deployed?" without exec'ing by hand."""

from __future__ import annotations

import subprocess

from blastbox.host.doctor import UNKNOWN, drift, survey


def _fake_docker(containers: dict[str, dict]):
    """A docker stand-in. `containers[name]` = {image, status, project, version|None}."""

    def run(argv):
        argv = list(argv)
        def done(code=0, out="", err=""):
            return subprocess.CompletedProcess(argv, code, out, err)

        if argv[:2] == ["docker", "ps"]:
            lines = [
                '{"name":"%s","image":"%s","status":"%s"}' % (n, c["image"], c["status"])
                for n, c in containers.items()
            ]
            return done(out="\n".join(lines) + "\n")
        if argv[:2] == ["docker", "inspect"]:
            return done(out=containers[argv[2]].get("project", "") + "\n")
        if argv[:2] == ["docker", "exec"]:
            spec = containers[argv[2]]
            if "restarting" in spec["status"].lower():
                return done(1, err="Error response from daemon: container is restarting")
            version = spec.get("version")
            if version is None:
                return done(1, err="exec: python3: not found")
            return done(out=version + "\n")
        return done(1, err="unexpected: " + " ".join(argv))

    return run


def test_reports_the_version_running_in_each_container():
    run = _fake_docker({
        "api":  {"image": "rt:1", "status": "Up 2 days", "project": "rt", "version": "0.1.27"},
        "disp": {"image": "rt:1", "status": "Up 2 days", "project": "rt", "version": "0.1.27"},
    })
    found = survey(run)
    assert {c.version for c in found} == {"0.1.27"}
    assert drift(found) == {"rt": {"0.1.27"}}


def test_mixed_versions_in_one_project_are_drift():
    """The real shape: an api on one build, dispatchers pinned to an older one."""
    run = _fake_docker({
        "api":   {"image": "t:pha2", "status": "Up", "project": "t", "version": "0.1.17"},
        "disp":  {"image": "t:024",  "status": "Up", "project": "t", "version": "0.1.24"},
        "dispf": {"image": "t:024",  "status": "Up", "project": "t", "version": "0.1.24"},
    })
    assert drift(survey(run)) == {"t": {"0.1.17", "0.1.24"}}


def test_a_restarting_container_is_UNKNOWN_not_a_value():
    """The trap that misled a human operator.

    `docker exec` against a restarting container fails, and reading that as
    "the setting is absent" turned a crash-loop into a wrong diagnosis. It must
    report UNKNOWN and say why.
    """
    run = _fake_docker({
        "ok":     {"image": "t:1", "status": "Up 3 minutes", "project": "t", "version": "0.1.27"},
        "broken": {"image": "t:1", "status": "Restarting (1) 5 seconds ago", "project": "t"},
    })
    found = {c.name: c for c in survey(run)}
    assert found["broken"].version == UNKNOWN
    # The status pre-check produces this phrasing; falling through to the exec
    # would yield docker's raw daemon error instead. Asserting the friendly form
    # is what makes this test see the difference.
    assert "cannot exec" in found["broken"].detail
    assert "Restarting (1)" in found["broken"].detail
    assert not found["broken"].known
    # and it must NOT be silently counted as agreeing with the healthy one
    assert drift(survey(run)) == {"t": {"0.1.27"}}


def test_non_blastbox_containers_are_skipped():
    run = _fake_docker({
        "redis": {"image": "redis:7", "status": "Up", "project": "x", "version": None},
        "api":   {"image": "rt:1", "status": "Up", "project": "rt", "version": "0.1.27"},
    })
    assert [c.name for c in survey(run)] == ["api"]


def test_local_version_suffixes_are_preserved():
    """`0.1.26+g<sha>` means built from source at that commit -- do not truncate."""
    run = _fake_docker({
        "api": {"image": "rt:d", "status": "Up", "project": "rt", "version": "0.1.26+g793c48f"},
    })
    assert survey(run)[0].version == "0.1.26+g793c48f"


def test_a_daemon_refusal_is_UNKNOWN_not_NOPKG():
    """Distinguish "docker refused" from "no python here".

    Both fail the exec. Only the first means we do not know what is running.
    """
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        return subprocess.CompletedProcess(
            argv, 1, "", "Error response from daemon: container x is not running"
        )
    found = survey(run)
    assert [c.version for c in found] == [UNKNOWN]
    assert "daemon" in found[0].detail.lower()


def test_a_venv_only_interpreter_is_found():
    """Consumer images install into /opt/<name>/bin/python, not on exec's PATH."""
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        assert argv[1] == "exec", f"unexpected docker call: {argv[:2]}"
        if argv[3] in ("python3", "python"):
            return subprocess.CompletedProcess(argv, 127, "", "exec: python3: not found")
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    assert [c.version for c in survey(run)] == ["0.1.27"]
