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


def test_keeps_probing_past_a_system_python_without_blastbox():
    """P1: the system interpreter is often NOT the one with blastbox.

    Consumer images ship a venv at /opt/<name>/bin/python. Returning on the
    first NOPKG DROPS a container that does run blastbox.
    """
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        if argv[3] in ("python3", "python"):
            return subprocess.CompletedProcess(argv, 0, "NOPKG\n", "")
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    assert [c.version for c in survey(run)] == ["0.1.27"]


def test_docker_ps_failure_raises_instead_of_reporting_an_empty_fleet():
    """"The daemon is down" must not look like "nothing is running"."""
    import pytest as _pytest

    from blastbox.host.doctor import DockerUnavailable

    def run(argv):
        return subprocess.CompletedProcess(list(argv), 1, "", "Cannot connect to the Docker daemon")
    with _pytest.raises(DockerUnavailable):
        survey(run)


def test_a_probe_timeout_is_UNKNOWN():
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        raise subprocess.TimeoutExpired(argv, 60)
    found = survey(run)
    assert [c.version for c in found] == [UNKNOWN]
    assert "timed out" in found[0].detail


def test_unreadable_metadata_is_UNKNOWN_not_absent():
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        return subprocess.CompletedProcess(argv, 0, "PROBEFAIL PermissionError\n", "")
    found = survey(run)
    assert [c.version for c in found] == [UNKNOWN]
    assert "metadata unreadable" in found[0].detail


def test_container_controlled_output_is_sanitised():
    """A compromised worker controls stdout; it must not reach the terminal raw."""
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        return subprocess.CompletedProcess(argv, 0, "0.1.27\x1b[31mEVIL\x07\n", "")
    version = survey(run)[0].version
    assert "\x1b" not in version and "\x07" not in version


def test_unlabeled_containers_are_not_merged_into_one_project():
    """Two unrelated `docker run` boxes must not look like one drifting project.

    "Unrelated" means DIFFERENT IMAGES: containers from one image are expected
    to agree, so they deliberately do share a group (see the image-grouping
    test below).
    """
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0,
                '{"name":"a","image":"ia","status":"Up"}\n{"name":"b","image":"ib","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "\n", "")
        return subprocess.CompletedProcess(argv, 0, ("0.1.17" if argv[2] == "a" else "0.1.27") + "\n", "")
    d = drift(survey(run))
    assert len(d) == 2, d
    assert all(len(v) == 1 for v in d.values())


def _base_fake(exec_response):
    """ps + inspect stubs; `exec_response(argv)` answers the probe."""
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        return exec_response(argv)
    return run


def test_a_hung_project_lookup_does_not_abort_the_survey():
    """One hung `docker inspect` must not kill the whole run; the project is
    only used for grouping, not for the version."""
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            raise subprocess.TimeoutExpired(argv, 60)
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    found = survey(run)
    assert [c.version for c in found] == ["0.1.27"]
    assert found[0].project.startswith("(none:")


def test_a_no_value_project_label_is_treated_as_absent():
    """Some docker builds render a missing key as the literal '<no value>'.

    Grouping every unlabeled container under that string invents drift between
    unrelated boxes.
    """
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0,
                '{"name":"a","image":"ia","status":"Up"}\n{"name":"b","image":"ib","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "<no value>\n", "")
        return subprocess.CompletedProcess(
            argv, 0, ("0.1.17" if argv[2] == "a" else "0.1.27") + "\n", "")
    d = drift(survey(run))
    assert len(d) == 2, d          # two containers, two projects, no invented drift
    assert all(len(v) == 1 for v in d.values())


def test_a_long_banner_does_not_truncate_the_version():
    """Sanitising the whole stream truncates at 200 chars; an interpreter that
    prints a warning first would have its version cut off."""
    banner = "x" * 400
    found = survey(_base_fake(
        lambda argv: subprocess.CompletedProcess(argv, 0, f"{banner}\n0.1.27\n", "")))
    assert [c.version for c in found] == ["0.1.27"]


def test_the_first_venv_with_blastbox_wins():
    """Running every /opt/*/bin/python and reading the LAST line drops a
    container whose blastbox lives in an earlier venv."""
    def exec_response(argv):
        # the shell loop is expected to stop at the first hit and print only it
        return subprocess.CompletedProcess(argv, 0, "0.1.27", "")
    assert [c.version for c in survey(_base_fake(exec_response))] == ["0.1.27"]


def test_a_missing_docker_binary_raises_rather_than_reporting_an_empty_fleet():
    """"docker is not installed" must not read as "nothing is running"."""
    from unittest.mock import patch

    import pytest as _pytest

    from blastbox.host.doctor import DockerUnavailable

    # Patch the lookup rather than depending on the test host lacking docker.
    with patch("blastbox.host.doctor.shutil.which", return_value=None):
        with _pytest.raises(DockerUnavailable):
            survey()


def test_unlabeled_containers_group_by_image_so_drift_is_visible():
    """The regression this fixes: making each unlabeled container its own key
    meant drift() -- which compares WITHIN a group -- could never flag them, so
    the exact three-way fleet in this module's docstring reported OK."""
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            rows = [
                '{"name":"bb-host","image":"rt:1","status":"Up"}',
                '{"name":"bb-cold","image":"rt:1","status":"Up"}',
            ]
            return subprocess.CompletedProcess(argv, 0, "\n".join(rows) + "\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "\n", "")   # no compose label
        return subprocess.CompletedProcess(
            argv, 0, ("0.1.26" if argv[2] == "bb-host" else "0.1.17") + "\n", "")
    d = drift(survey(run))
    assert len(d) == 1, d                       # one image -> one group
    assert d["(image:rt:1)"] == {"0.1.17", "0.1.26"}


def test_unrelated_images_still_do_not_share_a_group():
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            rows = [
                '{"name":"a","image":"one:1","status":"Up"}',
                '{"name":"b","image":"two:1","status":"Up"}',
            ]
            return subprocess.CompletedProcess(argv, 0, "\n".join(rows) + "\n", "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "\n", "")
        return subprocess.CompletedProcess(
            argv, 0, ("0.1.26" if argv[2] == "a" else "0.1.17") + "\n", "")
    d = drift(survey(run))
    assert len(d) == 2 and all(len(v) == 1 for v in d.values())


def test_version_in_image_reads_an_image_not_a_container():
    from blastbox.host.doctor import version_in_image

    def run(argv):
        argv = list(argv)
        assert argv[:2] == ["docker", "run"], argv
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    assert version_in_image("img", run) == ("0.1.27", "")
