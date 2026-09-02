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
    # NOT "(none:…)": a container that IS in a compose stack would then be filed
    # away from its siblings and its drift hidden. A distinct key says so.
    assert found[0].project.startswith("(unknown-project:")


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


def test_the_venv_probe_stops_at_the_first_interpreter_that_answers():
    """Running every /opt/*/bin/python and reading the LAST line drops a
    container whose blastbox lives in an earlier venv.

    The first version of this test passed for the wrong reason: its fake
    answered the `python3` attempt, so the venv command was never built and the
    test could not see the loop being deleted. It now REFUSES the system
    interpreters, forcing the venv path, and asserts the emitted shell actually
    short-circuits.
    """
    seen: list[str] = []

    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        if argv[3] in ("python3", "python"):
            return subprocess.CompletedProcess(argv, 127, "", "exec: not found")
        seen.append(argv[-1])                       # the venv shell command
        return subprocess.CompletedProcess(argv, 0, "0.1.27", "")

    assert [c.version for c in survey(run)] == ["0.1.27"]
    assert seen, "the venv fallback was never reached"
    shell = seen[0]
    assert "/opt/*/bin/python" in shell
    # short-circuit: the loop must exit on the first interpreter that answers,
    # not run them all and let the last one win.
    assert "exit 0" in shell and "continue" in shell


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
        if "{{.Id}}" in argv:                    # tag -> immutable ID first
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        assert argv[:2] == ["docker", "run"], argv
        assert "sha256:pinned" in argv, "the probe must run the PINNED id"
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    assert version_in_image("img", run) == ("0.1.27", "")


def test_a_non_daemon_exec_failure_is_UNKNOWN_not_a_silent_drop():
    """gVisor/OCI/permission failures are "could not look", not "not ours".

    Returning NOPKG dropped the container from the report entirely, so nothing
    told the operator a box had been skipped — and --expect then passed on the
    containers that survived the filter.
    """
    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0, '{"name":"worker","image":"rt:1","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "rt\n", "")
        return subprocess.CompletedProcess(
            argv, 126, "",
            "OCI runtime exec failed: unable to start container process: permission denied")
    found = survey(run)
    assert [c.name for c in found] == ["worker"], "the container must not vanish"
    assert found[0].version == UNKNOWN
    assert "OCI runtime" in found[0].detail


def test_an_image_probe_is_confined():
    """version_in_image EXECUTES an image whose provenance is in question."""
    from blastbox.host.doctor import version_in_image

    seen = []

    def run(argv):
        argv = list(argv)
        seen.append(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        return subprocess.CompletedProcess(argv, 0, "0.1.27\n", "")
    version_in_image("suspect:img", run)
    argv = next(a for a in seen if a[:2] == ["docker", "run"])
    for flag in ("--network", "none", "--read-only", "--pids-limit",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                 "--user", "--memory"):
        assert flag in argv, (flag, argv)


def test_a_banner_before_the_venv_answer_is_ignored():
    """An /opt interpreter may print a warning before the version; the answer is
    the LAST line, and the emitted shell must take it."""
    seen: list[str] = []

    def run(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(
                argv, 0, '{"name":"x","image":"i","status":"Up"}\n', "")
        if argv[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "proj\n", "")
        if argv[3] in ("python3", "python"):
            return subprocess.CompletedProcess(argv, 127, "", "exec: not found")
        seen.append(argv[-1])
        return subprocess.CompletedProcess(argv, 0, "0.1.27", "")

    survey(run)
    assert "tail -n1" in seen[0], seen[0]


def test_the_emitted_venv_shell_actually_runs():
    """EXECUTE the probe, do not just assert its text.

    A previous version placed `| tail -n1` after the heredoc terminator, which
    is a shell syntax error -- and every unit test still passed, because the
    fakes return canned output and never run the string. This runs it against a
    real interpreter that prints a banner before the version.
    """
    import os
    import pathlib
    import tempfile

    from blastbox.host import doctor

    captured: list[str] = []

    def capture(argv):
        argv = list(argv)
        if argv[:2] == ["docker", "exec"] and argv[3] == "sh":
            captured.append(argv[-1])
        return subprocess.CompletedProcess(argv, 127, "", "exec: not found")

    doctor._version_in(capture, "x", "Up")
    assert captured, "the venv probe was never built"

    root = tempfile.mkdtemp()
    binpath = pathlib.Path(root) / "venvA" / "bin"
    binpath.mkdir(parents=True)
    fake = binpath / "python"
    fake.write_text('#!/bin/sh\ncat >/dev/null\necho "WARNING: banner"\necho "0.1.27"\n')
    os.chmod(fake, 0o755)

    shell = captured[0].replace("/opt/*/bin/python", f"{root}/*/bin/python")
    proc = subprocess.run(["sh", "-lc", shell], capture_output=True, text=True)
    assert proc.returncode == 0, f"rc={proc.returncode} stderr={proc.stderr!r}"
    assert proc.stdout == "0.1.27", f"stdout={proc.stdout!r}"


def test_an_image_without_blastbox_reports_NOPKG_not_UNKNOWN():
    """"Ran fine, blastbox is not here" is an ANSWER, not a failed look.

    Collapsing it into UNKNOWN made `stamp --read` call RedTusk's worker base
    -- a pure JVM/Tika image with no python at all -- a stamp DISAGREEMENT, and
    failed a build that was entirely correct.
    """
    from blastbox.host.doctor import NOPKG, version_in_image

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        return subprocess.CompletedProcess(argv, 0, "NOPKG\n", "")

    version, detail = version_in_image("redtusk-worker:x", run)
    assert version == NOPKG, f"got {version!r} ({detail})"


def test_a_probe_that_produced_nothing_is_still_UNKNOWN():
    """No output at all is "could not look", and must stay distinguishable."""
    from blastbox.host.doctor import UNKNOWN, version_in_image

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    version, _ = version_in_image("redtusk-worker:x", run)
    assert version == UNKNOWN


def test_an_interpreter_that_could_not_run_is_not_reported_as_absence():
    """The confined UID cannot execute a root-only python.

    The fallback shell ends in `printf NOPKG` and exits 0 either way, so a
    failure to RUN looked exactly like "blastbox is not installed" -- saying
    "not a blastbox image" about an image nobody could look inside.
    """
    from blastbox.host.doctor import UNKNOWN, version_in_image

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        return subprocess.CompletedProcess(argv, 0, "PROBEFAIL\n", "")

    version, detail = version_in_image("img", run)
    assert version == UNKNOWN, f"got {version!r}"
    assert detail, "an unreadable probe must say why"


def test_the_fallback_shell_distinguishes_absence_from_failure():
    """The emitted script must set the marker; asserting on its text is not enough."""
    import re

    from blastbox.host import doctor

    seen = []

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        if "sh" not in argv:            # the direct interpreter attempts
            return subprocess.CompletedProcess(argv, 1, "", "exec format error")
        seen.append(argv[-1])           # the fallback shell script
        return subprocess.CompletedProcess(argv, 0, "PROBEFAIL\n", "")

    version, _ = doctor.version_in_image("img", run)
    assert seen, "the fallback shell was never reached"
    script = seen[0]
    assert "tried=" in script, "no marker distinguishing found-but-failed"
    assert re.search(r'\[ -n "\$tried" \].*PROBEFAIL', script), script
    assert version == doctor.UNKNOWN, f"a failed interpreter must not read as absence: {version!r}"


def _emitted_fallback_shell():
    """The shell script version_in_image would run inside an image."""
    from blastbox.host.doctor import version_in_image

    seen = []

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        if "sh" not in argv:                       # direct attempts unavailable
            return subprocess.CompletedProcess(argv, 1, "", "no such file")
        seen.append(argv[-1])
        return subprocess.CompletedProcess(argv, 0, "NOPKG\n", "")

    version_in_image("img", run)
    assert seen, "the fallback shell was never reached"
    return seen[0]


def _run_fallback(tmp_path, interpreters):
    """EXECUTE the emitted script against fake interpreters.

    Asserting on the script's TEXT is how the previous version of this test
    passed with the marker deleted: the string `nopkg=` survives in the
    initialiser even when the assignment inside the loop is gone. The only way
    to test a shell program is to run it. `/opt/` is rewritten to a temp dir --
    the glob path differs, the branching logic under test does not.

    ``interpreters`` maps a venv name to what its python prints (or None for
    an unrunnable one).
    """
    script = _emitted_fallback_shell().replace("/opt/", f"{tmp_path}/opt/")
    for name, output in interpreters.items():
        d = tmp_path / "opt" / name / "bin"
        d.mkdir(parents=True)
        py = d / "python"
        if output is None:
            py.write_text("#!/bin/sh\nexit 13\n")     # present, cannot answer
        else:
            py.write_text(f"#!/bin/sh\ncat >/dev/null\nprintf %s '{output}'\n")
        py.chmod(0o755)
    proc = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
    return proc.stdout.strip()


def test_the_fallback_shell_answers_NOPKG_when_a_python_says_so(tmp_path):
    """A definite answer must not be downgraded to "could not look"."""
    assert _run_fallback(tmp_path, {"redtusk": "NOPKG"}) == "NOPKG"


def test_the_fallback_shell_answers_PROBEFAIL_when_a_python_cannot_run(tmp_path):
    """The confined UID cannot execute a root-only interpreter."""
    assert _run_fallback(tmp_path, {"redtusk": None}) == "PROBEFAIL"


def test_the_fallback_shell_answers_NOPKG_when_there_is_no_python_at_all(tmp_path):
    """An image with no python is not a blastbox image -- RedTusk's worker base."""
    assert _run_fallback(tmp_path, {}) == "NOPKG"


def test_the_fallback_shell_prefers_a_real_version_over_either_sentinel(tmp_path):
    """One venv answering must win over another that could not run."""
    out = _run_fallback(tmp_path, {"a": None, "b": "0.1.29"})
    assert out == "0.1.29", out


def test_a_venv_python_reporting_NOPKG_stays_NOPKG():
    """A definite answer must not be downgraded to "could not look".

    The found-but-failed marker made every NOPKG from a venv interpreter come
    back as PROBEFAIL, because reaching the end of the loop was treated as
    failure regardless of WHY the loop ended.
    """
    from blastbox.host.doctor import NOPKG, version_in_image

    def run(argv):
        argv = list(argv)
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(argv, 0, "sha256:pinned\n", "")
        if "sh" not in argv:                       # direct attempts unavailable
            return subprocess.CompletedProcess(argv, 1, "", "no such file")
        script = argv[-1]
        assert "nopkg=" in script, "no marker separating 'answered NOPKG' from 'failed'"
        return subprocess.CompletedProcess(argv, 0, "NOPKG\n", "")

    version, _ = version_in_image("img", run)
    assert version == NOPKG, f"a venv python answering NOPKG became {version!r}"
