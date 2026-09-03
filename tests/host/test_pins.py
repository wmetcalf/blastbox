"""A pin is what gets INSTALLED. Prose about a version is not a pin."""

from __future__ import annotations

import textwrap

from blastbox.host.pins import disagreements, scan


def _repo(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


PYPROJECT = '''
    [project]
    name = "consumer"
    version = "0.1.0"
    dependencies = [
        "blastbox>=0.1.27,<0.2",
    ]
    [project.optional-dependencies]
    host = ["blastbox[host,s3]>=0.1.27,<0.2"]
'''


def test_finds_pins_across_every_install_path(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.worker": '''
            FROM python:3.12
            ARG BLASTBOX_VERSION=0.1.27
            RUN pip install --no-cache-dir "blastbox==${BLASTBOX_VERSION}"
        ''',
        "deploy/requirements.lock": '''
            blastbox==0.1.27 \\
                --hash=sha256:abc
        ''',
    })
    kinds = sorted(p.kind for p in scan(root))
    assert kinds == ["dockerfile-arg", "lock", "pyproject", "pyproject"]
    assert {p.floor for p in scan(root)} == {"0.1.27"}


def test_a_commented_out_install_line_is_not_a_pin(tmp_path):
    """Kills the comment-stripping guard specifically.

    This comment contains `pip`, `install`, `blastbox` AND a specifier, so it
    survives every other filter -- only stripping the comment excludes it. That
    is the exact shape that made a naive grep report phantom pins.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.worker": """
            FROM python:3.12
            # was: pip install "blastbox==0.1.9" before the lock existed
            ARG BLASTBOX_VERSION=0.1.27
            RUN pip install "blastbox==${BLASTBOX_VERSION}"
        """,
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.line, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_a_specifier_outside_an_install_line_is_not_a_pin(tmp_path):
    """Kills the install-verb guard specifically.

    Uncommented, so comment-stripping cannot save it; it names blastbox with a
    specifier but installs nothing.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.host": """
            FROM python:3.12
            ENV BLASTBOX_NOTE=blastbox>=0.1.9
            LABEL requires="blastbox>=0.1.9"
        """,
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.line, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_lockfiles_under_docs_and_tests_are_ignored(tmp_path):
    """Kills the skip-directory guard specifically.

    A fixture lock inside tests/ is a fixture, not this repo's install path.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "tests/fixtures/requirements.lock": "blastbox==0.1.9 \\\n    --hash=sha256:abc\n",
        "docs/examples/requirements.lock": "blastbox==0.1.5 \\\n    --hash=sha256:def\n",
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.path, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_drift_between_install_paths_is_reported(tmp_path):
    """The real shape: pyproject moved, the worker Dockerfile did not."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.worker": '''
            FROM python:3.12
            ARG BLASTBOX_VERSION=0.1.17
            RUN pip install "blastbox==${BLASTBOX_VERSION}"
        ''',
    })
    groups = disagreements(scan(root))
    assert sorted(groups) == ["0.1.17", "0.1.27"]


def test_a_mention_without_an_install_is_not_a_pin(tmp_path):
    """COPY/ENV naming blastbox must not count; only an install line does."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.host": '''
            FROM python:3.12
            ENV BLASTBOX_BLOB_URL=s3://blastbox/x
            COPY blastbox-0.1.9-py3-none-any.whl /tmp/
        ''',
    })
    assert [p.kind for p in scan(root)] == ["pyproject", "pyproject"]


def test_extras_do_not_truncate_line_attribution(tmp_path):
    """`req.split(",")[0]` truncated `blastbox[host,s3]` to `blastbox[host`."""
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]
            [project.optional-dependencies]
            a = ["blastbox[host,s3]>=0.1.27,<0.2"]
            b = ["blastbox[host,s3]>=0.1.27,<0.2"]
        '''
    })
    lines = sorted(p.line for p in scan(root))
    assert lines == [5, 7, 8], lines          # distinct, real lines
    assert all(p.line != 0 for p in scan(root))


def test_environment_markers_do_not_leak_into_the_version(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27; python_version >= '3.12'"]
        '''
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_compatible_release_pins_count_as_drift(tmp_path):
    """`~=` was matched but yielded no floor, so it vanished from drift groups."""
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox~=0.1.17"]
        ''',
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "blastbox==0.1.27"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_a_wrapped_run_install_is_one_logical_line(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install --no-cache-dir \\
                  "blastbox[host]>=0.1.17,<0.2" \\
             && echo done
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_an_unused_ARG_is_not_a_pin(tmp_path):
    """Documented contract: the ARG is a pin only if an install consumes it."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            ARG BLASTBOX_VERSION=0.1.9
            RUN echo "$BLASTBOX_VERSION" > /etc/note
        ''',
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_lock_pins_with_extras_are_found(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/requirements.lock": 'blastbox[host]==0.1.17 \\\n    --hash=sha256:abc\n',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_a_malformed_pyproject_raises_instead_of_reporting_clean(tmp_path):
    """Silently returning no pins makes a drifted repo look OK."""
    import pytest as _pytest

    from blastbox.host.pins import PinScanError

    root = _repo(tmp_path, {"pyproject.toml": "[project\nname = broken"})
    with _pytest.raises(PinScanError):
        scan(root)


def test_echoing_a_requirement_is_not_an_install(tmp_path):
    """`pip`/`install` as bare words is not an install command."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN echo "to install run: blastbox>=0.1.9" > /etc/readme
        ''',
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_a_bare_name_does_not_attribute_to_the_description(tmp_path):
    """Real shape: pdf-titan-arum's description contains the word "blastbox".

    A bare-name needle matched the description line and reported pyproject:8
    instead of the dependency at :12.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "titanarum"
            version = "0.1.0"
            description = "PDF forensic engine for blastbox"
            dependencies = ["blastbox>=0.1.27,<0.2"]
        '''
    })
    pins = scan(root)
    assert [p.line for p in pins] == [6], [(p.line, p.raw) for p in pins]


def test_an_upper_bound_is_not_a_floor(tmp_path):
    """`blastbox<=0.2,>=0.1.27` guarantees 0.1.27, not 0.2.

    Specifier order is not meaningful, so a leading upper bound must not be
    read as the version.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox<=0.2,>=0.1.27"]
        '''
    })
    assert [p.floor for p in scan(root)] == ["0.1.27"]


def test_only_an_upper_bound_yields_no_floor(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox<0.2"]
        '''
    })
    assert [p.floor for p in scan(root)] == [None]
    assert disagreements(scan(root)) == {}


def test_distribution_name_is_case_insensitive(tmp_path):
    """PEP 508 names are case-insensitive; `Blastbox` is the same project."""
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["Blastbox>=0.1.27,<0.2"]
        ''',
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "BlastBox==0.1.17"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_equal_releases_spelled_differently_are_one_group(tmp_path):
    """0.1.27 and 0.1.27.0 are the same release -- grouping raw text invents drift."""
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]
        ''',
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "blastbox==0.1.27.0"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.27"]


def test_a_directory_symlink_is_not_followed(tmp_path):
    """is_dir() follows links: a link to / would walk the filesystem."""
    root = _repo(tmp_path, {"pyproject.toml": PYPROJECT})
    outside = tmp_path.parent / "outside_repo"
    (outside / "deploy" / "docker").mkdir(parents=True, exist_ok=True)
    (outside / "deploy" / "docker" / "Dockerfile.x").write_text(
        'FROM p\nRUN pip install "blastbox==0.1.1"\n', encoding="utf-8"
    )
    (root / "link").symlink_to(outside, target_is_directory=True)
    assert {p.floor for p in scan(root)} == {"0.1.27"}


def test_a_different_distribution_ending_in_blastbox_is_not_matched(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "not-blastbox==0.1.1" "myblastbox==0.1.2"
        ''',
    })
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind == "dockerfile-pip"]


def test_the_strongest_lower_bound_wins(tmp_path):
    """A set may carry several lower bounds; the first written is arbitrary."""
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.5,>=0.1.27,<0.2"]
        '''
    })
    assert [p.floor for p in scan(root)] == ["0.1.27"]


def test_pip_global_options_before_install(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN python -m pip --isolated --no-cache-dir install "blastbox==0.1.17"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_every_install_on_one_logical_run_is_reported(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "blastbox==0.1.17" \\
             && pip install "blastbox[host]==0.1.20"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.20", "0.1.27"]


def test_suffix_convention_dockerfiles_are_scanned(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/worker.Dockerfile": '''
            FROM p
            RUN pip install "blastbox==0.1.17"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_indented_lock_entries_are_found(tmp_path):
    """Leading whitespace is legal in a requirements-format file.

    NOTE the leading `#` line: _repo() runs textwrap.dedent, which would strip
    the very indentation under test if every line were indented.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/requirements.lock": "# lock\n    blastbox==0.1.17 \\\n        --hash=sha256:abc\n",
    })
    lock_pins = [p for p in scan(root) if p.kind == "lock"]
    assert [p.floor for p in lock_pins] == ["0.1.17"], lock_pins
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_an_unreadable_directory_fails_instead_of_under_reporting(tmp_path):
    """Silently skipping a directory returns OK on a repo never fully read."""
    import os

    import pytest as _pytest

    from blastbox.host.pins import PinScanError

    root = _repo(tmp_path, {"pyproject.toml": PYPROJECT})
    blocked = root / "deploy"
    blocked.mkdir(exist_ok=True)
    (blocked / "Dockerfile.w").write_text('RUN pip install "blastbox==0.1.1"\n', encoding="utf-8")
    os.chmod(blocked, 0o000)
    try:
        with _pytest.raises(PinScanError):
            scan(root)
    finally:
        os.chmod(blocked, 0o755)


def test_a_direct_reference_is_a_pin_not_a_silent_drop(tmp_path):
    """`blastbox @ git+https://...` is the STRONGEST pin a repo can express.

    It carries no comparison specifier, so the requirement pattern could not see
    it and it vanished — the repo then reported OK against a drifted Dockerfile.
    """
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox @ git+https://example.invalid/blastbox@v0.1.30"]
        ''',
    })
    pins = scan(root)
    assert len(pins) == 1, pins
    assert "git+https" in pins[0].specifier
    assert pins[0].floor is None          # a URL is not a version; never fake one


def test_pep735_dependency_groups_are_scanned(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": '''
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]

            [dependency-groups]
            dev = ["blastbox>=0.1.5"]
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.27", "0.1.5"]


def test_a_toml_lock_is_parsed_as_toml_not_as_requirements(tmp_path):
    """uv.lock/poetry.lock were selected then handed to a requirements regex
    that can never match TOML: read, zero pins, reported clean."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "uv.lock": '''
            [[package]]
            name = "blastbox"
            version = "0.1.17"
        ''',
    })
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_constraints_and_requirements_dir_are_install_paths(tmp_path):
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "constraints.txt": "blastbox==0.1.9\n",
        "requirements/base.txt": "blastbox==0.1.11\n",
    })
    assert sorted(disagreements(scan(root))) == ["0.1.11", "0.1.27", "0.1.9"]


def test_constraint_files_with_range_specifiers_are_parsed(tmp_path):
    """A hashed lock pins with ==, but constraints/requirements files carry any
    specifier; matching only == skipped them silently."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "constraints.txt": "blastbox>=0.1.9,<0.2\n",
    })
    assert sorted(disagreements(scan(root))) == ["0.1.27", "0.1.9"]


def test_a_direct_reference_on_a_dockerfile_install_line_is_a_pin(tmp_path):
    """A Dockerfile can install a direct reference just as a pyproject can."""
    root = _repo(tmp_path, {
        "pyproject.toml": PYPROJECT,
        "deploy/docker/Dockerfile.w": '''
            FROM p
            RUN pip install "blastbox @ git+https://example.invalid/b@v0.1.30"
        ''',
    })
    refs = [p for p in scan(root) if p.specifier.startswith("@")]
    assert len(refs) == 1, [(p.file if hasattr(p, "file") else p.path, p.specifier) for p in scan(root)]


# --- set_version -----------------------------------------------------------

_D = ["1" * 64, "2" * 64]


def _consumer(tmp_path, *, lock=True):
    """A repo pinning blastbox by every path the scanner recognises."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["blastbox>=0.1.27,<0.2"]\n'
        '[project.optional-dependencies]\nhost = ["blastbox[host,s3]>=0.1.27,<0.2"]\n'
    )
    (tmp_path / "Dockerfile.worker").write_text(
        "ARG BLASTBOX_VERSION=0.1.27\nFROM x\n"
        'RUN pip install "blastbox==${BLASTBOX_VERSION}"\n'
    )
    if lock:
        (tmp_path / "deploy").mkdir(exist_ok=True)
        (tmp_path / "deploy" / "requirements.lock").write_text(
            "blastbox==0.1.27 \\\n"
            "    --hash=sha256:" + "a" * 64 + " \\\n"
            "    --hash=sha256:" + "b" * 64 + "\n"
            "    # via x (pyproject.toml)\n"
        )
    return tmp_path


def test_one_input_moves_every_pin(tmp_path):
    """The point of the command: seven places, one version."""
    from blastbox.host.pins import disagreements, scan, set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    groups = disagreements(scan(root))
    assert sorted(groups) == ["0.1.30"], groups


def test_an_upper_bound_is_not_moved(tmp_path):
    """`<0.2` is a deliberate ceiling.

    Rewriting it down silently narrows what the consumer accepts; rewriting it
    up raises a ceiling nobody chose.
    """
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    assert '"blastbox>=0.1.30,<0.2"' in (root / "pyproject.toml").read_text()


def test_extras_and_quoting_survive(tmp_path):
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    assert '"blastbox[host,s3]>=0.1.30,<0.2"' in (root / "pyproject.toml").read_text()


def test_a_dockerfile_arg_moves_too(tmp_path):
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    assert "ARG BLASTBOX_VERSION=0.1.30" in (root / "Dockerfile.worker").read_text()


def test_a_hash_pinned_lock_without_digests_is_refused(tmp_path):
    """A version bumped without its hashes is a lock pip rejects outright."""
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = _consumer(tmp_path)
    with _pytest.raises(PinScanError) as e:
        set_version(root, "0.1.30", digests=None)
    assert "hash-pinned" in str(e.value)


def test_the_rewritten_lock_keeps_the_space_before_the_continuation(tmp_path):
    """`...hash\\` abuts the digest, so what pip reads as the hash is not the hash."""
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    text = (root / "deploy" / "requirements.lock").read_text()
    assert f"--hash=sha256:{_D[0]} \\\n" in text, text
    assert f"{_D[0]}\\" not in text.replace(f"{_D[0]} \\", ""), "backslash abuts the digest"
    assert text.count("--hash=sha256:") == len(_D)


def test_the_lock_still_parses_as_a_requirements_file(tmp_path):
    """Shape, not just substrings: the continuation-joined result is read."""
    import re
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    lock = (root / "deploy" / "requirements.lock")
    # Join continuations the way pip does, then check the requirement line.
    joined = re.sub(r"\\\n\s*", " ", lock.read_text())
    line = next(ln for ln in joined.splitlines() if ln.startswith("blastbox=="))
    assert line.split()[0] == "blastbox==0.1.30"
    assert line.count("--hash=sha256:") == len(_D)
    for d in _D:
        assert f"--hash=sha256:{d}" in line


def test_nothing_is_written_when_one_file_cannot_be_rewritten(tmp_path, monkeypatch):
    """A half-applied bump leaves the repo pinned to TWO versions.

    That is the drift this module reports, so producing it while claiming to
    fix it is the worst available outcome.
    """
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path)
    before = {p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")}

    real = pins_mod._rewrite_line
    calls = {"n": 0}

    def flaky(line, pin, version):
        calls["n"] += 1
        if calls["n"] > 2:
            raise pins_mod.PinScanError("simulated failure on a later file")
        return real(line, pin, version)

    monkeypatch.setattr(pins_mod, "_rewrite_line", flaky)
    with _pytest.raises(pins_mod.PinScanError):
        pins_mod.set_version(root, "0.1.30", digests=_D)
    for rel, text in before.items():
        assert (root / rel).read_text() == text, f"{rel} was written despite the failure"


def test_an_incomplete_rewrite_is_caught_by_rescanning(tmp_path, monkeypatch):
    """The scanner reports drift, so agreeing with it is the only real check."""
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path, lock=False)
    monkeypatch.setattr(pins_mod, "_rewrite_line", lambda line, pin, version: line)
    with _pytest.raises(pins_mod.PinScanError) as e:
        pins_mod.set_version(root, "0.1.30")
    assert "did not reach every pin" in str(e.value)


def test_setting_a_repo_with_no_pins_is_refused(tmp_path):
    """Rewriting nothing and reporting success is how a bump gets skipped."""
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    with _pytest.raises(PinScanError):
        set_version(tmp_path, "0.1.30", digests=_D)


def test_a_direct_reference_is_refused_rather_than_silently_left(tmp_path):
    """`blastbox @ git+...` has no floor, so the re-scan cannot notice it.

    Left in place it survives a "successful" bump while still pointing at the
    old revision -- the one pin whose staleness is completely invisible.
    """
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = _consumer(tmp_path, lock=False)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n'
        '  "blastbox @ git+https://example/blastbox@v0.1.27",\n]\n'
    )
    with _pytest.raises(PinScanError) as e:
        set_version(root, "0.1.30", digests=_D)
    assert "cannot be rewritten safely" in str(e.value)
    assert "git+" in str(e.value)


def test_a_version_that_violates_a_preserved_bound_is_refused(tmp_path):
    """Keeping `<0.2` while setting 0.2.0 writes a specifier nothing satisfies."""
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = _consumer(tmp_path, lock=False)
    with _pytest.raises(PinScanError) as e:
        set_version(root, "0.2.0", digests=_D)
    assert "does not satisfy" in str(e.value)
    # and nothing was written
    assert "0.1.27" in (root / "pyproject.toml").read_text()


def test_another_package_with_the_same_specifier_is_not_rewritten(tmp_path):
    """`line.find(specifier)` rewrites whoever comes first on the line."""
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path, lock=False)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\n'
        'dependencies = ["other>=0.1.27,<0.2", "blastbox>=0.1.27,<0.2"]\n'
    )
    set_version(root, "0.1.30", digests=_D)
    text = (root / "pyproject.toml").read_text()
    assert '"other>=0.1.27,<0.2"' in text, f"someone else's dependency moved: {text}"
    assert '"blastbox>=0.1.30,<0.2"' in text, text


def test_hashes_written_on_the_requirement_line_are_replaced(tmp_path):
    """`blastbox==X --hash=...` inline: the version moved, the hashes must too."""
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path, lock=False)
    (root / "deploy").mkdir(exist_ok=True)
    lock = root / "deploy" / "requirements.lock"
    lock.write_text("blastbox==0.1.27 --hash=sha256:" + "a" * 64 + "\n")
    set_version(root, "0.1.30", digests=_D)
    text = lock.read_text()
    assert "blastbox==0.1.30" in text
    assert "a" * 64 not in text, f"old digest survived beside the new version: {text}"
    assert f"--hash=sha256:{_D[0]}" in text


def test_a_quoted_dockerfile_arg_default_is_rewritten(tmp_path):
    from blastbox.host.pins import scan, set_version

    root = _consumer(tmp_path, lock=False)
    (root / "Dockerfile.worker").write_text(
        'ARG BLASTBOX_VERSION="0.1.27"\nFROM x\n'
        'RUN pip install "blastbox==${BLASTBOX_VERSION}"\n'
    )
    # Asserted, not skipped on. A conditional skip here would hide the very
    # regression this test exists for -- if the scanner stopped reporting a
    # quoted ARG, the pin would go unrewritten and nothing would say so.
    assert any(p.kind == "dockerfile-arg" for p in scan(root)), (
        "the scanner no longer reports a quoted ARG default; the rewrite below "
        "would silently cover nothing"
    )
    set_version(root, "0.1.30", digests=_D)
    assert 'ARG BLASTBOX_VERSION="0.1.30"' in (root / "Dockerfile.worker").read_text()


def test_a_tag_style_version_is_accepted_and_written_without_the_v(tmp_path):
    """Callers paste tags. `v0.1.30` must not end up inside the pins.

    Written verbatim it produced `>=v0.1.30` and then failed verification
    against the scanner, which strips the prefix -- a bump that damaged the
    repo and reported failure.
    """
    from blastbox.host.pins import disagreements, scan, set_version

    root = _consumer(tmp_path, lock=False)
    set_version(root, "v0.1.30", digests=_D)
    assert '"blastbox>=0.1.30,<0.2"' in (root / "pyproject.toml").read_text()
    assert sorted(disagreements(scan(root))) == ["0.1.30"]


def test_a_specifier_with_spaces_is_rewritten_not_refused(tmp_path):
    """`scan` strips whitespace; the FILE may contain it."""
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path, lock=False)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["blastbox >= 0.1.27, <0.2"]\n'
    )
    set_version(root, "0.1.30", digests=_D)
    assert "0.1.30" in (root / "pyproject.toml").read_text()
    assert "0.1.27" not in (root / "pyproject.toml").read_text()


def test_a_nonsense_version_is_refused(tmp_path):
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = _consumer(tmp_path, lock=False)
    with _pytest.raises(PinScanError):
        set_version(root, ">=0.1.30", digests=_D)


def test_a_requirement_on_a_continuation_line_is_rewritten(tmp_path):
    """Shell requirements are routinely written across backslashes.

    The scanner attributes the pin to the FIRST physical line, because that is
    where the logical line begins -- but the text is on a later one, so
    rewriting only that first line found nothing. Measured on two real repos:
    pdf-titan-arum and win-validator both refused a bump for this reason.
    """
    from blastbox.host.pins import disagreements, scan, set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile.ingress"
    df.write_text(
        "FROM x\n"
        "RUN pip install --no-cache-dir \\\n"
        '        "blastbox>=0.1.19" \\\n'
        '        "fastapi"\n'
    )
    set_version(root, "0.1.32")
    text = df.read_text()
    assert '"blastbox>=0.1.32" \\\n' in text, text
    assert '"fastapi"' in text, "the rest of the command must survive"
    assert text.count("\\\n") == 2, "the continuations must survive"
    assert sorted(disagreements(scan(root))) == ["0.1.32"]


def test_only_the_line_holding_the_requirement_is_touched(tmp_path):
    """Other lines of the same logical line keep their exact text."""
    from blastbox.host.pins import set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile.ingress"
    before = (
        "FROM x\n"
        "RUN pip install --no-cache-dir \\\n"
        '        "blastbox>=0.1.19" \\\n'
        '        "psycopg[binary,pool]" "redis"\n'
    )
    df.write_text(before)
    set_version(root, "0.1.32")
    after = df.read_text().splitlines()
    for n in (0, 1, 3):
        assert after[n] == before.splitlines()[n], f"line {n + 1} changed: {after[n]!r}"


def test_a_requirement_that_is_nowhere_in_its_logical_line_still_refuses(tmp_path):
    """The span search must not become a licence to rewrite the wrong line."""
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\nRUN pip install \\\n"
        '        "blastbox>=0.1.19" \\\n'
        '        "fastapi"\n'
    )
    # Make every line unmatchable, as a corrupted file would be.
    monkey = pins_mod._rewrite_line

    def never(line, pin, version):
        raise pins_mod.PinScanError("no match here")

    pins_mod._rewrite_line = never
    try:
        with _pytest.raises(pins_mod.PinScanError) as e:
            pins_mod.set_version(root, "0.1.32")
        assert "cannot locate" in str(e.value)
    finally:
        pins_mod._rewrite_line = monkey


def test_a_comment_ends_a_continuation_for_the_span_too(tmp_path):
    """`_logical_span` must join exactly what `_logical_lines` joined.

    A `#` ends that physical line even inside a continued RUN, so a span
    computed from the raw text would search lines the scanner never joined.
    """
    from blastbox.host.pins import _logical_span, _logical_lines

    text = (
        "RUN pip install \\\n"
        '        "blastbox>=0.1.19" \\\n'
        "# a comment, whose trailing backslash is prose \\\n"
        '        "fastapi"\n'
    )
    lines = text.splitlines(keepends=True)
    span = _logical_span(lines, 0)
    joined_start, _ = _logical_lines(text)[0]
    assert joined_start == 1
    # The comment line ends the join for the scanner, so the span must stop there.
    assert span.stop == 3, f"span {span} joined past the comment"


def test_a_dockerfile_arg_keeps_its_specific_diagnosis(tmp_path):
    """A one-line span has nothing to search; its own error is the useful one."""
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, scan

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path, lock=False)
    pins = [p for p in scan(root) if p.kind == "dockerfile-arg"]
    assert pins, "fixture assumption: the scanner reports the ARG"

    # A line whose ARG has no version to replace. The span is one line, so the
    # specific diagnosis is the only useful one -- "not found anywhere in its
    # logical line" would describe a search that never happened.
    with _pytest.raises(PinScanError) as e:
        pins_mod._rewrite_line("ARG BLASTBOX_VERSION=", pins[0], "0.1.32")
    assert "no version found after" in str(e.value)


def test_a_one_line_span_propagates_its_own_error_through_set_version(tmp_path):
    """The re-raise, exercised where it actually lives.

    Asserting on `_rewrite_line` directly leaves `set_version`'s handling
    untested: a mutant that always emits the generic "not found anywhere in its
    logical line" message survived until this test existed.
    """
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = tmp_path
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["blastbox>=0.1.19"]\n'
    )
    real = pins_mod._rewrite_line

    def specific(line, pin, version):
        raise pins_mod.PinScanError("SPECIFIC-DIAGNOSIS: no version found after `=`")

    pins_mod._rewrite_line = specific
    try:
        with _pytest.raises(pins_mod.PinScanError) as e:
            pins_mod.set_version(root, "0.1.32")
    finally:
        pins_mod._rewrite_line = real
    assert "SPECIFIC-DIAGNOSIS" in str(e.value), (
        f"a one-line span must keep its own diagnosis, got: {e.value}"
    )
    assert "anywhere in its logical line" not in str(e.value)


def test_a_package_whose_name_ends_in_blastbox_is_not_rewritten(tmp_path):
    """`blastbox` matches the SUFFIX of `not-blastbox` without a left boundary.

    Listed first in a continued install, the unrelated distribution was
    rewritten and the search stopped there, leaving the real pin stale -- a
    corrupted file AND a missed bump.
    """
    from blastbox.host.pins import set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile"
    df.write_text(
        "FROM x\nRUN pip install \\\n"
        '        "not-blastbox>=0.1.19" \\\n'
        '        "blastbox>=0.1.19"\n'
    )
    set_version(root, "0.1.32")
    text = df.read_text()
    assert '"not-blastbox>=0.1.19"' in text, f"an unrelated package was rewritten: {text}"
    assert '"blastbox>=0.1.32"' in text, text


def test_a_failed_verification_restores_every_file(tmp_path, monkeypatch):
    """The verification runs against the files on DISK, which are already written."""
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path, lock=False)
    before = {p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")}

    # Rewrite the pyproject but not the Dockerfile, so the re-scan sees drift.
    real = pins_mod._rewrite_line

    def partial(line, pin, version):
        if pin.kind == "dockerfile-arg":
            return line
        return real(line, pin, version)

    monkeypatch.setattr(pins_mod, "_rewrite_line", partial)
    with _pytest.raises(pins_mod.PinScanError) as e:
        pins_mod.set_version(root, "0.1.32", digests=_D)
    assert "did not reach every pin" in str(e.value)
    for rel, text in before.items():
        assert (root / rel).read_text() == text, f"{rel} was left modified"


def test_files_are_restored_when_the_verification_itself_raises(tmp_path, monkeypatch):
    """A rollback that only covers the "stale pin" branch is not a rollback.

    If the re-scan raises -- which a file this rewrite made unparseable would
    do -- returning without restoring leaves exactly the half-applied state the
    staging exists to prevent.
    """
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path, lock=False)
    before = {p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")}

    real_scan = pins_mod.scan
    calls = {"n": 0}

    def scan_then_explode(r):
        calls["n"] += 1
        if calls["n"] > 1:                    # the verification pass
            raise pins_mod.PinScanError("unparseable after rewrite")
        return real_scan(r)

    monkeypatch.setattr(pins_mod, "scan", scan_then_explode)
    with _pytest.raises(pins_mod.PinScanError):
        pins_mod.set_version(root, "0.1.32", digests=_D)
    for rel, text in before.items():
        assert (root / rel).read_text() == text, f"{rel} was left modified"
