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
