"""A pin is what gets INSTALLED. Prose about a version is not a pin."""

from __future__ import annotations

import textwrap

import pytest

from blastbox.host.pins import disagreements, scan


def _repo(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


PYPROJECT = """
    [project]
    name = "consumer"
    version = "0.1.0"
    dependencies = [
        "blastbox>=0.1.27,<0.2",
    ]
    [project.optional-dependencies]
    host = ["blastbox[host,s3]>=0.1.27,<0.2"]
"""


def test_finds_pins_across_every_install_path(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.worker": """
            FROM python:3.12
            ARG BLASTBOX_VERSION=0.1.27
            RUN pip install --no-cache-dir "blastbox==${BLASTBOX_VERSION}"
        """,
            "deploy/requirements.lock": """
            blastbox==0.1.27 \\
                --hash=sha256:abc
        """,
        },
    )
    kinds = sorted(p.kind for p in scan(root))
    assert kinds == ["dockerfile-arg", "lock", "pyproject", "pyproject"]
    assert {p.floor for p in scan(root)} == {"0.1.27"}


def test_a_commented_out_install_line_is_not_a_pin(tmp_path):
    """Kills the comment-stripping guard specifically.

    This comment contains `pip`, `install`, `blastbox` AND a specifier, so it
    survives every other filter -- only stripping the comment excludes it. That
    is the exact shape that made a naive grep report phantom pins.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.worker": """
            FROM python:3.12
            # was: pip install "blastbox==0.1.9" before the lock existed
            ARG BLASTBOX_VERSION=0.1.27
            RUN pip install "blastbox==${BLASTBOX_VERSION}"
        """,
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.line, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_a_specifier_outside_an_install_line_is_not_a_pin(tmp_path):
    """Kills the install-verb guard specifically.

    Uncommented, so comment-stripping cannot save it; it names blastbox with a
    specifier but installs nothing.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.host": """
            FROM python:3.12
            ENV BLASTBOX_NOTE=blastbox>=0.1.9
            LABEL requires="blastbox>=0.1.9"
        """,
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.line, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_lockfiles_under_docs_and_tests_are_ignored(tmp_path):
    """Kills the skip-directory guard specifically.

    A fixture lock inside tests/ is a fixture, not this repo's install path.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "tests/fixtures/requirements.lock": "blastbox==0.1.9 \\\n    --hash=sha256:abc\n",
            "docs/examples/requirements.lock": "blastbox==0.1.5 \\\n    --hash=sha256:def\n",
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}, [
        (p.path, p.raw) for p in scan(root) if p.floor != "0.1.27"
    ]


def test_drift_between_install_paths_is_reported(tmp_path):
    """The real shape: pyproject moved, the worker Dockerfile did not."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.worker": """
            FROM python:3.12
            ARG BLASTBOX_VERSION=0.1.17
            RUN pip install "blastbox==${BLASTBOX_VERSION}"
        """,
        },
    )
    groups = disagreements(scan(root))
    assert sorted(groups) == ["0.1.17", "0.1.27"]


def test_a_mention_without_an_install_is_not_a_pin(tmp_path):
    """COPY/ENV naming blastbox must not count; only an install line does."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.host": """
            FROM python:3.12
            ENV BLASTBOX_BLOB_URL=s3://blastbox/x
            COPY blastbox-0.1.9-py3-none-any.whl /tmp/
        """,
        },
    )
    assert [p.kind for p in scan(root)] == ["pyproject", "pyproject"]


def test_extras_do_not_truncate_line_attribution(tmp_path):
    """`req.split(",")[0]` truncated `blastbox[host,s3]` to `blastbox[host`."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]
            [project.optional-dependencies]
            a = ["blastbox[host,s3]>=0.1.27,<0.2"]
            b = ["blastbox[host,s3]>=0.1.27,<0.2"]
        """
        },
    )
    lines = sorted(p.line for p in scan(root))
    assert lines == [5, 7, 8], lines  # distinct, real lines
    assert all(p.line != 0 for p in scan(root))


def test_environment_markers_do_not_leak_into_the_version(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27; python_version >= '3.12'"]
        """
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_compatible_release_pins_count_as_drift(tmp_path):
    """`~=` was matched but yielded no floor, so it vanished from drift groups."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox~=0.1.17"]
        """,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "blastbox==0.1.27"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_a_wrapped_run_install_is_one_logical_line(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install --no-cache-dir \\
                  "blastbox[host]>=0.1.17,<0.2" \\
             && echo done
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_an_unused_ARG_is_not_a_pin(tmp_path):
    """Documented contract: the ARG is a pin only if an install consumes it."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            ARG BLASTBOX_VERSION=0.1.9
            RUN echo "$BLASTBOX_VERSION" > /etc/note
        """,
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_lock_pins_with_extras_are_found(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/requirements.lock": "blastbox[host]==0.1.17 \\\n    --hash=sha256:abc\n",
        },
    )
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
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN echo "to install run: blastbox>=0.1.9" > /etc/readme
        """,
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind.startswith("dockerfile")]


def test_a_bare_name_does_not_attribute_to_the_description(tmp_path):
    """Real shape: pdf-titan-arum's description contains the word "blastbox".

    A bare-name needle matched the description line and reported pyproject:8
    instead of the dependency at :12.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "titanarum"
            version = "0.1.0"
            description = "PDF forensic engine for blastbox"
            dependencies = ["blastbox>=0.1.27,<0.2"]
        """
        },
    )
    pins = scan(root)
    assert [p.line for p in pins] == [6], [(p.line, p.raw) for p in pins]


def test_an_upper_bound_is_not_a_floor(tmp_path):
    """`blastbox<=0.2,>=0.1.27` guarantees 0.1.27, not 0.2.

    Specifier order is not meaningful, so a leading upper bound must not be
    read as the version.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox<=0.2,>=0.1.27"]
        """
        },
    )
    assert [p.floor for p in scan(root)] == ["0.1.27"]


def test_only_an_upper_bound_yields_no_floor(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox<0.2"]
        """
        },
    )
    assert [p.floor for p in scan(root)] == [None]
    assert disagreements(scan(root)) == {}


def test_distribution_name_is_case_insensitive(tmp_path):
    """PEP 508 names are case-insensitive; `Blastbox` is the same project."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["Blastbox>=0.1.27,<0.2"]
        """,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "BlastBox==0.1.17"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_equal_releases_spelled_differently_are_one_group(tmp_path):
    """0.1.27 and 0.1.27.0 are the same release -- grouping raw text invents drift."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]
        """,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "blastbox==0.1.27.0"
        """,
        },
    )
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
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "not-blastbox==0.1.1" "myblastbox==0.1.2"
        """,
        },
    )
    assert {p.floor for p in scan(root)} == {"0.1.27"}
    assert not [p for p in scan(root) if p.kind == "dockerfile-pip"]


def test_the_strongest_lower_bound_wins(tmp_path):
    """A set may carry several lower bounds; the first written is arbitrary."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.5,>=0.1.27,<0.2"]
        """
        },
    )
    assert [p.floor for p in scan(root)] == ["0.1.27"]


def test_pip_global_options_before_install(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN python -m pip --isolated --no-cache-dir install "blastbox==0.1.17"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_every_install_on_one_logical_run_is_reported(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "blastbox==0.1.17" \\
             && pip install "blastbox[host]==0.1.20"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.20", "0.1.27"]


def test_suffix_convention_dockerfiles_are_scanned(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/worker.Dockerfile": """
            FROM p
            RUN pip install "blastbox==0.1.17"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_indented_lock_entries_are_found(tmp_path):
    """Leading whitespace is legal in a requirements-format file.

    NOTE the leading `#` line: _repo() runs textwrap.dedent, which would strip
    the very indentation under test if every line were indented.
    """
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/requirements.lock": "# lock\n    blastbox==0.1.17 \\\n        --hash=sha256:abc\n",
        },
    )
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
    (blocked / "Dockerfile.w").write_text(
        'RUN pip install "blastbox==0.1.1"\n', encoding="utf-8"
    )
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
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox @ git+https://example.invalid/blastbox@v0.1.30"]
        """,
        },
    )
    pins = scan(root)
    assert len(pins) == 1, pins
    assert "git+https" in pins[0].specifier
    assert pins[0].floor is None  # a URL is not a version; never fake one


def test_pep735_dependency_groups_are_scanned(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": """
            [project]
            name = "c"
            version = "0.1.0"
            dependencies = ["blastbox>=0.1.27,<0.2"]

            [dependency-groups]
            dev = ["blastbox>=0.1.5"]
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.27", "0.1.5"]


def test_a_toml_lock_is_parsed_as_toml_not_as_requirements(tmp_path):
    """uv.lock/poetry.lock were selected then handed to a requirements regex
    that can never match TOML: read, zero pins, reported clean."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "uv.lock": """
            [[package]]
            name = "blastbox"
            version = "0.1.17"
        """,
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.17", "0.1.27"]


def test_constraints_and_requirements_dir_are_install_paths(tmp_path):
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "constraints.txt": "blastbox==0.1.9\n",
            "requirements/base.txt": "blastbox==0.1.11\n",
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.11", "0.1.27", "0.1.9"]


def test_constraint_files_with_range_specifiers_are_parsed(tmp_path):
    """A hashed lock pins with ==, but constraints/requirements files carry any
    specifier; matching only == skipped them silently."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "constraints.txt": "blastbox>=0.1.9,<0.2\n",
        },
    )
    assert sorted(disagreements(scan(root))) == ["0.1.27", "0.1.9"]


def test_a_direct_reference_on_a_dockerfile_install_line_is_a_pin(tmp_path):
    """A Dockerfile can install a direct reference just as a pyproject can."""
    root = _repo(
        tmp_path,
        {
            "pyproject.toml": PYPROJECT,
            "deploy/docker/Dockerfile.w": """
            FROM p
            RUN pip install "blastbox @ git+https://example.invalid/b@v0.1.30"
        """,
        },
    )
    refs = [p for p in scan(root) if p.specifier.startswith("@")]
    assert len(refs) == 1, [
        (p.file if hasattr(p, "file") else p.path, p.specifier) for p in scan(root)
    ]


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
    assert f"{_D[0]}\\" not in text.replace(f"{_D[0]} \\", ""), (
        "backslash abuts the digest"
    )
    assert text.count("--hash=sha256:") == len(_D)


def test_the_lock_still_parses_as_a_requirements_file(tmp_path):
    """Shape, not just substrings: the continuation-joined result is read."""
    import re
    from blastbox.host.pins import set_version

    root = _consumer(tmp_path)
    set_version(root, "0.1.30", digests=_D)
    lock = root / "deploy" / "requirements.lock"
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
    before = {
        p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")
    }

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
        assert (root / rel).read_text() == text, (
            f"{rel} was written despite the failure"
        )


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
        'FROM x\nRUN pip install \\\n        "blastbox>=0.1.19" \\\n        "fastapi"\n'
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
    assert '"not-blastbox>=0.1.19"' in text, (
        f"an unrelated package was rewritten: {text}"
    )
    assert '"blastbox>=0.1.32"' in text, text


def test_a_failed_verification_restores_every_file(tmp_path, monkeypatch):
    """The verification runs against the files on DISK, which are already written."""
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = _consumer(tmp_path, lock=False)
    before = {
        p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")
    }

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
    before = {
        p: (root / p).read_text() for p in ("pyproject.toml", "Dockerfile.worker")
    }

    real_scan = pins_mod.scan
    calls = {"n": 0}

    def scan_then_explode(r):
        calls["n"] += 1
        if calls["n"] > 1:  # the verification pass
            raise pins_mod.PinScanError("unparseable after rewrite")
        return real_scan(r)

    monkeypatch.setattr(pins_mod, "scan", scan_then_explode)
    with _pytest.raises(pins_mod.PinScanError):
        pins_mod.set_version(root, "0.1.32", digests=_D)
    for rel, text in before.items():
        assert (root / rel).read_text() == text, f"{rel} was left modified"


def test_a_requirement_split_mid_token_is_refused_not_mangled(tmp_path):
    """`"blastbox>=\\` / `0.1.19"` -- the continuation falls INSIDE the token.

    No physical line holds the whole requirement, so the rewriter cannot place
    it. Refusing is the correct outcome and the file must be untouched: joining
    the write across lines to support a form nobody writes would risk
    corrupting the ones everybody does. Pinned as a test so this stays a
    refusal rather than drifting into a partial rewrite later.
    """
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile"
    df.write_text('FROM x\nRUN pip install "blastbox>=\\\n0.1.19"\n')
    before = df.read_text()
    with _pytest.raises(PinScanError) as e:
        set_version(root, "0.1.32")
    assert "cannot locate" in str(e.value)
    assert df.read_text() == before, "a refused bump must leave the file alone"


def test_two_pins_sharing_a_specifier_on_one_logical_line(tmp_path):
    """`==0.1` must not match inside the `==0.1.2` it was just rewritten to.

    Without a trailing boundary the second pin's search re-matched the FIRST,
    already-rewritten occurrence and extended it to `0.1.2.2`, so a legitimate
    bump failed on a version that merely extends the old one.
    """
    from blastbox.host.pins import disagreements, scan, set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile"
    df.write_text(
        "FROM x\nRUN pip install \\\n"
        '        "blastbox==0.1" \\\n'
        '        "blastbox[host]==0.1"\n'
    )
    set_version(root, "0.1.2")
    text = df.read_text()
    assert '"blastbox==0.1.2"' in text, text
    assert '"blastbox[host]==0.1.2"' in text, text
    assert "0.1.2.2" not in text, f"a rewritten occurrence was rewritten again: {text}"
    assert sorted(disagreements(scan(root))) == ["0.1.2"]


def test_a_blastbox_token_outside_the_install_is_refused_not_corrupted(tmp_path):
    """A diagnostic string sharing the requirement's text.

    The rewriter has no model of which words are install ARGUMENTS -- that
    parsing lives in the scanner, and duplicating it here is the divergence
    that caused the comment-stripping bug. So the guarantee is the safe one:
    the bump fails and every file is restored, rather than the echo text being
    quietly rewritten and the real dependency left stale.
    """
    import pytest as _pytest

    from blastbox.host.pins import PinScanError, set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile"
    df.write_text(
        "FROM x\n"
        'RUN echo "blastbox==0.1.19" \\\n'
        '        && pip install "blastbox==0.1.19"\n'
    )
    before = df.read_text()
    with _pytest.raises(PinScanError):
        set_version(root, "0.1.32")
    assert df.read_text() == before, "a failed bump must leave the file untouched"


def test_a_token_after_the_install_command_is_not_a_pin(tmp_path):
    """Mirror of the echo-before case: the stray token comes AFTER the install.

    Trimming the front does not help there; each `&&` segment is considered on
    its own so only the install's own arguments count.
    """
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\n"
        'RUN pip install "blastbox==0.1.30" \\\n'
        '        && echo "blastbox==0.1.19"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the echoed version was read as a pin: {floors}"


def test_a_crlf_file_keeps_its_line_endings(tmp_path):
    """`read_text` translates CRLF to LF, so both the write AND the rollback
    would silently rewrite every line of a file they were meant to leave alone."""
    from blastbox.host.pins import set_version

    root = tmp_path
    (root / "pyproject.toml").write_bytes(
        b'[project]\r\nname = "x"\r\ndependencies = ["blastbox>=0.1.27,<0.2"]\r\n'
    )
    set_version(root, "0.1.30", digests=_D)
    data = (root / "pyproject.toml").read_bytes()
    assert b"0.1.30" in data
    assert data.count(b"\r\n") == 3, f"line endings were rewritten: {data!r}"
    assert b"\n" not in data.replace(b"\r\n", b""), "a bare LF was introduced"


def test_a_local_version_does_not_rematch_the_pin_it_just_wrote(tmp_path):
    """`==1.0` must not match inside `==1.0+cpu`."""
    from blastbox.host.pins import set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    df = root / "Dockerfile"
    df.write_text(
        "FROM x\nRUN pip install \\\n"
        '        "blastbox==1.0" \\\n'
        '        "blastbox[host]==1.0"\n'
    )
    set_version(root, "1.0+cpu", digests=_D)
    text = df.read_text()
    assert '"blastbox==1.0+cpu"' in text, text
    assert '"blastbox[host]==1.0+cpu"' in text, text
    assert "+cpu+cpu" not in text and "1.0+cpu.0" not in text, text


def test_a_rollback_restores_crlf_files_byte_for_byte(tmp_path, monkeypatch):
    """Snapshotting with `read_text` would restore LF endings.

    That is a "rollback" which rewrites every line of the file it was meant to
    leave alone -- so the snapshot is taken as bytes.
    """
    import pytest as _pytest

    from blastbox.host import pins as pins_mod

    root = tmp_path
    pyproject = root / "pyproject.toml"
    original = (
        b'[project]\r\nname = "x"\r\ndependencies = ["blastbox>=0.1.27,<0.2"]\r\n'
    )
    pyproject.write_bytes(original)
    (root / "Dockerfile.w").write_bytes(
        b"ARG BLASTBOX_VERSION=0.1.27\r\nFROM x\r\n"
        b'RUN pip install "blastbox==${BLASTBOX_VERSION}"\r\n'
    )
    df_original = (root / "Dockerfile.w").read_bytes()

    # Rewrite the pyproject but not the Dockerfile, so verification sees drift.
    real = pins_mod._rewrite_line

    def partial(line, pin, version):
        if pin.kind == "dockerfile-arg":
            return line
        return real(line, pin, version)

    monkeypatch.setattr(pins_mod, "_rewrite_line", partial)
    with _pytest.raises(pins_mod.PinScanError):
        pins_mod.set_version(root, "0.1.30", digests=_D)
    assert pyproject.read_bytes() == original, "CRLF was not restored byte-for-byte"
    assert (root / "Dockerfile.w").read_bytes() == df_original


def test_a_separator_inside_a_quoted_option_does_not_split_the_command(tmp_path):
    """`--index-url "https://a|b"` must not cut the requirement off the scan.

    A regex split loses the pin entirely, and a pin that is never seen is the
    silent under-report this module exists to prevent.
    """
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install --index-url "https://mirror/a|b" "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_an_unquoted_separator_still_splits(tmp_path):
    """The quote awareness must not disable the splitting it wraps."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install "blastbox==0.1.30" && echo "blastbox==0.1.19"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the echoed version leaked in: {floors}"


def test_a_pipeline_inside_a_command_substitution_does_not_split(tmp_path):
    """`$(cmd | grep x)` is one argument, not two commands."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\n"
        'RUN pip install --extra-index-url $(cat /u | head -1) "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_backtick_substitution_does_not_split_either(tmp_path):
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\n"
        'RUN pip install --extra-index-url `cat /u | head -1` "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_top_level_semicolon_ends_the_install_command(tmp_path):
    """`pip install X ; echo Y` is two commands, and only the first installs."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install "blastbox==0.1.30" ; echo "blastbox==0.1.19"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the echoed version leaked in: {floors}"


def test_a_quoted_pep508_marker_is_not_split(tmp_path):
    """A marker that survives the shell is quoted, and quoting is respected."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\nRUN pip install \"blastbox>=0.1.30; python_version >= '3.12'\"\n"
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the marker broke the requirement: {floors}"


def test_a_background_ampersand_ends_the_command(tmp_path):
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install "blastbox==0.1.30" & echo "blastbox==0.1.19"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the backgrounded command leaked in: {floors}"


def test_a_redirection_ampersand_is_not_a_separator(tmp_path):
    """`2>&1` is a redirection, not a background command."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install -q 2>&1 "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_parameter_expansion_does_not_split(tmp_path):
    """`${VAR//a|b/}` holds a pipe that belongs to the expansion."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install --extra-index-url ${U//a|b/} "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_crlf_lock_keeps_crlf_in_the_regenerated_hash_block(tmp_path):
    """The hash block is rebuilt, so it does not inherit endings like a rewrite.

    Emitting "\\n" into a CRLF lock leaves the file with mixed endings.
    """
    from blastbox.host.pins import set_version

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "deploy").mkdir()
    lock = root / "deploy" / "requirements.lock"
    lock.write_bytes(
        b"blastbox==0.1.27 \\\r\n"
        b"    --hash=sha256:" + b"a" * 64 + b" \\\r\n"
        b"    --hash=sha256:" + b"b" * 64 + b"\r\n"
    )
    set_version(root, "0.1.30", digests=_D)
    data = lock.read_bytes()
    assert b"0.1.30" in data
    assert b"\n" not in data.replace(b"\r\n", b""), (
        f"a bare LF was introduced: {data!r}"
    )


def test_a_bash_combined_redirection_is_not_a_separator(tmp_path):
    """`&>file` starts with the ampersand, so the `2>&1` guard does not see it."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        'FROM x\nRUN pip install &>/tmp/log "blastbox==0.1.30"\n'
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_process_substitution_does_not_split(tmp_path):
    """`<(cmd | x)` opens a nested command, like `$( … )`."""
    from blastbox.host.pins import scan

    root = tmp_path
    (root / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (root / "Dockerfile").write_text(
        "FROM x\nRUN pip install -r <(cat a | tr -d ' ') \"blastbox==0.1.30\"\n"
    )
    floors = sorted({p.floor for p in scan(root) if p.floor})
    assert floors == ["0.1.30"], f"the requirement was lost: {floors}"


def test_a_hash_pinned_lock_missing_a_new_dependency_is_reported(tmp_path):
    """`pip install --require-hashes` refuses the WHOLE file over one gap.

    Measured with pip 26:

        ERROR: In --require-hashes mode, all requirements must have their
        versions pinned with ==. These do not: pydantic>=2.6.0 (from blastbox)

    So a release that gains a dependency turns every consumer's hash-pinned
    lock into one that cannot install, and rewriting only the blastbox line
    makes the bump look successful until the image build fails.
    """
    from blastbox.host.pins import missing_from_locks

    lock = tmp_path / "deploy" / "requirements.lock"
    lock.parent.mkdir()
    lock.write_text(
        "blastbox==0.1.38 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        "pydantic==2.13.5 \\\n    --hash=sha256:" + "b" * 64 + "\n"
    )
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"])
    assert list(gaps) == [str(lock)], gaps
    assert gaps[str(lock)] == ["packaging"], gaps


def test_a_lock_that_carries_everything_is_not_reported(tmp_path):
    """The check must not fire on a lock that is actually complete."""
    from blastbox.host.pins import missing_from_locks

    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "blastbox==0.1.39 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        "pydantic==2.13.5 \\\n    --hash=sha256:" + "b" * 64 + "\n"
        "packaging==25.0 \\\n    --hash=sha256:" + "c" * 64 + "\n"
    )
    assert missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"]) == {}


def test_a_lock_without_hashes_is_left_alone(tmp_path):
    """Only `--require-hashes` makes an incomplete closure fatal.

    A plain requirements file lets pip resolve the rest itself, so reporting it
    would be noise -- and noise is how a check stops being read.
    """
    from blastbox.host.pins import missing_from_locks

    plain = tmp_path / "requirements.txt"
    plain.write_text("blastbox==0.1.39\npydantic==2.13.5\n")
    assert missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"]) == {}


def test_distribution_names_compare_normalised(tmp_path):
    """A lock may spell `ruamel.yaml` as `ruamel-yaml`; they are one package."""
    from blastbox.host.pins import missing_from_locks

    lock = tmp_path / "requirements.lock"
    lock.write_text("Ruamel-YAML==0.18.6 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert missing_from_locks(tmp_path, ["ruamel.yaml>=0.18"]) == {}


_R = [
    "pydantic>=2.6.0",
    "packaging>=23.0",
    'fastapi>=0.115.0; extra == "host"',
    'uvicorn>=0.27; extra == "host"',
    'structlog>=24.1; extra == "host"',
    'boto3>=1.34; extra == "s3"',
    'pytest>=8; extra == "dev"',
    'ruff>=0.6; extra == "dev"',
    'mypy>=1.11; extra == "dev"',
    # dev pulls the host extra in, so `blastbox` is one of its requirements --
    # and every lock pins blastbox.
    'blastbox[host]; extra == "dev"',
    # Shared with the runtime closure: starlette brings httpx in too.
    'httpx>=0.27; extra == "dev"',
    # An extra whose only other dependency is absent from a runtime lock.
    'blastbox[host]; extra == "docs"',
    'sphinx>=7; extra == "docs"',
    'colorama>=0.4; sys_platform == "win32"',
]


def _lock(path, *entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{e} \\\n    --hash=sha256:{'a' * 64}\n" for e in entries))
    return path


def test_a_hashed_lock_that_does_not_pin_blastbox_is_not_ours_to_judge(tmp_path):
    """A repo may hold an unrelated hashed lock -- tooling, docs.

    Reporting it as missing every blastbox dependency would refuse a bump that
    is perfectly fine.
    """
    from blastbox.host.pins import missing_from_locks

    _lock(tmp_path / "tooling.lock", "ruff==0.6.9")
    assert missing_from_locks(tmp_path, _R) == {}


def test_an_extra_the_lock_was_compiled_for_is_checked(tmp_path):
    """uv records resolved names only, so the entry cannot say which extras.

    A lock carrying fastapi and uvicorn was compiled for the host extra whether
    or not it says so -- and a dependency added to that extra must be reported.
    """
    from blastbox.host.pins import missing_from_locks

    lock = _lock(
        tmp_path / "req.lock",
        "blastbox==0.1.39",
        "pydantic==2.13.5",
        "packaging==26.3",
        "fastapi==0.115.0",
        "uvicorn==0.30.0",
    )
    gaps = missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"})
    # A RUNTIME hole, not an install failure: the lock line is a plain
    # `blastbox==`, which pip does not bind to the host extra.
    assert gaps == {str(lock): ["structlog" + _RUNTIME]}, gaps


def test_an_extra_the_lock_never_asked_for_is_not_reported(tmp_path):
    """`boto3` missing from a repo that never wanted s3 is not a gap.

    Nor are pytest and ruff: `dev` depends on `blastbox[host]`, so the lock's
    own blastbox entry once inferred the whole dev extra and reported a
    runtime lock as missing a test framework.
    """
    from blastbox.host.pins import missing_from_locks

    _lock(
        tmp_path / "req.lock",
        "blastbox==0.1.39",
        "pydantic==2.13.5",
        "packaging==26.3",
    )
    assert missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"}) == {}


def test_a_marker_that_does_not_apply_is_not_a_gap(tmp_path):
    """A Linux lock correctly omits a win32-only dependency."""
    from blastbox.host.pins import missing_from_locks

    _lock(
        tmp_path / "req.lock", "blastbox==0.1.39", "pydantic==2.13.5", "packaging==26.3"
    )
    assert missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"}) == {}
    gaps = missing_from_locks(tmp_path, _R, environment={"sys_platform": "win32"})
    assert list(gaps.values()) == [["colorama"]], gaps


def test_a_pinned_version_must_also_satisfy_the_requirement(tmp_path):
    """Presence is not enough: pip cannot resolve `packaging==22` for `>=23`."""
    from blastbox.host.pins import missing_from_locks

    lock = _lock(
        tmp_path / "req.lock", "blastbox==0.1.39", "pydantic==2.13.5", "packaging==22.0"
    )
    gaps = missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"})
    assert gaps == {str(lock): ["packaging (pinned 22.0, needs >=23.0)"]}, gaps


def test_a_split_lock_is_complete_across_its_includes(tmp_path):
    """pip installs `-r base.lock` as ONE requirement set.

    Checking each physical file alone reports pins that are correctly hashed in
    the file next door, so a valid split lock could never be bumped.
    """
    from blastbox.host.pins import missing_from_locks

    _lock(tmp_path / "base.lock", "pydantic==2.13.5", "packaging==26.3")
    top = tmp_path / "req.lock"
    top.write_text(f"-r base.lock\nblastbox==0.1.39 \\\n    --hash=sha256:{'a' * 64}\n")
    assert missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"}) == {}


def test_a_single_shared_dependency_does_not_infer_a_whole_extra(tmp_path):
    """Measured on RedTusk's real lock, which is why this is a majority.

    `httpx` is in a runtime closure for its own reasons, and the `dev` extra
    happens to want it too. Inferring dev from that reported pytest, mypy and
    ruff missing from a RUNTIME lock -- noise that teaches people to ignore the
    check.
    """
    from blastbox.host.pins import missing_from_locks

    _lock(
        tmp_path / "req.lock",
        "blastbox==0.1.39",
        "pydantic==2.13.5",
        "packaging==26.3",
        "httpx==0.27.2",
    )
    assert missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"}) == {}


def test_an_extras_own_blastbox_requirement_does_not_infer_it(tmp_path):
    """`dev` depends on `blastbox[host]`, and every lock pins blastbox.

    Counting that as evidence the extra was requested infers it from the lock's
    own entry -- which is what happened on the real lock, reporting a runtime
    lock as missing sphinx and a test framework.
    """
    from blastbox.host.pins import missing_from_locks

    _lock(
        tmp_path / "req.lock",
        "blastbox==0.1.39",
        "pydantic==2.13.5",
        "packaging==26.3",
    )
    assert missing_from_locks(tmp_path, _R, environment={"sys_platform": "linux"}) == {}


_H = "--hash=sha256:" + "a" * 64
# Appended when a gap is reachable only through an extra the LOCK LINE does
# not spell: pip installs such a file happily and the image is short a
# package it imports. Measured against real pip; see the module docstring.
_RUNTIME = " [not an install failure: the image would import it]"
_RM = [
    "pydantic>=2.6.0",
    "packaging>=23.0",
    'fastapi>=1; extra == "host"',
    'uvicorn>=1; extra == "host"',
    'boto3>=1; extra == "s3"',
    'sphinx>=7; extra == "s3"',
    'backport>=1; python_version < "3.13"',
]


def _write(d, name, body):
    (d / name).write_text(body)
    return d / name


def _entry(spec, hashed=True):
    return f"{spec} \\\n    {_H}\n" if hashed else f"{spec}\n"


def test_sibling_includes_are_one_install_set(tmp_path):
    """`pip install -r all.txt` where all.txt names two locks installs BOTH.

    Judging blastbox.lock alone reports everything its sibling carries -- and
    the aggregator itself is skipped for having no hashes of its own, so the
    valid split lock could never be bumped.
    """
    from blastbox.host.pins import missing_from_locks

    _write(tmp_path, "blastbox.lock", _entry("blastbox==0.1.39"))
    _write(
        tmp_path,
        "deps.lock",
        _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    _write(tmp_path, "all.txt", "-r blastbox.lock\n-r deps.lock\n")
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert gaps == {}, gaps

    # NOT vacuous: {} is also what "nothing was judged" looks like, which is
    # exactly what an earlier version of this fix produced -- the aggregator was
    # excluded from the candidates while its children were marked included, so
    # there were no roots at all and every closure passed. Break the set and the
    # same call must report it.
    _write(tmp_path, "deps.lock", _entry("pydantic==2.13.5"))
    broken = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(broken.values()) == [["packaging", "backport"]], broken


def test_an_included_pin_without_a_hash_does_not_satisfy_anything(tmp_path):
    """`--require-hashes` needs a hash for EVERY requirement.

    An unhashed `packaging==25.0` in an included file is pinned and present and
    still fails the install it appears to satisfy.
    """
    from blastbox.host.pins import missing_from_locks

    _write(tmp_path, "req.lock", _entry("blastbox==0.1.39") + "-r deps.txt\n")
    _write(tmp_path, "deps.txt", "pydantic==2.13.5\npackaging==25.0\nbackport==1.0\n")
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps.values()) == [
        [
            "pydantic (pinned but not hashed)",
            "packaging (pinned but not hashed)",
            "backport (pinned but not hashed)",
        ]
    ], gaps


def test_a_distribution_pinned_twice_under_exclusive_markers(tmp_path):
    """A portable lock legitimately pins one distribution twice.

    Discarding the markers let the last physical entry overwrite the earlier
    one, so a valid 3.12 lock was rejected -- or an invalid one accepted, if
    the lines happened to be the other way round.
    """
    from blastbox.host.pins import missing_from_locks

    base = (
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
    )
    lock = (
        base
        + _entry('backport==1.0 ; python_version < "3.13"')
        + _entry('backport==0.5 ; python_version >= "3.13"')
    )
    _write(tmp_path, "req.lock", lock)
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )
    # The 3.13 entry is the one that does not satisfy `backport>=1`; under that
    # environment the requirement no longer applies at all, so still no gap.
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.13"}) == {}
    )


def test_the_marker_appropriate_pin_is_the_one_checked(tmp_path):
    """Selecting by marker has to actually select, not merely not-crash."""
    from blastbox.host.pins import missing_from_locks

    base = (
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
    )
    lock = (
        base
        + _entry('backport==0.5 ; python_version < "3.13"')
        + _entry('backport==9.0 ; python_version >= "3.13"')
    )
    _write(tmp_path, "req.lock", lock)
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps.values()) == [["backport (pinned 0.5, needs >=1)"]], gaps


def test_half_the_dependencies_of_an_extra_is_not_a_majority(tmp_path):
    """`s3` has two unique dependencies and the lock pins one for its own reasons.

    Equality is half, not a majority -- and inferring the extra from a single
    shared package is the false positive the threshold exists to avoid.
    """
    from blastbox.host.pins import missing_from_locks

    lock = (
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("boto3==1.34")
        + _entry("backport==1.0")
    )
    _write(tmp_path, "req.lock", lock)
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_the_lock_states_the_environment_its_markers_are_for(tmp_path):
    """A lock compiled for 3.12 must not be judged by whatever runs `pins`.

    uv records its command line in the header, so the lock says which
    interpreter it targets. Evaluating against the running one skipped a
    dependency guarded by `python_version < "3.13"` whenever the CLI happened
    to be newer.
    """
    from blastbox.host.pins import missing_from_locks

    header = (
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes "
        "--python-version 3.12 -o req.lock\n"
    )
    _write(
        tmp_path,
        "req.lock",
        header
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    # No environment passed: the lock's own header has to supply it.
    gaps = missing_from_locks(tmp_path, _RM)
    assert list(gaps.values()) == [["backport"]], gaps

    # And the other direction, so the running interpreter cannot mask this: a
    # lock compiled for 3.14 does not need a dependency guarded by < 3.13.
    # Whichever version happens to run these tests, one of the two assertions
    # disagrees with it.
    newer = header.replace("--python-version 3.12", "--python-version 3.14")
    _write(
        tmp_path,
        "req.lock",
        newer
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    assert missing_from_locks(tmp_path, _RM) == {}


_RN = [
    "pydantic>=2.6.0",
    'fastapi>=0.100; extra == "host"',
    'uvicorn>=0.20; extra == "host"',
    'structlog>=24; extra == "host"',
    'pywin32>=306; extra == "host" and sys_platform == "win32"',
    'blastbox[host]; extra == "dev"',
    'pytest>=8; extra == "dev"',
]


def test_an_extras_platform_only_members_do_not_dilute_the_evidence(tmp_path):
    """`pywin32` is a host dependency that a Linux lock correctly lacks.

    Counting it against a Linux lock pushed `host` under the threshold, so the
    extra was not recognised -- and the genuinely missing `structlog` pin was
    then accepted. The evidence set has to be the requirements that APPLY.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("fastapi==0.115.0")
        + _entry("uvicorn==0.30.0"),
    )
    # Two of THREE applicable host dependencies is a majority; two of four,
    # counting the Windows-only one, is not.
    gaps = missing_from_locks(tmp_path, _RN, environment={"sys_platform": "linux"})
    assert list(gaps.values()) == [["structlog" + _RUNTIME]], gaps


def test_an_extra_that_enables_another_pulls_its_closure_in(tmp_path):
    """`blastbox[host]; extra == "dev"` means a dev lock installs host too.

    pip enables it transitively and then demands hashes for all of it, so
    recording only the distribution name -- discarding `[host]` -- left those
    dependencies unchecked while the lock looked complete.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox[dev]==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("pytest==8.3.3"),
    )
    gaps = missing_from_locks(tmp_path, _RN, environment={"sys_platform": "linux"})
    assert list(gaps.values()) == [
        [n + _RUNTIME for n in ("fastapi", "uvicorn", "structlog")]
    ], gaps


def test_a_lock_that_asks_for_no_extras_is_still_left_alone(tmp_path):
    """Neither fix may turn the base case into noise."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "req.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    assert (
        missing_from_locks(tmp_path, _RN, environment={"sys_platform": "linux"}) == {}
    )


def test_a_lock_installed_directly_is_still_judged_on_its_own(tmp_path):
    """Inclusion does not prove a file is never an entrypoint.

    A Dockerfile installs prod.lock directly while dev.lock includes it. If
    prod.lock is dropped from the roots, only the complete dev closure is
    checked and a bump is accepted that leaves the production install failing
    under `--require-hashes`.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r prod.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "prod.lock")], gaps
    assert list(gaps.values()) == [["packaging", "backport"]], gaps


def test_a_lock_only_ever_included_is_not_judged_alone(tmp_path):
    """The other half: with no direct install, the set is what counts."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_marker_specific_blastbox_entries_do_not_pool_their_extras(tmp_path):
    """A portable lock can pin blastbox twice under exclusive markers.

    Unioning both extras checks a closure pip would never install on either
    interpreter, and refuses a lock that is correct for both.
    """
    from blastbox.host.pins import missing_from_locks

    lock = (
        _entry('blastbox[host]==0.1.39 ; python_version < "3.13"')
        + _entry('blastbox[s3]==0.1.39 ; python_version >= "3.13"')
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("fastapi==1.2.0")
        + _entry("uvicorn==1.1.0")
        + _entry("backport==1.0")
    )
    _write(tmp_path, "req.lock", lock)
    # On 3.12 only the host entry applies, so s3's boto3 is not demanded.
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert gaps == {}, gaps
    # And the lock IS being judged: drop a host dependency and it says so.
    _write(tmp_path, "req.lock", lock.replace(_entry("uvicorn==1.1.0"), ""))
    broken = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(broken.values()) == [["uvicorn"]], broken


def test_one_extras_dependencies_do_not_infer_another(tmp_path):
    """`dev` requiring everything `host` does, plus pytest, is common.

    Counting the shared names as evidence for dev means a host-only lock
    satisfies dev's majority and gets refused for missing pytest.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = [
        "pydantic>=2.6.0",
        'a-lib>=1; extra == "host"',
        'b-lib>=1; extra == "host"',
        'a-lib>=1; extra == "dev"',
        'b-lib>=1; extra == "dev"',
        'pytest>=8; extra == "dev"',
    ]
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("a-lib==1.0")
        + _entry("b-lib==1.0"),
    )
    assert missing_from_locks(tmp_path, reqs) == {}


def test_only_requirement_files_are_treated_as_install_sets(tmp_path):
    """`_walk` yields everything, and reading it all pulls VM images into memory.

    Asserted by CONSEQUENCE rather than by timing: a document that merely
    mentions a pinned, hashed blastbox is judged as a lock if the candidate set
    is everything, and then reports its dependencies missing.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "req.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    # Prose, not a lock -- but indistinguishable from one if it is read as one.
    (tmp_path / "UPGRADING.md").write_text(
        "Pin it like this:\n\n" + _entry("blastbox==0.1.39")
    )
    blob = tmp_path / "rootfs.ext4"
    with blob.open("wb") as fh:
        fh.truncate(64 * 1024 * 1024)  # sparse; only its SIZE matters here
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0"])
    assert gaps == {}, gaps


def test_the_lock_states_the_platform_its_markers_are_for(tmp_path):
    """`uv pip compile --python-platform windows` resolves for another machine.

    Evaluating that lock's markers against the local `sys_platform` skips the
    Windows-only requirements it exists to carry.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", 'pywin32>=306; sys_platform == "win32"']
    header = (
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes "
        "--python-platform windows -o req.lock\n"
    )
    _write(
        tmp_path,
        "req.lock",
        header + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    gaps = missing_from_locks(tmp_path, reqs)
    assert list(gaps.values()) == [["pywin32"]], gaps

    # And the other direction, so the local platform cannot mask it.
    linux = header.replace("--python-platform windows", "--python-platform linux")
    _write(
        tmp_path,
        "req.lock",
        linux + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    assert missing_from_locks(tmp_path, reqs) == {}


def test_pins_that_do_not_apply_are_not_evidence_for_an_extra(tmp_path):
    """A portable lock carries names it never installs on this platform.

    Counting those as present infers an extra from packages that are not there,
    and then reports every one of its dependencies missing.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = [
        "pydantic>=2.6.0",
        'win-a>=1; extra == "gui"',
        'win-b>=1; extra == "gui"',
        'gui-c>=1; extra == "gui"',
    ]
    lock = (
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry('win-a==1.0 ; sys_platform == "win32"')
        + _entry('win-b==1.0 ; sys_platform == "win32"')
    )
    _write(tmp_path, "req.lock", lock)
    assert (
        missing_from_locks(tmp_path, reqs, environment={"sys_platform": "linux"}) == {}
    )


def test_an_include_outside_the_repository_is_refused(tmp_path):
    """`_walk` stays inside the repo and refuses symlinks; includes must too.

    A `-r /dev/zero` exhausts memory and a FIFO blocks forever, both reached
    from a file the scanner was merely told to look at.
    """
    from blastbox.host.pins import missing_from_locks

    outside = tmp_path.parent / f"outside-{tmp_path.name}.lock"
    outside.write_text(_entry("pydantic==2.13.5"))
    try:
        _write(tmp_path, "req.lock", _entry("blastbox==0.1.39") + f"-r {outside}\n")
        gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0"])
        assert list(gaps.values()) == [["pydantic"]], gaps
    finally:
        outside.unlink()


def test_an_include_naming_a_special_file_is_refused(tmp_path):
    """Reading a FIFO blocks forever; the check must not open one."""
    import os

    from blastbox.host.pins import missing_from_locks

    fifo = tmp_path / "pipe.lock"
    os.mkfifo(fifo)
    _write(tmp_path, "req.lock", _entry("blastbox==0.1.39") + "-r pipe.lock\n")
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0"])
    assert list(gaps.values()) == [["pydantic"]], gaps


def test_a_lock_that_does_not_install_blastbox_here_is_not_judged(tmp_path):
    """A portable lock may pin blastbox only for another platform.

    pip skips the package entirely on this one, so demanding its dependency
    closure refuses a lock that is correct.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "req.lock",
        _entry('blastbox==0.1.39 ; sys_platform == "win32"')
        + _entry("pydantic==2.13.5"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"sys_platform": "linux"}) == {}
    )

    # NOT vacuous: on the platform where blastbox IS installed, the same lock
    # is judged and its gaps reported.
    gaps = missing_from_locks(
        tmp_path, _RM, environment={"sys_platform": "win32", "python_version": "3.12"}
    )
    assert list(gaps.values()) == [["packaging", "backport"]], gaps


def test_a_recognised_lock_that_cannot_be_read_is_an_error_not_an_absence(tmp_path):
    """Reading a lock as empty reports its whole closure present.

    `pins --set` would then update every other pin and report success while the
    lock stays stale -- the silent half-bump this module exists to prevent.
    """
    import blastbox.host.pins as mod
    from blastbox.host.pins import PinScanError, missing_from_locks

    lock = tmp_path / "requirements.lock"
    lock.write_text(_entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"))
    monkey = mod._LOCK_READ_LIMIT
    try:
        mod._LOCK_READ_LIMIT = 10  # anything real is "too large"
        with pytest.raises(PinScanError, match="too large"):
            missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    finally:
        mod._LOCK_READ_LIMIT = monkey


def test_a_directly_installed_lock_is_a_candidate_whatever_its_name(tmp_path):
    """pip imposes no naming convention on `-r`.

    A hashed `deps.txt` that includes nothing is a real install set, and
    deriving the candidate list from names alone never evaluates it.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "deps.txt", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r deps.txt\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps.values()) == [["packaging", "backport"]], gaps


def test_a_reference_is_resolved_against_the_build_context(tmp_path):
    """`docker build -f deploy/Dockerfile .` copies from the CONTEXT.

    `pip install -r prod.lock` inside it names `<root>/prod.lock`, not
    `deploy/prod.lock`. Resolving only the latter drops the reference, which
    removes the lock from the roots and accepts its incomplete closure.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "Dockerfile").write_text(
        "FROM python:3.12\nCOPY prod.lock .\nRUN pip install --require-hashes -r prod.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "prod.lock")], gaps


def test_setting_the_version_already_pinned_reports_no_change(tmp_path):
    """Re-running `pins --set` on a correct repo should say nothing happened.

    Every staged file is still WRITTEN -- the atomic restore depends on that --
    but a rewrite producing identical bytes is not an update, and reporting one
    tells an operator their repo moved when it did not.
    """
    from blastbox.host.pins import set_version

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox>=0.1.39,<0.2"]\n'
    )
    assert set_version(tmp_path, "0.1.39") == []


def test_a_real_change_is_still_reported(tmp_path):
    """The other direction: silence must mean nothing changed, not nothing ran."""
    from blastbox.host.pins import set_version

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox>=0.1.38,<0.2"]\n'
    )
    assert set_version(tmp_path, "0.1.39") == [str(pyproject)]
    assert "0.1.39" in pyproject.read_text()


def test_a_dependency_that_gains_an_extra_needs_that_closure_too(tmp_path):
    """`uvicorn` becoming `uvicorn[standard]` enables packages pip must hash.

    A version match alone says nothing about those, so an older lock passes the
    check and then fails the install.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", "uvicorn[standard]>=0.27"]
    closure = {("uvicorn", "0.30.0"): ['watchfiles>=0.13; extra == "standard"']}
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("uvicorn==0.30.0"),
    )
    gaps = missing_from_locks(
        tmp_path, reqs, requirements_of=lambda n, v: closure.get((n, v))
    )
    assert list(gaps.values()) == [["watchfiles (needed by uvicorn)"]], gaps

    # With the closure present it is satisfied -- so the check is not simply
    # refusing every extras-bearing dependency.
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("uvicorn==0.30.0")
        + _entry("watchfiles==0.24.0"),
    )
    assert (
        missing_from_locks(
            tmp_path, reqs, requirements_of=lambda n, v: closure.get((n, v))
        )
        == {}
    )


def test_without_metadata_the_closure_is_not_claimed_either_way(tmp_path):
    """A resolver that cannot answer means one unknown edge, not a gap.

    Refusing a bump because an index was unreachable is worse than the drift it
    guards against, and claiming the closure verified would be a lie. The
    direct requirements are still checked.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", "uvicorn[standard]>=0.27"]
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("uvicorn==0.30.0"),
    )
    assert missing_from_locks(tmp_path, reqs, requirements_of=lambda n, v: None) == {}

    # ... and a DIRECT requirement is still reported without any resolver.
    gaps = missing_from_locks(tmp_path, [*reqs, "packaging>=23.0"])
    assert list(gaps.values()) == [["packaging"]], gaps


def test_the_space_form_of_hash_counts_as_hashed(tmp_path):
    """pip documents `--hash <hash>` and its parser accepts it.

    Reading such a lock as unhashed makes `set_version` rewrite the blastbox
    version without replacing its artifact hashes.
    """
    from blastbox.host.pins import missing_from_locks

    h = "--hash sha256:" + "a" * 64
    (tmp_path / "req.lock").write_text(
        f"blastbox==0.1.39 \\\n    {h}\npydantic==2.13.5 \\\n    {h}\n"
    )
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"])
    assert list(gaps.values()) == [["packaging"]], gaps


def test_a_target_triple_records_its_architecture(tmp_path):
    """`--python-platform aarch64-unknown-linux-gnu` is not just "linux"."""
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", 'arm-only>=1; platform_machine == "aarch64"']
    header = (
        "# uv pip compile pyproject.toml --generate-hashes "
        "--python-platform aarch64-unknown-linux-gnu -o req.lock\n"
    )
    _write(
        tmp_path,
        "req.lock",
        header + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    assert list(missing_from_locks(tmp_path, reqs).values()) == [["arm-only"]]

    x86 = header.replace("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
    _write(
        tmp_path,
        "req.lock",
        x86 + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    assert missing_from_locks(tmp_path, reqs) == {}


def test_a_directly_named_lock_with_any_suffix_is_a_candidate(tmp_path):
    """pip imposes no suffix convention on `-r`."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.pins", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\npip install --require-hashes -r prod.pins\n"
    )
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"])
    assert list(gaps.values()) == [["packaging"]], gaps


def test_the_scanner_refuses_a_lock_it_cannot_read(tmp_path):
    """`scan()` is what `pins` reports and what `set_version` verifies against.

    A lock read as empty simply vanishes from it, so the rewrite updates every
    other pin and the re-scan agrees -- a half-bumped repo reported as correct.
    """
    import blastbox.host.pins as mod
    from blastbox.host.pins import PinScanError, scan

    lock = tmp_path / "requirements.lock"
    lock.write_text(_entry("blastbox==0.1.39"))
    limit = mod._LOCK_READ_LIMIT
    try:
        mod._LOCK_READ_LIMIT = 10
        with pytest.raises(PinScanError, match="too large"):
            scan(tmp_path)
    finally:
        mod._LOCK_READ_LIMIT = limit


def test_the_repository_declares_which_blastbox_extras_it_installs(tmp_path):
    """`blastbox[host,s3]` says exactly which optional sets are installed.

    NOT uv's `--extra` header: that selects the CONSUMER's own optional group.
    RedTusk's real lock says `--extra host`, which is redtusk's `host` group
    whose contents are `blastbox[host,s3]` -- the names coincide and the
    meanings do not, so reading it as blastbox's extras claims `host` by
    accident and misses `s3` entirely.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n\n[project.optional-dependencies]\n'
        'host = ["blastbox[host]>=0.1.39,<0.2"]\n'
    )
    # Only ONE of host's dependencies -- below any inference threshold, so the
    # declaration is the only thing that can find this.
    _write(
        tmp_path,
        "req.lock",
        "# uv pip compile pyproject.toml --extra host --generate-hashes "
        "--python-version 3.12 -o req.lock\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0")
        + _entry("fastapi==1.2.0"),
    )
    gaps = missing_from_locks(tmp_path, _RM)
    assert list(gaps.values()) == [["uvicorn" + _RUNTIME]], gaps


def test_an_extra_the_repository_never_asks_for_is_not_demanded(tmp_path):
    """The other direction: declaring host must not drag s3 in."""
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox[host]>=0.1.39,<0.2"]\n'
    )
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0")
        + _entry("fastapi==1.2.0")
        + _entry("uvicorn==1.1.0"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_the_space_form_of_hash_is_replaced_on_a_bump(tmp_path):
    """The READ side learned both spellings; the WRITE side had not.

    `set_version` would change `blastbox==...` and leave the OLD artifact
    hashes beside the new version, and its version-only rescan reports success
    while the next hashed install rejects the file.
    """
    from blastbox.host.pins import set_version

    old_hash = "b" * 64
    lock = tmp_path / "requirements.lock"
    lock.write_text(f"blastbox==0.1.38 \\\n    --hash sha256:{old_hash}\n")
    new = "c" * 64
    set_version(tmp_path, "0.1.39", digests=[new])
    text = lock.read_text()
    assert "0.1.39" in text, text
    assert old_hash not in text, text
    assert new in text, text


def test_a_quoted_requirement_path_is_still_a_reference(tmp_path):
    """The shell strips the quotes before pip ever sees them."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12\nRUN pip install --require-hashes -r "prod.lock"\n'
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "prod.lock")], gaps


def test_an_apple_target_calls_that_architecture_arm64(tmp_path):
    """uv evaluates `aarch64-apple-darwin` as `platform_machine == "arm64"`."""
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", 'mac-arm>=1; platform_machine == "arm64"']
    header = (
        "# uv pip compile --generate-hashes --python-platform aarch64-apple-darwin\n"
    )
    _write(
        tmp_path,
        "req.lock",
        header + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    assert list(missing_from_locks(tmp_path, reqs).values()) == [["mac-arm"]]

    # The Linux spelling of the same architecture stays `aarch64`.
    linux = "# uv pip compile --python-platform aarch64-unknown-linux-gnu\n"
    _write(
        tmp_path,
        "req.lock",
        linux + _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    assert missing_from_locks(tmp_path, reqs) == {}


def test_a_declaration_for_one_install_set_does_not_bind_another(tmp_path):
    """A `dev` group naming `blastbox[host]` says nothing about a prod lock.

    Applying the repository's declarations to every root rejects a correct
    production lock for omitting host-only dependencies it never selected.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox>=0.1.39,<0.2"]\n\n'
        '[project.optional-dependencies]\ndev = ["blastbox[host]>=0.1.39,<0.2"]\n'
    )
    _write(
        tmp_path,
        "prod.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    _write(
        tmp_path,
        "dev.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0")
        + _entry("fastapi==1.2.0")
        + _entry("uvicorn==1.1.0"),
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert gaps == {}, gaps


def test_a_nested_extra_is_traversed(tmp_path):
    """`parent[feature]` requiring `child[nested]` enables nested too.

    Stopping at the child's own pin accepts a lock that carries `child` for
    some other reason and none of what `nested` adds.
    """
    from blastbox.host.pins import missing_from_locks

    meta = {
        ("parent", "1.0"): ['child[nested]>=1; extra == "feature"'],
        ("child", "1.0"): ['grandchild>=1; extra == "nested"'],
    }
    reqs = ["pydantic>=2.6.0", "parent[feature]>=1"]
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("parent==1.0")
        + _entry("child==1.0"),
    )
    gaps = missing_from_locks(
        tmp_path, reqs, requirements_of=lambda n, v: meta.get((n, v))
    )
    assert list(gaps.values()) == [["grandchild (needed by child)"]], gaps

    # With the grandchild pinned it is satisfied.
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("parent==1.0")
        + _entry("child==1.0")
        + _entry("grandchild==1.0"),
    )
    assert (
        missing_from_locks(
            tmp_path, reqs, requirements_of=lambda n, v: meta.get((n, v))
        )
        == {}
    )


def test_an_extras_cycle_terminates(tmp_path):
    """Packages can depend on each other's extras."""
    from blastbox.host.pins import missing_from_locks

    meta = {
        ("a-pkg", "1.0"): ['b-pkg[y]>=1; extra == "x"'],
        ("b-pkg", "1.0"): ['a-pkg[x]>=1; extra == "y"'],
    }
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("a-pkg==1.0")
        + _entry("b-pkg==1.0"),
    )
    gaps = missing_from_locks(
        tmp_path,
        ["pydantic>=2.6.0", "a-pkg[x]>=1"],
        requirements_of=lambda n, v: meta.get((n, v)),
    )
    assert gaps == {}, gaps


def test_an_inline_space_form_hash_is_replaced_too(tmp_path):
    """Hashes may sit on the requirement line itself, not only below it.

    That is a separate branch of the rewrite, and it kept the old digests while
    the continuation-line branch was fixed.
    """
    from blastbox.host.pins import set_version

    old_hash = "b" * 64
    lock = tmp_path / "requirements.lock"
    lock.write_text(f"blastbox==0.1.38 --hash sha256:{old_hash}\n")
    new = "c" * 64
    set_version(tmp_path, "0.1.39", digests=[new])
    text = lock.read_text()
    assert "0.1.39" in text and new in text, text
    assert old_hash not in text, text


def test_a_spelled_extra_is_an_install_failure_and_a_plain_one_is_not(tmp_path):
    """The distinction is measured against real pip, not assumed.

    On RedTusk's own lock with fastapi removed, in python:3.12-slim:

        blastbox[host]==...  ->  pip install --require-hashes  FAILS
        blastbox==...        ->  pip install --require-hashes  SUCCEEDS

    Both are worth reporting -- the second leaves the image short a package it
    imports, because the Dockerfiles then run `pip install -e . --no-deps` --
    but calling the second a pip rejection would send an operator looking for
    an error that never happens.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox[host]>=0.1.39,<0.2"]\n'
    )
    body = (
        _entry("pydantic==2.13.5") + _entry("packaging==26.3") + _entry("backport==1.0")
    )

    # The lock LINE spells the extra: pip enforces it, so no annotation.
    _write(tmp_path, "req.lock", _entry("blastbox[host]==0.1.39") + body)
    spelled = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(spelled.values()) == [["fastapi", "uvicorn"]], spelled

    # A plain line: the same packages are missing, and pip would not care.
    _write(tmp_path, "req.lock", _entry("blastbox==0.1.39") + body)
    plain = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(plain.values()) == [["fastapi" + _RUNTIME, "uvicorn" + _RUNTIME]], plain


def test_a_base_dependency_is_always_an_install_failure(tmp_path):
    """`packaging` is the case that started this, and pip does reject it."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "req.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    gaps = missing_from_locks(tmp_path, ["pydantic>=2.6.0", "packaging>=23.0"])
    assert list(gaps.values()) == [["packaging"]], gaps


def test_a_quoted_include_is_followed(tmp_path):
    """pip accepts `-r "child.lock"`, and the shell is not involved here.

    Keeping the quotes made `_safe_include` reject a path that does not exist,
    so the child stayed unresolved while still being removed from the roots --
    leaving an install set nobody checked.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "child.lock", _entry("pydantic==2.13.5") + _entry("packaging==26.3")
    )
    _write(
        tmp_path,
        "root.lock",
        _entry("blastbox==0.1.39") + '-r "child.lock"\n' + _entry("backport==1.0"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )

    # NOT vacuous: break the child and the same call must report it.
    _write(tmp_path, "child.lock", _entry("pydantic==2.13.5"))
    broken = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(broken.values()) == [["packaging"]], broken


def test_two_extras_of_one_package_are_both_traversed(tmp_path):
    """`parent[feature]` needing `child[a]` and `child[b]` visits child twice.

    A cycle key of (name, version) makes the second visit a no-op, so a lock
    carrying a's dependencies but not b's is accepted although pip enables both.
    """
    from blastbox.host.pins import missing_from_locks

    meta = {
        ("parent", "1.0"): [
            'child[a]>=1; extra == "feature"',
            'child[b]>=1; extra == "feature"',
        ],
        ("child", "1.0"): ['dep-a>=1; extra == "a"', 'dep-b>=1; extra == "b"'],
    }
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("parent==1.0")
        + _entry("child==1.0")
        + _entry("dep-a==1.0"),
    )
    gaps = missing_from_locks(
        tmp_path,
        ["pydantic>=2.6.0", "parent[feature]>=1"],
        requirements_of=lambda n, v: meta.get((n, v)),
    )
    assert list(gaps.values()) == [["dep-b (needed by child)"]], gaps

    # BOTH orders. The walk pops depth-first, so with a (name, version) key
    # only one of these two arrangements short-circuits -- whichever extra is
    # visited second. Testing one of them lets the bug survive half the time.
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("parent==1.0")
        + _entry("child==1.0")
        + _entry("dep-b==1.0"),
    )
    other = missing_from_locks(
        tmp_path,
        ["pydantic>=2.6.0", "parent[feature]>=1"],
        requirements_of=lambda n, v: meta.get((n, v)),
    )
    assert list(other.values()) == [["dep-a (needed by child)"]], other


def test_a_commented_out_install_is_not_an_install(tmp_path):
    """`# old: pip install -r prod.lock` is a note, not a command.

    Promoting it to a root judges that lock alone and refuses a bump for
    dependencies its real parent install set supplies.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n# old: pip install -r prod.lock\n"
        "RUN pip install --require-hashes -r dev.lock\n"
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_extras_are_attributed_to_the_command_that_installs_the_lock(tmp_path):
    """A multi-stage Dockerfile installs different things in different stages.

    Taking every `blastbox[...]` in the file applies `host` to a production
    lock whose stage installs plain blastbox, and rejects it for omitting
    dependencies it never asked for.
    """
    from blastbox.host.pins import missing_from_locks

    body = (
        _entry("pydantic==2.13.5") + _entry("packaging==26.3") + _entry("backport==1.0")
    )
    _write(tmp_path, "prod.lock", _entry("blastbox==0.1.39") + body)
    _write(
        tmp_path,
        "dev.lock",
        _entry("blastbox==0.1.39")
        + body
        + _entry("fastapi==1.2.0")
        + _entry("uvicorn==1.1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12 AS prod\n"
        "RUN pip install --require-hashes -r prod.lock\n"
        "FROM python:3.12 AS dev\n"
        "RUN pip install blastbox[host] --require-hashes -r dev.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert gaps == {}, gaps


def test_the_cli_reports_an_unreadable_lock_instead_of_crashing(tmp_path, capsys):
    """Recognised locks RAISE when unreadable, on purpose.

    That has to reach the operator as the command's own diagnostic and exit 2,
    not as a traceback out of a check they did not ask for.
    """
    import blastbox.host.pins as mod
    from blastbox.host.cli import _pins_set

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox>=0.1.38,<0.2"]\n'
    )
    _write(tmp_path, "requirements.lock", _entry("blastbox==0.1.38"))
    limit = mod._LOCK_READ_LIMIT
    try:
        mod._LOCK_READ_LIMIT = 10
        rc = _pins_set(tmp_path, "0.1.39", allow_unreleased=True)
    finally:
        mod._LOCK_READ_LIMIT = limit
    assert rc == 2
    assert "cannot check the dependency closure" in capsys.readouterr().out


def test_the_attached_short_form_of_r_is_followed(tmp_path):
    """pip accepts `-rFILE` with no separator at all.

    Requiring whitespace or `=` left the child unresolved while it was still
    removed from the roots -- an install set nobody checks, which accepts any
    closure.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "child.pins", _entry("pydantic==2.13.5") + _entry("packaging==26.3")
    )
    _write(
        tmp_path,
        "root.lock",
        _entry("blastbox==0.1.39") + "-rchild.pins\n" + _entry("backport==1.0"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )

    # NOT vacuous: break the child and the same call must report it.
    _write(tmp_path, "child.pins", _entry("pydantic==2.13.5"))
    broken = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(broken.values()) == [["packaging"]], broken


def test_a_bare_platform_name_carries_uvs_default_architecture(tmp_path):
    """Measured, because uv's help lists the aliases without resolving them.

        uv pip compile --python-platform macos    -> platform_machine "arm64"
        uv pip compile --python-platform linux    -> platform_machine "x86_64"

    Leaving it to the running interpreter skipped an arm64-guarded dependency
    for a macos lock on an x86 Linux host.
    """
    from blastbox.host.pins import missing_from_locks

    reqs = ["pydantic>=2.6.0", 'mac-arm>=1; platform_machine == "arm64"']
    for platform, expected in (("macos", [["mac-arm"]]), ("linux", [])):
        _write(
            tmp_path,
            "req.lock",
            f"# uv pip compile --generate-hashes --python-platform {platform}\n"
            + _entry("blastbox==0.1.39")
            + _entry("pydantic==2.13.5"),
        )
        gaps = missing_from_locks(tmp_path, reqs)
        assert list(gaps.values()) == expected, (platform, gaps)

    # An explicit triple still wins over the bare default.
    _write(
        tmp_path,
        "req.lock",
        "# uv pip compile --python-platform x86_64-apple-darwin\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5"),
    )
    assert missing_from_locks(tmp_path, reqs) == {}


def test_bare_platform_names_map_to_uvs_measured_defaults():
    """Asserted on the mapping itself, not only through a gap.

    This host is x86_64 Linux, so a gap-level test of the `linux` default
    agrees with the ambient machine whether or not the mapping sets it -- the
    mutant survives. The values come from measuring uv:

        uv pip compile --python-platform macos    -> arm64
        uv pip compile --python-platform linux    -> x86_64
        uv pip compile --python-platform windows  -> x86_64
    """
    from blastbox.host.pins import _lock_environment

    def machine(target):
        return _lock_environment(f"# uv pip compile --python-platform {target}").get(
            "platform_machine"
        )

    assert machine("macos") == "arm64"
    assert machine("linux") == "x86_64"
    assert machine("windows") == "x86_64"
    # An explicit triple overrides the bare default in both directions.
    assert machine("aarch64-unknown-linux-gnu") == "aarch64"
    assert machine("x86_64-apple-darwin") == "x86_64"


def test_prose_mentioning_an_extra_is_not_an_install(tmp_path):
    """A comment is not an install path.

    Grepping the file text refused a base-only lock for missing every host
    dependency because a comment said `develop with blastbox[host]`.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n'
        "# develop with blastbox[host] if you need the ingress app\n"
        'description = "uses blastbox[host] in production"\n'
        'dependencies = ["blastbox>=0.1.39,<0.2"]\n'
    )
    _write(
        tmp_path,
        "req.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_an_install_line_with_a_placeholder_version_still_names_its_extras(tmp_path):
    """ClippyShot's real line is `blastbox[s3]==${BLASTBOX_VERSION}`.

    That will not parse as a requirement -- the specifier is a shell
    placeholder -- and dropping it lost the s3 extra from a repository that
    genuinely installs it.
    """
    from blastbox.host.pins import _blastbox_extras_in

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "RUN pip install '/tmp/build[host]' \"blastbox[s3]==${BLASTBOX_VERSION}\" \\\n"
        "    && echo done\n"
    )
    assert _blastbox_extras_in(dockerfile) == {"s3"}


def test_a_requirement_path_with_spaces_is_followed(tmp_path):
    """`pip install -r "prod lock.txt"` names a file with a space in it."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "prod lock.txt",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    _write(
        tmp_path,
        "dev.lock",
        '-r "prod lock.txt"\n' + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12\nRUN pip install --require-hashes -r "prod lock.txt"\n'
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "prod lock.txt")], gaps


def test_an_unrelated_large_text_file_does_not_block_the_check(tmp_path):
    """`_is_install_input` accepts any `.txt`, and data files are not locks.

    Sending them through the reader that RAISES made an unrelated corpus block
    `pins --set` on a repository whose data files are none of its business.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    with (tmp_path / "corpus.txt").open("wb") as fh:
        fh.truncate(65 * 1024 * 1024)  # sparse; only its SIZE matters
    assert missing_from_locks(tmp_path, ["pydantic>=2.6.0"]) == {}
    # ...and the lock is still JUDGED, so the clean result above is a verdict
    # rather than "the walk gave up before it got there".
    assert missing_from_locks(tmp_path, ["httpx>=0.27"]) != {}


def test_a_large_lock_still_refuses_to_be_read_as_absent(tmp_path):
    """Narrowing the strict reader must not make it lenient for real locks."""
    import blastbox.host.pins as mod
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    limit = mod._LOCK_READ_LIMIT
    try:
        mod._LOCK_READ_LIMIT = 16
        with pytest.raises(mod.PinScanError, match="requirements.lock"):
            missing_from_locks(tmp_path, ["pydantic>=2.6.0"])
    finally:
        mod._LOCK_READ_LIMIT = limit


def test_a_quoted_unconventional_path_in_an_install_command_is_a_root(tmp_path):
    """Only a shell-aware read finds `-r "prod set.pins"`.

    pip imposes no suffix convention, so this file is invisible to the name
    filter -- the install command naming it is the ONLY evidence it is a real
    install set. Splitting on whitespace reads the filename as `"prod`, and the
    set silently stops being checked.
    """
    from blastbox.host.pins import missing_from_locks

    _write(tmp_path, "prod set.pins", _entry("blastbox==0.1.39"))
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12\nRUN pip install --require-hashes -r "prod set.pins"\n'
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "prod set.pins")], gaps
    assert any("pydantic" in miss for miss in gaps[str(tmp_path / "prod set.pins")])


@pytest.mark.parametrize(
    "spelling",
    ['-r "prod set.txt"', "-rprod.txt", "-r=prod.txt", "--requirement=prod.txt"],
)
def test_every_pip_spelling_of_a_requirement_reference_is_followed(tmp_path, spelling):
    """pip accepts four spellings; a lock that uses any of them is one set.

    Missing one splits the set: the included file stops being recognised as
    included, is judged ALONE, and is reported incomplete for pins that sit in
    the very file that installs it.
    """
    from blastbox.host.pins import missing_from_locks

    name = "prod set.txt" if " " in spelling else "prod.txt"
    _write(tmp_path, name, _entry("pydantic==2.13.5"))
    _write(
        tmp_path,
        "dev.lock",
        f"{spelling}\n"
        + _entry("blastbox==0.1.39")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r dev.lock\n"
    )
    env = {"python_version": "3.12"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: the referenced file is genuinely being READ as part of the set,
    # so the clean verdict above is a judgement and not a silent skip.
    _write(tmp_path, name, _entry("unrelated==1.0"))
    assert missing_from_locks(tmp_path, _RM, environment=env) != {}


def test_naming_an_extra_outside_an_install_command_is_not_an_install(tmp_path):
    """A Dockerfile that WRITES the name down has not installed it."""
    from blastbox.host.pins import _blastbox_extras_in

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM python:3.12\n"
        "RUN echo blastbox[host] >> /etc/optional-deps.txt\n"
        "RUN pip install blastbox[s3]==0.1.39\n"
    )
    assert _blastbox_extras_in(dockerfile) == {"s3"}


@pytest.mark.parametrize(
    "spelling",
    [
        "blastbox[s3]==${BLASTBOX_VERSION}",
        "-e /src/blastbox[s3]",
        "git+https://example.invalid/blastbox.git#egg=blastbox[s3]",
    ],
)
def test_unparseable_but_real_installs_still_name_their_extras(tmp_path, spelling):
    """None of these parse as a requirement; all of them install the extra."""
    from blastbox.host.pins import _blastbox_extras_in

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(f"FROM python:3.12\nRUN pip install {spelling}\n")
    assert _blastbox_extras_in(dockerfile) == {"s3"}


def test_a_line_with_an_unbalanced_quote_does_not_stop_the_scan(tmp_path):
    """`RUN echo can't ...` is a shell error to shlex, and a real Dockerfile line.

    Raising there aborts the whole check over a line that has nothing to do
    with installing anything -- so the tokeniser skips what it cannot read and
    keeps going.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN echo can't hurt > /etc/note\n"
        "RUN pip install --require-hashes -r requirements.lock\n"
    )
    env = {"python_version": "3.12"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: the install line after the broken one is still being read.
    _write(tmp_path, "requirements.lock", _entry("blastbox==0.1.39"))
    assert missing_from_locks(tmp_path, _RM, environment=env) != {}


@pytest.mark.parametrize("where", ["before", "after"])
def test_only_the_generated_header_names_the_target_interpreter(tmp_path, where):
    """A note that mentions a target option is prose, not the lock's target.

    RedTusk's real lock opens with four lines of human preamble before uv's
    header, so text on both sides of the command has to stay out of it.
    """
    from blastbox.host.pins import missing_from_locks

    note = "# migration target: --python-version 3.13\n"
    header = (
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes --python-version 3.12\n"
    )
    body = _entry("blastbox==0.1.39")
    text = (note + header + body) if where == "before" else (header + note + body)
    _write(tmp_path, "requirements.lock", text)
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    requires = ['oldpy>=1.0; python_version < "3.13"']
    gaps = missing_from_locks(tmp_path, requires)
    assert [
        g for g in gaps.get(str(tmp_path / "requirements.lock"), []) if "oldpy" in g
    ], f"the 3.12 header must decide, not the note: {gaps}"


def test_the_generated_header_still_sets_the_target(tmp_path):
    """Control for the test above: a real 3.13 header DOES skip the marker."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes --python-version 3.13\n"
        + _entry("blastbox==0.1.39"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    assert missing_from_locks(tmp_path, ['oldpy>=1.0; python_version < "3.13"']) == {}


def test_two_locks_in_one_pip_command_are_one_install_set(tmp_path):
    """`pip install -r a.lock -r b.lock` is ONE resolution; pip merges them.

    Judging each alone reported the first incomplete for dependencies the
    second supplies in the very same command.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==26.3") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    env = {"python_version": "3.12"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: the merged set is genuinely judged -- break the SECOND file and
    # the set is reported, keyed by both members.
    _write(tmp_path, "deps.lock", _entry("packaging==26.3"))
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    assert list(gaps) == [f"{tmp_path / 'blastbox.lock'} + {tmp_path / 'deps.lock'}"], (
        gaps
    )


def test_locks_installed_by_separate_commands_stay_separate(tmp_path):
    """Two commands are two resolutions, and neither covers the other."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==26.3") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock\n"
        "RUN pip install --require-hashes -r deps.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "blastbox.lock")], gaps


def test_a_constraint_that_excludes_a_pin_is_reported(tmp_path):
    """pip applies `-c` and refuses the resolution; the check must too.

    Every name is present and hashed, so the closure looks complete -- and the
    install fails anyway, which is exactly the outcome this check exists to
    prevent.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "-c constraints.txt\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "constraints.txt").write_text("packaging==22.0\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    env = {"python_version": "3.12"}
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    reported = gaps[str(tmp_path / "requirements.lock")]
    assert any(
        "excluded by the constraint" in g and "packaging" in g for g in reported
    ), reported
    # Control: a constraint that ADMITS the pin is not a conflict.
    (tmp_path / "constraints.txt").write_text("packaging>=22.0\n")
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}


def test_a_constraint_reached_through_another_constraint_still_counts(tmp_path):
    """pip follows `-c` inside a constraint file too."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "-c outer.txt\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "outer.txt").write_text("-c inner.txt\n")
    (tmp_path / "inner.txt").write_text("packaging==22.0\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert any(
        "excluded by the constraint" in g
        for g in gaps.get(str(tmp_path / "requirements.lock"), [])
    ), gaps


def test_a_portable_locks_two_pins_are_not_constraints_on_each_other(tmp_path):
    """A lock legitimately pins one distribution twice under exclusive markers.

    Those lines are pins, not constraints: reading a requirements file's own
    entries as constraints makes the branch that does not apply here forbid the
    branch that does, and reports a conflict pip would never see.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry('packaging==22.0 ; sys_platform == "win32"')
        + _entry('packaging==26.3 ; sys_platform == "linux"')
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    gaps = missing_from_locks(
        tmp_path, _RM, environment={"python_version": "3.12", "sys_platform": "linux"}
    )
    assert gaps == {}, gaps


def test_a_hashed_constraint_file_is_still_read(tmp_path):
    """Hash arguments are not requirement grammar; stripping them is required.

    Leaving them in makes every entry in a hashed constraint file unparseable,
    so the file reads as empty and constrains nothing.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "-c constraints.txt\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    _write(tmp_path, "constraints.txt", _entry("packaging==22.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert any(
        "excluded by the constraint" in g
        for g in gaps.get(str(tmp_path / "requirements.lock"), [])
    ), gaps


_UNIVERSAL_HEADER = (
    "# This file was autogenerated by uv via the following command:\n"
    "#    uv pip compile pyproject.toml --generate-hashes --universal\n"
)
_PLAIN_HEADER = (
    "# This file was autogenerated by uv via the following command:\n"
    "#    uv pip compile pyproject.toml --generate-hashes\n"
)


@pytest.mark.parametrize(
    ("header", "reported"), [(_UNIVERSAL_HEADER, True), (_PLAIN_HEADER, False)]
)
def test_a_universal_lock_is_judged_on_every_branch_it_covers(
    tmp_path, header, reported
):
    """`--universal` is one file for ALL platforms, so all of them are checked.

    Judged under the machine running `pins`, a newly required
    `winonly; sys_platform == "win32"` is skipped on Linux and the lock is
    accepted although its Windows install fails under hash mode.
    """
    from blastbox.host.pins import missing_from_locks

    _write(tmp_path, "requirements.lock", header + _entry("blastbox==0.1.39"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    requires = ['winonly>=1.0; sys_platform == "win32"']
    gaps = missing_from_locks(tmp_path, requires).get(
        str(tmp_path / "requirements.lock"), []
    )
    hits = [g for g in gaps if "winonly" in g]
    assert bool(hits) is reported, gaps
    if reported:
        assert "[on windows]" in hits[0], hits


def test_a_universal_gap_on_every_branch_is_not_labelled(tmp_path):
    """A requirement missing everywhere is not a per-branch fact."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "requirements.lock", _UNIVERSAL_HEADER + _entry("blastbox==0.1.39")
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    gaps = missing_from_locks(tmp_path, ["everywhere>=1.0"])[
        str(tmp_path / "requirements.lock")
    ]
    assert any("everywhere" in g and "[on " not in g for g in gaps), gaps


def test_an_explicit_environment_still_narrows_a_universal_lock(tmp_path):
    """Naming a target is a deliberate question about ONE platform."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "requirements.lock", _UNIVERSAL_HEADER + _entry("blastbox==0.1.39")
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    requires = ['winonly>=1.0; sys_platform == "win32"']
    assert (
        missing_from_locks(tmp_path, requires, environment={"sys_platform": "linux"})
        == {}
    )


def test_a_quoted_hash_does_not_hide_the_install_behind_it(tmp_path):
    """`RUN echo "step # 1" && pip install ...` is one command, not a comment.

    Cutting the line at the quoted hash hid the pin, and `pins --set` then
    reported success while that Dockerfile stayed on the old version.
    """
    from blastbox.host.pins import _scan_dockerfile

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        'FROM python:3.12\nRUN echo "step # 1" && pip install blastbox==0.1.30\n'
    )
    assert [p.specifier for p in _scan_dockerfile(dockerfile)] == ["==0.1.30"]


def test_an_exact_pin_is_found_wherever_it_sits_in_the_specifier_set(tmp_path):
    """`packaging!=21,==23` is an exact pin; pip resolves it to 23."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging!=21.0,==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_a_range_is_still_not_a_pin(tmp_path):
    """Control: `packaging>=23,<27` resolves to nothing in particular."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging>=23.0,<27")
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    env = {"python_version": "3.12"}
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    assert any(
        "packaging" in g for g in gaps.get(str(tmp_path / "requirements.lock"), [])
    ), gaps
    # And it is reported because nothing is PINNED, not because some invented
    # version fails the comparison: a requirement that ANY version satisfies is
    # still a gap here, since `--require-hashes` needs an exact pin.
    loose = missing_from_locks(tmp_path, ["packaging>=0"], environment=env)
    assert any(
        "packaging" in g for g in loose.get(str(tmp_path / "requirements.lock"), [])
    ), loose


def test_a_pep_735_group_declares_extras_too(tmp_path):
    """A lock is commonly compiled from a top-level dependency group."""
    from blastbox.host.pins import _blastbox_extras_in

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox>=0.1.39,<0.2"]\n\n'
        '[dependency-groups]\ndev = ["blastbox[host]>=0.1.39,<0.2"]\n'
    )
    assert _blastbox_extras_in(pyproject) == {"host"}


def test_only_an_install_command_names_a_root(tmp_path):
    """`echo -r prod.lock` is not an install; judging prod.lock alone is wrong.

    Its real parent set (`dev.lock`) supplies the rest, so promoting it blocks
    a bump for dependencies that are present in the file pip actually installs.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path, "prod.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5")
    )
    _write(
        tmp_path,
        "dev.lock",
        "-r prod.lock\n" + _entry("packaging==26.3") + _entry("backport==1.0"),
    )
    (tmp_path / "build.sh").write_text(
        "#!/bin/sh\n"
        "echo -r prod.lock > /dev/null\n"
        "pip install --require-hashes -r dev.lock\n"
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_a_constraint_given_on_the_command_line_applies(tmp_path):
    """`pip install -r req.lock -c limits.txt` constrains that resolution.

    Nothing installs `limits.txt`, so it is not a member of the set -- and
    walking only members meant pip's own constraint was never applied.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "limits.txt").write_text("packaging==22.0\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r requirements.lock -c limits.txt\n"
    )
    env = {"python_version": "3.12"}
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    assert any(
        "excluded by the constraint" in g
        for g in gaps.get(str(tmp_path / "requirements.lock"), [])
    ), gaps
    # Control: the same command without the constraint is clean.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}


def test_every_constraint_on_a_package_applies_not_just_the_first(tmp_path):
    """`packaging>=20` and `packaging<23` together reject a pinned 26.3."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "-c floor.txt\n-c ceiling.txt\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "floor.txt").write_text("packaging>=20\n")  # admits 26.3
    (tmp_path / "ceiling.txt").write_text("packaging<23\n")  # forbids it
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert any(
        "excluded by the constraint" in g
        for g in gaps.get(str(tmp_path / "requirements.lock"), [])
    ), gaps


def test_a_constraint_whose_marker_does_not_apply_is_not_a_conflict(tmp_path):
    """`packaging<23; sys_platform == "win32"` does not constrain a Linux install."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "-c limits.txt\n"
        + _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "limits.txt").write_text('packaging<23; sys_platform == "win32"\n')
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    env = {"python_version": "3.12", "sys_platform": "linux"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: on the platform it names, it DOES constrain.
    win = {"python_version": "3.12", "sys_platform": "win32"}
    assert missing_from_locks(tmp_path, _RM, environment=win) != {}


def test_two_installs_on_one_line_are_two_resolutions(tmp_path):
    """`pip install -r a.lock && pip install -r b.lock` is two commands.

    Merging them lets the second satisfy dependencies the first install would
    fail without -- and it fails at build time, not here.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==26.3") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock \\\n"
        "    && pip install --require-hashes -r deps.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert list(gaps) == [str(tmp_path / "blastbox.lock")], gaps


def test_one_command_installing_two_locks_is_one_set_for_declared_extras(tmp_path):
    """A grouped set is ONE resolution, so the single-set inference applies.

    Counting its member files instead disabled the fallback that reads what the
    repository declares, and a newly missing `s3` dependency went unreported.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox[s3]>=0.1.39,<0.2"]\n'
    )
    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==26.3") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    requires = [*_RM, 's3only>=1.0; extra == "s3"']
    gaps = missing_from_locks(
        tmp_path, requires, environment={"python_version": "3.12"}
    )
    assert any("s3only" in g for entries in gaps.values() for g in entries), gaps


def test_the_target_interpreter_also_sets_implementation_version(tmp_path):
    """A marker asking the implementation's version asks about the TARGET.

    The target is deliberately far from any host this runs on: with 3.12
    on both sides, the host's own value satisfies the marker and the test
    passes whether or not the header is consulted.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes --python-version 3.9\n"
        + _entry("blastbox==0.1.39"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    lock = str(tmp_path / "requirements.lock")
    # True for the 3.9 target, false for any interpreter that can run this.
    old = missing_from_locks(
        tmp_path, ['oldimpl>=1.0; implementation_version < "3.10"']
    )
    assert any("oldimpl" in g for g in old.get(lock, [])), old
    # ...and the other direction, so neither answer can come from the host.
    new = missing_from_locks(
        tmp_path, ['newimpl>=1.0; implementation_version >= "3.10"']
    )
    assert new == {}, new


def test_two_exact_pins_for_one_package_in_a_set_are_unresolvable(tmp_path):
    """pip must satisfy BOTH, and cannot; either one matching is not enough."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==22.0") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    reported = [g for entries in gaps.values() for g in entries]
    assert any("more than one version" in g and "packaging" in g for g in reported), (
        reported
    )


def test_equivalent_version_spellings_are_one_pin(tmp_path):
    """`packaging==26.3` and `packaging==26.3.0` are the same pin to pip.

    Calling them a contradiction rejects a lock pip resolves without complaint.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    _write(tmp_path, "deps.lock", _entry("packaging==26.3.0") + _entry("backport==1.0"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    env = {"python_version": "3.12"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: a genuinely different version IS a contradiction.
    _write(tmp_path, "deps.lock", _entry("packaging==22.0") + _entry("backport==1.0"))
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    assert any(
        "more than one version" in g for entries in gaps.values() for g in entries
    ), gaps


def test_arbitrary_equality_compares_the_spelling(tmp_path):
    """`===` is textual: `===26.3` and `===26.3.0` are NOT the same pin."""
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging===26.3"),
    )
    _write(
        tmp_path, "deps.lock", _entry("packaging===26.3.0") + _entry("backport==1.0")
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert any(
        "more than one version" in g for entries in gaps.values() for g in entries
    ), gaps


def test_extras_are_attributed_only_within_their_install_segment(tmp_path):
    """`echo -r prod.lock && pip install blastbox[host] -r dev.lock`.

    Reading the whole line attributes host to prod.lock, whose own base-only
    install is then reported missing dependencies it deliberately omits.
    """
    from blastbox.host.pins import _install_sets

    (tmp_path / "prod.lock").write_text("")
    (tmp_path / "dev.lock").write_text("")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN echo -r prod.lock > /dev/null \\\n"
        "    && pip install blastbox[host] -r dev.lock\n"
    )
    named = {
        tuple(m.name for m in iset.members): set(iset.extras)
        for iset in _install_sets(tmp_path)
    }
    assert named.get(("dev.lock",)) == {"host"}, named
    assert named.get(("prod.lock",)) == set(), named


def test_a_shared_lock_keeps_the_extras_of_each_command_apart(tmp_path):
    """One command installs `blastbox[host] -r a.lock -r b.lock`; another
    installs plain `-r b.lock`.

    Both succeed. Attributing host to the standalone base install reports it
    incomplete for dependencies that live in a.lock and that this resolution
    never asked for.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "a.lock",
        _entry("blastbox==0.1.39")
        + _entry("fastapi==1.2.0")
        + _entry("uvicorn==1.1.0"),
    )
    _write(
        tmp_path,
        "b.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install blastbox[host] --require-hashes -r a.lock -r b.lock\n"
        "RUN pip install --require-hashes -r b.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert gaps == {}, gaps


def test_a_local_version_satisfies_a_plain_exact_pin(tmp_path):
    """`==1.0` matches the candidate `1.0+vendor`; pip resolves both to it.

    Comparing parsed versions for equality calls that a contradiction and
    blocks a valid bump.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    _write(
        tmp_path,
        "deps.lock",
        _entry("packaging==26.3+vendor1") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    env = {"python_version": "3.12"}
    assert missing_from_locks(tmp_path, _RM, environment=env) == {}
    # Control: two DIFFERENT local versions cannot both be resolved.
    _write(
        tmp_path, "deps.lock", _entry("packaging==26.3+other") + _entry("backport==1.0")
    )
    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3+vendor1"),
    )
    gaps = missing_from_locks(tmp_path, _RM, environment=env)
    assert any(
        "more than one version" in g for entries in gaps.values() for g in entries
    ), gaps


def test_a_prerelease_target_keeps_its_suffix(tmp_path):
    """uv accepts `--python-version 3.13rc1` and records it in the header.

    Truncating it to 3.13 skips a dependency guarded by a marker that compares
    against the prerelease -- one that applies to this very lock.
    """
    from blastbox.host.pins import _lock_environment, missing_from_locks

    header = (
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes --python-version 3.13rc1\n"
    )
    assert _lock_environment(header)["python_full_version"] == "3.13.0rc1"
    _write(tmp_path, "requirements.lock", header + _entry("blastbox==0.1.39"))
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nRUN pip install --require-hashes -r requirements.lock\n"
    )
    lock = str(tmp_path / "requirements.lock")
    early = missing_from_locks(
        tmp_path, ['early>=1.0; python_full_version < "3.13.0rc2"']
    )
    assert any("early" in g for g in early.get(lock, [])), early
    late = missing_from_locks(tmp_path, ['late>=1.0; python_full_version >= "3.13.0"'])
    assert late == {}, late


def test_one_lock_installed_by_two_commands_still_infers_declarations(tmp_path):
    """Different `-c` files make two resolutions, but there is one lock.

    A declaration like `blastbox[s3]` has only that lock to apply to, and
    counting commands disabled the inference for both.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox[s3]>=0.1.39,<0.2"]\n'
    )
    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "a.txt").write_text("packaging>=20\n")
    (tmp_path / "b.txt").write_text("packaging>=21\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r requirements.lock -c a.txt\n"
        "RUN pip install --require-hashes -r requirements.lock -c b.txt\n"
    )
    requires = [*_RM, 's3only>=1.0; extra == "s3"']
    gaps = missing_from_locks(
        tmp_path, requires, environment={"python_version": "3.12"}
    )
    assert any("s3only" in g for entries in gaps.values() for g in entries), gaps


def test_member_order_does_not_make_one_set_look_like_two(tmp_path):
    """`-r a.lock -r b.lock` and `-r b.lock -r a.lock` install the same files.

    Two commands, one set of files -- and treating them as two disabled the
    repository-declaration inference that reports a missing extra dependency.
    """
    from blastbox.host.pins import missing_from_locks

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["blastbox[s3]>=0.1.39,<0.2"]\n'
    )
    _write(tmp_path, "a.lock", _entry("blastbox==0.1.39") + _entry("pydantic==2.13.5"))
    _write(tmp_path, "b.lock", _entry("packaging==26.3") + _entry("backport==1.0"))
    (tmp_path / "one.txt").write_text("packaging>=20\n")
    (tmp_path / "two.txt").write_text("packaging>=21\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r a.lock -r b.lock -c one.txt\n"
        "RUN pip install --require-hashes -r b.lock -r a.lock -c two.txt\n"
    )
    requires = [*_RM, 's3only>=1.0; extra == "s3"']
    gaps = missing_from_locks(
        tmp_path, requires, environment={"python_version": "3.12"}
    )
    assert any("s3only" in g for entries in gaps.values() for g in entries), gaps


def test_both_constrained_resolutions_of_one_lock_are_reported(tmp_path):
    """Two commands over the same files share an output label.

    Assigning meant the second verdict replaced the first, so fixing what was
    reported merely revealed the other failure on the next run.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "requirements.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3")
        + _entry("backport==1.0"),
    )
    (tmp_path / "first.txt").write_text("packaging<23\n")
    (tmp_path / "second.txt").write_text("backport<1\n")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r requirements.lock -c first.txt\n"
        "RUN pip install --require-hashes -r requirements.lock -c second.txt\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    reported = gaps[str(tmp_path / "requirements.lock")]
    assert any("packaging" in g and "excluded" in g for g in reported), reported
    assert any("backport" in g and "excluded" in g for g in reported), reported


def test_a_co_restriction_on_an_exact_pin_still_counts(tmp_path):
    """`==26.3,!=26.3+vendor1` excludes the very candidate the other pins.

    Rebuilding the specifier from the version alone drops the `!=`, and the
    pair looks compatible while pip refuses to resolve it.
    """
    from blastbox.host.pins import missing_from_locks

    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3,!=26.3+vendor1"),
    )
    _write(
        tmp_path,
        "deps.lock",
        _entry("packaging==26.3+vendor1") + _entry("backport==1.0"),
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "RUN pip install --require-hashes -r blastbox.lock -r deps.lock\n"
    )
    gaps = missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"})
    assert any(
        "more than one version" in g for entries in gaps.values() for g in entries
    ), gaps
    # Control: without the exclusion the same pair is compatible.
    _write(
        tmp_path,
        "blastbox.lock",
        _entry("blastbox==0.1.39")
        + _entry("pydantic==2.13.5")
        + _entry("packaging==26.3"),
    )
    assert (
        missing_from_locks(tmp_path, _RM, environment={"python_version": "3.12"}) == {}
    )


def test_a_v_prefixed_target_is_still_a_version(tmp_path):
    """uv accepts `--python-version v3.9` and writes it into the header."""
    from blastbox.host.pins import _lock_environment

    header = (
        "# This file was autogenerated by uv via the following command:\n"
        "#    uv pip compile pyproject.toml --generate-hashes --python-version v3.9\n"
    )
    env = _lock_environment(header)
    assert env["python_version"] == "3.9", env
    assert env["python_full_version"] == "3.9.0", env
