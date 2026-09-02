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
