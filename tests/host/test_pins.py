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
