"""`blastbox.__version__` must report the INSTALLED distribution, not a source literal.

A fleet running a host-side fix that is not on PyPI installs a wheel stamped with a PEP 440
local version (`0.1.26+g<sha>`, from deploy/build_dev_wheel.sh) so the deployed artifact cannot
be mistaken for the release it was built on. A hardcoded `__version__` reports the bare release
for that wheel -- which makes the one attribute an operator reaches for to answer "what is
actually deployed here?" the one attribute that cannot see the difference.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import tomllib
from importlib.metadata import version as dist_version
from pathlib import Path

import blastbox


def test_version_matches_the_installed_distribution():
    assert blastbox.__version__ == dist_version("blastbox")


def test_a_local_version_wheel_is_reported_as_such(monkeypatch):
    """The test above is VACUOUS in a checkout whose installed metadata happens to equal the
    literal -- which is every normal dev environment, and is why pinning `__version__` back to
    the literal survived it. Force the case that actually matters: metadata that DIFFERS.

    MUTATION: `__version__ = _FALLBACK_VERSION` -> reports the bare release for a wheel that is
    not the release, and this fails.
    """
    stamped = f"{blastbox._FALLBACK_VERSION}+g0ffee11"
    monkeypatch.setattr(importlib.metadata, "version", lambda name: stamped)
    reloaded = importlib.reload(blastbox)
    try:
        assert reloaded.__version__ == stamped, (
            f"a pre-release wheel installed as {stamped} reported itself as "
            f"{reloaded.__version__!r} -- indistinguishable from the release"
        )
    finally:
        monkeypatch.undo()
        importlib.reload(blastbox)


def test_the_fallback_literal_still_tracks_pyproject():
    """The fallback is what an UNINSTALLED source tree reports, so it must not rot.

    MUTATION: bump pyproject's version without touching the literal -> this fails, which is the
    entire job the old `# keep in sync` comment was doing by hope alone.
    """
    root = Path(blastbox.__file__).resolve().parents[2]
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():          # installed-only environment; nothing to compare against
        return
    declared = tomllib.loads(pyproject.read_text())["project"]["version"]
    assert blastbox._FALLBACK_VERSION == declared, (
        f"fallback {blastbox._FALLBACK_VERSION!r} != pyproject {declared!r}"
    )


def test_an_uninstalled_source_tree_still_imports(monkeypatch):
    """A checkout on sys.path with no dist-info has no metadata to read; importing blastbox
    there must still work (that is what the literal is FOR).

    MUTATION: drop the PackageNotFoundError fallback and re-raise -> `import blastbox` dies in
    every uninstalled checkout, including the one a contributor just cloned.
    """
    literal = blastbox._FALLBACK_VERSION

    def _no_metadata(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", _no_metadata)
    try:
        reloaded = importlib.reload(blastbox)
        assert reloaded.__version__ == literal
    finally:
        monkeypatch.undo()
        importlib.reload(blastbox)
