"""blastbox — reusable detonation framework for untrusted documents.

Engine authors need only the lean core (`pip install blastbox`): implement the
``Engine`` protocol's ``detonate()`` and return a ``DetonationResult``; the
host orchestrator (``blastbox[host]``) handles ingress, disposable-worker
launch, output-trust validation, and serving.
"""
from importlib.metadata import PackageNotFoundError, version as _dist_version

from blastbox.worker.engine import DetonationResult, Engine
from blastbox.worker.harness import run_detonation

# Report what is INSTALLED, not what this file was written with. A fleet running a pre-release
# host fix installs a wheel stamped with a PEP 440 local version (0.1.26+g<sha>, see
# deploy/build_dev_wheel.sh); a hardcoded literal here reports the plain release for it, so the
# one attribute an operator reaches for to answer "what is actually deployed?" is precisely the
# one that cannot tell a pre-release apart from the release it was built on.
#
# The literal remains the fallback for an uninstalled source tree (a checkout on sys.path with
# no dist-info), where there is no metadata to read and this file is the only answer available.
_FALLBACK_VERSION = "0.1.30"  # keep in sync with pyproject [project].version
try:
    __version__ = _dist_version("blastbox")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = _FALLBACK_VERSION

__all__ = ["Engine", "DetonationResult", "run_detonation", "__version__"]
