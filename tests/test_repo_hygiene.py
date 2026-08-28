"""No tracked file may be a symlink pointing outside the repository.

A `.venv` symlink into a scratch worktree was committed as a mode-120000 blob. In every other
checkout it is a DANGLING symlink, and because the path already exists the README's own setup step
(`python3 -m venv .venv`) refuses to run, leaving every documented `.venv/bin/...` command --
including this suite's own gates -- unusable. `.gitignore` did not stop it: a pattern with a
trailing slash (`.venv/`) matches directories only, never a symlink of the same name.
"""
import os
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _tracked_symlinks() -> "list[tuple[str, str]] | None":
    """(path, target) for every tracked symlink, or None if git cannot answer."""
    try:
        out = subprocess.run(["git", "ls-files", "-s"], cwd=_ROOT, capture_output=True,
                             text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    found = []
    for line in out.stdout.splitlines():
        meta, _, path = line.partition("\t")
        if meta.split()[0] == "120000":
            link = _ROOT / path
            found.append((path, os.readlink(link) if link.is_symlink() else "<not present>"))
    return found


def test_no_tracked_symlink_escapes_the_repository() -> None:
    tracked = _tracked_symlinks()
    if tracked is None:                      # not a git checkout: scan the tree instead
        tracked = [
            (str(p.relative_to(_ROOT)), os.readlink(p))
            for p in _ROOT.rglob("*")
            if p.is_symlink() and ".git" not in p.parts
        ]
    escaping = []
    for path, target in tracked:
        resolved = Path(target) if os.path.isabs(target) else (_ROOT / path).parent / target
        try:
            resolved.resolve().relative_to(_ROOT)
        except ValueError:
            escaping.append(f"{path} -> {target}")
    assert not escaping, (
        "symlink(s) pointing outside the repo; in any other checkout these dangle:\n  "
        + "\n  ".join(escaping)
    )
