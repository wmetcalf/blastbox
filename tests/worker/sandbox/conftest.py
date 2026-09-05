"""Shared host probes for the sandbox backends.

`nsjail_usable()` lives here because two modules need the same answer and had different
ones: `test_nsjail.py` ran a real one-shot to decide, while `test_detect.py` checked only
that the BINARY existed. On a host where nsjail is installed but unprivileged user
namespaces are restricted -- Ubuntu 24.04's default, and the state of this workstation --
the second guard let a test run that could not pass, and `select_sandbox` correctly raised
`SandboxUnavailable`.

That difference was invisible while nsjail was installed NOWHERE that runs these tests.
"""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def nsjail_usable() -> str | None:
    """The reason nsjail cannot be used here, or None if it can.

    Asks the HOST by running nsjail, not the product by asking its selector: a test that
    asserts `select_sandbox` succeeds cannot use that same selector to decide whether to run.
    Cached because it spawns a process and several tests ask.
    """
    if not shutil.which("nsjail"):
        return "nsjail not installed"
    true_path = "/usr/bin/true" if Path("/usr/bin/true").exists() else "/bin/true"
    try:
        r = subprocess.run(
            [
                "nsjail",
                "--mode", "o",
                "--user", "65534",
                "--group", "65534",
                "--quiet", "--really_quiet",
                "--bindmount_ro", "/usr:/usr",
                "--symlink", "usr/bin:/bin",
                "--symlink", "usr/lib:/lib",
                "--symlink", "usr/lib64:/lib64",
                "--symlink", "usr/sbin:/sbin",
                "--bindmount_ro", "/etc:/etc",
                "--tmpfsmount", "/tmp",
                "--",
                true_path,
            ],
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return f"nsjail probe failed: {exc}"
    if r.returncode != 0:
        return (
            f"nsjail user-namespace not usable on this host "
            f"(exit={r.returncode}, stderr={r.stderr.decode(errors='replace')[:200]!r})"
        )
    return None
