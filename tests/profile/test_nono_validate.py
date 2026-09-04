"""Gated: the emitted nono profile passes nono's OWN `profile validate`."""

import json
import os
import shutil
import subprocess

import pytest

from blastbox.profile import PolicyDraft

_NONO = shutil.which("nono") or os.environ.get("BLASTBOX_NONO_BIN", "")
_HAVE_NONO = bool(_NONO and os.path.isfile(_NONO)) or shutil.which("nono") is not None


@pytest.mark.skipif(not _HAVE_NONO, reason="nono binary not installed")
def test_emitted_profile_validates_with_nono(tmp_path):
    d = PolicyDraft()
    d.read_paths = {"/usr/lib/x", "/etc/fonts/y"}
    d.write_paths = {"/tmp/out/a"}
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps(d.to_nono_profile("soffice")))
    nono = shutil.which("nono") or _NONO
    r = subprocess.run(
        [nono, "profile", "validate", str(pf)],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert "valid" in (r.stdout + r.stderr).lower() and r.returncode == 0, (
        r.stdout + r.stderr
    )
