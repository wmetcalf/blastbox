"""`blastbox macos doctor`: every probe has a control, and failures are reported."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from blastbox.worker.sandbox import macos_tool
from blastbox.worker.sandbox.base import SandboxResult

pytestmark = pytest.mark.host_platform
darwin = pytest.mark.skipif(sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists(),
                            reason="needs macOS")


class _Unconfined:
    """A 'sandbox' that confines nothing: doctor must FAIL it, not pass it."""

    name = "fake"
    secure = True

    def run(self, request):
        import subprocess
        r = subprocess.run(request.argv, capture_output=True)
        return SandboxResult(exit_code=r.returncode, stdout=r.stdout, stderr=r.stderr)


@darwin
def test_an_unconfined_backend_fails_the_confinement_probes():
    checks = macos_tool.doctor(backends=["fake"], self_test=None, accelerators=frozenset(),
                               ro=[], make=lambda name: _Unconfined())
    by = {c.name: c.ok for c in checks}
    assert by["runs /usr/bin/true"] is True
    assert by["ungranted file is unreadable"] is False
    assert by["write outside grants is denied"] is False
    assert by["network connect is denied (loopback listener)"] is False


@darwin
def test_seatbelt_passes_doctor():
    checks = macos_tool.doctor(backends=["seatbelt"], self_test=None,
                               accelerators=frozenset(), ro=[])
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]


@darwin
def test_failing_self_test_fails_doctor():
    checks = macos_tool.doctor(backends=["seatbelt"], self_test=["/usr/bin/false"],
                               accelerators=frozenset(), ro=[])
    assert [c.ok for c in checks if c.name.startswith("self-test")] == [False]


def test_non_darwin_reports_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(macos_tool.sys, "platform", "linux")
    checks = macos_tool.doctor(backends=["seatbelt"], self_test=None,
                               accelerators=frozenset(), ro=[])
    assert len(checks) == 1 and not checks[0].ok


def _doctor_exit(monkeypatch, exc):
    def fake_doctor(**kw):
        return [macos_tool.Check("seatbelt", "backend available", True),
                macos_tool.Check("appsandbox", "backend available", False, str(exc),
                                 unprepared=isinstance(exc, macos_tool.AppSandboxNotPrepared))]
    monkeypatch.setattr(macos_tool, "doctor", fake_doctor)
    return macos_tool.main(["doctor"])


def test_an_unprepared_appsandbox_does_not_fail_the_default_doctor(monkeypatch, capsys):
    assert _doctor_exit(monkeypatch, macos_tool.AppSandboxNotPrepared("not prepared")) == 0


def test_a_broken_prepared_appsandbox_fails_the_default_doctor(monkeypatch, capsys):
    from blastbox.errors import SandboxUnavailable
    assert _doctor_exit(monkeypatch, SandboxUnavailable("slot 0: signature invalid")) == 1


def test_doctor_marks_only_a_missing_manifest_as_unprepared(tmp_path):
    import json
    from blastbox.worker.sandbox import appsandbox as asb
    if sys.platform != "darwin":
        pytest.skip("needs macOS")
    missing = macos_tool.doctor(backends=["appsandbox"], self_test=None, accelerators=frozenset(),
                                ro=[], appsandbox_root=tmp_path / "none")
    assert missing[0].unprepared is True
    (tmp_path / "old").mkdir()
    (tmp_path / "old" / asb.MANIFEST_NAME).write_text(json.dumps({"version": 999}))
    old = macos_tool.doctor(backends=["appsandbox"], self_test=None, accelerators=frozenset(),
                            ro=[], appsandbox_root=tmp_path / "old")
    assert old[0].ok is False and old[0].unprepared is False
