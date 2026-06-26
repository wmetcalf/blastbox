"""Unit tests for guest TLS trust-anchor installation (pure; no SSH/guest needed)."""
from __future__ import annotations

import base64

from blastbox.host.runtime.guest_ca import (
    install_trust_anchors,
    linux_install_command,
    windows_install_command,
)


def test_windows_install_command_embeds_cert_and_imports():
    cmd = windows_install_command(b"-----BEGIN CERTIFICATE-----\nABC\n", "0")
    assert cmd.startswith("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ")
    decoded = base64.b64decode(cmd.split()[-1]).decode("utf-16-le")
    assert "Import-Certificate" in decoded
    assert "Cert:\\LocalMachine\\Root" in decoded
    assert "FromBase64String" in decoded  # cert bytes embedded, not scp'd


def test_linux_install_command_embeds_cert_and_updates_store():
    cmd = linux_install_command(b"PEMDATA", "0")
    assert "/usr/local/share/ca-certificates/bb_anchor_0.crt" in cmd
    assert "base64 -d" in cmd
    assert "update-ca-certificates" in cmd


class _Runner:
    """Records the argv of each subprocess call; returns rc from a script."""

    def __init__(self, rcs):
        self.calls: list[list[str]] = []
        self._rcs = list(rcs)

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        rc = self._rcs.pop(0) if self._rcs else 0

        class _R:
            returncode = rc
            stdout = ""
            stderr = ""
        return _R()


def test_install_one_ssh_per_cert_no_scp(tmp_path):
    cert = tmp_path / "fakenet_ca.crt"
    cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nXYZ\n")
    r = _Runner([0])  # one ssh, ok
    ok = install_trust_anchors("192.168.122.9", [str(cert)],
                               user="Administrator", key_path="/k", guest_os="windows", runner=r)
    assert ok is True
    assert len(r.calls) == 1 and r.calls[0][0] == "ssh"           # no scp
    assert r.calls[0][-2] == "Administrator@192.168.122.9"
    assert "EncodedCommand" in r.calls[0][-1]


def test_install_reports_false_when_cert_unreadable():
    r = _Runner([])
    ok = install_trust_anchors("h", ["/no/such/ca.crt"], user="root", key_path="/k",
                               guest_os="linux", runner=r)
    assert ok is False
    assert r.calls == []  # unreadable cert -> never reaches SSH


def test_install_reports_false_when_ssh_fails(tmp_path):
    cert = tmp_path / "c.crt"
    cert.write_bytes(b"PEM")
    r = _Runner([1])  # ssh fails
    ok = install_trust_anchors("h", [str(cert)], user="root", key_path="/k",
                               guest_os="linux", runner=r)
    assert ok is False and "base64 -d" in r.calls[0][-1]
