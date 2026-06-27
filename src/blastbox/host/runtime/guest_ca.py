"""Install TLS trust anchors (CA certs) into a libvirt worker's guest trust store over SSH.

For HTTPS/TLS interception of a worker's traffic — e.g. routing it through a FakeNet-NG / mitmproxy
sinkhole that MITMs TLS — the guest must trust the interceptor's CA, otherwise every HTTPS flow
fails the handshake and only the destination (DNS + TCP) is observable, not the decrypted body.

Getting a CA into a guest's trust store is guest-OS-specific (Windows ``LocalMachine\\Root`` vs the
Linux ca-certificates dir), so blastbox provides it once here rather than every libvirt-worker engine
reinventing it. Call it from a worker's finalize path (the runtime does this when
``LibvirtVmConfig.trust_anchors`` is set) so the trust anchor is captured in the warm snapshot and
every restored worker inherits it.

The cert bytes are embedded (base64) in the install command itself — ONE SSH call per cert, no scp.
That sidesteps broken/locked-down file transfer (e.g. a Windows guest whose default shell is
PowerShell, where scp does not work) and needs no writable share.

SECURITY NOTE: a MITM CA is a trusted root — anything it signs validates. NEVER install one into a
guest whose job is to *judge* trust (e.g. a certificate validator); use it only for interception
workers where the guest is the thing being observed, not the oracle.
"""
from __future__ import annotations

import base64
import logging
import subprocess

logger = logging.getLogger(__name__)

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=15",
]


def windows_install_command(cert_bytes: bytes, name: str) -> str:
    """A self-contained Windows remote command: decode the embedded cert, write it to %TEMP%, and
    import it into ``LocalMachine\\Root``. base64 ``-EncodedCommand`` dodges SSH→PowerShell quoting;
    the cert content rides inside it (no scp)."""
    cert_b64 = base64.b64encode(cert_bytes).decode()
    ps = (
        f"$b=[Convert]::FromBase64String('{cert_b64}');"
        f"$p=Join-Path $env:TEMP 'bb_anchor_{name}.crt';"
        "[IO.File]::WriteAllBytes($p,$b);"
        "Import-Certificate -FilePath $p -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null;"
        "Remove-Item $p -Force -ErrorAction SilentlyContinue"
    )
    return "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + \
        base64.b64encode(ps.encode("utf-16-le")).decode()


def linux_install_command(cert_bytes: bytes, name: str) -> str:
    """A self-contained Debian/RHEL remote command: decode the embedded cert into the trust-source dir
    that the AVAILABLE tool actually reads, then refresh the store.

    Debian's ``update-ca-certificates`` reads ``/usr/local/share/ca-certificates``; RHEL/Fedora's
    ``update-ca-trust`` reads ``/etc/pki/ca-trust/source/anchors``. Writing to the Debian path and
    falling back to ``update-ca-trust extract`` would leave the CA UNTRUSTED on RHEL (wrong source
    dir), so pick the destination by which tool exists."""
    cert_b64 = base64.b64encode(cert_bytes).decode()  # [A-Za-z0-9+/=] — safe unquoted in `b=...`
    deb = f"/usr/local/share/ca-certificates/bb_anchor_{name}.crt"
    rhel = f"/etc/pki/ca-trust/source/anchors/bb_anchor_{name}.crt"
    return ("sh -c '"
            f"b={cert_b64}; "
            "if command -v update-ca-certificates >/dev/null 2>&1; then "
            f"echo $b | base64 -d > {deb} && update-ca-certificates; "
            "elif command -v update-ca-trust >/dev/null 2>&1; then "
            f"echo $b | base64 -d > {rhel} && update-ca-trust extract; "
            "else exit 1; fi'")


def install_trust_anchors(
    host: str,
    certs: list[str],
    *,
    user: str,
    key_path: str,
    port: int = 22,
    guest_os: str = "windows",
    timeout: float = 60.0,
    runner=subprocess.run,
) -> bool:
    """Read each CA cert file and install it into the guest trust store over SSH (one call per cert,
    cert bytes embedded — no scp). Returns True iff every cert installed cleanly. Best-effort +
    non-fatal at the call site: a failed anchor must not strand a worker, but the caller should log
    when interception silently won't decrypt. ``runner`` is injectable for testing."""
    ssh_base = ["ssh", "-n", *_SSH_OPTS, "-p", str(port), "-i", key_path, f"{user}@{host}"]
    ok = True
    for i, cert in enumerate(certs):
        try:
            with open(cert, "rb") as fh:
                data = fh.read()
        except OSError:
            logger.warning("guest_ca: cannot read trust anchor %s", cert)
            ok = False
            continue
        remote_cmd = (windows_install_command(data, str(i)) if guest_os == "windows"
                      else linux_install_command(data, str(i)))
        if runner([*ssh_base, remote_cmd], capture_output=True, text=True, timeout=timeout).returncode != 0:
            logger.warning("guest_ca: installing %s into the %s trust store failed", cert, guest_os)
            ok = False
    return ok
