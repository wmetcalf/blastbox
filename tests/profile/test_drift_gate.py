"""The drift-gate: profile a real conversion and assert it stays within bounds.

Two layers:
  * a strace-only pipeline check (runs wherever strace exists) — proves profile_command
    captures syscalls + the opened path for a trivial command;
  * the soffice drift-gate (strace + soffice) — profiles a real docx/odt→pdf and asserts
    the engine uses NO escape-only syscall and opens NO real network egress. This is the
    CI regression check: it fails if a dependency bump quietly widens the syscall/net
    surface (e.g. soffice suddenly phoning home, or needing ptrace).

Both skip cleanly where the tools are absent, so the suite is safe to run anywhere.
"""

import shutil

import pytest

from blastbox.profile import profile_command

_HAVE_STRACE = shutil.which("strace") is not None
_HAVE_SOFFICE = shutil.which("soffice") is not None

# Escape-only syscalls that must NEVER appear in a document conversion (mirrors the
# shipped seccomp denylist's intent — container-escape / host-state chains).
_ESCAPE_DENYLIST = {
    "bpf",
    "keyctl",
    "add_key",
    "request_key",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "mount",
    "umount2",
    "pivot_root",
    "swapon",
    "setns",
    "unshare",
    "reboot",
    "settimeofday",
    "sethostname",
    "iopl",
    "ioperm",
    "name_to_handle_at",
    "open_by_handle_at",
    "perf_event_open",
    "userfaultfd",
    "fanotify_init",
    "acct",
    "quotactl",
}


@pytest.mark.skipif(not _HAVE_STRACE, reason="strace not installed")
def test_pipeline_captures_command(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("hello drift gate")
    draft = profile_command(["/bin/cat", str(f)], trace_dir=tmp_path)
    assert "openat" in draft.syscalls or "open" in draft.syscalls
    assert str(f) in draft.read_paths
    assert draft.net.inet == set()  # cat opens no sockets


@pytest.mark.skipif(
    not (_HAVE_STRACE and _HAVE_SOFFICE), reason="needs strace + soffice"
)
def test_soffice_conversion_stays_within_bounds(tmp_path):
    # minimal Flat ODT — soffice renders it natively to PDF
    src = tmp_path / "in.fodt"
    src.write_text(
        '<?xml version="1.0"?><office:document '
        'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        'office:version="1.2" office:mimetype="application/vnd.oasis.opendocument.text">'
        "<office:body><office:text><text:p>drift gate</text:p></office:text>"
        "</office:body></office:document>"
    )
    outdir = tmp_path / "out"
    outdir.mkdir()
    home = tmp_path / "h"
    home.mkdir()
    argv = [
        "soffice",
        "--headless",
        "--nologo",
        "--nofirststartwizard",
        "--nolockcheck",
        f"-env:UserInstallation=file://{home}/lou",
        "--convert-to",
        "pdf",
        "--outdir",
        str(outdir),
        str(src),
    ]
    draft = profile_command(argv, trace_dir=tmp_path, label="soffice")

    # captured a real run (soffice makes hundreds of syscalls)
    assert len(draft.syscalls) > 20, f"suspiciously few syscalls: {draft.syscalls}"
    # DRIFT-GATE assertions:
    violations = draft.denylist_violations(_ESCAPE_DENYLIST)
    assert violations == set(), f"soffice used escape-only syscalls: {violations}"
    assert draft.net.inet == set(), f"soffice opened network egress: {draft.net.inet}"
