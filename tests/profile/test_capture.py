"""StraceCapture parsing — deterministic against a sample strace log."""
from pathlib import Path

from blastbox.profile import StraceCapture

_SAMPLE = r'''1234 execve("/usr/bin/soffice", ["soffice"], 0x7f) = 0
1234 openat(AT_FDCWD, "/usr/lib/libreoffice/program/libuno.so", O_RDONLY|O_CLOEXEC) = 3
1234 newfstatat(AT_FDCWD, "/etc/fonts/fonts.conf", {st_mode=S_IFREG}, 0) = 0
1234 openat(AT_FDCWD, "/tmp/out/page-001.pdf", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
1235 socket(AF_UNIX, SOCK_STREAM, 0) = 5
1235 connect(5, {sa_family=AF_UNIX, sun_path="@/tmp/dbus-abc"}, 12) = 0
1234 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f00
1234 +++ exited with 0 +++
'''

_WITH_EGRESS = _SAMPLE + (
    '1236 connect(7, {sa_family=AF_INET, sin_port=htons(443), '
    'sin_addr=inet_addr("93.184.216.34")}, 16) = 0\n'
)


def test_wrap_builds_strace_argv(tmp_path):
    argv = StraceCapture().wrap(["soffice", "--convert-to", "pdf"], tmp_path / "t.log")
    assert argv[0] == "strace" and "-f" in argv and argv[-3:] == ["soffice", "--convert-to", "pdf"]
    assert "-o" in argv and str(tmp_path / "t.log") in argv


def test_parse_extracts_syscalls_paths_net(tmp_path):
    log = tmp_path / "t.log"
    log.write_text(_SAMPLE)
    d = StraceCapture().parse(log)
    assert {"execve", "openat", "newfstatat", "socket", "connect", "mmap"} <= d.syscalls
    assert "exited" not in d.syscalls
    assert "/tmp/out/page-001.pdf" in d.write_paths            # O_WRONLY|O_CREAT
    assert "/usr/lib/libreoffice/program/libuno.so" in d.read_paths
    assert "/etc/fonts/fonts.conf" in d.read_paths
    assert "/tmp/out/page-001.pdf" not in d.read_paths          # write, not read
    assert d.net.unix is True and d.net.inet == set()           # local IPC only


def test_parse_flags_inet_egress(tmp_path):
    log = tmp_path / "t.log"
    log.write_text(_WITH_EGRESS)
    d = StraceCapture().parse(log)
    assert ("93.184.216.34", 443) in d.net.inet                # real egress flagged


def test_parse_path_in_memory(tmp_path: Path):
    log = tmp_path / "t.log"
    log.write_text(_SAMPLE)
    d = StraceCapture().parse(log)
    assert d.denylist_violations({"ptrace", "bpf", "kexec_load"}) == set()


def test_parse_is_line_bounded_no_bleed(tmp_path):
    """A truncated/odd line must not let a path match bleed across lines into garbage
    (the bug: whole-text [^"]+ spanning newlines produced paths like '/, O_RDONLY) = 13')."""
    log = tmp_path / "t.log"
    log.write_text(
        '1 openat(AT_FDCWD, "/usr/lib/a", O_RDONLY) = 3\n'
        '2 openat(AT_FDCWD, "/etc/b", O_RDONLY) = 4\n'
        '3 write(5, "junk with ) and , chars no path here", 36) = 36\n'
    )
    d = StraceCapture().parse(log)
    assert d.read_paths == {"/usr/lib/a", "/etc/b"}
    for p in d.read_paths | d.write_paths:
        assert ")" not in p and "O_RDONLY" not in p and "\n" not in p
