"""App Sandbox backend: prepare/manifest, slot staging + wipe, and real confinement.

``TestReal*`` builds real ad-hoc-signed slots (needs macOS + clang + codesign). They use a
FIXED bundle prefix so repeated runs reuse the same two ``~/Library/Containers`` entries
instead of minting new ones per tmp dir.
"""
from __future__ import annotations

import fcntl
import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox import appsandbox as asb
from blastbox.worker.sandbox import macos_common as mc
from blastbox.worker.sandbox.base import Mount, SandboxRequest

pytestmark = pytest.mark.host_platform

REAL = (sys.platform == "darwin" and shutil.which("clang") is not None
        and Path("/usr/bin/codesign").exists())
needs_real = pytest.mark.skipif(not REAL, reason="needs macOS with clang + codesign")
TEST_PREFIX = "io.blastbox.pytest"


def _fake_runner(calls):
    def run(argv, **kw):
        calls.append(argv)
        if argv[0].endswith("clang"):
            out = Path(argv[argv.index("-o") + 1])
            out.write_bytes(b"\xcf\xfa\xed\xfe fake launcher")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    return run


class TestPrepare:
    def test_manifest_and_per_slot_entitlements(self, tmp_path):
        engine = tmp_path / "engine"
        engine.mkdir()
        calls: list[list[str]] = []
        m = asb.prepare(tmp_path / "root", slots=3, ro_paths=[engine],
                        runner=_fake_runner(calls))
        assert [s.index for s in m.slots] == [0, 1, 2]
        assert len({s.bundle_id for s in m.slots}) == 3
        for s in m.slots:
            ent = plistlib.loads((s.bundle.parent / "entitlements.plist").read_bytes())
            assert ent[asb._APP_SANDBOX] is True
            # Each slot may write ONLY its own io dir -- never a sibling's.
            assert ent[asb._RW_EXCEPTION] == [str(s.io_dir) + "/"]
            assert ent[asb._RO_EXCEPTION] == [str(engine.resolve()) + "/"]
            info = plistlib.loads((s.bundle / "Contents" / "Info.plist").read_bytes())
            assert info["CFBundleIdentifier"] == s.bundle_id
            assert info["CFBundleExecutable"] == asb.LAUNCHER_EXE
        signs = [c for c in calls if c[0].endswith("codesign")]
        assert len(signs) == 3 and all(["--sign", "-"] == c[2:4] for c in signs)
        loaded = asb.Manifest.load(m.root)
        assert loaded.slots == m.slots and loaded.ro_paths == m.ro_paths

    def test_ro_path_overlapping_root_refused(self, tmp_path):
        with pytest.raises(SandboxError, match="overlaps"):
            asb.prepare(tmp_path / "root", slots=1, ro_paths=[tmp_path], runner=_fake_runner([]))

    def test_shrinking_removes_stale_slots(self, tmp_path):
        root = tmp_path / "root"
        asb.prepare(root, slots=3, ro_paths=[], runner=_fake_runner([]))
        asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
        assert sorted(p.name for p in (root / "slots").iterdir()) == ["0"]

    @pytest.mark.parametrize("n", [0, 257])
    def test_slot_bounds(self, tmp_path, n):
        with pytest.raises(SandboxError):
            asb.prepare(tmp_path / "r", slots=n, ro_paths=[], runner=_fake_runner([]))

    def test_unprepared_root_is_unavailable(self, tmp_path):
        with pytest.raises(SandboxUnavailable, match="not prepared"):
            asb.AppSandboxSandbox(root=tmp_path, platform_ok=True, verify=False)

    def test_manifest_version_mismatch(self, tmp_path):
        (tmp_path / asb.MANIFEST_NAME).write_text(json.dumps({"version": 999}))
        with pytest.raises(SandboxUnavailable, match="version"):
            asb.Manifest.load(tmp_path)

    def test_refuses_off_darwin(self, tmp_path):
        with pytest.raises(SandboxUnavailable):
            asb.AppSandboxSandbox(root=tmp_path, platform_ok=False)


class _Popen:
    """Runs the TARGET (argv[3:]) unsandboxed, standing in for the signed launcher -- including
    its handshake (``handshake=False``: a chain that dies before the sandboxed launcher)."""

    def __init__(self, handshake=True):
        self.calls = []
        self.handshake = handshake

    def __call__(self, argv, **kw):
        inner = mc.unwrap_launcher(argv)
        self.calls.append((inner, kw))
        if self.handshake:
            Path(inner[1]).write_text(inner[2])
        return subprocess.Popen(inner[3:], **kw)


class TestRunStaging:
    @pytest.fixture
    def setup(self, tmp_path):
        root = tmp_path / "root"
        asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]))
        home = tmp_path / "home"
        popen = _Popen()
        sb = asb.AppSandboxSandbox(root=root, popen=popen, home=home, platform_ok=True,
                                   verify=False, slot_wait_s=0)
        return sb, popen, home, tmp_path

    def test_mounts_are_staged_rewritten_and_copied_back(self, setup):
        sb, popen, home, tmp = setup
        inp = tmp / "job" / "input.bin"
        inp.parent.mkdir()
        inp.write_text("payload")
        out = tmp / "job" / "out"
        out.mkdir()
        (out / "stale").write_text("from a previous attempt")
        r = sb.run(SandboxRequest(
            argv=["/bin/sh", "-c", 'cat "$0" > "$1/copy" && rm "$1/stale" && echo "$0"',
                  str(inp), str(out)],
            ro_mounts=[Mount(inp, inp)], rw_mounts=[Mount(out, out)],
        ))
        assert r.exit_code == 0, r.stderr
        argv, kw = popen.calls[0]
        slot = sb.manifest.slots[0]
        assert argv[0] == str(slot.launcher)
        # The child saw the staged copy, never the real job path.
        assert str(inp) not in argv and r.stdout.decode().startswith(str(slot.io_dir))
        assert (out / "copy").read_text() == "payload"
        assert not (out / "stale").exists()        # bind-mount semantics: a child delete lands
        assert list(slot.io_dir.iterdir()) == []    # wiped after the run

    def test_container_data_is_wiped(self, setup):
        sb, _, home, _ = setup
        slot = sb.manifest.slots[0]
        data = slot.container_data(home)
        data.mkdir(parents=True)
        (data / "planted-by-last-job").write_text("x")
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
        assert list(data.iterdir()) == []

    def test_exec_outside_prepared_paths_refused(self, setup):
        sb, _, _, tmp = setup
        tool = tmp / "tool"
        tool.write_text("#!/bin/sh\n")
        tool.chmod(0o755)
        with pytest.raises(SandboxError, match="prepare --ro"):
            sb.run(SandboxRequest(argv=[str(tool)]))

    def test_all_slots_busy(self, setup):
        sb, _, _, _ = setup
        fds = []
        try:
            for slot in sb.manifest.slots:
                fd = os.open(slot.lock_path, os.O_RDWR | os.O_CREAT)
                fcntl.flock(fd, fcntl.LOCK_EX)
                fds.append(fd)
            with pytest.raises(SandboxError, match="busy"):
                sb.run(SandboxRequest(argv=["/usr/bin/true"]))
        finally:
            for fd in fds:
                os.close(fd)

    def test_sigtrap_gets_an_actionable_hint(self, setup):
        sb, _, _, _ = setup
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", "kill -TRAP $$"]))
        assert b"com.apple.security.inherit" in r.stderr


@pytest.fixture(scope="module")
def real_sb(tmp_path_factory):
    root = tmp_path_factory.mktemp("asroot")
    asb.prepare(root, slots=2, ro_paths=[], bundle_prefix=TEST_PREFIX)
    return asb.AppSandboxSandbox(root=root)


@needs_real
class TestRealAppSandbox:
    @pytest.fixture
    def sb(self, real_sb):
        return real_sb

    def test_signed_slots_verify(self, sb):
        assert all(asb.verify_slot(s) is None for s in sb.manifest.slots)

    def test_true_runs(self, sb):
        assert sb.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0

    def test_home_is_unreadable(self, sb):
        r = sb.run(SandboxRequest(argv=["/bin/ls", str(Path.home() / "Documents")]))
        assert r.exit_code != 0

    def test_network_denied(self, sb):
        r = sb.run(SandboxRequest(argv=["/usr/bin/nc", "-z", "-w", "3", "1.1.1.1", "80"],
                                  limits=Limits(timeout_s=20)))
        assert r.exit_code != 0

    def test_staged_round_trip(self, sb, tmp_path):
        inp = tmp_path / "in.txt"
        inp.write_text("payload")
        out = tmp_path / "out"
        out.mkdir()
        r = sb.run(SandboxRequest(
            argv=["/bin/sh", "-c", 'cat "$0" > "$1/copy"', str(inp), str(out)],
            ro_mounts=[Mount(inp, inp)], rw_mounts=[Mount(out, out)]))
        assert r.exit_code == 0, r.stderr
        assert (out / "copy").read_text() == "payload"

    def test_unsigned_launcher_fails_closed(self, sb, tmp_path):
        # Run the launcher binary OUTSIDE its bundle (no App Sandbox applied): it must refuse.
        raw = sb.manifest.root / "build" / asb.LAUNCHER_EXE
        marker = tmp_path / "marker"
        r = subprocess.run([str(raw), str(marker), "n", "/usr/bin/true"], capture_output=True)
        assert r.returncode == 70 and b"not sandboxed" in r.stderr
        assert not marker.exists()          # no handshake from an unsandboxed launcher


@needs_real
def test_seed_and_capture_use_the_container_and_cannot_be_poisoned(real_sb, tmp_path):
    sb = real_sb
    write = 'mkdir -p "$HOME/Library/Caches/x" && echo plan > "$HOME/Library/Caches/x/p"'
    sb.run(SandboxRequest(argv=["/usr/bin/true"]))       # first launch creates the container
    seed = tmp_path / "seed"
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", write], capture_home=seed))
    assert r.exit_code == 0, r.stderr
    assert (seed / "Library" / "Caches" / "x" / "p").read_text() == "plan\n"
    poison = 'cat "$HOME/Library/Caches/x/p" && echo poisoned > "$HOME/Library/Caches/x/p"'
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", poison], seed_home=seed))
    assert r.stdout == b"plan\n"
    assert (seed / "Library" / "Caches" / "x" / "p").read_text() == "plan\n"
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'cat "$HOME/Library/Caches/x/p"'], seed_home=seed))
    assert r.stdout == b"plan\n"


def test_a_slot_that_cannot_be_wiped_is_retired(tmp_path, monkeypatch):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home", platform_ok=True,
                               verify=False, slot_wait_s=0)
    slot = sb.manifest.slots[0]

    def stuck(path):
        raise SandboxError(f"could not empty {path}: ['planted']")
    monkeypatch.setattr(mc, "wipe_dir", stuck)
    with pytest.raises(SandboxError, match="could not empty"):
        sb.run(SandboxRequest(argv=["/bin/echo", "x"]))
    assert asb.AppSandboxSandbox.retired_marker(slot).exists()
    monkeypatch.undo()
    # Never handed out again -- until `prepare` is re-run.
    with pytest.raises(SandboxError, match="every appsandbox slot is retired"):
        sb.run(SandboxRequest(argv=["/bin/echo", "x"]))
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    assert not asb.AppSandboxSandbox.retired_marker(slot).exists()


class _PrimingPopen(_Popen):
    """Like _Popen, but a launch of ``/usr/bin/true`` creates the slot's container, the way
    containermanagerd does on a real slot's first launch."""

    def __init__(self, container):
        super().__init__()
        self.container = container

    def __call__(self, argv, **kw):
        if mc.unwrap_launcher(argv)[3:] == ["/usr/bin/true"]:
            self.container.mkdir(parents=True, exist_ok=True)
        return super().__call__(argv, **kw)


def _seed(tmp_path):
    seed = tmp_path / "seed"
    (seed / "Library" / "Caches" / "x").mkdir(parents=True)
    (seed / "Library" / "Caches" / "x" / "p").write_text("plan\n")
    return seed


def test_a_fresh_slot_is_primed_so_the_first_run_gets_its_seed(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    home = tmp_path / "home"
    m = asb.Manifest.load(root)
    container = m.slots[0].container_data(home)
    popen = _PrimingPopen(container)
    sb = asb.AppSandboxSandbox(root=root, popen=popen, home=home, platform_ok=True,
                               verify=False, slot_wait_s=0)
    assert not container.exists()
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", f'cat "{container}/Library/Caches/x/p"'],
                              seed_home=_seed(tmp_path)))
    assert r.stdout == b"plan\n", r.stderr
    assert popen.calls[0][0][3:] == ["/usr/bin/true"]     # the priming launch came first


def test_a_seed_that_cannot_be_applied_fails_the_run_loudly(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                               platform_ok=True, verify=False, slot_wait_s=0)
    with pytest.raises(SandboxError, match="seed_home cannot be applied"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"], seed_home=_seed(tmp_path)))


def test_a_container_swapped_for_a_symlink_retires_the_slot(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    home = tmp_path / "home"
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=home, platform_ok=True,
                               verify=False, slot_wait_s=0)
    slot = sb.manifest.slots[0]
    victim = tmp_path / "engine-install"
    victim.mkdir()
    (victim / "keep").write_text("x")
    data = slot.container_data(home)
    data.parent.mkdir(parents=True)
    data.symlink_to(victim)
    with pytest.raises(SandboxError, match="symlink"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert (victim / "keep").read_text() == "x"
    assert asb.AppSandboxSandbox.retired_marker(slot).exists()


@needs_real
def test_an_escapee_is_swept_from_the_slot_container(real_sb, tmp_path, monkeypatch):
    # Blind the watchdog: only the container sweep can find a forked, setsid()'d orphan.
    monkeypatch.setattr(mc.RssWatchdog, "_sample", lambda self: None)
    escape = ("use POSIX; my $pid = fork(); "
              "if ($pid) { select(undef, undef, undef, 0.01) until -s $ARGV[0]; exit 0 } "
              "POSIX::setsid(); close STDIN; close STDOUT; close STDERR; "
              "open(my $f, '>', $ARGV[0] . '.tmp') or die; print $f $$; close $f; "
              "rename($ARGV[0] . '.tmp', $ARGV[0]); sleep 30;")
    rw = tmp_path / "rw"
    rw.mkdir()
    r = real_sb.run(SandboxRequest(argv=["/usr/bin/perl", "-e", escape, str(rw / "pid")],
                                   rw_mounts=[Mount(rw, rw)]))
    assert r.exit_code == 0, r.stderr
    pid = int((rw / "pid").read_text())
    out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                         text=True).stdout.strip()
    assert not out or out.startswith("Z"), f"escapee {pid} survived the run"



def test_a_root_locked_by_the_child_retires_the_slot_instead_of_crashing(tmp_path, monkeypatch):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                               platform_ok=True, verify=False, slot_wait_s=0)
    slot = sb.manifest.slots[0]
    real_iterdir = mc.Path.iterdir

    def denied(self):
        if self == slot.io_dir:
            raise PermissionError(13, "Permission denied", str(self))
        return real_iterdir(self)
    monkeypatch.setattr(mc.Path, "iterdir", denied)
    with pytest.raises(SandboxError, match="could not empty"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert asb.AppSandboxSandbox.retired_marker(slot).exists()


@needs_real
def test_a_hidden_grandchild_is_metered_and_killed_during_the_run(real_sb, monkeypatch):
    import time
    monkeypatch.setattr(mc.RssWatchdog, "_ancestry", lambda self, table: {self._proc.pid})
    from tests.worker.sandbox.test_seatbelt import _HIDDEN_HOG as hog
    t0 = time.monotonic()
    r = real_sb.run(SandboxRequest(argv=["/usr/bin/perl", "-e", hog, "400"],
                                   limits=Limits(timeout_s=40, memory_bytes=150 * 1024 * 1024)))
    assert r.killed and b"RSS" in r.stderr, r.stderr
    assert time.monotonic() - t0 < 30



def _fake_root(tmp_path, name="root", prefix=None):
    root = tmp_path / name
    asb.prepare(root, slots=1, ro_paths=[], bundle_prefix=prefix, runner=_fake_runner([]))
    return root


def test_only_a_handshake_from_the_sandboxed_launcher_credits_the_run(tmp_path):
    from blastbox.worker.sandbox.base import confined_runs
    root = _fake_root(tmp_path)
    home = tmp_path / "home"
    before = confined_runs()
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=home, platform_ok=True,
                               verify=False, slot_wait_s=0)
    assert sb.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0
    assert confined_runs() == before + 1
    # The chain dies before the sandboxed launcher: here the "launcher" is prepare's fake bytes,
    # so the rlimit launcher's execve fails. Nothing ran confined; nothing is credited.
    sb = asb.AppSandboxSandbox(root=root, home=home, platform_ok=True, verify=False,
                               slot_wait_s=0)
    r = sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert r.exit_code != 0
    assert confined_runs() == before + 1
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(handshake=False), home=home,
                               platform_ok=True, verify=False, slot_wait_s=0)
    sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert confined_runs() == before + 1


def test_env_with_nul_is_refused_up_front(tmp_path):
    sb = asb.AppSandboxSandbox(root=_fake_root(tmp_path), popen=_Popen(), home=tmp_path / "home",
                               platform_ok=True, verify=False, slot_wait_s=0)
    for env in ({"K": "a\0b"}, {"K\0": "v"}, {"A=B": "v"}):
        with pytest.raises(SandboxError, match="invalid env entry"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"], env=env))


def test_roots_sharing_a_bundle_prefix_share_one_container_lock(tmp_path):
    home = tmp_path / "home"
    a = asb.AppSandboxSandbox(root=_fake_root(tmp_path, "a", prefix="io.blastbox.pytest.same"),
                              popen=_Popen(), home=home, platform_ok=True, verify=False,
                              slot_wait_s=0)
    b = asb.AppSandboxSandbox(root=_fake_root(tmp_path, "b", prefix="io.blastbox.pytest.same"),
                              popen=_Popen(), home=home, platform_ok=True, verify=False,
                              slot_wait_s=0)
    c = asb.AppSandboxSandbox(root=_fake_root(tmp_path, "c", prefix="io.blastbox.pytest.other"),
                              popen=_Popen(), home=home, platform_ok=True, verify=False,
                              slot_wait_s=0)
    assert a.manifest.slots[0].bundle_id == b.manifest.slots[0].bundle_id
    with a._acquire_slot():
        # b's own slot lock is free, but its container (same bundle id) is in use
        with pytest.raises(SandboxError, match="busy"):
            b.run(SandboxRequest(argv=["/usr/bin/true"]))
        assert c.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0
    assert b.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0


@needs_real
def test_a_real_sandboxed_launch_is_credited(real_sb):
    from blastbox.worker.sandbox.base import confined_runs
    before = confined_runs()
    assert real_sb.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0
    assert confined_runs() == before + 1


def _sb_with(tmp_path, popen=None, ro_paths=(), **kw):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=list(ro_paths), runner=_fake_runner([]))
    home = tmp_path / "home"
    sb = asb.AppSandboxSandbox(root=root, popen=popen or _Popen(), home=home, platform_ok=True,
                               verify=False, slot_wait_s=0, **kw)
    return sb, home


class TestStagingBudgetIsRunWide:
    def test_mounts_share_one_byte_budget(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        mounts = []
        for n in ("a", "b"):
            d = tmp_path / n
            d.mkdir()
            (d / "blob").write_bytes(b"x" * 600)
            mounts.append(Mount(d, d))
        with pytest.raises(SandboxError, match="budget"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"], rw_mounts=mounts,
                                  limits=Limits(tmpfs_bytes=1000)))
        assert list(sb.manifest.slots[0].io_dir.iterdir()) == []      # staging cleaned up

    def test_an_entry_bomb_stops_staging(self, tmp_path, monkeypatch):
        monkeypatch.setattr(mc, "MAX_SCRATCH_ENTRIES", 50)
        sb, _ = _sb_with(tmp_path)
        d = tmp_path / "bomb"
        d.mkdir()
        for i in range(100):
            (d / f"e{i}").touch()
        with pytest.raises(SandboxError, match="entries"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"], ro_mounts=[Mount(d, d)]))


class TestSlotWait:
    @pytest.mark.parametrize("raw", ["nan", "inf", "-1", "soon"])
    def test_a_bad_env_value_refuses_the_backend(self, tmp_path, monkeypatch, raw):
        root = tmp_path / "root"
        asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
        monkeypatch.setenv("BLASTBOX_APPSANDBOX_SLOT_WAIT_S", raw)
        with pytest.raises(SandboxUnavailable, match="slot wait"):
            asb.AppSandboxSandbox(root=root, platform_ok=True, verify=False)

    def test_a_nan_argument_is_refused(self, tmp_path):
        root = tmp_path / "root"
        asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
        with pytest.raises(SandboxUnavailable, match="slot wait"):
            asb.AppSandboxSandbox(root=root, platform_ok=True, verify=False,
                                  slot_wait_s=float("nan"))


class TestCreditOnlyForCompletedRuns:
    def test_failed_or_killed_runs_are_not_credited(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        sb, _ = _sb_with(tmp_path)
        before = confined_runs()
        sb.run(SandboxRequest(argv=["/bin/sh", "-c", "exit 3"]))
        r = sb.run(SandboxRequest(argv=["/bin/sleep", "5"], limits=Limits(timeout_s=1)))
        assert r.killed
        assert confined_runs() == before
        assert sb.run(SandboxRequest(argv=["/usr/bin/true"])).exit_code == 0
        assert confined_runs() == before + 1

    def test_a_copy_back_that_raises_is_not_credited(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        before = confined_runs()
        with pytest.raises(SandboxError):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'head -c 5000 /dev/zero > "$0/big"',
                                        str(out)],
                                  rw_mounts=[Mount(out, out)], limits=Limits(tmpfs_bytes=1000)))
        assert confined_runs() == before


class TestCopyBackRootType:
    def test_a_file_mount_replaced_by_a_symlink_is_not_planted(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        target = tmp_path / "result.json"
        target.write_text("{}")
        elsewhere = tmp_path / "victim"
        elsewhere.write_text("host data")
        with pytest.raises(SandboxError, match="replaced inside the sandbox"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'rm "$0" && ln -s "$1" "$0"',
                                        str(target), str(elsewhere)],
                                  rw_mounts=[Mount(target, target)]))
        assert not target.is_symlink() and target.read_text() == "{}"

    def test_a_dir_mount_replaced_by_a_symlink_does_not_empty_the_host_dir(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        (out / "keep").write_text("x")
        with pytest.raises(SandboxError, match="replaced inside the sandbox"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'rm -rf "$0" && ln -s /tmp "$0"',
                                        str(out)],
                                  rw_mounts=[Mount(out, out)]))
        assert (out / "keep").read_text() == "x"

    def test_a_copy_back_that_fails_partway_leaves_the_host_dir_intact(self, tmp_path):
        # the replacement is built before anything in the host dir is removed: a copy-back that
        # runs out of budget mid-tree leaves the original contents, and no temp dir behind
        out = tmp_path / "out"
        out.mkdir()
        (out / "keep").write_text("original")
        budget = mc.CopyBudget(max_bytes=1 << 20, max_entries=5)
        staged = tmp_path / "staged"
        staged.mkdir()
        for i in range(20):
            (staged / f"f{i}").write_text("new")
        with pytest.raises(SandboxError, match="entries"):
            asb.AppSandboxSandbox._copy_back(staged, out, budget, was_dir=True)
        assert sorted(p.name for p in out.iterdir()) == ["keep"]
        assert (out / "keep").read_text() == "original"

    def test_a_completed_copy_back_mirrors_the_staged_tree(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        (out / "gone").write_text("old")
        staged = tmp_path / "staged"
        (staged / "sub").mkdir(parents=True)
        (staged / "sub" / "f").write_text("new")
        asb.AppSandboxSandbox._copy_back(staged, out, mc.CopyBudget(max_bytes=1 << 20), was_dir=True)
        assert sorted(p.name for p in out.iterdir()) == ["sub"]
        assert (out / "sub" / "f").read_text() == "new"
        f = tmp_path / "file"
        f.write_text("old")
        (tmp_path / "sf").write_text("new file")
        asb.AppSandboxSandbox._copy_back(tmp_path / "sf", f, mc.CopyBudget(max_bytes=1 << 20), was_dir=False)
        assert f.read_text() == "new file"
        assert not [p for p in tmp_path.iterdir() if "blastbox-copyback" in p.name]


def test_an_executable_named_by_its_mount_target_runs(tmp_path):
    engine = tmp_path / "engine"
    (engine / "bin").mkdir(parents=True)
    tool = engine / "bin" / "parser"
    tool.write_text("#!/bin/sh\necho parsed\n")
    tool.chmod(0o755)
    sb, _ = _sb_with(tmp_path, ro_paths=[engine])
    target = Path("/bb-test-engine-not-on-host")
    assert not target.exists()
    r = sb.run(SandboxRequest(argv=[str(target / "bin" / "parser")],
                              ro_mounts=[Mount(engine, target)]))
    assert r.exit_code == 0 and r.stdout == b"parsed\n", r.stderr


def test_overlapping_rw_mounts_copy_back_parent_first(tmp_path):
    sb, _ = _sb_with(tmp_path)
    parent = tmp_path / "work"
    nested = parent / "out"
    nested.mkdir(parents=True)
    # nested listed first; the child writes through the nested mount's path
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo new > "$0/f"', str(nested)],
                              rw_mounts=[Mount(nested, nested), Mount(parent, parent)]))
    assert r.exit_code == 0, r.stderr
    assert (nested / "f").read_text() == "new\n"


def test_a_container_swapped_during_the_run_is_never_captured(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    home = tmp_path / "home"
    container = asb.Manifest.load(root).slots[0].container_data(home)
    container.mkdir(parents=True)
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=home, platform_ok=True,
                               verify=False, slot_wait_s=0)
    victim = tmp_path / "host-secrets"
    victim.mkdir()
    (victim / "key").write_text("secret")
    cap = tmp_path / "capture"
    with pytest.raises(SandboxError):
        sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'rm -rf "$0" && ln -s "$1" "$0"',
                                    str(container), str(victim)],
                              capture_home=cap))
    assert not (cap / "key").exists()
    assert (victim / "key").read_text() == "secret"


class TestVerifySlotEntitlements:
    def _runner(self, slot, ents, ident=None):
        xml = plistlib.dumps(ents)

        def run(argv, **kw):
            if "--verify" in argv:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            if "-v" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, stdout="", stderr=f"Executable=x\nIdentifier={ident or slot.bundle_id}\n")
            return subprocess.CompletedProcess(argv, 0, stdout=xml, stderr=b"")
        return run

    def _slot(self, tmp_path):
        engine = tmp_path / "engine"
        engine.mkdir()
        m = asb.prepare(tmp_path / "root", slots=2, ro_paths=[engine], runner=_fake_runner([]))
        return m

    def test_exact_entitlements_pass(self, tmp_path):
        m = self._slot(tmp_path)
        s = m.slots[0]
        want = asb.expected_entitlements(s, m.ro_paths)
        assert asb.verify_slot(s, ro_paths=m.ro_paths, runner=self._runner(s, want)) is None

    def test_extra_or_wrong_grants_fail(self, tmp_path):
        m = self._slot(tmp_path)
        s, other = m.slots
        want = asb.expected_entitlements(s, m.ro_paths)
        net = {**want, "com.apple.security.network.client": True}
        assert "unexpected" in asb.verify_slot(s, ro_paths=m.ro_paths, runner=self._runner(s, net))
        wrong_io = {**want, asb._RW_EXCEPTION: [str(other.io_dir) + "/"]}
        assert "mismatched" in asb.verify_slot(s, ro_paths=m.ro_paths,
                                               runner=self._runner(s, wrong_io))
        broad = {**want, asb._RO_EXCEPTION: ["/"]}
        assert "mismatched" in asb.verify_slot(s, ro_paths=m.ro_paths,
                                               runner=self._runner(s, broad))

    def test_wrong_signing_identifier_fails(self, tmp_path):
        m = self._slot(tmp_path)
        s = m.slots[0]
        want = asb.expected_entitlements(s, m.ro_paths)
        why = asb.verify_slot(s, ro_paths=m.ro_paths,
                              runner=self._runner(s, want, ident=m.slots[1].bundle_id))
        assert why and "signed as" in why


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin requires the process APIs")
def test_backend_refuses_without_process_apis(tmp_path, monkeypatch):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    monkeypatch.setattr(mc, "_LIBSYSTEM", None)
    with pytest.raises(SandboxUnavailable, match="process APIs"):
        asb.AppSandboxSandbox(root=root, platform_ok=True, verify=False)
