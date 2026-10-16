"""App Sandbox backend: prepare/manifest, slot staging + wipe, and real confinement.

``TestReal*`` builds real ad-hoc-signed slots (needs macOS + clang + codesign). They use a
FIXED bundle prefix so repeated runs reuse the same two ``~/Library/Containers`` entries
instead of minting new ones per tmp dir.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
import plistlib
import shutil
import stat
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
            # Read-only: the slot's own ro/ staging dir (never under the writable io/) + the
            # operator's paths.
            assert ent[asb._RO_EXCEPTION] == [str(s.ro_dir) + "/", str(engine.resolve()) + "/"]
            assert s.ro_dir.is_dir() and s.io_dir not in s.ro_dir.parents
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
        assert str(inp) not in argv and r.stdout.decode().startswith(str(slot.ro_dir))
        assert (out / "copy").read_text() == "payload"
        assert not (out / "stale").exists()        # bind-mount semantics: a child delete lands
        assert list(slot.io_dir.iterdir()) == []    # wiped after the run
        assert list(slot.ro_dir.iterdir()) == []

    def test_ro_mounts_are_staged_outside_the_writable_dir(self, setup):
        sb, popen, home, tmp = setup
        inp = tmp / "cfg.json"
        inp.write_text("{}")
        out = tmp / "out"
        out.mkdir()
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo "$0"; echo "$1"', str(inp), str(out)],
                                  ro_mounts=[Mount(inp, inp)], rw_mounts=[Mount(out, out)]))
        assert r.exit_code == 0, r.stderr
        slot = sb.manifest.slots[0]
        ro_seen, rw_seen = (Path(x) for x in r.stdout.decode().split())
        assert slot.ro_dir in ro_seen.parents and slot.io_dir not in ro_seen.parents
        assert slot.io_dir in rw_seen.parents

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

    def test_a_ro_mount_cannot_be_written_or_chmodded(self, sb, tmp_path):
        cfg = tmp_path / "cfg.json"
        cfg.write_text("{}")
        cfg.chmod(0o644)
        for cmd in ['echo pwned > "$0"', 'chmod 777 "$0"', 'rm -f "$0"']:
            r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", f'{cmd} && cat "$0"', str(cfg)],
                                      ro_mounts=[Mount(cfg, cfg)]))
            assert r.exit_code != 0, (cmd, r.stdout)
        assert cfg.read_text() == "{}"

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


def test_the_seed_and_the_staged_mounts_share_one_budget(tmp_path):
    # each fits the run's limit alone; together they'd stage twice it before the watchdog runs
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    home = tmp_path / "home"
    container = asb.Manifest.load(root).slots[0].container_data(home)
    sb = asb.AppSandboxSandbox(root=root, popen=_PrimingPopen(container), home=home,
                               platform_ok=True, verify=False, slot_wait_s=0)
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "plan").write_bytes(b"s" * 40_000)
    data = tmp_path / "data"
    data.write_bytes(b"d" * 40_000)
    with pytest.raises(SandboxError, match="budget"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"], seed_home=seed,
                              ro_mounts=[Mount(data, data)],
                              limits=Limits(tmpfs_bytes=60_000)))


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

    @pytest.mark.skipif(not hasattr(os, "chflags"), reason="BSD file flags")
    def test_an_immutable_host_entry_fails_the_copy_back_untouched(self, tmp_path):
        # a uchg entry can't be removed or renamed: refuse up front, never erase its siblings
        out = tmp_path / "out"
        (out / "sub").mkdir(parents=True)
        (out / "a").write_text("A")
        (out / "sub" / "locked").write_text("L")
        os.chflags(out / "sub" / "locked", stat.UF_IMMUTABLE)
        try:
            staged = tmp_path / "staged"
            staged.mkdir()
            (staged / "new").write_text("N")
            with pytest.raises(SandboxError, match="can't be replaced"):
                asb.AppSandboxSandbox._copy_back(staged, out, mc.CopyBudget(max_bytes=1 << 20),
                                                 was_dir=True)
            assert sorted(p.name for p in out.iterdir()) == ["a", "sub"]
            assert (out / "a").read_text() == "A" and (out / "sub" / "locked").read_text() == "L"
        finally:
            os.chflags(out / "sub" / "locked", 0)

    @pytest.mark.skipif(not hasattr(os, "chflags"), reason="BSD file flags")
    def test_an_immutable_host_file_fails_the_copy_back_before_copying(self, tmp_path):
        f = tmp_path / "host.json"
        f.write_text("orig")
        os.chflags(f, stat.UF_IMMUTABLE)
        try:
            (tmp_path / "staged").write_text("new")
            with pytest.raises(SandboxError, match="can't be replaced"):
                asb.AppSandboxSandbox._copy_back(tmp_path / "staged", f,
                                                 mc.CopyBudget(max_bytes=1 << 20), was_dir=False)
            assert f.read_text() == "orig"
            assert not [p for p in tmp_path.iterdir() if "blastbox-copyback" in p.name]
        finally:
            os.chflags(f, 0)

    def test_a_failed_file_replace_removes_the_sibling_copy(self, tmp_path, monkeypatch):
        f = tmp_path / "host.json"
        f.write_text("orig")
        (tmp_path / "staged").write_text("untrusted")

        def no_replace(src, dst):
            raise PermissionError("EPERM")
        monkeypatch.setattr(asb.os, "replace", no_replace)
        with pytest.raises(PermissionError):
            asb.AppSandboxSandbox._copy_back(tmp_path / "staged", f,
                                             mc.CopyBudget(max_bytes=1 << 20), was_dir=False)
        assert f.read_text() == "orig"
        assert not [p for p in tmp_path.iterdir() if "blastbox-copyback" in p.name]

    def test_a_rename_that_fails_mid_swap_restores_the_host_dir(self, tmp_path, monkeypatch):
        out = tmp_path / "out"
        out.mkdir()
        for n in ("a", "b", "c"):
            (out / n).write_text(n)
        staged = tmp_path / "staged"
        staged.mkdir()
        for n in ("x", "y"):
            (staged / n).write_text(n)
        real_rename, count = os.rename, {"n": 0}

        def flaky(src, dst):
            count["n"] += 1
            if count["n"] == 5:          # after a, b, c moved aside and x moved in
                raise PermissionError("EPERM")
            real_rename(src, dst)
        monkeypatch.setattr(asb.os, "rename", flaky)
        with pytest.raises(PermissionError):
            asb.AppSandboxSandbox._copy_back(staged, out, mc.CopyBudget(max_bytes=1 << 20),
                                             was_dir=True)
        monkeypatch.setattr(asb.os, "rename", real_rename)
        assert sorted(p.name for p in out.iterdir()) == ["a", "b", "c"]
        assert [(out / n).read_text() for n in ("a", "b", "c")] == ["a", "b", "c"]


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


def test_duplicate_rw_sources_share_one_staged_tree(tmp_path):
    # Two writable aliases of one host dir: a write through the first must survive (the second
    # alias's unchanged snapshot used to be copied back over it) and be visible via the second.
    sb, _ = _sb_with(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    a, b = Path("/bb-test-alias-a"), Path("/bb-test-alias-b")
    r = sb.run(SandboxRequest(
        argv=["/bin/sh", "-c", 'echo new > "$0/f" && cat "$1/f"', str(a), str(b)],
        rw_mounts=[Mount(out, a), Mount(out, b)]))
    assert r.exit_code == 0, r.stderr
    assert r.stdout == b"new\n"
    assert (out / "f").read_text() == "new\n"


def test_a_write_through_the_parent_into_a_nested_rw_mount_survives(tmp_path):
    sb, _ = _sb_with(tmp_path)
    parent = tmp_path / "work"
    nested = parent / "out"
    nested.mkdir(parents=True)
    # the child writes into out/ through the PARENT mount; the nested mount must not undo it
    r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo new > "$0/out/f"', str(parent)],
                              rw_mounts=[Mount(parent, parent), Mount(nested, nested)]))
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


def test_a_container_removed_during_the_run_fails_a_requested_capture(tmp_path):
    # capture_home was asked for and the child deleted Data/: that is a failed capture, not a
    # run that "succeeded" while the destination keeps an earlier run's contents
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    home = tmp_path / "home"
    container = asb.Manifest.load(root).slots[0].container_data(home)
    container.mkdir(parents=True)
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=home, platform_ok=True,
                               verify=False, slot_wait_s=0)
    cap = tmp_path / "capture"
    cap.mkdir()
    (cap / "stale").write_text("from an earlier run")
    from blastbox.worker.sandbox.base import confined_runs
    before = confined_runs()
    with pytest.raises(SandboxError, match="removed"):
        sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'rm -rf "$0"', str(container)],
                              capture_home=cap))
    assert confined_runs() == before


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


def test_a_run_whose_final_wipe_fails_is_not_credited(tmp_path, monkeypatch):
    # Credit only after the post-run sweep + wipe: a run whose cleanup raised is a failed run.
    from blastbox.worker.sandbox.base import confined_runs
    sb, _ = _sb_with(tmp_path)
    real_wipe = sb._wipe_slot
    calls = []

    def wipe(slot):
        calls.append(slot)
        if len(calls) == 2:
            raise SandboxError("could not empty the slot")
        real_wipe(slot)
    monkeypatch.setattr(sb, "_wipe_slot", wipe)
    before = confined_runs()
    with pytest.raises(SandboxError, match="could not empty"):
        sb.run(SandboxRequest(argv=["/usr/bin/true"]))
    assert len(calls) == 2
    assert confined_runs() == before


class TestDeletedMountRoot:
    def test_a_deleted_dir_mount_fails_the_run(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        (out / "stale").write_text("old")
        before = confined_runs()
        with pytest.raises(SandboxError, match="deleted inside the sandbox"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'rm -rf "$0"', str(out)],
                                  rw_mounts=[Mount(out, out)]))
        assert (out / "stale").read_text() == "old"
        assert confined_runs() == before

    def test_a_deleted_file_mount_fails_the_run(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        target = tmp_path / "result.json"
        target.write_text("{}")
        with pytest.raises(SandboxError, match="deleted inside the sandbox"):
            sb.run(SandboxRequest(argv=["/bin/rm", str(target)],
                                  rw_mounts=[Mount(target, target)]))
        assert target.read_text() == "{}"


class TestBundleIds:
    @pytest.mark.parametrize("prefix", ["../../evil", "/abs/path", "a/b", "a..b", ".x", "x.",
                                        "has space", "a/../b"])
    def test_prepare_refuses_a_path_like_prefix(self, tmp_path, prefix):
        with pytest.raises(SandboxError, match="invalid bundle prefix"):
            asb.prepare(tmp_path / "root", slots=1, ro_paths=[], bundle_prefix=prefix,
                        runner=_fake_runner([]))

    def test_a_prefix_too_long_with_its_slot_suffix_is_refused_before_building(self, tmp_path):
        prefix = "a" * 194              # valid alone; "<prefix>.slot11" is 201 characters
        assert asb._valid_bundle_id(prefix)
        calls: list[list[str]] = []
        with pytest.raises(SandboxError, match="too long"):
            asb.prepare(tmp_path / "root", slots=12, ro_paths=[], bundle_prefix=prefix,
                        runner=_fake_runner(calls))
        assert calls == [] and not (tmp_path / "root" / "slots").exists()
        m = asb.prepare(tmp_path / "root", slots=10, ro_paths=[], bundle_prefix=prefix,
                        runner=_fake_runner([]))   # "<prefix>.slot9" is exactly 200: fits
        assert asb.Manifest.load(m.root).slots == m.slots

    def test_a_valid_prefix_is_accepted(self, tmp_path):
        m = asb.prepare(tmp_path / "root", slots=1, ro_paths=[], bundle_prefix="io.ex-ample.sbx2",
                        runner=_fake_runner([]))
        assert m.slots[0].bundle_id == "io.ex-ample.sbx2.slot0"

    @pytest.mark.parametrize("field", ["bundle_prefix", "bundle_id"])
    def test_a_tampered_manifest_is_refused(self, tmp_path, field):
        root = _fake_root(tmp_path)
        path = root / asb.MANIFEST_NAME
        raw = json.loads(path.read_text())
        if field == "bundle_prefix":
            raw["bundle_prefix"] = "../../../../tmp/victim"
        else:
            raw["slots"][0]["bundle_id"] = "/Users/someone/important"
        path.write_text(json.dumps(raw))
        with pytest.raises(SandboxUnavailable, match="invalid bundle ids"):
            asb.Manifest.load(root)


class TestManifestShape:
    """A syntactically valid but malformed manifest is SandboxUnavailable -- never a KeyError /
    TypeError that crashes backend selection or `macos doctor`."""

    def _tamper(self, tmp_path, edit):
        root = _fake_root(tmp_path)
        path = root / asb.MANIFEST_NAME
        raw = json.loads(path.read_text())
        raw = edit(raw)
        path.write_text(json.dumps(raw))
        return root

    @pytest.mark.parametrize("edit", [
        lambda r: {"version": asb.MANIFEST_VERSION},                         # no fields
        lambda r: [r],                                                       # not an object
        lambda r: {**r, "slots": {"0": r["slots"][0]}},                      # slots not a list
        lambda r: {**r, "slots": ["not a slot"]},                            # slot not an object
        lambda r: {**r, "slots": [{**r["slots"][0], "index": "0"}]},         # index not an int
        lambda r: {**r, "slots": [{**r["slots"][0], "index": True}]},
        lambda r: {**r, "slots": [{k: v for k, v in r["slots"][0].items() if k != "io_dir"}]},
        lambda r: {**r, "ro_paths": "/opt"},                                 # not a list
        lambda r: {**r, "ro_paths": ["relative"]},
        lambda r: {**r, "bundle_prefix": 7},
    ])
    def test_malformed_manifests_are_unavailable(self, tmp_path, edit):
        root = self._tamper(tmp_path, edit)
        with pytest.raises(SandboxUnavailable):
            asb.Manifest.load(root)
        with pytest.raises(SandboxUnavailable):
            asb.AppSandboxSandbox(root=root, platform_ok=True, verify=False)

    @pytest.mark.parametrize("field", ["io_dir", "bundle", "lock_path"])
    def test_slot_paths_must_be_where_prepare_put_them(self, tmp_path, field):
        # io_dir is wiped before and after every run: an edited manifest must not aim it (or the
        # launched bundle, or the lock) at another directory.
        victim = tmp_path / "victim"
        victim.mkdir()
        root = self._tamper(tmp_path, lambda r: {
            **r, "slots": [{**r["slots"][0], field: str(victim)}]})
        with pytest.raises(SandboxUnavailable, match=field):
            asb.Manifest.load(root)

    def test_a_slot_id_not_derived_from_the_prefix_is_refused(self, tmp_path):
        root = self._tamper(tmp_path, lambda r: {
            **r, "slots": [{**r["slots"][0], "bundle_id": "com.apple.Safari"}]})
        with pytest.raises(SandboxUnavailable, match="invalid bundle ids"):
            asb.Manifest.load(root)

    def test_a_prepared_manifest_still_loads(self, tmp_path):
        root, ro = tmp_path / "root", tmp_path / "engine"
        ro.mkdir()
        m = asb.prepare(root, slots=3, ro_paths=[ro], runner=_fake_runner([]))
        assert asb.Manifest.load(root) == m


class TestMountRewriteCollisions:
    def test_ro_and_rw_mounts_at_one_target_are_refused(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        src_ro, src_rw = tmp_path / "in", tmp_path / "out"
        src_ro.mkdir()
        src_rw.mkdir()
        target = Path("/bb-test-collide")
        popen = sb._popen
        with pytest.raises(SandboxError, match="names two different mounts"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo hi > "$0/f"', str(target)],
                                  ro_mounts=[Mount(src_ro, target)],
                                  rw_mounts=[Mount(src_rw, target)]))
        assert popen.calls == []                       # nothing was launched
        assert list(src_rw.iterdir()) == []

    def test_a_target_equal_to_another_mounts_source_is_refused(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        data, out = tmp_path / "data", tmp_path / "out"
        data.mkdir()
        out.mkdir()
        with pytest.raises(SandboxError, match="names two different mounts"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"],
                                  ro_mounts=[Mount(data, Path("/bb-test-in"))],
                                  rw_mounts=[Mount(out, data)]))

    @pytest.mark.parametrize("ro_rel", ["", "sub", ".."])
    def test_read_only_sources_overlapping_a_writable_source_are_refused(self, tmp_path, ro_rel):
        # equal, inside, or containing: separate staged copies would not share writes
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "data" / "out"
        (out / "sub").mkdir(parents=True)
        ro_src = (out / ro_rel) if ro_rel else out
        popen = sb._popen
        with pytest.raises(SandboxError, match="overlaps writable mount"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"],
                                  ro_mounts=[Mount(ro_src, Path("/bb-test-ro"))],
                                  rw_mounts=[Mount(out, Path("/bb-test-rw"))]))
        assert popen.calls == []

    def test_disjoint_read_only_and_writable_sources_still_run(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        a, b = tmp_path / "a", tmp_path / "ab"     # a name prefix is not containment
        a.mkdir()
        b.mkdir()
        r = sb.run(SandboxRequest(argv=["/usr/bin/true"],
                                  ro_mounts=[Mount(a, Path("/bb-test-ro"))],
                                  rw_mounts=[Mount(b, Path("/bb-test-rw"))]))
        assert r.exit_code == 0

    @pytest.mark.parametrize("outer_rw", [True, False])
    def test_a_target_nested_under_another_mounts_target_is_refused(self, tmp_path, outer_rw):
        # X at /mnt and Y at /mnt/sub: "/mnt" + "sub" would reach X/sub, "/mnt/sub" reaches Y --
        # a nested bind mount always shows Y, so the ambiguity is refused before launch
        sb, _ = _sb_with(tmp_path)
        x, y = tmp_path / "x", tmp_path / "y"
        (x / "sub").mkdir(parents=True)
        y.mkdir()
        outer, inner = Mount(x, Path("/bb-test-mnt")), Mount(y, Path("/bb-test-mnt/sub"))
        req = (SandboxRequest(argv=["/usr/bin/true"], rw_mounts=[outer, inner]) if outer_rw else
               SandboxRequest(argv=["/usr/bin/true"], ro_mounts=[outer], rw_mounts=[inner]))
        popen = sb._popen
        with pytest.raises(SandboxError, match="nested under"):
            sb.run(req)
        assert popen.calls == []

    def test_a_nested_alias_of_one_writable_tree_still_runs(self, tmp_path):
        # the same tree at nested targets IS consistent: the inner one points into the outer copy
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        (out / "sub").mkdir(parents=True)
        r = sb.run(SandboxRequest(
            argv=["/bin/sh", "-c", 'echo hi > "$0/f"', str(out / "sub")],
            rw_mounts=[Mount(out, out), Mount(out / "sub", out / "sub")]))
        assert r.exit_code == 0, r.stderr
        assert (out / "sub" / "f").read_text() == "hi\n"

    def test_aliases_of_one_writable_tree_are_still_fine(self):
        asb._check_mapping([("/a", "/s/x"), ("/b", "/s/x"), ("/a/", "/s/x")])


def test_prepare_refuses_while_a_run_holds_a_slot(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]))
    before = (root / asb.MANIFEST_NAME).read_bytes()
    fd = os.open(root / "locks" / "1.lock", os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(SandboxError, match="in use by a running job"):
            asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]), lock_wait_s=0.2)
        assert (root / asb.MANIFEST_NAME).read_bytes() == before
    finally:
        os.close(fd)
    asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]), lock_wait_s=0.2)
    assert (root / asb.MANIFEST_NAME).read_bytes() != before     # a new generation


def test_prepare_refuses_while_another_prepare_runs(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    before = (root / asb.MANIFEST_NAME).read_bytes()
    fd = os.open(root / "locks" / asb.PREPARE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(SandboxError, match="another `blastbox macos prepare` is running"):
            asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]), lock_wait_s=0.2)
        assert (root / asb.MANIFEST_NAME).read_bytes() == before
    finally:
        os.close(fd)


def test_overlapping_prepares_never_drop_a_slot_the_first_one_added(tmp_path):
    # Prepare A (holding the root lock) grows the root to 4 slots and an agent starts a run in
    # slot 3. Prepare B, asking for 1 slot, was started meanwhile: it must read the slot set
    # only once A is done, so it waits on slot 3's lock -- not lock just slot 0 and delete 3.
    import threading
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    a = os.open(root / "locks" / asb.PREPARE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(a, fcntl.LOCK_EX)                      # A is running
    errors: list[BaseException] = []

    def prepare_b():
        try:
            asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]), lock_wait_s=2)
        except BaseException as exc:
            errors.append(exc)
    b = threading.Thread(target=prepare_b)
    b.start()
    run = None
    try:
        time.sleep(0.2)                                 # B is now waiting for A
        for i in (1, 2, 3):                             # what A creates
            (root / "slots" / str(i) / "io").mkdir(parents=True)
        (root / "slots" / "3" / "io" / "job").write_text("in use")
        run = os.open(root / "locks" / "3.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(run, fcntl.LOCK_EX)                 # an agent runs in A's new slot 3
        os.close(a)                                     # A finishes
        a = -1
        b.join(timeout=10)
        assert not b.is_alive()
        assert errors and "slot 3 is in use" in str(errors[0])
        assert (root / "slots" / "3" / "io" / "job").read_text() == "in use"
    finally:
        if a != -1:
            os.close(a)
        if run is not None:
            os.close(run)
        b.join(timeout=10)


def test_a_live_instance_refuses_runs_once_the_slots_are_re_prepared(tmp_path):
    # Re-prepared under another prefix, the slots now launch into other containers than the
    # ones this instance matches and sweeps: it must not run until restarted.
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    sb = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                               platform_ok=True, verify=False, slot_wait_s=0)
    assert sb.run(SandboxRequest(argv=["/bin/echo", "x"])).exit_code == 0
    asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.other",
                runner=_fake_runner([]))
    for _ in range(2):          # and stays refused
        with pytest.raises(SandboxUnavailable, match="changed since this agent loaded it"):
            sb.run(SandboxRequest(argv=["/bin/echo", "x"]))
    fresh = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                                  platform_ok=True, verify=False, slot_wait_s=0)
    assert fresh.manifest.bundle_prefix == "io.example.other"
    assert fresh.run(SandboxRequest(argv=["/bin/echo", "x"])).exit_code == 0


def test_a_manifest_without_a_generation_still_loads(tmp_path):
    root = tmp_path / "root"
    asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]))
    raw = json.loads((root / asb.MANIFEST_NAME).read_text())
    raw.pop("generation")
    (root / asb.MANIFEST_NAME).write_text(json.dumps(raw))
    assert asb.Manifest.load(root).generation == ""
    raw["generation"] = 7
    (root / asb.MANIFEST_NAME).write_text(json.dumps(raw))
    with pytest.raises(SandboxUnavailable, match="generation"):
        asb.Manifest.load(root)


def test_a_prepare_that_fails_part_way_leaves_every_agent_refusing(tmp_path):
    # A re-prepare under another prefix rebuilds slot 0, then codesign fails on slot 1: the
    # old manifest must not survive (a live agent would launch slot 0 under the new bundle id
    # while matching and sweeping the old one).
    root = tmp_path / "root"
    asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]))
    live = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                                 platform_ok=True, verify=False, slot_wait_s=0)
    assert live.run(SandboxRequest(argv=["/bin/echo", "x"])).exit_code == 0

    ok = _fake_runner([])
    signed: list[str] = []

    def failing(argv, **kw):
        if argv[0].endswith("codesign"):
            signed.append(argv[-1])
            if len(signed) == 2:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom")
        return ok(argv, **kw)

    with pytest.raises(SandboxError, match="codesign failed"):
        asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.other",
                    runner=failing)
    assert len(signed) == 2                     # slot 0 was rebuilt before the failure
    with pytest.raises(SandboxUnavailable, match="changed since this agent loaded it"):
        live.run(SandboxRequest(argv=["/bin/echo", "x"]))
    with pytest.raises(SandboxUnavailable, match="running or failed part-way"):
        asb.Manifest.load(root)
    with pytest.raises(SandboxUnavailable, match="running or failed part-way"):
        asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                              platform_ok=True, verify=False, slot_wait_s=0)
    # a prepare that completes restores service (for a restarted agent)
    asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.other",
                runner=_fake_runner([]))
    fresh = asb.AppSandboxSandbox(root=root, popen=_Popen(), home=tmp_path / "home",
                                  platform_ok=True, verify=False, slot_wait_s=0)
    assert fresh.manifest.bundle_prefix == "io.example.other"
    assert fresh.run(SandboxRequest(argv=["/bin/echo", "x"])).exit_code == 0


class TestContainerIdentity:
    """Data/ must be the directory it was before the run, and nothing may appear beside it."""

    def _setup(self, tmp_path):
        sb, home = _sb_with(tmp_path)
        container = sb.manifest.slots[0].container_data(home)
        container.mkdir(parents=True)
        (container.parent / ".com.apple.containermanagerd.metadata.plist").write_text("meta")
        return sb, container

    def test_a_data_dir_renamed_aside_and_recreated_fails_and_is_removed(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        sb, container = self._setup(tmp_path)
        before = confined_runs()
        with pytest.raises(SandboxError, match="replaced during the run"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c",
                                        'mv "$0" "$0.stash" && mkdir "$0" && '
                                        'echo kept > "$0.stash/f"', str(container)]))
        assert confined_runs() == before
        # the stash sat outside every wiped root: gone, and containermanagerd's file kept
        assert sorted(os.listdir(container.parent)) == [
            ".com.apple.containermanagerd.metadata.plist", "Data"]
        assert not asb.AppSandboxSandbox.retired_marker(sb.manifest.slots[0]).exists()

    def test_an_entry_left_beside_the_container_fails_the_run(self, tmp_path):
        from blastbox.worker.sandbox.base import confined_runs
        sb, container = self._setup(tmp_path)
        before = confined_runs()
        with pytest.raises(SandboxError, match="beside its container"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo x > "$0/../extra"',
                                        str(container)]))
        assert confined_runs() == before
        assert not (container.parent / "extra").exists()

    def test_an_entry_that_cannot_be_removed_retires_the_slot(self, tmp_path, monkeypatch):
        sb, container = self._setup(tmp_path)
        real = mc.remove_tree
        monkeypatch.setattr(mc, "remove_tree", lambda p: None if p.name == "stuck" else real(p))
        with pytest.raises(SandboxError, match="could not remove"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'mkdir "$0/../stuck"',
                                        str(container)]))
        assert asb.AppSandboxSandbox.retired_marker(sb.manifest.slots[0]).exists()

    def test_an_untouched_container_runs_clean(self, tmp_path):
        sb, container = self._setup(tmp_path)
        assert sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo hi > "$0/f"',
                                           str(container)])).exit_code == 0
        assert list(container.iterdir()) == []          # wiped after the run


@needs_real
def test_app_sandbox_denies_renaming_data_or_writing_beside_it(real_sb):
    # The OS guarantee the identity check backs up: the child cannot touch its bundle container.
    slot = real_sb.manifest.slots[0]
    container = slot.container_data(Path.home())
    real_sb.run(SandboxRequest(argv=["/usr/bin/true"]))          # the container exists now
    for cmd in ['mv "$0" "$0.stash"', 'echo x > "$0/../extra"', 'mkdir "$0/../d"']:
        r = real_sb.run(SandboxRequest(argv=["/bin/sh", "-c", cmd, str(container)]))
        assert r.exit_code != 0, cmd
    assert sorted(os.listdir(container.parent)) == [
        ".com.apple.containermanagerd.metadata.plist", "Data"]


class TestShutdownCoversTheTeardown:
    """The agent retiring during the copy-back (after run_confined dropped its own cleanup)
    must still remove a half-built copy-back beside the host dir and wipe the slot -- and must
    never exit between the copy-back's renames."""

    def test_an_emergency_during_the_copy_back_removes_leftovers_and_wipes_the_slot(
            self, tmp_path, monkeypatch):
        from blastbox.worker.sandbox import base
        sb, _ = _sb_with(tmp_path)
        slot = sb.manifest.slots[0]
        out = tmp_path / "out"
        out.mkdir()
        seen: dict[str, object] = {}

        def copy_back(staged, dest, budget, was_dir, leftovers=None, links=None):
            half = dest / ".blastbox-copyback-half"
            half.mkdir()
            leftovers.add(half)
            assert base.run_emergency_cleanups(5) == 1      # the agent retires here
            seen["half gone"] = not half.exists()
            seen["io"] = sorted(os.listdir(slot.io_dir))
            raise SandboxError("interrupted by the retirement")

        monkeypatch.setattr(asb.AppSandboxSandbox, "_build_copy_back", staticmethod(copy_back))
        registered = len(base._EMERGENCY)
        with pytest.raises(SandboxError, match="interrupted"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo x > "$0/f"', str(out)],
                                  rw_mounts=[Mount(out, out)]))
        assert seen == {"half gone": True, "io": []}
        assert len(base._EMERGENCY) == registered

    def test_a_retiring_agent_waits_for_the_swap_renames(self, tmp_path, monkeypatch):
        import threading

        from blastbox.worker.sandbox.base import begin_shutdown, end_shutdown
        dest, new = tmp_path / "dest", tmp_path / "dest" / ".new"
        new.mkdir(parents=True)
        (dest / "a").write_text("old")
        (new / "a").write_text("new")
        entered, release = threading.Event(), threading.Event()
        real_rename = os.rename

        def slow_rename(src, dst):
            entered.set()
            release.wait(5)
            real_rename(src, dst)
        monkeypatch.setattr(asb.os, "rename", slow_rename)
        t = threading.Thread(target=asb.AppSandboxSandbox._swap_children,
                             args=(dest, new, dest / ".old"))
        t.start()
        try:
            assert entered.wait(5)
            assert begin_shutdown(0.2) is False             # mid-swap: still waiting
            release.set()
            assert begin_shutdown(5) is True
            t.join(5)
        finally:
            release.set()
            end_shutdown()
        assert (dest / "a").read_text() == "new"
        assert sorted(os.listdir(dest)) == ["a"]

    def test_no_swap_starts_once_shutdown_has_begun(self, tmp_path):
        from blastbox.worker.sandbox.base import begin_shutdown, end_shutdown
        dest, new = tmp_path / "dest", tmp_path / "dest" / ".new"
        new.mkdir(parents=True)
        (dest / "a").write_text("old")
        assert begin_shutdown(0)
        try:
            with pytest.raises(SandboxError, match="shutting down"):
                asb.AppSandboxSandbox._swap_children(dest, new, dest / ".old")
        finally:
            end_shutdown()
        assert (dest / "a").read_text() == "old"


class TestSourcesMustNotOverlapStaging:
    """A source that is, holds or sits inside the root (every slot's io/ and ro/) or a slot's
    container would be copied into itself: refused before anything is created."""

    @pytest.mark.parametrize("which", ["root", "parent of root", "inside root", "container"])
    def test_refused_before_the_slot_is_touched(self, tmp_path, monkeypatch, which):
        sb, home = _sb_with(tmp_path)
        slot = sb.manifest.slots[0]
        container_parent = slot.container_data(home).parent
        container_parent.mkdir(parents=True)
        src = {"root": tmp_path / "root", "parent of root": tmp_path,
               "inside root": slot.io_dir, "container": container_parent}[which]
        wiped: list[object] = []
        monkeypatch.setattr(sb, "_wipe_slot", lambda s: wiped.append(s) or [])
        with pytest.raises(SandboxError, match="overlaps"):
            sb.run(SandboxRequest(argv=["/bin/echo"], ro_mounts=[Mount(src, src)]))
        assert wiped == []

    def test_a_seed_or_capture_inside_the_root_is_refused(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        inside = tmp_path / "root" / "cache"
        inside.mkdir()
        for req in (SandboxRequest(argv=["/bin/echo"], seed_home=inside),
                    SandboxRequest(argv=["/bin/echo"], capture_home=inside)):
            with pytest.raises(SandboxError, match="overlaps"):
                sb.run(req)

    def test_a_disjoint_source_still_runs(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        data = tmp_path / "data"
        data.mkdir()
        (data / "f").write_text("x")
        r = sb.run(SandboxRequest(argv=["/bin/cat", str(data / "f")],
                                  ro_mounts=[Mount(data, data)]))
        assert r.exit_code == 0 and r.stdout == b"x"


class TestPrepareSweepsEveryPreviousSlot:
    """A slot may still hold a process from a run: one the run couldn't kill (retired), or one
    an agent SIGKILLed mid-run left (no marker -- the next run's pre-run sweep was to catch
    it). Re-preparing under another prefix, or dropping the slot, must first sweep EVERY slot
    under each identity it may carry, or that process keeps its grant to the slot's io/ with no
    future sweep matching it."""

    def _retire(self, root, i):
        (root / "locks" / f"{i}.lock.retired").write_text("could not prove clean\n")

    @staticmethod
    def _record(monkeypatch):
        swept: list[Path] = []
        monkeypatch.setattr(mc, "sweep_containers",
                            lambda cs, what: swept.extend(cs) or 0)
        return swept

    @staticmethod
    def _data(home, bid):
        return home / "Library" / "Containers" / bid / "Data"

    def test_every_slot_is_swept_and_emptied_under_its_old_and_new_ids(self, tmp_path,
                                                                      monkeypatch):
        # no retirement marker anywhere: the agent was SIGKILLed, so none was written
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        old_data = self._data(home, "io.example.old.slot1")
        old_data.mkdir(parents=True)
        (old_data / "left").write_text("x")
        (root / "slots" / "1" / "io" / "out").write_text("x")
        swept = self._record(monkeypatch)
        m = asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.new",
                        runner=_fake_runner([]), home=home)
        assert set(swept) == {self._data(home, f"io.example.{p}.slot{i}")
                              for p in ("old", "new") for i in (0, 1)}
        assert list(old_data.iterdir()) == []
        assert not (root / "slots" / "1").exists()          # the dropped slot, after its sweep
        assert [s.bundle_id for s in m.slots] == ["io.example.new.slot0"]

    def test_a_retired_slot_is_cleared_after_its_sweep(self, tmp_path, monkeypatch):
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        self._retire(root, 1)
        swept = self._record(monkeypatch)
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.new",
                    runner=_fake_runner([]), home=home)
        assert self._data(home, "io.example.old.slot1") in swept
        assert not (root / "locks" / "1.lock.retired").exists()

    def test_a_slot_that_cannot_be_proven_empty_refuses_the_prepare(self, tmp_path,
                                                                   monkeypatch):
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        self._retire(root, 1)
        manifest = (root / asb.MANIFEST_NAME).read_bytes()

        def stuck(containers, what):
            raise SandboxError("a process in the container keeps coming back")
        monkeypatch.setattr(mc, "sweep_containers", stuck)
        with pytest.raises(SandboxError, match="can't be proven free of a previous run"):
            asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.new",
                        runner=_fake_runner([]), home=home)
        # nothing changed: the manifest, the marker and the slot itself are all still there
        assert (root / asb.MANIFEST_NAME).read_bytes() == manifest
        assert (root / "locks" / "1.lock.retired").exists()
        assert (root / "slots" / "1").is_dir()

    def test_the_old_id_comes_from_the_bundle_when_the_manifest_is_gone(self, tmp_path,
                                                                       monkeypatch):
        # a prepare that failed part-way leaves only the "preparing" marker as the manifest
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        (root / asb.MANIFEST_NAME).write_text(json.dumps({"version": asb.MANIFEST_VERSION,
                                                          "preparing": "x"}))
        swept = self._record(monkeypatch)
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.new",
                    runner=_fake_runner([]), home=home)
        assert self._data(home, "io.example.old.slot0") in swept

    def test_a_manifest_slot_with_no_directory_is_still_swept(self, tmp_path, monkeypatch):
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=3, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        mc.remove_tree(root / "slots" / "2")
        swept = self._record(monkeypatch)
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.new",
                    runner=_fake_runner([]), home=home)
        assert self._data(home, "io.example.old.slot2") in swept

    def test_an_unknowable_old_id_of_a_retired_slot_refuses_the_prepare(self, tmp_path,
                                                                        monkeypatch):
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]), home=home)
        self._retire(root, 0)
        (root / asb.MANIFEST_NAME).write_text("not json")
        (root / "slots" / "0" / "bb-slot-0.app" / "Contents" / "Info.plist").unlink()
        self._record(monkeypatch)
        with pytest.raises(SandboxError, match="previous bundle id can't be read"):
            asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]), home=home)
        assert (root / "locks" / "0.lock.retired").exists()

    def test_a_first_prepare_has_nothing_to_sweep(self, tmp_path, monkeypatch):
        calls: list[object] = []
        monkeypatch.setattr(mc, "sweep_containers", lambda cs, what: calls.append(cs) or 0)
        asb.prepare(tmp_path / "root", slots=2, ro_paths=[], runner=_fake_runner([]),
                    home=tmp_path / "home")
        assert calls == []

    def test_a_dropped_retired_slot_does_not_come_back_retired(self, tmp_path, monkeypatch):
        root, home = tmp_path / "root", tmp_path / "home"
        asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]), home=home)
        self._retire(root, 1)
        self._record(monkeypatch)
        asb.prepare(root, slots=1, ro_paths=[], runner=_fake_runner([]), home=home)
        asb.prepare(root, slots=2, ro_paths=[], runner=_fake_runner([]), home=home)
        assert not (root / "locks" / "1.lock.retired").exists()



class TestPrepareTakesTheSharedBundleLocks:
    """Two roots prepared with the same --bundle-prefix share each slot's container (it is keyed
    by bundle id, not root). A run in the other root holds the per-user bundle lock for the run
    and both wipes; re-preparing this root must wait for it -- else its sweep SIGKILLs that
    run's child and empties its Data mid-job."""

    @staticmethod
    def _hold(path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    @staticmethod
    def _record(monkeypatch):
        swept: list[Path] = []
        monkeypatch.setattr(mc, "sweep_containers",
                            lambda cs, what: swept.extend(cs) or 0)
        return swept

    def test_a_run_in_another_root_holding_a_bundle_lock_refuses_the_prepare(
            self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        mine, other = tmp_path / "mine", tmp_path / "other"
        for r in (mine, other):
            asb.prepare(r, slots=2, ro_paths=[], bundle_prefix="io.example.shared",
                        runner=_fake_runner([]), home=home)
        data = home / "Library" / "Containers" / "io.example.shared.slot1" / "Data"
        data.mkdir(parents=True)
        (data / "in-flight").write_text("the other root's job")
        manifest = (mine / asb.MANIFEST_NAME).read_bytes()
        swept = self._record(monkeypatch)
        fd = self._hold(asb.bundle_lock_path(home, "io.example.shared.slot1"))  # other's run
        try:
            with pytest.raises(SandboxError, match="io.example.shared.slot1 is in use"):
                asb.prepare(mine, slots=2, ro_paths=[], bundle_prefix="io.example.shared",
                            runner=_fake_runner([]), home=home, lock_wait_s=0.2)
        finally:
            os.close(fd)
        assert swept == []                                   # nothing killed
        assert (data / "in-flight").exists()                 # nothing wiped
        assert (mine / asb.MANIFEST_NAME).read_bytes() == manifest   # nothing changed

    def test_a_previous_id_and_a_new_slots_id_are_both_locked(self, tmp_path, monkeypatch):
        # the old prefix (what the sweep matches) and a slot only this prepare creates (what
        # the rebuild empties) are each another root's container just the same
        home, root = tmp_path / "home", tmp_path / "root"
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.old",
                    runner=_fake_runner([]), home=home)
        self._record(monkeypatch)
        for held in ("io.example.old.slot0", "io.example.new.slot1"):
            fd = self._hold(asb.bundle_lock_path(home, held))
            try:
                with pytest.raises(SandboxError, match=f"{held} is in use"):
                    asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.new",
                                runner=_fake_runner([]), home=home, lock_wait_s=0.2)
            finally:
                os.close(fd)

    def test_the_prepare_waits_for_the_run_then_proceeds(self, tmp_path, monkeypatch):
        import threading
        home, root = tmp_path / "home", tmp_path / "root"
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.p",
                    runner=_fake_runner([]), home=home)
        swept = self._record(monkeypatch)
        fd = self._hold(asb.bundle_lock_path(home, "io.example.p.slot0"))
        released = threading.Event()

        def finish_run():
            time.sleep(0.3)
            released.set()
            os.close(fd)
        t = threading.Thread(target=finish_run)
        t.start()
        try:
            asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example.p",
                        runner=_fake_runner([]), home=home, lock_wait_s=10)
        finally:
            t.join()
        assert released.is_set() and swept                   # swept only once the run ended

    def test_the_locks_are_released_after_the_prepare(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "root"
        asb.prepare(root, slots=2, ro_paths=[], bundle_prefix="io.example.r",
                    runner=_fake_runner([]), home=home)
        for i in range(2):
            os.close(self._hold(asb.bundle_lock_path(home, f"io.example.r.slot{i}")))


class TestWritableMountsShareHardLinks:
    """A file hard-linked into two writable mounts is one inode on the host. Staged as bind
    mounts would be, a write through one name shows through the other, its bytes count once
    against the staging budget, and the copy-back keeps the two names linked. A read-only copy
    never shares an inode with a writable one."""

    @staticmethod
    def _linked(tmp_path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        (a / "f").write_bytes(b"x" * 600)
        os.link(a / "f", b / "g")
        return a, b

    def test_a_write_through_one_mount_shows_through_the_other(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        a, b = self._linked(tmp_path)
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo new > "$0/f" && cat "$1/g"',
                                        str(a), str(b)],
                                  rw_mounts=[Mount(a, a), Mount(b, b)]))
        assert r.exit_code == 0, r.stderr
        assert r.stdout == b"new\n"                         # one inode inside the sandbox
        assert (b / "g").read_text() == "new\n"
        assert os.stat(a / "f").st_ino == os.stat(b / "g").st_ino    # still linked on the host

    def test_the_shared_inode_is_charged_once(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        a, b = self._linked(tmp_path)
        r = sb.run(SandboxRequest(argv=["/usr/bin/true"], rw_mounts=[Mount(a, a), Mount(b, b)],
                                  limits=Limits(tmpfs_bytes=1000)))     # 600 fits once, not twice
        assert r.exit_code == 0, r.stderr

    def test_a_writable_file_linked_into_a_read_only_mount_is_refused(self, tmp_path):
        # Staged apart they would be two inodes, and the copy-back would cut the host's link;
        # so the layout is refused before anything is staged (as Seatbelt refuses it too).
        sb, _ = _sb_with(tmp_path)
        a, c = tmp_path / "a", tmp_path / "c"
        a.mkdir()
        c.mkdir()
        (a / "f").write_text("old\n")
        os.link(a / "f", c / "h")
        with pytest.raises(SandboxError, match="hard link"):
            sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'echo new > "$0/f"', str(a)],
                                  ro_mounts=[Mount(c, c)], rw_mounts=[Mount(a, a)]))
        assert os.stat(a / "f").st_ino == os.stat(c / "h").st_ino
        assert (c / "h").read_text() == "old\n"


class TestWritableMountsWithSpecialFilesAreRefused:
    """The copier skips FIFOs, sockets and device nodes, so one already in a writable mount
    would be missing from the staged copy and deleted from the host by the copy-back."""

    def test_a_fifo_in_a_writable_mount_is_refused_and_kept(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        (out / "sub").mkdir(parents=True)
        os.mkfifo(out / "sub" / "pipe")
        with pytest.raises(SandboxError, match="FIFO, socket or device node"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"], rw_mounts=[Mount(out, out)]))
        assert stat.S_ISFIFO(os.lstat(out / "sub" / "pipe").st_mode)
        assert list(sb.manifest.slots[0].io_dir.iterdir()) == []      # nothing was staged

    def test_a_socket_in_a_writable_mount_is_refused_and_kept(self, tmp_path):
        import socket
        import tempfile
        sb, _ = _sb_with(tmp_path)
        # AF_UNIX paths are short (104 bytes on macOS): a socket under pytest's tmp may not fit
        out = Path(tempfile.mkdtemp(prefix="bbsock", dir="/tmp")).resolve()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(str(out / "s"))
            with pytest.raises(SandboxError, match="FIFO, socket or device node"):
                sb.run(SandboxRequest(argv=["/usr/bin/true"], rw_mounts=[Mount(out, out)]))
            assert stat.S_ISSOCK(os.lstat(out / "s").st_mode)
        finally:
            s.close()
            shutil.rmtree(out)

    def test_a_fifo_in_a_read_only_mount_is_simply_not_staged(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        os.mkfifo(src / "pipe")
        r = sb.run(SandboxRequest(argv=["/usr/bin/true"], ro_mounts=[Mount(src, src)]))
        assert r.exit_code == 0, r.stderr

    def test_a_fifo_the_child_makes_is_dropped_not_refused(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        r = sb.run(SandboxRequest(argv=["/bin/sh", "-c", 'mkfifo "$0/p" && echo x > "$0/f"',
                                        str(out)], rw_mounts=[Mount(out, out)]))
        assert r.exit_code == 0, r.stderr
        assert (out / "f").read_text() == "x\n"
        assert not os.path.lexists(out / "p")


class TestTheRootStaysOutsideTheSlotContainers:
    """A slot's container is wiped before and after every run: a root inside one would lose its
    manifest, launchers and locks to the first pre-run wipe; a root holding one would put the
    child's container in the tree prepare stages."""

    def test_prepare_refuses_a_root_inside_a_slot_container(self, tmp_path):
        home = tmp_path / "home"
        root = home / "Library" / "Containers" / "io.example.slot0" / "Data" / "root"
        with pytest.raises(SandboxError, match="overlaps the slot container"):
            asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example", home=home,
                        runner=_fake_runner([]))
        assert not root.exists()                                     # nothing written

    def test_prepare_refuses_a_root_inside_a_later_slots_container(self, tmp_path):
        home = tmp_path / "home"
        root = home / "Library" / "Containers" / "io.example.slot2" / "r"
        with pytest.raises(SandboxError, match="overlaps the slot container"):
            asb.prepare(root, slots=3, ro_paths=[], bundle_prefix="io.example", home=home,
                        runner=_fake_runner([]))

    def test_prepare_refuses_a_root_that_holds_a_slot_container(self, tmp_path):
        home = tmp_path / "home"
        with pytest.raises(SandboxError, match="overlaps the slot container"):
            asb.prepare(home / "Library", slots=1, ro_paths=[], bundle_prefix="io.example",
                        home=home, runner=_fake_runner([]))

    def test_the_backend_refuses_a_root_inside_a_slot_container(self, tmp_path):
        # prepared for another user's home (so prepare's own check passes), then loaded by a
        # worker whose home puts the root inside slot 0's container
        home = tmp_path / "home"
        root = home / "Library" / "Containers" / "io.example.slot0" / "Data" / "root"
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example",
                    home=tmp_path / "other", runner=_fake_runner([]))
        with pytest.raises(SandboxUnavailable, match="overlaps the slot container"):
            asb.AppSandboxSandbox(root=root, home=home, platform_ok=True, verify=False)

    def test_a_root_beside_the_containers_is_fine(self, tmp_path):
        home = tmp_path / "home"
        root = home / "Library" / "Containers" / "io.other.slot0" / "root"
        asb.prepare(root, slots=1, ro_paths=[], bundle_prefix="io.example", home=home,
                    runner=_fake_runner([]))
        assert (root / asb.MANIFEST_NAME).exists()


class TestHardLinksOutOfTheWritableMountsAreRefused:
    """Staging shares links within the writable mounts; a name outside them can't be shared,
    so the copy-back would replace the mounted name with a new inode and cut the host's link."""

    def test_a_link_to_a_file_outside_the_writable_mounts_is_refused(self, tmp_path):
        sb, _ = _sb_with(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        (tmp_path / "elsewhere").write_text("x")
        os.link(tmp_path / "elsewhere", out / "f")
        with pytest.raises(SandboxError, match="hard link"):
            sb.run(SandboxRequest(argv=["/usr/bin/true"], rw_mounts=[Mount(out, out)]))
        assert os.stat(out / "f").st_ino == os.stat(tmp_path / "elsewhere").st_ino
        assert list(sb.manifest.slots[0].io_dir.iterdir()) == []      # nothing was staged


class TestWritableSourcesAreClaimedPerRun:
    """Codex P2 (#198): each run stages its own snapshot of a writable mount and copies it back
    over the host tree, so two runs on one tree (or on nested trees) would undo each other's
    writes. A run holds a claim on its writable sources from staging through copy-back; an
    overlapping run is refused at once."""

    def test_the_same_source_is_refused_while_another_run_holds_it(self, tmp_path):
        home = tmp_path / "home"
        src = tmp_path / "data"
        src.mkdir()
        with asb.hold_rw_sources(home, [src]):
            with pytest.raises(SandboxError, match="in use by another run"):
                with asb.hold_rw_sources(home, [src]):
                    pass

    def test_nested_sources_conflict_both_ways(self, tmp_path):
        home = tmp_path / "home"
        outer = tmp_path / "data"
        inner = outer / "sub"
        inner.mkdir(parents=True)
        with asb.hold_rw_sources(home, [outer]):
            with pytest.raises(SandboxError, match="in use"):
                with asb.hold_rw_sources(home, [inner]):
                    pass
        with asb.hold_rw_sources(home, [inner]):
            with pytest.raises(SandboxError, match="in use"):
                with asb.hold_rw_sources(home, [outer]):
                    pass

    def test_disjoint_sources_run_side_by_side(self, tmp_path):
        home = tmp_path / "home"
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir()
        b.mkdir()
        with asb.hold_rw_sources(home, [a]), asb.hold_rw_sources(home, [b]):
            pass

    def test_a_claim_is_released_when_its_run_ends(self, tmp_path):
        home = tmp_path / "home"
        src = tmp_path / "data"
        src.mkdir()
        with asb.hold_rw_sources(home, [src]):
            pass
        with asb.hold_rw_sources(home, [src]):
            pass
        reg = asb._rw_registry_dir(home)
        assert [p for p in reg.iterdir() if p.suffix == ".claim"] == []

    def test_a_dead_runs_claim_is_ignored_and_removed(self, tmp_path):
        # a worker killed mid-run leaves its claim file, but not its lock
        home = tmp_path / "home"
        src = tmp_path / "data"
        src.mkdir()
        reg = asb._rw_registry_dir(home)
        stale = reg / "dead.claim"
        stale.write_bytes(os.fsencode(src) + b"\0")
        with asb.hold_rw_sources(home, [src]):
            assert not stale.exists()

    def test_a_run_with_no_writable_mounts_claims_nothing(self, tmp_path):
        home = tmp_path / "home"
        with asb.hold_rw_sources(home, []):
            assert not (home / "Library").exists()


class TestInterruptedCopyBacksAreNeverStaged:
    """Codex P1 (#198): a worker that exits mid-copy-back leaves hidden entries in the host tree,
    which a later run would stage into its job. The swap renames the replaced contents to a
    `done-` tree (and lists it for the emergency cleanup) once every rename is done; before
    staging, a RECORDED `done-` tree is removed and any other leftover -- an unrecorded `done-`
    name included -- refuses the mount."""

    def test_the_replaced_contents_are_listed_for_cleanup_until_removed(self, tmp_path,
                                                                        monkeypatch):
        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "old-file").write_text("host")
        new = dest / f"{mc.COPY_BACK_MARK}abcd"
        new.mkdir()
        (new / "new-file").write_text("run")
        old = dest / f"{mc.COPY_BACK_MARK}old-abcd"
        leftovers = mc.Leftovers()
        seen: list[set] = []
        real_remove = mc.remove_tree

        def remove_tree(p):
            seen.append(set(leftovers._paths))
            real_remove(p)

        monkeypatch.setattr(mc, "remove_tree", remove_tree)
        asb.AppSandboxSandbox._swap_children(dest, new, old, leftovers)
        done = dest / f"{mc.COPY_BACK_MARK}done-abcd"
        assert seen and done in seen[-1]            # listed while it was being removed
        assert sorted(p.name for p in dest.iterdir()) == ["new-file"]
        assert leftovers._paths == set()

    def test_an_unrecorded_done_name_is_refused_not_removed(self, tmp_path):
        # a done- NAME alone proves nothing (Codex #198): only a recorded tree is removed
        src = tmp_path / "data"
        done = src / "sub" / f"{mc.COPY_BACK_MARK}done-abcd"
        done.mkdir(parents=True)
        (done / "earlier-run").write_text("x")
        assert mc.clear_stale_copy_backs(src) == done
        assert (done / "earlier-run").exists()

    @pytest.mark.parametrize("name", [f"{mc.COPY_BACK_MARK}old-abcd", f"{mc.COPY_BACK_MARK}abcd"])
    def test_an_ambiguous_leftover_is_returned_not_removed(self, tmp_path, name):
        src = tmp_path / "data"
        left = src / name
        left.mkdir(parents=True)
        assert mc.clear_stale_copy_backs(src) == left
        assert left.exists()                        # may hold the operator's own entries

    def test_a_file_mounts_leftover_sibling_is_found(self, tmp_path):
        f = tmp_path / "out.json"
        f.write_text("{}")
        sib = tmp_path / f".out.json{mc.COPY_BACK_MARK}abcd"
        sib.write_text("run")
        assert mc.clear_stale_copy_backs(f) == sib

    def test_a_clean_tree_passes(self, tmp_path):
        src = tmp_path / "data"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f").write_text("x")
        assert mc.clear_stale_copy_backs(src) is None


class TestSharedStateIsNeverMounted:
    """Codex P1 (#198): the workers' shared locks, writable-source claims and cleanup records
    live in one per-user directory. A mount (or seed, or capture) holding it would let a copy-back
    replace lock files other runs hold by inode -- refused before any claim is made."""

    @pytest.mark.parametrize("which", ["state dir", "lock dir", "holds it", "records"])
    def test_refused_before_a_claim(self, tmp_path, monkeypatch, which):
        sb, home = _sb_with(tmp_path)
        state = mc.shared_state_dir(home)
        locks = asb.bundle_lock_path(home, "io.x").parent
        src = {"state dir": state, "lock dir": locks, "holds it": home,
               "records": mc.internal_state_dirs(home)[-1]}[which]
        src.mkdir(parents=True, exist_ok=True)
        claimed: list[object] = []
        real = asb.hold_rw_sources
        monkeypatch.setattr(asb, "hold_rw_sources", lambda h, s: claimed.append(s) or real(h, s))
        with pytest.raises(SandboxError, match="shared lock and cleanup state"):
            sb.run(SandboxRequest(argv=["/bin/echo"], rw_mounts=[Mount(src, src)]))
        assert claimed == []

    def test_a_capture_over_the_state_is_refused(self, tmp_path):
        sb, home = _sb_with(tmp_path)
        with pytest.raises(SandboxError, match="shared lock and cleanup state"):
            sb.run(SandboxRequest(argv=["/bin/echo"],
                                  capture_home=mc.shared_state_dir(home) / "cache"))


class TestCapturesAreClaimed:
    """Codex P2 (#198): a capture replaces its destination as a whole tree, like a copy-back.
    It is claimed with the writable mounts, so it can't race another run over that tree."""

    def test_a_capture_is_refused_while_another_run_holds_the_tree(self, tmp_path):
        sb, home = _sb_with(tmp_path)
        data = tmp_path / "data"
        data.mkdir()
        with asb.hold_rw_sources(home, [data.resolve()]):
            with pytest.raises(SandboxError, match="in use by another run"):
                sb.run(SandboxRequest(argv=["/bin/echo"], capture_home=data / "cache"))

    def test_a_running_capture_blocks_a_writable_mount_of_the_tree(self, tmp_path, monkeypatch):
        sb, home = _sb_with(tmp_path)
        cache = tmp_path / "cache"
        seen: list[list] = []
        real = asb.hold_rw_sources
        monkeypatch.setattr(asb, "hold_rw_sources", lambda h, s: seen.append(list(s)) or real(h, s))
        try:        # (the fake child makes no container to capture; only the claim matters)
            sb.run(SandboxRequest(argv=["/bin/echo"], capture_home=cache))
        except SandboxError:
            pass
        assert seen and cache.resolve() in seen[-1]


class TestSeedAndCaptureStayClearOfTheMounts:
    """Codex P1 (#198): a seed under a writable mount was copied back over by the run (later runs
    seeded from what the child wrote); a capture over any mount replaced that tree with the
    slot's cache. Both refused before any claim is made or anything is staged."""

    @staticmethod
    def _claims(monkeypatch):
        claimed: list[object] = []
        real = asb.hold_rw_sources
        monkeypatch.setattr(asb, "hold_rw_sources", lambda h, s: claimed.append(s) or real(h, s))
        return claimed

    @pytest.mark.parametrize("where", ["equal", "inside", "contains"])
    def test_a_seed_overlapping_a_writable_mount_is_refused(self, tmp_path, monkeypatch, where):
        sb, _ = _sb_with(tmp_path)
        data = tmp_path / "x" / "data"
        (data / "seed").mkdir(parents=True)
        seed = {"equal": data, "inside": data / "seed", "contains": data.parent}[where]
        claimed = self._claims(monkeypatch)
        with pytest.raises(SandboxError, match="seed_home .* overlaps writable mount"):
            sb.run(SandboxRequest(argv=["/bin/echo"], rw_mounts=[Mount(data, data)],
                                  seed_home=seed))
        assert claimed == []

    @pytest.mark.parametrize("kind", ["ro", "rw"])
    def test_a_capture_overlapping_a_mount_is_refused(self, tmp_path, monkeypatch, kind):
        sb, _ = _sb_with(tmp_path)
        data = tmp_path / "data"
        data.mkdir()
        claimed = self._claims(monkeypatch)
        with pytest.raises(SandboxError, match="capture_home .* overlaps"):
            sb.run(SandboxRequest(argv=["/bin/echo"], capture_home=data / "cache",
                                  **{f"{kind}_mounts": [Mount(data, data)]}))
        assert claimed == []
