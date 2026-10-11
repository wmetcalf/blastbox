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
    """Runs the TARGET (argv[1:]) unsandboxed, standing in for the signed launcher."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        inner = mc.unwrap_launcher(argv)
        self.calls.append((inner, kw))
        return subprocess.Popen(inner[1:], **kw)


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

    def test_unsigned_launcher_fails_closed(self, sb):
        # Run the launcher binary OUTSIDE its bundle (no App Sandbox applied): it must refuse.
        raw = sb.manifest.root / "build" / asb.LAUNCHER_EXE
        r = subprocess.run([str(raw), "/usr/bin/true"], capture_output=True)
        assert r.returncode == 70 and b"not sandboxed" in r.stderr


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
