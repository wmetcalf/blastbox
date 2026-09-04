"""Unit tests for the CRaC snapshot backend + launcher (Phase 3 groundwork).

The CRaC argv + boot/checkpoint/restore orchestration are tested with INJECTED
subprocess deps (no real CRaC JVM) — exactly how the FC/gVisor backends are tested.
Real validation is Phase 4 (redtusk's CRaC JVM + Tika workload).
"""

from __future__ import annotations

import os

import pytest

from blastbox.host.runtime.crac_snapshot_backend import (
    CracConfig,
    CracSnapshotArtifact,
    CracSnapshotBackend,
)
from blastbox.host.runtime.crac_snapshot_launcher import (
    CracSnapshotLauncher,
    crac_boot_argv,
    crac_checkpoint_argv,
    crac_restore_argv,
)
from blastbox.host.runtime.fc_snapshot import SnapshotRestoreError


class _FakeProc:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self._rc: int | None = None

    def poll(self):
        return self._rc

    def terminate(self):
        self._rc = 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._rc = -9


# --- argv -------------------------------------------------------------------


def test_boot_argv():
    assert crac_boot_argv("java", "/img", ["-jar", "e.jar"]) == [
        "java",
        "-XX:CRaCCheckpointTo=/img",
        "-jar",
        "e.jar",
    ]


def test_checkpoint_argv():
    assert crac_checkpoint_argv("jcmd", 99) == ["jcmd", "99", "JDK.checkpoint"]


def test_restore_argv():
    assert crac_restore_argv("java", "/img") == ["java", "-XX:CRaCRestoreFrom=/img"]


# --- available() (fail-closed) ---------------------------------------------


def test_available_true_when_all_present(tmp_path):
    lr = CracSnapshotLauncher(CracConfig(), tmp_path, which=lambda b: f"/usr/bin/{b}")
    assert lr.available() is True


def test_available_false_when_criu_missing(tmp_path):
    lr = CracSnapshotLauncher(
        CracConfig(), tmp_path, which=lambda b: None if b == "criu" else f"/usr/bin/{b}"
    )
    assert lr.available() is False


# --- boot -> checkpoint -> artifact ----------------------------------------


def test_boot_base_then_checkpoint_produces_artifact(tmp_path):
    spawned: dict = {}
    ran: dict = {}

    def fake_popen(argv, cwd=None, env=None):
        spawned["argv"] = argv
        spawned["env"] = env
        return _FakeProc()

    def fake_runner(argv, **kw):
        ran["argv"] = argv
        return None

    cfg = CracConfig(engine_argv=("-jar", "engine.jar"))
    lr = CracSnapshotLauncher(cfg, tmp_path, popen=fake_popen, runner=fake_runner)
    handle = lr.boot_base()
    assert spawned["argv"][0] == "java"
    assert any(a.startswith("-XX:CRaCCheckpointTo=") for a in spawned["argv"])
    assert spawned["argv"][-2:] == ["-jar", "engine.jar"]

    art = handle.checkpoint(tmp_path / "dest")
    assert isinstance(art, CracSnapshotArtifact)
    # honors the manager-provided dest_dir (FC/gVisor parity), not the boot-time dir
    assert art.image_dir == tmp_path / "dest" / "cracimg"
    assert art.image_dir.exists()
    assert ran["argv"][0] == "jcmd" and ran["argv"][-1] == "JDK.checkpoint"


# --- restore (via the backend) ---------------------------------------------


def test_backend_restore_rejects_wrong_artifact_type(tmp_path):
    backend = CracSnapshotBackend(
        tmp_path, CracSnapshotLauncher(CracConfig(), tmp_path)
    )
    with pytest.raises(SnapshotRestoreError):
        backend.restore_in(tmp_path / "slot", object())


def test_backend_restore_spawns_java_restore(tmp_path):
    spawned: dict = {}

    def fake_popen(argv, cwd=None, env=None):
        spawned["argv"] = argv
        spawned["env"] = env
        return _FakeProc()

    backend = CracSnapshotBackend(
        tmp_path, CracSnapshotLauncher(CracConfig(), tmp_path, popen=fake_popen)
    )
    backend.restore_in(tmp_path / "slot", CracSnapshotArtifact(tmp_path / "img"))
    assert spawned["argv"][0] == "java"
    assert spawned["argv"][1].startswith("-XX:CRaCRestoreFrom=")


# --- config from env --------------------------------------------------------


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("BLASTBOX_CRAC_JAVA_BIN", "/opt/jdk/bin/java")
    monkeypatch.setenv("BLASTBOX_CRAC_ENGINE_ARGV", "-jar redtusk.jar --warm")
    cfg = CracConfig.from_env()
    assert cfg.java_bin == "/opt/jdk/bin/java"
    assert cfg.engine_argv == ("-jar", "redtusk.jar", "--warm")


def test_config_from_env_shlex_quoted(monkeypatch):
    monkeypatch.setenv("BLASTBOX_CRAC_ENGINE_ARGV", '-Dfoo="a b" -jar e.jar')
    cfg = CracConfig.from_env()
    assert cfg.engine_argv == ("-Dfoo=a b", "-jar", "e.jar")


# --- PR #7 review fixes -----------------------------------------------------


def test_boot_base_empty_engine_argv_raises(tmp_path):
    lr = CracSnapshotLauncher(
        CracConfig(engine_argv=()), tmp_path, popen=lambda *a, **k: _FakeProc()
    )
    with pytest.raises(ValueError):
        lr.boot_base()


def test_boot_base_prepends_custom_criu_dir_to_path(tmp_path):
    spawned: dict = {}

    def fake_popen(argv, cwd=None, env=None):
        spawned["env"] = env
        return _FakeProc()

    cfg = CracConfig(
        engine_argv=("-jar", "e.jar"), criu_bin=str(tmp_path / "crbin" / "criu")
    )
    CracSnapshotLauncher(cfg, tmp_path, popen=fake_popen).boot_base()
    assert spawned["env"]["PATH"].split(os.pathsep)[0] == str(
        (tmp_path / "crbin").resolve()
    )


def test_boot_base_cleans_stale_checkpoint_dir(tmp_path):
    stale = tmp_path / "base" / "cracimg" / "stale.img"
    stale.parent.mkdir(parents=True)
    stale.write_text("old")
    CracSnapshotLauncher(
        CracConfig(engine_argv=("-jar", "e.jar")),
        tmp_path,
        popen=lambda *a, **k: _FakeProc(),
    ).boot_base()
    assert not stale.exists()  # stale image removed before the new boot
