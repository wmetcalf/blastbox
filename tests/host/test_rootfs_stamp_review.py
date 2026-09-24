"""PR #186 review: the rootfs stamp is untrusted input, describes the IMAGE, and every doctor
verdict applies the whole policy.

Each test pins one upstream review finding against the stamp/doctor change.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from blastbox.host import doctor, platform_id as plat, rootfs_stamp as rfs

from .test_imagerun import FakeRunner, _fake_extract, _plan


def _stamp(**kw) -> rfs.RootfsStamp:
    base = dict(blastbox_version="0.1.42", image="eng-fc:1", revision="deadbeef")
    base.update(kw)
    return rfs.RootfsStamp(**base)  # type: ignore[arg-type]


# --- the stamp destination is inside an UNTRUSTED image ------------------------------------


@pytest.mark.parametrize("link_at", ["opt", "opt/blastbox", rfs.STAMP_PATH])
def test_a_symlink_on_the_stamp_path_is_refused_not_followed(tmp_path: Path, link_at) -> None:
    """The image controls the tree; the write runs as root. A link anywhere on the path
    would let it create or truncate a HOST file (e.g. /etc/sudoers)."""
    tree, outside = tmp_path / "tree", tmp_path / "outside"
    tree.mkdir()
    outside.mkdir()
    link = tree / link_at
    link.parent.mkdir(parents=True, exist_ok=True)
    target = outside / "victim"
    if link_at == rfs.STAMP_PATH:
        target.write_text("host file")
    link.symlink_to(target if link_at == rfs.STAMP_PATH else outside)
    with pytest.raises(rfs.RootfsStampError, match="symlink"):
        rfs.write_into_tree(tree, _stamp())
    assert list(outside.rglob("rootfs-stamp.json")) == []
    if link_at == rfs.STAMP_PATH:
        assert target.read_text() == "host file"


def test_the_privileged_write_checks_links_before_running_anything(tmp_path: Path) -> None:
    tree, outside = tmp_path / "tree", tmp_path / "outside"
    (tree / "opt").mkdir(parents=True)
    outside.mkdir()
    (tree / "opt" / "blastbox").symlink_to(outside)
    ran: list[list[str]] = []

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        ran.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(rfs.RootfsStampError, match="symlink"):
        rfs.write_into_tree(tree, _stamp(), priv=["sudo", "-n"], run=run)
    assert ran == []


# --- reading the stamp is bounded ----------------------------------------------------------


def test_an_oversized_directory_stamp_is_refused(tmp_path: Path) -> None:
    rfs.write_into_tree(tmp_path, _stamp())
    (tmp_path / rfs.STAMP_PATH).write_text(" " * (rfs.MAX_STAMP_BYTES + 1))
    with pytest.raises(rfs.RootfsStampError, match="larger than"):
        rfs.read_from_dir(tmp_path)


def test_a_symlinked_directory_stamp_is_not_followed(tmp_path: Path) -> None:
    (tmp_path / "opt" / "blastbox").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(_stamp().to_json())
    (tmp_path / rfs.STAMP_PATH).symlink_to(elsewhere)
    with pytest.raises(rfs.RootfsStampError, match="symlink"):
        rfs.read_from_dir(tmp_path)


def test_an_oversized_ext4_stamp_is_refused(tmp_path: Path) -> None:
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        return subprocess.CompletedProcess(argv, 0, "x" * (rfs.MAX_STAMP_BYTES + 1), "")

    with pytest.raises(rfs.RootfsStampError, match="larger than"):
        rfs.read_from_ext4(img, run=run)


def test_debugfs_is_bounded_in_time_and_output(tmp_path: Path, monkeypatch) -> None:
    """A malformed filesystem must not hang doctor or firecracker_available()."""
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")
    monkeypatch.setattr(rfs.shutil, "which", lambda _n: "/usr/sbin/debugfs")
    seen: dict = {}

    class _Proc:
        def __init__(self, argv, **kw):
            seen.update(kw)
            self.stdout = open(os.devnull, "rb")  # noqa: SIM115
            self.returncode = 0

        def communicate(self, timeout=None):
            seen["timeout"] = timeout
            raise subprocess.TimeoutExpired("debugfs", timeout)

        def kill(self):
            seen["killed"] = True

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(rfs.subprocess, "Popen", _Proc)
    with pytest.raises(rfs.RootfsStampError, match="timed out"):
        rfs.read_from_ext4(img)
    assert seen["timeout"] and seen["timeout"] <= 60
    assert seen.get("killed")


# --- a rootfs binds arch + runtime, not the exporter's CPU ---------------------------------


def test_a_rootfs_is_not_bound_to_the_export_hosts_cpu() -> None:
    """The snapshot is taken on the DEPLOYING host by SnapshotManager.build; the machine that
    ran mkfs.ext4 leaves nothing CPU-specific in the rootfs."""
    live = plat.host_platform(runtime="firecracker")
    stamp = _stamp(platform={
        "arch": live.arch, "runtime": "firecracker",
        "cpu_vendor": "SomeOtherVendor", "cpu_model": "x", "kernel": "1.0",
        "runtime_version": "0.0.1",
    })
    assert plat.compare(rfs.platform_of(stamp), live) == []


def test_a_rootfs_for_another_arch_is_still_refused() -> None:
    live = plat.host_platform(runtime="firecracker")
    stamp = _stamp(platform={"arch": "s390x", "runtime": "firecracker"})
    assert [f.field for f in plat.refusals(plat.compare(rfs.platform_of(stamp), live))] == [
        "arch"
    ]


# --- the stamp describes the IMAGE, not the exporter ---------------------------------------


class _ImgStamp:
    blastbox = "9.9.9"
    revision = "c0ffee" * 6 + "abcd"


def _stage_capturing(tmp_path, monkeypatch, *, arch_out="arm64"):
    import blastbox.host.imagerun as mod

    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    monkeypatch.setattr(mod, "_blastbox_version", lambda: "0.0.1")      # the EXPORTER
    monkeypatch.setattr(mod, "_source_revision", lambda plan: "plan-root-rev")
    monkeypatch.setattr(mod, "_read_stamp", lambda ident, r=None: _ImgStamp())
    captured: list[rfs.RootfsStamp] = []
    monkeypatch.setattr(mod._rootfs_stamp, "write_into_tree",
                        lambda tree, stamp, **kw: captured.append(stamp))

    class Run(FakeRunner):
        def __call__(self, argv, **kw):
            if "{{.Architecture}}" in argv:
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 0, arch_out + "\n", "")
            return super().__call__(argv, **kw)

    plan = _plan(tmp_path)
    mod.stage_rootfs(plan, plan.rootfs[0], "t1", run=Run(), log=lambda _: None,
                     extract=_fake_extract({"/init": "x"}), extract_preserves_ownership=True,
                     verified_id="sha256:" + "e" * 64)
    assert len(captured) == 1
    return captured[0]


def test_the_stamp_records_the_version_built_into_the_image(tmp_path, monkeypatch) -> None:
    """An older CLI building a newly pinned version is the normal upgrade path; stamping the
    exporter's version made the upgraded host refuse a correctly built guest."""
    stamp = _stage_capturing(tmp_path, monkeypatch)
    assert stamp.blastbox_version == "9.9.9"


def test_the_stamp_records_the_images_own_revision(tmp_path, monkeypatch) -> None:
    stamp = _stage_capturing(tmp_path, monkeypatch)
    assert stamp.revision == _ImgStamp.revision


def test_the_stamp_records_the_images_architecture(tmp_path, monkeypatch) -> None:
    stamp = _stage_capturing(tmp_path, monkeypatch, arch_out="arm64")
    assert stamp.platform["arch"] == "aarch64"
    assert not stamp.platform.get("cpu_vendor")
    assert not stamp.platform.get("cpu_model")


# --- gVisor checks its directory rootfs too ------------------------------------------------


def test_a_stale_gvisor_guest_is_refused_at_selection(tmp_path, monkeypatch) -> None:
    from blastbox.host.runtime import gvisor_snapshot as gs
    from blastbox.host.runtime import gvisor_snapshot_runtime as gr

    monkeypatch.setattr(gs.GvisorSnapshotBackend, "available", lambda self: True)
    tree = tmp_path / "rootfs"
    rfs.write_into_tree(tree, _stamp(
        blastbox_version="0.0.1",
        platform={"arch": plat.host_platform().arch, "runtime": "gvisor"}))
    cfg = gr._gvisor_config_from_env({
        **os.environ, "BLASTBOX_GVISOR_ROOTFS": str(tree),
        "BLASTBOX_GVISOR_RUNSC": "/bin/true",
    })
    assert gr.select_gvisor_snapshot_runtime(cfg=cfg) is None
    with pytest.raises(gr.GvisorUnavailable, match="0.0.1"):
        gr.select_gvisor_snapshot_runtime(cfg=cfg, require_available=True)


# --- doctor: stamp text is untrusted, and the verdict applies the whole policy ----------


def test_stamp_fields_are_sanitised_before_display(tmp_path: Path) -> None:
    rfs.write_into_tree(tmp_path / "a", _stamp(
        blastbox_version="0.1.42\x1b[2J\nOK: forged",
        image="img\x07", platform={"arch": "x86\x1b]0;t\x07", "runtime": "fc\r"}))
    (art,) = doctor.survey_rootfs([str(tmp_path / "a")])
    for value in (art.version, art.image, art.arch, art.runtime):
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in value), repr(value)


def _art(path="/r/a", version="0.1.42", **kw) -> doctor.Artifact:
    return doctor.Artifact(path=path, version=version,
                           runtime=kw.get("runtime", "firecracker"),
                           arch=kw.get("arch", plat.host_platform().arch))


def _ctr(name="c1", project="p1", version="0.1.42") -> doctor.Container:
    return doctor.Container(name=name, image="i", project=project, status="Up",
                            version=version)


def _doctor(monkeypatch, capsys, containers, artifacts, **args):
    from blastbox.host import cli

    monkeypatch.setattr(doctor, "survey", lambda *a, **k: list(containers))
    monkeypatch.setattr(doctor, "survey_rootfs", lambda paths: list(artifacts))
    ns = argparse.Namespace(rootfs=[a.path for a in artifacts], expect=None,
                            allow_mixed=False, json=False)
    for k, v in args.items():
        setattr(ns, k, v)
    rc = cli._doctor_cmd(ns)
    return rc, capsys.readouterr().out


@pytest.mark.parametrize("as_json", [False, True])
def test_expect_is_applied_in_both_output_modes(monkeypatch, capsys, as_json) -> None:
    rc, _ = _doctor(monkeypatch, capsys, [_ctr()], [], expect="0.1.43", json=as_json)
    assert rc == 1


@pytest.mark.parametrize("as_json", [False, True])
def test_allow_mixed_is_applied_in_both_output_modes(monkeypatch, capsys, as_json) -> None:
    ctrs = [_ctr("a", "p1", "0.1.42"), _ctr("b", "p2", "0.1.41")]
    assert _doctor(monkeypatch, capsys, ctrs, [], json=as_json)[0] == 1
    assert _doctor(monkeypatch, capsys, ctrs, [], json=as_json, allow_mixed=True)[0] == 0


def test_json_mode_reports_the_policy_verdict(monkeypatch, capsys) -> None:
    rc, out = _doctor(monkeypatch, capsys, [_ctr()], [], expect="0.1.43", json=True)
    report = json.loads(out)
    assert report["ok"] is False and rc == 1
    assert any("0.1.43" in p for p in report["problems"])


@pytest.mark.parametrize("as_json", [False, True])
def test_allow_mixed_does_not_excuse_a_bad_artifact(monkeypatch, capsys, as_json) -> None:
    ctrs = [_ctr("a", "p1", "0.1.42"), _ctr("b", "p2", "0.1.41")]
    bad = doctor.Artifact(path="/r/x", version=doctor.UNKNOWN, detail="unreadable")
    rc, _ = _doctor(monkeypatch, capsys, ctrs, [bad], allow_mixed=True, json=as_json)
    assert rc == 1


@pytest.mark.parametrize("as_json", [False, True])
def test_rootfs_only_applies_version_policy(monkeypatch, capsys, as_json) -> None:
    arts = [_art("/r/a", "0.1.42"), _art("/r/b", "0.1.41")]
    assert _doctor(monkeypatch, capsys, [], arts, json=as_json)[0] == 1
    assert _doctor(monkeypatch, capsys, [], arts, json=as_json, allow_mixed=True)[0] == 0
    one = [_art("/r/a", "0.1.42")]
    assert _doctor(monkeypatch, capsys, [], one, json=as_json)[0] == 0
    assert _doctor(monkeypatch, capsys, [], one, json=as_json, expect="0.1.43")[0] == 1


@pytest.mark.parametrize("as_json", [False, True])
def test_allow_mixed_does_not_excuse_an_unbootable_artifact(monkeypatch, capsys, as_json) -> None:
    ctrs = [_ctr("a", "p1", "0.1.42"), _ctr("b", "p2", "0.1.41")]
    alien = _art("/r/alien", "0.1.42", arch="s390x")
    rc, _ = _doctor(monkeypatch, capsys, ctrs, [alien], allow_mixed=True, json=as_json)
    assert rc == 1
