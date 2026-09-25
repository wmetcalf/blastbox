"""PR #186 review: the rootfs stamp is untrusted input, describes the IMAGE, and every doctor
verdict applies the whole policy.

Each test pins one upstream review finding against the stamp/doctor change.
"""

from __future__ import annotations

import argparse
import io
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


class _FakeDebugfs:
    """A debugfs whose stdout streams forever (or blocks), recording what was asked of it."""

    instances: list = []

    def __init__(self, argv, **kw):
        self.argv, self.kw = list(argv), kw
        self.killed = False
        self.requested = 0
        self.block = _FakeDebugfs.block_next
        self.stdout = self
        self.stderr = io.BytesIO(b"")
        self.returncode = None
        _FakeDebugfs.instances.append(self)

    block_next = False

    def read(self, n=-1):
        if self.block:
            import time as _t
            deadline = _t.monotonic() + 10
            while not self.killed and _t.monotonic() < deadline:
                _t.sleep(0.01)
            return b""
        assert n > 0, "an unbounded read() is exactly the defect"
        self.requested += n
        return b"x" * n

    closed = False

    def close(self):
        self.closed = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.returncode = -9
        return -9

    def poll(self):
        return self.returncode


def _debugfs_env(tmp_path, monkeypatch, *, block=False):
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")
    monkeypatch.setattr(rfs.shutil, "which", lambda _n: "/usr/sbin/debugfs")
    _FakeDebugfs.instances = []
    _FakeDebugfs.block_next = block
    monkeypatch.setattr(rfs.subprocess, "Popen", _FakeDebugfs)
    return img


def test_debugfs_output_is_read_bounded_not_buffered_whole(tmp_path, monkeypatch) -> None:
    """communicate() buffered ALL of it before slicing: a sparse 1 GiB stamp drove the
    reader to 2 GB RSS (the dispatcher, in-process)."""
    img = _debugfs_env(tmp_path, monkeypatch)
    with pytest.raises(rfs.RootfsStampError, match="larger than"):
        rfs.read_from_ext4(img)
    (proc,) = _FakeDebugfs.instances
    assert proc.requested <= rfs.MAX_STAMP_BYTES + 1
    assert proc.killed


def test_debugfs_is_bounded_in_time(tmp_path, monkeypatch) -> None:
    img = _debugfs_env(tmp_path, monkeypatch, block=True)
    monkeypatch.setattr(rfs, "DEBUGFS_TIMEOUT_S", 0.2)
    with pytest.raises(rfs.RootfsStampError, match="timed out"):
        rfs.read_from_ext4(img)
    assert _FakeDebugfs.instances[0].killed


def test_debugfs_cannot_take_the_image_path_as_an_option(tmp_path, monkeypatch) -> None:
    img = _debugfs_env(tmp_path, monkeypatch)
    with pytest.raises(rfs.RootfsStampError):
        rfs.read_from_ext4(img)
    argv = _FakeDebugfs.instances[0].argv
    assert argv[-2:] == ["--", str(img)]


def _within(seconds, fn):
    """Run fn; fail (instead of hanging the suite) if it blocks."""
    import threading

    box: dict = {}

    def go():
        try:
            box["ret"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["exc"] = exc

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "blocked -- a FIFO or device node at the stamp path was opened"
    if "exc" in box:
        raise box["exc"]
    return box.get("ret")


def test_a_fifo_at_the_stamp_path_is_refused_on_read(tmp_path: Path) -> None:
    (tmp_path / "opt" / "blastbox").mkdir(parents=True)
    os.mkfifo(tmp_path / rfs.STAMP_PATH)
    with pytest.raises(rfs.RootfsStampError, match="not a regular file"):
        _within(5, lambda: rfs.read_from_dir(tmp_path))


def test_a_fifo_at_the_stamp_path_is_refused_on_write(tmp_path: Path) -> None:
    """As root the write took the plain-open branch: a FIFO hung the build, and a block
    device node in the image would have had the stamp written into a HOST disk."""
    (tmp_path / "opt" / "blastbox").mkdir(parents=True)
    os.mkfifo(tmp_path / rfs.STAMP_PATH)
    with pytest.raises(rfs.RootfsStampError, match="not a regular file"):
        _within(5, lambda: rfs.write_into_tree(tmp_path, _stamp()))


@pytest.mark.parametrize("privileged", [False, True])
def test_a_directory_at_the_stamp_path_is_refused(tmp_path: Path, privileged) -> None:
    """`install -D` into an existing directory writes INSIDE it and reports success -- a
    rootfs that claims to be stamped and boots unchecked."""
    (tmp_path / rfs.STAMP_PATH).mkdir(parents=True)
    ran: list = []

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        ran.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    kw = {"priv": ["sudo", "-n"], "run": run} if privileged else {}
    with pytest.raises(rfs.RootfsStampError, match="not a regular file"):
        rfs.write_into_tree(tmp_path, _stamp(), **kw)
    assert ran == []


def test_the_privileged_install_never_treats_the_target_as_a_directory(tmp_path) -> None:
    ran: list = []

    def run(argv, **kw):  # type: ignore[no-untyped-def]
        ran.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    rfs.write_into_tree(tmp_path, _stamp(), priv=["sudo", "-n"], run=run)
    assert "-T" in ran[0]


def test_stamp_fields_are_sanitised_at_parse() -> None:
    """guest_problem logs and raises with stamp fields; the dispatcher's log is not doctor."""
    raw = json.dumps({"blastbox_version": "0.0.1\nINFO forged", "image": "x\x1b]0;t\x07",
                      "platform": {"arch": "x86_64\r", "runtime": "gv\nERROR forged"}})
    st = rfs.RootfsStamp.from_json(raw)
    flat = [st.blastbox_version, st.image, *[str(v) for v in st.platform.values()]]
    for value in flat:
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in value), repr(value)


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


# --- round 1 of the panel on #186 ----------------------------------------------------------


def test_provenance_reads_the_label_through_the_production_runner_contract(tmp_path) -> None:
    """The real runner returns stdout only when asked to capture it; the wrapper dropped
    capture_output, stamp.read() crashed on None, and a bare except fell back to the
    EXPORTER's version on every production export -- the exact bug b5872c9 claimed fixed."""
    import blastbox.host.imagerun as mod

    from blastbox.host import stamp as st

    labels = {st.LABEL_BLASTBOX: "9.9.9", st.LABEL_REVISION: "c0ffee" * 6 + "abcd"}

    def run(argv, *, cwd=None, capture_output=False, stdout=None):  # the real contract
        out = None
        if capture_output:
            if "{{json .Config.Labels}}" in argv:
                out = json.dumps(labels)
            elif "{{.Architecture}}" in argv:
                out = "amd64\n"
        return subprocess.CompletedProcess(list(argv), 0, out, "")

    version, revision, arch = mod._image_provenance(_plan(tmp_path), "sha256:x", run)
    assert (version, revision, arch) == ("9.9.9", "c0ffee" * 6 + "abcd", "x86_64")


@pytest.mark.parametrize(("guest", "host"), [("0.2.0-rc1", "0.2.0rc1"), ("0.2", "0.2.0"),
                                             ("0.1.42+gdeadbee", "0.1.42")])
def test_the_guest_check_compares_releases_not_spellings(guest, host) -> None:
    assert rfs.compare_to_host(_stamp(blastbox_version=guest), host) == ""


@pytest.mark.parametrize(("art", "ctr"), [("0.1.42+gdeadbee", "0.1.42"), ("0.2", "0.2.0")])
def test_doctor_agrees_with_the_tier_about_equivalent_versions(art, ctr) -> None:
    assert doctor.verdict([_ctr(version=ctr)], [_art(version=art)]) == []
    assert doctor.verdict([_ctr(version=ctr)], [_art(version=art)], expect=art) == []


def test_allow_mixed_does_not_switch_off_the_guest_check() -> None:
    """--allow-mixed is for separate PRODUCTS; it is exactly what a multi-product host
    passes, so it cannot also be what disables the rootfs check."""
    ctrs = [_ctr("a", "p1", "0.1.42"), _ctr("b", "p2", "0.1.41")]
    stale = _art("/stale", "0.1.30")
    assert doctor.verdict(ctrs, [stale], allow_mixed=True)


def test_a_paired_artifact_is_checked_against_its_own_project(tmp_path) -> None:
    """Unpaired, a stale rootfs passes if ANY product on the host runs its version."""
    rfs.write_into_tree(tmp_path / "a", _stamp(
        blastbox_version="0.1.41",
        platform={"arch": plat.host_platform().arch, "runtime": "firecracker"}))
    (art,) = doctor.survey_rootfs([f"clippy={tmp_path / 'a'}"])
    assert art.project == "clippy" and art.path == str(tmp_path / "a")
    ctrs = [_ctr("a", "clippy", "0.1.42"), _ctr("b", "other", "0.1.41")]
    assert any("clippy" in p for p in doctor.verdict(ctrs, [art], allow_mixed=True))


@pytest.mark.parametrize("as_json", [False, True])
def test_docker_down_is_not_healthy(monkeypatch, capsys, as_json) -> None:
    from blastbox.host import cli

    def down(*a, **k):
        raise doctor.DockerUnavailable("docker ps failed")

    monkeypatch.setattr(doctor, "survey", down)
    monkeypatch.setattr(doctor, "survey_rootfs", lambda paths: [_art()])
    ns = argparse.Namespace(rootfs=["/r/a"], expect=None, allow_mixed=False, json=as_json)
    assert cli._doctor_cmd(ns) != 0
    out = capsys.readouterr().out
    if as_json:
        assert json.loads(out)["ok"] is False


def test_json_mode_speaks_json_even_when_docker_is_down(monkeypatch, capsys) -> None:
    from blastbox.host import cli

    def down(*a, **k):
        raise doctor.DockerUnavailable("docker ps failed")

    monkeypatch.setattr(doctor, "survey", down)
    monkeypatch.setattr(doctor, "survey_rootfs", lambda paths: [])
    ns = argparse.Namespace(rootfs=[], expect=None, allow_mixed=False, json=True)
    assert cli._doctor_cmd(ns) == 2
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_allow_mixed_never_prints_ok_beside_several_versions(monkeypatch, capsys) -> None:
    ctrs = [_ctr("a", "p1", "0.1.42"), _ctr("b", "p2", "0.1.41")]
    rc, out = _doctor(monkeypatch, capsys, ctrs, [], allow_mixed=True)
    assert rc == 0
    assert "OK:" not in out and "MIXED" in out


@pytest.mark.parametrize("which", ["cold", "snapshot"])
def test_the_fc_tiers_name_the_guest_problem_when_they_refuse(monkeypatch, which) -> None:
    from blastbox.host.runtime import fc_snapshot_runtime as sr
    from blastbox.host.runtime import firecracker as fc

    monkeypatch.setattr(fc, "firecracker_available", lambda cfg=None: False)
    monkeypatch.setattr(sr, "firecracker_available", lambda cfg=None: False, raising=False)
    monkeypatch.setattr(fc, "_guest_refusal", lambda cfg: "guest is blastbox 0.0.1")
    cfg = type("C", (), {"fc_rootfs": "/r.ext4"})()
    select = fc.select_fc_runtime if which == "cold" else sr.select_snapshot_runtime
    with pytest.raises(fc.FCUnavailable, match="guest is blastbox 0.0.1"):
        select(cfg=cfg, require_available=True)


def test_a_paired_rootfs_whose_project_cannot_be_found_is_a_problem() -> None:
    """Pairing is the operator asserting which containers vouch for this rootfs. None found
    -- scaled to zero, or a project label that could not be read -- is "could not look"."""
    ctrs = [_ctr("x", "other", "0.1.42"), _ctr("y", "(unknown-project:dispatcher)", "0.1.42")]
    art = doctor.Artifact(path="/r", version="0.1.17", runtime="firecracker",
                          arch=plat.host_platform().arch, project="clippy")
    problems = doctor.verdict(ctrs, [art], allow_mixed=True)
    assert any("clippy" in p for p in problems)


def test_equivalent_spellings_are_not_reported_as_mixed(monkeypatch, capsys) -> None:
    ctrs = [_ctr("a", "p1", "0.2"), _ctr("b", "p2", "0.2.0")]
    rc, out = _doctor(monkeypatch, capsys, ctrs, [])
    assert rc == 0 and "MIXED" not in out and "OK:" in out


def test_an_allowed_artifact_only_mix_is_not_ok(monkeypatch, capsys) -> None:
    arts = [_art("/r/a", "0.1.17"), _art("/r/b", "0.2.0")]
    rc, out = _doctor(monkeypatch, capsys, [], arts, allow_mixed=True)
    assert rc == 0 and "OK:" not in out and "MIXED" in out


def test_an_empty_ext4_stamp_says_unstamped_not_the_debugfs_banner(tmp_path, monkeypatch) -> None:
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")
    monkeypatch.setattr(rfs.shutil, "which", lambda _n: "/usr/sbin/debugfs")

    class _P:
        def __init__(self, argv, stdout=None, stderr=None, **kw):
            banner = b"debugfs 1.47.0 (5-Feb-2023)\n"
            # Honour whatever stderr the caller chose -- a file (the pre-fix code) or a PIPE --
            # so this test reproduces the original bug rather than only pinning the new path.
            if hasattr(stderr, "write"):
                stderr.write(banner)
                stderr.flush()
            self.stderr = io.BytesIO(banner)
            self.stdout = self
            self.returncode = 0

        def read(self, n=-1):
            return b"   \n"

        def poll(self):
            return 0

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(rfs.subprocess, "Popen", _P)
    with pytest.raises(rfs.RootfsStampError, match="carries no"):
        rfs.read_from_ext4(img)


def test_a_real_debugfs_error_is_reported_past_the_banner(tmp_path, monkeypatch) -> None:
    img = tmp_path / "rootfs.ext4"
    img.write_bytes(b"\0")
    monkeypatch.setattr(rfs.shutil, "which", lambda _n: "/usr/sbin/debugfs")

    class _P:
        def __init__(self, argv, stdout=None, stderr=None, **kw):
            self.stderr = io.BytesIO(
                b"debugfs 1.47.0 (5-Feb-2023)\nBad magic number in super-block\n")
            self.stdout = self

        def read(self, n=-1):
            return b""

        def poll(self):
            return 1

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(rfs.subprocess, "Popen", _P)
    with pytest.raises(rfs.RootfsStampError, match="Bad magic"):
        rfs.read_from_ext4(img)


def test_a_failed_unprivileged_write_is_a_stamp_error(tmp_path, monkeypatch) -> None:
    def denied(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(rfs.os, "open", denied)
    with pytest.raises(rfs.RootfsStampError, match="could not write"):
        rfs.write_into_tree(tmp_path, _stamp())


def test_an_existing_path_containing_equals_is_never_split(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "build=2.ext4").write_bytes(b"\0")
    assert doctor._pairing("build=2.ext4") == ("", "build=2.ext4")
    assert doctor._pairing("clippy=/r/rootfs.ext4") == ("clippy", "/r/rootfs.ext4")


def test_unicode_separators_and_bidi_are_stripped_at_parse() -> None:
    st = rfs.RootfsStamp.from_json(json.dumps(
        {"blastbox_version": "0.1.40‮ FAKE: ok ⁦​﻿"}))
    assert st.blastbox_version == "0.1.40FAKE: ok"
    assert len(rfs.compare_to_host(st, "0.1.41").splitlines()) == 1


def test_an_unreadable_rootfs_path_is_a_row_not_a_crash(monkeypatch) -> None:
    """survey_rootfs never raises on a bad path; the pairing probe ran before its try."""
    real = Path.exists

    def denied(self, *a, **k):
        if str(self).startswith("/denied"):
            raise PermissionError(13, "Permission denied")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "exists", denied)
    got = doctor.survey_rootfs(["/denied/rootfs.ext4", "/also/missing.ext4"])
    assert [a.known for a in got] == [False, False]
    assert got[0].path == "/denied/rootfs.ext4"


def test_docker_down_does_not_also_blame_every_pairing() -> None:
    art = doctor.Artifact(path="/r", version="0.1.42", runtime="firecracker",
                          arch=plat.host_platform().arch, project="clippy")
    problems = doctor.verdict([], [art], docker_error="permission denied on docker.sock")
    assert len(problems) == 1 and "docker.sock" in problems[0]


def test_an_image_digest_reference_survives_the_survey(tmp_path) -> None:
    ref = "ghcr.io/x/y@sha256:" + "a" * 64
    rfs.write_into_tree(tmp_path / "a", _stamp(image=ref, platform={
        "arch": plat.host_platform().arch, "runtime": "firecracker"}))
    (art,) = doctor.survey_rootfs([str(tmp_path / "a")])
    assert art.image == ref


def test_debugfs_pipes_are_closed(tmp_path, monkeypatch) -> None:
    img = _debugfs_env(tmp_path, monkeypatch)
    with pytest.raises(rfs.RootfsStampError):
        rfs.read_from_ext4(img)
    proc = _FakeDebugfs.instances[0]
    assert proc.closed and proc.stderr.closed


# --- the legacy export scripts stamp too -----------------------------------------------


def test_stamp_tree_records_what_the_image_says(tmp_path, monkeypatch) -> None:
    from blastbox.host import stamp as st

    monkeypatch.setattr(doctor, "version_in_image", lambda image, runner=None: ("9.9.9", ""))

    labels = {st.LABEL_BLASTBOX: "9.9.9", st.LABEL_REVISION: "c0ffee" * 6 + "abcd"}

    def run(argv, **kw):
        if "{{json .Config.Labels}}" in argv:
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(labels), "")
        if "{{.Architecture}}" in argv:
            return subprocess.CompletedProcess(list(argv), 0, "arm64\n", "")
        if "{{.Id}}" in argv:
            return subprocess.CompletedProcess(list(argv), 0, "sha256:" + "f" * 64 + "\n", "")
        raise AssertionError(argv)

    rfs.stamp_tree(tmp_path, "eng-fc:1", "firecracker", run=run)
    got = rfs.read_from_dir(tmp_path)
    assert (got.blastbox_version, got.revision, got.image) == ("9.9.9", labels[st.LABEL_REVISION],
                                                              "eng-fc:1")
    assert got.image_id == "sha256:" + "f" * 64
    assert got.platform == {"arch": "aarch64", "runtime": "firecracker"}


def test_stamp_tree_prefers_the_installed_version_to_a_missing_label(tmp_path,
                                                                     monkeypatch) -> None:
    """The legacy scripts build with plain `docker build`: no labels at all. What the image
    actually has installed is the truth anyway -- the label is only a self-report."""
    monkeypatch.setattr(doctor, "version_in_image", lambda image, runner=None: ("0.1.42", ""))

    def run(argv, **kw):
        out = "{}" if "{{json .Config.Labels}}" in argv else "amd64\n"
        return subprocess.CompletedProcess(list(argv), 0, out, "")

    rfs.stamp_tree(tmp_path, "eng-fc:1", "firecracker", run=run)
    assert rfs.read_from_dir(tmp_path).blastbox_version == "0.1.42"


def test_stamp_tree_refuses_an_image_that_records_no_version(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(doctor, "version_in_image",
                        lambda image, runner=None: (doctor.UNKNOWN, "no blastbox"))

    def run(argv, **kw):
        out = "{}" if "{{json .Config.Labels}}" in argv else "amd64\n"
        return subprocess.CompletedProcess(list(argv), 0, out, "")

    with pytest.raises(rfs.RootfsStampError, match="no blastbox version"):
        rfs.stamp_tree(tmp_path, "eng-fc:1", "firecracker", run=run)


def test_the_module_entry_point_writes_a_stamp(tmp_path, monkeypatch) -> None:
    seen: list = []
    monkeypatch.setattr(rfs, "stamp_tree", lambda *a, **k: seen.append(a))
    assert rfs.main(["write", str(tmp_path), "eng-fc:1", "gvisor"]) == 0
    assert seen == [(str(tmp_path), "eng-fc:1", "gvisor")]
    assert rfs.main(["write", str(tmp_path), "eng-fc:1", "sparc"]) == 2


def test_both_legacy_export_scripts_stamp_what_they_export() -> None:
    root = Path(__file__).resolve().parents[2]
    for script in ("deploy/firecracker/build-rootfs.sh", "deploy/redeploy-warm.sh"):
        assert "-m blastbox.host.rootfs_stamp write" in (root / script).read_text(), script
