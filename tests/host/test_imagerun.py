"""Execution of a declared image plan.

Every test here is a failure that has actually happened on this fleet. The
runner is a double, so the assertions are about the ARGV and the ORDER — which
is where all of those failures lived — rather than about docker.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from blastbox.host.images import load_plan
from blastbox.host.imagerun import (
    BuildError,
    build_plan,
    export_rootfs,
    run_plan,
)

SPEC = """
[engine]
name = "demo"

[[image]]
name = "demo-base"
dockerfile = "deploy/docker/Dockerfile.base"
base = "upstream:1"

[[image]]
name = "demo-worker"
dockerfile = "deploy/docker/Dockerfile.worker"
base = "demo-base"

[[rootfs]]
kind = "ext4"
image = "demo-worker"
dest = "$DEMO_DIR/demo.ext4"
size_mib = 64
requires = ["/init"]
"""


class FakeRunner:
    """Records argv and returns a scripted result per command."""

    def __init__(self, fail: str | None = None, stdout: str = "") -> None:
        self.calls: list[list[str]] = []
        self.fail = fail
        self.stdout = stdout

    def __call__(self, argv, *, cwd=None, capture_output=False, stdout=None):
        self.calls.append(list(argv))
        rc = 1 if self.fail and self.fail in " ".join(argv) else 0
        return subprocess.CompletedProcess(
            list(argv), rc, stdout=self.stdout, stderr="boom" if rc else ""
        )

    @staticmethod
    def _bare(call: list[str]) -> list[str]:
        """The command without its privilege prefix.

        Whether one is there depends on the MACHINE — CI runners have
        passwordless sudo, this laptop does not — so a matcher that did not
        strip it made two of these tests pass locally and fail in CI.
        """
        return call[1:] if call and call[0] == "sudo" else call

    def verb(self, *words: str) -> list[list[str]]:
        """Calls whose LEADING words are exactly these.

        Not a substring search over the whole argv: pytest's tmp_path contains
        the test's own name, so matching "pull" anywhere made a `docker build`
        whose -f pointed into `test_..._are_pulled_.../` count as a pull. The
        first version of this helper passed for that reason.
        """
        n = len(words)
        return [c for c in self.calls if list(self._bare(c)[:n]) == list(words)]

    def tagged(self, tag: str) -> list[list[str]]:
        return [c for c in self.calls if tag in c]


@pytest.fixture(autouse=True)
def _pinned_privilege(monkeypatch: pytest.MonkeyPatch):
    """Pin the privilege decision so these tests do not depend on whether the
    machine running them has passwordless sudo. Tests about privilege override
    it explicitly."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: [])
    monkeypatch.setattr(mod, "_can_be_root", lambda: False)


def _repo(tmp_path: Path, spec: str = SPEC) -> Path:
    d = tmp_path / "repo"
    (d / "deploy" / "docker").mkdir(parents=True)
    (d / "deploy" / "docker" / "Dockerfile.base").write_text(
        "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
    )
    (d / "deploy" / "docker" / "Dockerfile.worker").write_text(
        "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
    )
    (d / "blastbox-images.toml").write_text(spec)
    return d


def _plan(tmp_path: Path, spec: str = SPEC):
    return load_plan(_repo(tmp_path, spec))


def test_a_refused_stamp_stops_the_build_instead_of_building_unstamped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 2026-09-02 incident, in the form the bash produced it.

    A `$(...)` in docker's argument list has its status discarded by `set -e`,
    so a refusing stamp left the build running with no labels and no pin — the
    image took its Dockerfile's mutable default base, and the script printed
    that everything was stamped.
    """
    import blastbox.host.imagerun as mod
    from blastbox.host.stamp import StampError

    def refuse(**_kw):
        raise StampError("Dockerfile declares no ARG BASE_IMAGE")

    monkeypatch.setattr(mod, "_stamp_flags", refuse)
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(_plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None)
    assert "refusing to build unstamped" in str(e.value)
    assert run.verb("docker", "build") == [], "a build ran after the stamp refused"


def test_upstream_bases_are_pulled_and_chain_bases_are_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An upstream tag has to be local before it is inspected for a digest.

    Otherwise the build pulls it itself and can get a different push of the same
    mutable tag than the one recorded a moment earlier. A chain base was just
    built here, so pulling it would reach a registry for an image that only
    exists locally.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: ["--label", "x=y"])
    run = FakeRunner()
    build_plan(_plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None)
    pulls = [c[-1] for c in run.verb("docker", "pull")]
    assert pulls == ["upstream:1"]


def test_the_chain_stops_at_the_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Continuing would build the next image on a STALE tag of the same name,
    which is how a rebuild ships a mixture of two builds under one tag."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    run = FakeRunner(fail="demo-base:t1")
    with pytest.raises(BuildError):
        build_plan(_plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None)
    assert run.tagged("demo-worker:t1") == [], "the chain continued past a failure"


def test_a_plan_that_cannot_be_built_is_refused_before_docker_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Dockerfile that does not declare the base ARG makes docker discard the
    pin silently. Reported before anything is built, not after."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    repo = _repo(tmp_path)
    (repo / "deploy" / "docker" / "Dockerfile.worker").write_text("FROM scratch\n")
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(load_plan(repo), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None)
    assert "cannot be built as declared" in str(e.value)
    assert run.calls == []


def _fake_extract(files: dict[str, str]):
    """An extractor that writes a fixed tree, standing in for docker export."""

    def extract(_image: str, dest: Path) -> None:
        for rel, body in files.items():
            p = dest / rel.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)

    return extract


def test_a_rootfs_missing_what_it_requires_never_reaches_the_live_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The titanarum outage, encoded.

    A cold worker image was exported as a Firecracker rootfs. It had no /init,
    so every warm guest hung until the 120s boot timeout and the tier was dead
    until the previous file was restored by hand. Nothing checked, because
    nothing had written down what the artifact needed. Now the plan says, and
    the check runs BEFORE the live artifact is touched.
    """
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    live = dest_dir / "demo.ext4"
    live.write_text("the working rootfs")
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))

    plan = _plan(tmp_path)
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
            extract=_fake_extract({"/usr/bin/true": "x"}),
        )
    assert "/init" in str(e.value)
    assert live.read_text() == "the working rootfs", "the live artifact was replaced"
    assert run.verb("mkfs.ext4") == [], "an ext4 was built from a rootfs known to be broken"


def test_a_dangling_symlink_still_counts_as_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/init is very often a symlink into /opt, whose target is resolvable in
    the GUEST and not on the host doing the export. Resolving it here would
    reject a correct rootfs — and the natural fix for that rejection is to drop
    the check that catches the real outage."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)

    def extract(_image: str, dest: Path) -> None:
        (dest / "init").symlink_to("/opt/blastbox/bin/init")

    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None, extract=extract)
    assert run.verb("mkfs.ext4"), "a valid rootfs was not built"


def test_an_unresolved_destination_is_refused(tmp_path: Path, monkeypatch) -> None:
    """`$DEMO_DIR` unset would otherwise write to a path at the filesystem
    root that nobody chose."""
    monkeypatch.delenv("DEMO_DIR", raising=False)
    plan = _plan(tmp_path)
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "unset variable" in str(e.value)


def test_the_previous_artifact_is_kept_for_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The .bak is the only reason the Firecracker outage was minutes rather
    than a rebuild."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    (dest_dir / "demo.ext4").write_text("previous")
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    moves = [c for c in run.verb("mv") if c[-1].endswith(".bak")]  # prefix-stripped
    assert moves, f"nothing was kept for rollback: {run.calls}"


def test_export_never_removes_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards a specific near-miss in this module's own draft: a sentinel of
    `Path("")` stringifies to "." — truthy, and it exists — so clearing the
    staging path to it and then rmtree-ing on a falsy check would have deleted
    the directory the command was run from."""
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    spec_text = SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
    )
    plan = _plan(tmp_path / "dir-case", spec_text)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    removed = [c for c in run.calls if c and c[0] in {"rm", "sudo"} and "-rf" in c]
    assert not any(c[-1] in {".", str(Path.cwd())} for c in removed), run.calls


def test_verification_happens_before_anything_is_exported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exporting first would publish an artifact from an image that has not been
    shown to record what built it — the exact state this module exists to make
    impossible."""
    import blastbox.host.imagerun as mod

    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "fc"))
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])

    def unstamped(image, _runner=None):
        raise RuntimeError(f"{image} carries no stamp")

    monkeypatch.setattr(mod, "_read_stamp", unstamped)
    run = FakeRunner()
    calls: list[str] = []
    with pytest.raises(BuildError) as e:
        run_plan(
            _plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None,
            extract=lambda i, d: calls.append(i),
        )
    assert "not reproducible" in str(e.value)
    assert calls == [], "a rootfs was exported from an unverified image"


@pytest.mark.parametrize(
    ("pin", "want"),
    [
        ("blastbox>=0.1.27", "0.1.27"),
        ("blastbox==0.1.28", "0.1.28"),
        ("blastbox>=0.1.27,<0.2", "0.1.27"),
        ('"blastbox[host,s3]>=0.1.33"', "0.1.33"),
        ("requests>=2", ""),
    ],
)
def test_the_installed_version_is_read_from_the_pin_not_from_delimiters(
    tmp_path: Path, pin: str, want: str
) -> None:
    """`cut -d= -f<n>` cannot do this, which is how an earlier build script
    stamped an empty version: `>=` splits into two fields and `==` into three,
    and a range drags its upper bound into whichever field it lands in. A
    version mentioned in a COMMENT is not a pin either."""
    from blastbox.host.cli import _declared_blastbox_version

    (tmp_path / "pyproject.toml").write_text(f"[project]\ndependencies = [{pin}]\n")
    assert _declared_blastbox_version(tmp_path) == want


def test_a_version_in_a_comment_is_not_a_pin(tmp_path: Path) -> None:
    """Letting one win would stamp a version nothing installs — the same reason
    `blastbox pins` ignores comment lines."""
    from blastbox.host.cli import _declared_blastbox_version

    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        "# blastbox>=0.9.9 was considered and rejected\n"
        'dependencies = ["blastbox>=0.1.33"]\n'
    )
    assert _declared_blastbox_version(tmp_path) == "0.1.33"


def test_a_missing_pyproject_is_not_a_crash(tmp_path: Path) -> None:
    from blastbox.host.cli import _declared_blastbox_version

    assert _declared_blastbox_version(tmp_path / "nope") == ""


def test_progress_lines_are_flushed(tmp_path: Path) -> None:
    """Observed on the first real run of this code: the log file held pages of
    docker output and not one line saying which image was being built.

    Python block-buffers stdout to a FILE while the docker child writes straight
    to the same descriptor, so unflushed progress lines all land at the end —
    and on a failure the last line printed is not the step that failed.

    Asserting the ORDER in a real redirected file is the only thing that tests
    this. capfd reads the descriptor after the process ends, by which point
    everything has been flushed anyway, so a capfd version of this test passes
    with flush removed. Mine did.
    """
    import blastbox.host.imagerun as mod

    # .../<root>/blastbox/host/imagerun.py -> the directory holding `blastbox`
    pkg_root = Path(mod.__file__).resolve().parents[2]
    script = (
        "from blastbox.host.imagerun import _log\n"
        "import subprocess\n"
        '_log(">> build demo:t1")\n'
        'subprocess.run(["printf", "CHILD-OUTPUT\\n"], check=True)\n'
    )
    log = tmp_path / "run.log"
    with log.open("w") as fh:
        subprocess.run(
            [sys.executable, "-c", script],
            stdout=fh,
            check=True,
            env={
                **os.environ,
                "PYTHONPATH": os.pathsep.join(
                    [str(pkg_root), os.environ.get("PYTHONPATH", "")]
                ).rstrip(os.pathsep),
            },
        )
    text = log.read_text()
    assert ">> build demo:t1" in text and "CHILD-OUTPUT" in text, text
    assert text.index(">> build demo:t1") < text.index("CHILD-OUTPUT"), (
        f"progress landed after the child's output:\n{text}"
    )


def test_everything_that_reads_the_staging_tree_runs_at_one_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Extraction and mkfs.ext4 must share a privilege level.

    Measured on toolz2: the tree is extracted as root so ownership and setuid
    bits survive, and a user-run `mkfs.ext4 -d` over it then dies on
    `.pwd.lock` (mode 600, root) with "Permission denied while populating file
    system" — after all five images had been built and verified. Splitting the
    two is not a style question.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    mkfs = [c for c in run.calls if "mkfs.ext4" in c]
    assert mkfs, run.calls
    assert mkfs[0][0] == "sudo", f"mkfs ran unprivileged over a root tree: {mkfs[0]}"


def test_a_failed_export_does_not_leak_a_root_owned_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rmtree cannot remove what root extracted: mkdtemp makes the directory
    this user's, while its contents are not, so an ordinary walk fails partway
    and leaves a whole rootfs behind. Observed on toolz2 after the mkfs
    failure."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    with pytest.raises(BuildError):
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                      extract=_fake_extract({"/usr/bin/true": "x"}))
    removals = [c for c in run.calls if "rm" in c and "-rf" in c]
    assert removals and removals[-1][0] == "sudo", (
        f"the staging tree was cleaned up unprivileged: {removals}"
    )


def test_the_published_tree_root_is_not_left_at_mkdtemp_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mkdtemp makes the staging directory 0700 and owned by the invoking user,
    and moving it into place publishes it exactly so.

    Measured against production on toolz2: the gVisor tree came out
    `drwx------ coz coz` where the one it replaced is `drwxr-xr-x root root`.
    Everything INSIDE is root's, because extraction runs as root — it is only
    the top directory, which nothing extracts, that keeps mkdtemp's. A rootfs
    whose own root a runtime cannot traverse fails to boot for a reason that
    looks like anything but permissions.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    text = SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
    )
    plan = _plan(tmp_path / "dircase", text)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    assert [c for c in run.calls if "chmod" in c and "0755" in c], run.calls
    assert [c for c in run.calls if "chown" in c and "root:root" in c], run.calls
