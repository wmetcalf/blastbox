"""Execution of a declared image plan.

Every test here is a failure that has actually happened on this fleet. The
runner is a double, so the assertions are about the ARGV and the ORDER — which
is where all of those failures lived — rather than about docker.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from blastbox.host.images import PlanError, load_plan
from blastbox.host.imagerun import (
    BuildError,
    build_plan,
    export_rootfs,
    run_plan,
    verify_built,
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
        # An EXACT argv element, never a substring of the joined line. pytest's
        # tmp_path contains the test's own name, so `fail="chmod"` inside
        # `test_a_failed_chmod_...` matched every command's path argument and
        # made the test pass no matter what the code did.
        rc = 1 if self.fail and self.fail in list(argv) else 0
        out = self.stdout
        bare = self._bare(list(argv))
        if rc == 0 and bare[:2] == ["docker", "inspect"] and "{{.Id}}" in bare:
            # Verification resolves each tag to the id it is about to export.
            out = "sha256:" + "e" * 64
        if rc == 0 and bare[:2] == ["mktemp", "-d"]:
            # Behaves like the real thing: the code uses the path it prints, so
            # a double that returned "" would make every later step operate on
            # Path("") and the test would pass or fail for that instead.
            out = tempfile.mkdtemp(prefix="fake-stage-", dir=str(Path(bare[2]).parent))
        return subprocess.CompletedProcess(
            list(argv), rc, stdout=out, stderr="boom" if rc else ""
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
    # The extra ARGs are declared because some specs below pass them; docker
    # would silently discard an undeclared one, and arg_problems refuses first.
    (d / "deploy" / "docker" / "Dockerfile.base").write_text(
        "ARG BASE_IMAGE\nARG JDK_BUILD_IMAGE\nARG BLASTBOX_VERSION\nFROM ${BASE_IMAGE}\n"
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
        # `!=` names the version that will NOT be installed.
        ("blastbox!=0.1.27", ""),
        ("blastbox<=0.9.9", ""),
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


class _FakeStamp:
    def __init__(self, reproducible=True, moved="", name="base:1", ident="sha256:" + "a" * 64):
        self.reproducible = reproducible
        self._moved = moved
        self.base_name = name
        self.base_image_id = ident
        self.base_digest = ""
        self.revision = "b" * 40
        self.blastbox = "0.1.34"

    def base_moved(self, _runner=None):
        return self._moved


def test_an_unstamped_image_does_not_pass_verification(monkeypatch) -> None:
    """`stamp.read()` fills missing labels with the sentinel "unknown", which is
    TRUTHY — so checking `revision` accepted a completely unstamped image and
    exported it. `Stamp.reproducible` is the predicate that answers this."""
    import blastbox.host.imagerun as mod

    unstamped = _FakeStamp(reproducible=False)
    unstamped.revision = "unknown"  # the sentinel a bare image reads back
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: unstamped)
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "no source revision" in str(e.value)


def test_a_base_that_moved_is_caught_before_anything_is_exported(monkeypatch) -> None:
    """A local base is pinned by a mutable reference, so a concurrent build can
    retarget the tag between the inspection that wrote the label and the build
    that consumed it: a child of image B carrying image A's digest."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(
        mod, "_read_stamp", lambda i, r=None: _FakeStamp(moved="sha256:" + "c" * 64)
    )
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "does not name" in str(e.value)


def test_a_stamp_that_disagrees_with_the_image_contents_is_caught(monkeypatch) -> None:
    """Syntactically perfect labels can still be false: a stale Dockerfile
    default or a wrong --blastbox-version records a version the image does not
    contain, which is the precise thing provenance is for."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(
        mod, "_verify_contents", lambda i, r=None: (False, "labelled 0.1.34, contains 0.1.31")
    )
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "contains 0.1.31" in str(e.value)


def test_an_image_with_no_blastbox_at_all_still_passes(monkeypatch) -> None:
    """A pure-JVM worker base has no blastbox to compare against. That is not a
    disagreement, and treating it as one would block a legitimate chain."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (None, "no blastbox"))
    assert verify_built(["demo:t1"], run=FakeRunner(), log=lambda _: None)


def test_a_required_path_cannot_escape_through_a_symlinked_parent(
    tmp_path: Path, monkeypatch
) -> None:
    """The image controls the tree. With `usr -> /usr` inside it, a joined-path
    lexists finds a HOST file and approves a rootfs where the guest path is
    absent — defeating the guard in the direction that publishes."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    text = SPEC.replace('requires = ["/init"]', 'requires = ["/usr/bin/env"]')
    plan = _plan(tmp_path, text)

    def extract(_image: str, dest: Path) -> None:
        (dest / "usr").symlink_to("/usr")  # resolves on the HOST, not in the guest

    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None,
                      extract=extract)
    assert "/usr/bin/env" in str(e.value)


@pytest.mark.parametrize("bad", ["init", "/../etc/passwd", "/a/../../b"])
def test_a_requirement_that_is_not_a_confined_guest_path_is_refused(
    tmp_path: Path, monkeypatch, bad: str
) -> None:
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path, SPEC.replace('requires = ["/init"]', f'requires = ["{bad}"]'))
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "cannot be checked" in str(e.value)


def test_no_artifact_is_published_when_a_later_one_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """Publishing each as it is built leaves the earlier destinations on the new
    release and the later ones on the old — the warm tiers then run a MIXED
    release even though the command reported failure."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    d = tmp_path / "out"
    d.mkdir()
    (d / "first.ext4").write_text("old-first")
    monkeypatch.setenv("DEMO_DIR", str(d))
    text = SPEC.replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/first.ext4"') + (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "demo-worker"\n'
        'dest = "$DEMO_DIR/second.ext4"\nsize_mib = 64\nrequires = ["/init"]\n'
    )
    plan = _plan(tmp_path, text)

    seen: list[str] = []

    def extract(image: str, dest: Path) -> None:
        seen.append(image)
        if len(seen) == 1:  # the first artifact stages fine
            (dest / "init").write_text("x")
        # the second is missing /init and must abort the whole run

    run = FakeRunner()
    with pytest.raises(BuildError):
        run_plan(plan, "t1", blastbox_version="0.1.34", run=run, log=lambda _: None,
                 extract=extract)
    assert (d / "first.ext4").read_text() == "old-first", "an artifact was published anyway"


def test_a_builder_stage_image_is_pinned_to_a_digest(
    tmp_path: Path, monkeypatch
) -> None:
    """A multi-stage Dockerfile COPIES artifacts out of these. Only the primary
    base was ever resolved and recorded, so an upstream push could change what
    lands in the image while every label stayed identical."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    digest = "docker.io/library/jdk@sha256:" + "d" * 64
    monkeypatch.setattr(mod, "_digest_from", lambda _img, _json: digest)
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk" }',
        1,
    )
    run = FakeRunner(stdout='["jdk@sha256:' + "d" * 64 + '"]')
    build_plan(_plan(tmp_path, text), "t1", blastbox_version="0.1.34", run=run,
               log=lambda _: None)
    builds = run.verb("docker", "build")
    assert builds, run.calls
    assert any(f"JDK_BUILD_IMAGE={digest}" in a for a in builds[0]), builds[0]


def test_a_non_image_build_arg_is_left_alone(tmp_path: Path, monkeypatch) -> None:
    """A version is not an image. Trying to pin one would fail the build for a
    reason that has nothing to do with provenance."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { BLASTBOX_VERSION = "0.1.34" }',
        1,
    )
    run = FakeRunner()
    build_plan(_plan(tmp_path, text), "t1", blastbox_version="0.1.34", run=run,
               log=lambda _: None)
    assert run.verb("docker", "inspect") == [], "a plain version was treated as an image"


def test_load_plan_resolves_a_relative_root(tmp_path: Path, monkeypatch) -> None:
    """A relative root survives into dockerfile_path, and the build then runs
    with cwd=root — so docker resolves `repo/deploy/...` against `repo/` and
    looks for `repo/repo/deploy/...`."""
    from blastbox.host.images import dockerfile_path

    _repo(tmp_path)
    monkeypatch.chdir(tmp_path)
    plan = load_plan("repo")
    assert plan.root.is_absolute()
    assert dockerfile_path(plan, plan.images[0], {}).is_absolute()


def test_privilege_is_decided_from_the_parent_not_the_destination(tmp_path: Path) -> None:
    """Every write is a SIBLING of the destination — the staging directory, the
    `.new` image, the `.bak` rename.

    A directory rootfs published through sudo stays owned and writable by the
    invoking user under a /var/lib parent that is not writable, so probing the
    destination answers "no privilege needed" and the next run dies creating the
    staging directory, before the export starts.
    """
    from blastbox.host.imagerun import _sudo_needed

    parent = tmp_path / "locked"
    parent.mkdir()
    dest = parent / "rootfs"
    dest.mkdir()  # writable by us, exactly like a published tree
    parent.chmod(0o555)
    try:
        assert _sudo_needed(dest) is True, "the unwritable parent was not noticed"
    finally:
        parent.chmod(0o755)
    assert _sudo_needed(dest) is False


def test_a_successful_run_publishes_every_declared_artifact(
    tmp_path: Path, monkeypatch
) -> None:
    """The companion to the mixed-release test above.

    Without this, deleting the publish phase outright broke nothing: the only
    other test of it asserts that publication does NOT happen, which an
    implementation that never publishes satisfies perfectly.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    d = tmp_path / "out"
    d.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(d))
    text = SPEC.replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/first.ext4"') + (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "demo-worker"\n'
        'dest = "$DEMO_DIR/second.ext4"\nsize_mib = 64\nrequires = ["/init"]\n'
    )
    plan = _plan(tmp_path, text)
    run = FakeRunner()
    run_plan(plan, "t1", blastbox_version="0.1.34", run=run, log=lambda _: None,
             extract=_fake_extract({"/init": "x"}))
    published = [c[-1] for c in run.verb("mv")]
    assert str(d / "first.ext4") in published, run.calls
    assert str(d / "second.ext4") in published, run.calls


@pytest.mark.parametrize(
    ("field", "value", "expect"),
    [
        ("revision", "a" * 40 + "-dirty", "DIRTY"),
        ("revision", "unknown", "no source revision"),
        ("base_image_id", "", "no base digest"),
        ("blastbox", "unknown", "no blastbox version"),
    ],
)
def test_a_rejected_stamp_says_which_condition_it_failed(field, value, expect) -> None:
    """"stamp is incomplete" plus four fields is not actionable.

    Hit on the real chain: every image was refused for the same reason — a
    dirty tree — and the message named none of it. The fix is `git commit`, and
    an operator will not infer that from a field dump.
    """
    from blastbox.host.imagerun import _why_unusable

    stamp = _FakeStamp()
    setattr(stamp, field, value)
    assert expect in _why_unusable(stamp)


def test_a_setuid_binary_stops_the_rootfs_from_being_published(
    tmp_path: Path, monkeypatch
) -> None:
    """deploy/firecracker/build-rootfs.sh has always refused these, and
    replacing that flow with this module must not silently drop the gate."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    (dest_dir / "demo.ext4").write_text("live")
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)

    def extract(_image: str, dest: Path) -> None:
        (dest / "init").write_text("x")
        (dest / "bin").mkdir()
        suid = dest / "bin" / "mount"
        suid.write_text("#!/bin/sh\n")
        suid.chmod(0o4755)

    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None, extract=extract)
    assert "/bin/mount" in str(e.value)
    assert (dest_dir / "demo.ext4").read_text() == "live", "the live artifact was replaced"
    assert run.verb("mkfs.ext4") == [], "an ext4 was built from a rootfs known to be unsafe"


def test_the_setuid_gate_can_be_turned_off_deliberately(
    tmp_path: Path, monkeypatch
) -> None:
    """Turned off in the DECLARATION, where it is reviewable — not by an
    environment variable nobody sees."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path, SPEC.replace('requires = ["/init"]',
                                        'requires = ["/init"]\nforbid_setuid = false'))

    def extract(_image: str, dest: Path) -> None:
        (dest / "init").write_text("x")
        suid = dest / "su"
        suid.write_text("x")
        suid.chmod(0o4755)

    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None, extract=extract)
    assert run.verb("mkfs.ext4")


def test_a_failed_chmod_stops_publication(tmp_path: Path, monkeypatch) -> None:
    """Unchecked, a filesystem that permits rename but rejects metadata changes
    publishes a tree still at mkdtemp's 0700 and reports success."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: [])
    monkeypatch.setattr(mod, "_can_be_root", lambda: False)
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    text = SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
    )
    plan = _plan(tmp_path / "dc", text)
    run = FakeRunner(fail="chmod")
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "chmod" in str(e.value)
    assert not (dest_dir / "rootfs").exists(), "a tree was published after chmod failed"


def test_two_exports_to_one_destination_do_not_share_a_staging_file(
    tmp_path: Path, monkeypatch
) -> None:
    """A fixed `<dest>.new` means two concurrent runs truncate and format the
    SAME file, and one can rename it live while the other is still writing."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    seen = set()
    for _ in range(2):
        run = FakeRunner()
        staged = mod_stage(plan, run)
        seen.add(str(staged.ready))
    assert len(seen) == 2, f"both exports used the same staging file: {seen}"


def mod_stage(plan, run):
    from blastbox.host.imagerun import stage_rootfs

    return stage_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                        extract=_fake_extract({"/init": "x"}))


def test_the_rootfs_is_extracted_from_the_id_that_was_verified(
    tmp_path: Path, monkeypatch
) -> None:
    """A tag is mutable. Re-resolving it at export time can hand us an image
    nothing checked — verify A, publish B."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    extracted: list[str] = []
    run_plan(
        _plan(tmp_path), "t1", blastbox_version="0.1.34", run=FakeRunner(),
        log=lambda _: None,
        extract=lambda image, dest: (
            extracted.append(image), (dest / "init").write_text("x")
        )[0],
    )
    assert extracted == ["sha256:" + "e" * 64], extracted


def test_an_unresolved_build_arg_is_refused_before_docker_runs(
    tmp_path: Path, monkeypatch
) -> None:
    """`_expand` leaves `$VAR` visible so the hole is legible; handing that
    literal to docker builds with a placeholder, or fails deep inside the
    Dockerfile at a line unrelated to the missing variable."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.delenv("MISSING_THING", raising=False)
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { BLASTBOX_VERSION = "$MISSING_THING" }',
        1,
    )
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(_plan(tmp_path, text), "t1", blastbox_version="0.1.34", run=run,
                   log=lambda _: None)
    assert "MISSING_THING" in str(e.value)
    assert run.calls == [], "docker ran with an unresolved build arg"


def test_a_source_tree_that_changes_during_the_build_is_caught(
    tmp_path: Path, monkeypatch
) -> None:
    """The label records the revision read BEFORE the build; docker reads the
    context during it. A concurrent deploy or an editor save in between produces
    an image whose contents are not the commit it names — and it passes every
    stamp check, because the stamp is self-consistent."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    states = iter(["abc123:0000", "def456:0000"])  # HEAD moved under the build
    monkeypatch.setattr(mod, "_source_state", lambda _repo: next(states))
    with pytest.raises(BuildError) as e:
        build_plan(_plan(tmp_path), "t1", blastbox_version="0.1.34", run=FakeRunner(),
                   log=lambda _: None)
    assert "changed while it was being built" in str(e.value)


def test_a_stable_source_tree_builds(tmp_path: Path, monkeypatch) -> None:
    """The companion: a tree that does not move must not be reported as moving,
    or the check is just a way to fail every build."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_source_state", lambda _repo: "abc123:0000")
    assert build_plan(_plan(tmp_path), "t1", blastbox_version="0.1.34", run=FakeRunner(),
                      log=lambda _: None)


def test_the_setuid_default_is_on_when_the_spec_says_nothing(tmp_path: Path) -> None:
    """Stated once, in the dataclass. Repeating it at the parse site made the
    field's own default dead code that no mutation could reach."""
    plan = _plan(tmp_path)
    assert plan.rootfs[0].forbid_setuid is True


def test_a_non_boolean_setuid_flag_is_refused(tmp_path: Path) -> None:
    """`forbid_setuid = "false"` is a string, and a truthy one — it would keep
    a gate the author meant to turn off."""
    with pytest.raises(PlanError) as e:
        _plan(tmp_path, SPEC.replace('requires = ["/init"]',
                                     'requires = ["/init"]\nforbid_setuid = "false"'))
    assert "must be true or false" in str(e.value)
