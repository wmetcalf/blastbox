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

def _sized(path: Path, nbytes: int) -> Path:
    """A SPARSE file of exactly ``nbytes``.

    These tests only need the logical length that `stat` reports. Writing the
    bytes allocated the whole thing in RAM and then wrote it to disk -- a 5 GiB
    buffer in one case, which can OOM a CI runner outright.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.truncate(nbytes)
    return path

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
        if rc == 0 and bare[:3] == ["stat", "-c", "%s"]:
            # Really stats: a double that invented a size would make the shrink
            # guard assert on fiction. Absent files exit non-zero, as stat does.
            try:
                out = str(Path(bare[3]).stat().st_size)
            except OSError:
                return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="no such file")
        if rc == 0 and bare[:2] == ["test", "-e"]:
            return subprocess.CompletedProcess(
                list(argv), 0 if Path(bare[2]).exists() else 1, stdout="", stderr=""
            )
        if rc == 0 and bare[:1] == ["find"] and "/6000" in bare:
            # Really runs it: a double that returned "" would make every setuid
            # test pass by reporting a clean tree it never looked at.
            out = subprocess.run(  # noqa: S603
                bare, capture_output=True, text=True, check=False
            ).stdout
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


def test_a_builder_stage_image_is_pinned_to_a_resolvable_reference(
    tmp_path: Path, monkeypatch
) -> None:
    """A multi-stage Dockerfile COPIES artifacts out of these. Only the primary
    base was ever resolved and recorded, so an upstream push could change what
    lands in the image while every label stayed identical.

    The pin must be the FULL `repo@sha256:...`. My first version of this test
    monkeypatched the digest helper and asserted the value I had chosen, so it
    passed while the real code emitted a bare `sha256:...` -- which docker
    resolves as `docker.io/library/sha256:...` and refuses with an
    authorization error naming a repository nobody wrote. It got as far as a
    real build on toolz2 before anything noticed. The helper is no longer
    mocked: the runner returns what `docker inspect` actually prints.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk" }',
        1,
    )
    digest = "sha256:" + "d" * 64

    class InspectingRunner(FakeRunner):
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:2] == ["docker", "inspect"] and "{{json .RepoDigests}}" in bare:
                # exactly what docker prints for a pulled upstream image
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(
                    list(argv), 0,
                    stdout='["eclipse-temurin@' + digest + '"]', stderr="",
                )
            return super().__call__(argv, **kw)

    run = InspectingRunner()
    build_plan(_plan(tmp_path, text), "t1", blastbox_version="0.1.34", run=run,
               log=lambda _: None)
    builds = run.verb("docker", "build")
    assert builds, run.calls
    pinned = [a for a in builds[0] if a.startswith("JDK_BUILD_IMAGE=")]
    assert pinned == [f"JDK_BUILD_IMAGE=eclipse-temurin@{digest}"], pinned
    # the failure this encodes: a bare digest names no repository
    assert not pinned[0].endswith(f"={digest}"), "pinned to a bare digest docker cannot resolve"


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


def test_an_audit_that_cannot_look_is_not_a_pass(tmp_path: Path, monkeypatch) -> None:
    """A gate that always passes is worse than no gate, because it reads as
    evidence.

    The first version of this audit used `Path.rglob`, which skips a directory
    it cannot read and raises nothing — so an unprivileged walk over a
    root-extracted tree scanned almost none of it and reported clean. Verified
    directly: rglob over a 0o000 directory containing a setuid file returns the
    directory and not the file.
    """
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    (dest_dir / "demo.ext4").write_text("live")
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner(fail="find")
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "could not audit" in str(e.value)
    assert (dest_dir / "demo.ext4").read_text() == "live"


def test_the_audit_sees_a_setuid_file_below_an_unreadable_directory(
    tmp_path: Path, monkeypatch
) -> None:
    """The exact shape rglob missed."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)

    def extract(_image: str, dest: Path) -> None:
        (dest / "init").write_text("x")
        locked = dest / "locked"
        locked.mkdir()
        suid = locked / "mount"
        suid.write_text("x")
        suid.chmod(0o4755)

    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                      extract=extract)
    assert "/locked/mount" in str(e.value)


def test_a_staging_directory_that_was_never_named_is_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """An empty stdout with a zero exit is not a directory.

    `Path("")` is `.` — it exists and is writable — so the export would extract
    an image over the working directory and then try to move it into place. Not
    hypothetical: a stubbed runner returning "" did exactly that and left a
    `usr/bin/true` in the repo, which `git add -A` then committed.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)

    class SilentMktemp(FakeRunner):
        def __call__(self, argv, **kw):
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")

    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=SilentMktemp(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "named no directory" in str(e.value)


def test_a_requirement_under_an_unreadable_directory_is_not_reported_missing(
    tmp_path: Path, monkeypatch
) -> None:
    """Hit on real hardware: `mktemp -d` under sudo makes the staging root
    0700 and owned by ROOT, so the in-process walk could not traverse into it
    and reported `/init` missing on a rootfs that contained it.

    "Cannot look" is not "absent" — reporting absence sends an operator hunting
    for a file that is right there.
    """
    from blastbox.host.imagerun import _Unreadable, _present_in

    if os.geteuid() == 0:
        pytest.skip("root traverses 0o000 directories, so this cannot be provoked here")

    tree = tmp_path / "tree"
    tree.mkdir()
    locked = tree / "opt"
    locked.mkdir()
    (locked / "init").write_text("x")
    locked.chmod(0o000)
    try:
        with pytest.raises(_Unreadable):
            _present_in(tree, "/opt/init")
    finally:
        locked.chmod(0o755)
    assert _present_in(tree, "/opt/init") is True


def test_the_staging_root_is_made_traversable_before_it_is_checked(
    tmp_path: Path, monkeypatch
) -> None:
    """The ORDER is the fix: normalize, then check.

    The root's mode is ours to set; the contents are the image's. Checking
    first meant every requirement lookup ran against a directory the process
    could not enter.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()

    # The REQUIREMENT check is what the ordering bug broke, so that is what has
    # to be observed. Asserting only that chmod precedes the setuid `find` left
    # a hole: moving _normalize_root between the two checks restores the
    # production bug and still satisfies it.
    order: list[str] = []
    real_requires = mod._check_requires
    real_normalize = mod._normalize_root

    def spy_requires(*a, **kw):
        order.append("check_requires")
        return real_requires(*a, **kw)

    def spy_normalize(*a, **kw):
        order.append("normalize_root")
        return real_normalize(*a, **kw)

    monkeypatch.setattr(mod, "_check_requires", spy_requires)
    monkeypatch.setattr(mod, "_normalize_root", spy_normalize)
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    assert order == ["normalize_root", "check_requires"], (
        f"the tree was checked before it was made traversable: {order}"
    )



def test_the_size_may_come_from_the_environment(tmp_path: Path, monkeypatch) -> None:
    """The exporter this replaces honoured a ROOTFS_MIB override. A spec that
    could only hold a literal would take that away."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.setenv("ROOTFS_MIB", "128")
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"'))
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    truncate = run.verb("truncate")
    assert truncate and "128M" in truncate[0], truncate


def test_a_literal_size_never_shrinks_a_live_artifact(
    tmp_path: Path, monkeypatch
) -> None:
    """A literal in the spec is the fallback for a FRESH artifact, not an
    instruction to resize a live one.

    An earlier version of this test expected a refusal here. Refusing is
    correct and useless: every rebuild of a deployment that had grown its
    rootfs would fail until someone repeated an override the old exporter never
    needed. The size is preserved instead, and the guard is left for the case
    where an operator actually asked for something smaller.
    """
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    live = dest_dir / "demo.ext4"
    _sized(live, 200 * 1024 * 1024)  # 200 MiB already in place
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.delenv("ROOTFS_MIB", raising=False)
    plan = _plan(tmp_path)  # declares a literal 64 MiB
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    assert "200M" in run.verb("truncate")[0], run.verb("truncate")


def test_growing_a_rootfs_is_allowed(tmp_path: Path, monkeypatch) -> None:
    """The guard is against SHRINKING; growing is the ordinary case when an
    engine's payload gets bigger."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 32 * 1024 * 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)  # declares 64 MiB
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    assert run.verb("mkfs.ext4")


def test_a_size_that_cannot_resolve_fails_before_anything_is_built(
    tmp_path: Path, monkeypatch
) -> None:
    """`resolved_size_mib` raises PlanError, which is NOT a BuildError — left to
    surface from the export it escaped the CLI's handler and ended the command
    in a traceback, after every image had been built and verified."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.delenv("ROOTFS_MIB", raising=False)
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "$ROOTFS_MIB"'))
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        run_plan(plan, "t1", blastbox_version="0.1.35", run=run, log=lambda _: None,
                 extract=_fake_extract({"/init": "x"}))
    assert "cannot be built as declared" in str(e.value)
    assert run.calls == [], "docker ran before the size was known"


def test_a_shrink_is_refused_again_at_publication(tmp_path: Path, monkeypatch) -> None:
    """Staging and publication are separated in time, and this module supports
    concurrent exports to one destination — so a larger run can publish in
    between, and a check made only against the old artifact would let this one
    shrink it back."""
    import blastbox.host.imagerun as mod

    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)  # 64 MiB
    run = FakeRunner()
    staged = mod.stage_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                              extract=_fake_extract({"/init": "x"}))
    # another run publishes something larger while ours sits staged
    _sized(dest_dir / "demo.ext4", 200 * 1024 * 1024)
    with pytest.raises(BuildError) as e:
        mod.publish_staged(staged, run=run, log=lambda _: None)
    assert "Refusing to shrink" in str(e.value)
    assert (dest_dir / "demo.ext4").stat().st_size == 200 * 1024 * 1024


def test_a_destination_that_cannot_be_measured_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    """An unprivileged `Path.stat()` on a root-only directory raises EACCES.
    Reading that as "absent" lets a smaller image replace a larger one, which is
    exactly what the guard exists to prevent."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)

    class UnreadableStat(FakeRunner):
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:3] == ["stat", "-c", "%s"]:
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="EACCES")
            if bare[:2] == ["test", "-e"]:
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")
            return super().__call__(argv, **kw)

    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=UnreadableStat(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "could not be measured" in str(e.value)


def test_the_shrink_check_compares_bytes_not_floored_mib(
    tmp_path: Path, monkeypatch
) -> None:
    """An image of 64 MiB plus one filesystem block floors to 64, so a 64 MiB
    replacement passed the guard and `truncate` removed that block from a
    filesystem somebody had deliberately extended."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    live = dest_dir / "demo.ext4"
    _sized(live, 64 * 1024 * 1024 + 4096)  # 64 MiB + one block
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    # An EXPLICIT override, because a defaulted size now preserves this
    # artifact rather than refusing it. The byte precision still matters here:
    # floored, 64 MiB + one block reads as 64 and an explicit 64 slips through.
    monkeypatch.setenv("ROOTFS_MIB", "64")
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"'))
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "Refusing to shrink" in str(e.value)
    assert live.stat().st_size == 64 * 1024 * 1024 + 4096


def test_the_destination_is_measured_at_the_selected_privilege(
    tmp_path: Path, monkeypatch
) -> None:
    """The measurement has to run as whatever can actually see the file.

    Without the prefix an unprivileged `stat` on a root-only destination fails,
    and the guard then decides on a size it never read. The fake runner stats
    the real file whatever prefix it is given, so only asserting on the argv
    catches this — dropping `priv` from the call otherwise breaks nothing.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    stats = [c for c in run.calls if "stat" in c and "%s" in c]
    assert stats, run.calls
    assert all(c[0] == "sudo" for c in stats), f"measured unprivileged: {stats}"


def test_an_enlarged_rootfs_keeps_its_size_when_no_override_is_given(
    tmp_path: Path, monkeypatch
) -> None:
    """The exporter this replaces derived the default from `stat` on the
    existing file, so a deployment that had grown its rootfs kept it across
    rebuilds without anyone remembering.

    Taking the literal instead makes every such rebuild fail the shrink guard —
    correct, and useless.
    """
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 200 * 1024 * 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.delenv("ROOTFS_MIB", raising=False)
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"'))
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    truncate = run.verb("truncate")
    assert truncate and "200M" in truncate[0], truncate


def test_an_explicit_override_is_obeyed_not_maxed(tmp_path: Path, monkeypatch) -> None:
    """An operator who sets the size HAS expressed an opinion. Quietly taking
    the larger existing value instead would ignore them — and a deliberate
    shrink must reach the guard, which asks for confirmation, rather than being
    silently discarded."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 200 * 1024 * 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.setenv("ROOTFS_MIB", "100")
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"'))
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    assert "Refusing to shrink" in str(e.value)


def test_an_override_larger_than_the_existing_artifact_grows_it(
    tmp_path: Path, monkeypatch
) -> None:
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 100 * 1024 * 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.setenv("ROOTFS_MIB", "300")
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"'))
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    assert "300M" in run.verb("truncate")[0]


def test_sub_mib_growth_still_preserves_the_artifact(tmp_path: Path, monkeypatch) -> None:
    """64 MiB plus one filesystem block floors to 64, so the preservation did
    not trigger and the shrink guard aborted — on an enlarged artifact with no
    override, the exact case preservation exists for."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 64 * 1024 * 1024 + 4096)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.delenv("ROOTFS_MIB", raising=False)
    plan = _plan(tmp_path)  # declares 64 MiB
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    # rounded UP, so the new image is not smaller than what it replaces
    assert "65M" in run.verb("truncate")[0], run.verb("truncate")


def test_a_failing_builder_pull_does_not_record_a_stale_digest(
    tmp_path: Path, monkeypatch
) -> None:
    """Reaching the builder-pin path is a HEURISTIC — `CACHE_ENDPOINT
    = "cache:6379"` looks exactly like an image reference — so a pull failure
    must not abort a valid build over a value docker only ever receives as a
    string.

    What must not happen is resolving a STALE local image to a digest and
    recording it as though it were fresh. So the pull failure is reported and
    the inspect is skipped: the value goes through unpinned.

    An earlier version of this test asserted an abort. Review was right that
    aborting is the wrong trade for a heuristic match.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk" }',
        1,
    )
    run = FakeRunner(fail="eclipse-temurin:25-jdk")
    build_plan(_plan(tmp_path, text), "t1", blastbox_version="0.1.36", run=run,
               log=lambda _: None)
    builds = run.verb("docker", "build")
    assert builds, run.calls
    passed = [a for a in builds[0] if a.startswith("JDK_BUILD_IMAGE=")]
    assert passed == ["JDK_BUILD_IMAGE=eclipse-temurin:25-jdk"], passed
    assert run.verb("docker", "inspect") == [], "a stale image was resolved anyway"


def test_a_failed_ext4_stage_leaves_no_partial_image(tmp_path: Path, monkeypatch) -> None:
    """`ready` is a SIBLING file, not inside the staging tree, so removing the
    tree alone left a partly-formatted image of the declared size beside the
    destination after every failed attempt."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner(fail="mkfs.ext4")
    with pytest.raises(BuildError):
        export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                      extract=_fake_extract({"/init": "x"}))
    removed = [c for c in run.calls if "rm" in c and any(a.endswith(".img") for a in c)]
    assert removed, f"the staged image was not removed: {run.calls}"


def test_publication_rolls_back_when_a_later_artifact_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """A later publish failing left the earlier destinations on the NEW release
    and the rest on the old — the mixed release the staging phase was written to
    prevent, arriving one step later."""
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

    class FailSecondPublish(FakeRunner):
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:1] == ["mv"] and bare[-1].endswith("second.ext4"):
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="EIO")
            return super().__call__(argv, **kw)

    run = FailSecondPublish()
    with pytest.raises(BuildError):
        run_plan(plan, "t1", blastbox_version="0.1.36", run=run, log=lambda _: None,
                 extract=_fake_extract({"/init": "x"}))
    # first.ext4 did not exist before this run, so the inverse of publishing it
    # is removing it -- leaving it would be a partial publish of a failed release
    rolled = [c for c in run.calls if "rm" in c and any(a.endswith("first.ext4") for a in c)]
    assert rolled, f"the first artifact was not rolled back: {run.calls}"


def test_rollback_uses_what_this_run_found_not_what_is_on_disk(
    tmp_path: Path, monkeypatch
) -> None:
    """A stale `.bak` from an earlier run must not be resurrected as if it were
    this run's original state."""
    import blastbox.host.imagerun as mod

    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4.bak", 4096)  # left over from some earlier run
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    staged = mod.stage_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                              extract=_fake_extract({"/init": "x"}))
    mod.publish_staged(staged, run=run, log=lambda _: None)
    assert staged.had_previous is False, "the destination did not exist before this run"
    run.calls.clear()
    mod._restore_backup(staged, run, lambda _: None)
    # the inverse of publishing into an empty slot is REMOVING, not restoring
    assert [c for c in run.calls if "rm" in c and any("demo.ext4" == a.rsplit("/", 1)[-1]
                                                     for a in c)], run.calls
    assert not [c for c in run.calls if "mv" in c and any(a.endswith(".bak") for a in c)], (
        "a stale backup was resurrected"
    )


def test_rollback_of_a_directory_swaps_atomically(tmp_path: Path, monkeypatch) -> None:
    """`rm -rf dest` then `mv bak dest` leaves the live path absent for as long
    as the removal takes — reintroducing, during recovery, the outage window the
    atomic publish exists to avoid."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_exchange", lambda a, b, priv, run: True)
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    (dest_dir / "rootfs").mkdir()
    (dest_dir / "rootfs.bak").mkdir()
    staged = mod._Staged(
        spec=_plan(tmp_path / "dc2", SPEC.replace('kind = "ext4"', 'kind = "dir"')
                   .replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"')).rootfs[0],
        image="i:t", dest=dest_dir / "rootfs",
        priv=[], staging=dest_dir / "stg", ready=dest_dir / "stg", had_previous=True,
    )
    run = FakeRunner()
    mod._restore_backup(staged, run, lambda _: None)
    assert not [c for c in run.calls if "rm" in c and c[-1].endswith("/rootfs")], (
        f"the live path was removed before the backup was in place: {run.calls}"
    )


def test_publication_is_serialised_per_destination(tmp_path: Path, monkeypatch) -> None:
    """Re-checking narrows the check-then-swap races this module's concurrent
    exports create; only a lock closes them."""
    import blastbox.host.imagerun as mod

    dest = tmp_path / "fc" / "demo.ext4"
    order: list[str] = []
    with mod._destination_lock(dest):
        order.append("outer")
        import subprocess as sp

        # a second process must block on the same key rather than proceed
        code = (
            "import sys, fcntl, os, hashlib, tempfile, pathlib;"
            f"key=hashlib.sha256({str(dest)!r}.encode()).hexdigest()[:16];"
            "p=pathlib.Path(tempfile.gettempdir())/f'blastbox-publish-{key}.lock';"
            "fd=os.open(p, os.O_CREAT|os.O_RDWR, 0o666);"
            "sys.exit(0 if fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB) is None else 1)"
        )
        r = sp.run([sys.executable, "-c", code], capture_output=True, check=False)
        assert r.returncode != 0, "a second publisher took the lock while it was held"
    # released afterwards
    r2 = sp.run([sys.executable, "-c", code], capture_output=True, check=False)
    assert r2.returncode == 0, "the lock was not released"


def test_the_prior_state_is_read_at_the_selected_privilege(
    tmp_path: Path, monkeypatch
) -> None:
    """`Path.exists()` answers False for a real artifact under a root-only
    parent, and rollback would then DELETE what it just published instead of
    restoring the old one.

    Asserted on the argv: the fake runner answers truthfully whatever prefix it
    is given, so dropping the privilege breaks nothing a result-based check can
    see — the same shape as the size measurement.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: ["sudo"])
    monkeypatch.setattr(mod, "_can_be_root", lambda: True)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner()
    export_rootfs(plan, plan.rootfs[0], "t1", run=run, log=lambda _: None,
                  extract=_fake_extract({"/init": "x"}))
    probes = [c for c in run.calls if "test" in c and "-e" in c]
    assert probes, run.calls
    assert all(c[0] == "sudo" for c in probes), f"probed unprivileged: {probes}"


def test_rollback_never_removes_a_live_artifact_it_cannot_replace(
    tmp_path: Path, monkeypatch
) -> None:
    """The worst outcome available: after a successful exchange whose backup
    move failed, rollback assumed `<dest>.bak` existed, deleted the live tree
    and had nothing to put back.

    Removing the live artifact with no restorable copy is worse than leaving
    the new one in place, so it refuses and says so.
    """
    import blastbox.host.imagerun as mod

    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    (dest_dir / "rootfs").mkdir()
    staged = mod._Staged(
        spec=_plan(tmp_path / "dc2", SPEC.replace('kind = "ext4"', 'kind = "dir"')
                   .replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"')).rootfs[0],
        image="i:t", dest=dest_dir / "rootfs",
        priv=[], staging=dest_dir / "stg", ready=dest_dir / "stg",
        had_previous=True, restore_from=dest_dir / "does-not-exist",
    )
    run = FakeRunner()
    said: list[str] = []
    mod._restore_backup(staged, run, said.append)
    assert (dest_dir / "rootfs").exists(), "the live artifact was removed anyway"
    assert any("CANNOT roll back" in s for s in said), said


def test_rollback_uses_the_recorded_source_when_the_backup_move_failed(
    tmp_path: Path, monkeypatch
) -> None:
    """After the exchange the ORIGINAL sits at `ready`, not at `.bak`.
    Recording that is the difference between a rollback that works and one
    that finds nothing."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_exchange", lambda a, b, priv, run: True)
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    (dest_dir / "rootfs").mkdir()
    original = dest_dir / "stg"
    original.mkdir()
    staged = mod._Staged(
        spec=_plan(tmp_path / "dc2", SPEC.replace('kind = "ext4"', 'kind = "dir"')
                   .replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"')).rootfs[0],
        image="i:t", dest=dest_dir / "rootfs",
        priv=[], staging=original, ready=original,
        had_previous=True, restore_from=original,
    )
    run = FakeRunner()
    mod._restore_backup(staged, run, lambda _: None)
    # exchanged from the recorded source, not from a .bak that never existed
    assert not [c for c in run.calls if "mv" in c and any(a.endswith(".bak") for a in c)], (
        run.calls
    )


def test_the_publish_lock_is_reusable_by_another_user(tmp_path: Path) -> None:
    """The lock file PERSISTS. Created 0644 under the usual umask by a root
    run, every later run as the deployment user got EACCES on O_RDWR — and
    could not publish at all, for a lock it only wanted to read."""
    import hashlib
    import stat as statmod

    import blastbox.host.imagerun as mod

    dest = tmp_path / "fc" / "demo.ext4"
    with mod._destination_lock(dest):
        pass
    key = hashlib.sha256(str(dest).encode()).hexdigest()[:16]
    lock = Path(tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"
    try:
        assert statmod.S_IMODE(lock.stat().st_mode) == 0o666, oct(lock.stat().st_mode)
        # and it is opened read-only, so a foreign-owned 0644 lock still works
        fd = os.open(lock, os.O_CREAT | os.O_RDONLY, 0o666)
        os.close(fd)
    finally:
        lock.unlink(missing_ok=True)


def test_publish_records_where_the_original_went_when_the_backup_move_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercised through `publish_staged`, not by constructing the state.

    An earlier test set `restore_from` by hand, so it passed with the recording
    removed — it asserted my assumption about the field rather than the code
    that fills it.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_exchange", lambda a, b, priv, run: True)
    dest_dir = tmp_path / "gv"
    dest_dir.mkdir()
    (dest_dir / "rootfs").mkdir()
    dir_plan = _plan(
        tmp_path / "dircase",
        SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
            'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
        ),
    )
    staged = mod._Staged(
        spec=dir_plan.rootfs[0], image="i:t", dest=dest_dir / "rootfs",
        priv=[], staging=dest_dir / "stg", ready=dest_dir / "stg",
    )

    class BackupMoveFails(FakeRunner):
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:1] == ["mv"] and bare[-1].endswith(".bak"):
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 1, stdout="", stderr="EIO")
            return super().__call__(argv, **kw)

    mod.publish_staged(staged, run=BackupMoveFails(), log=lambda _: None)
    assert staged.restore_from == staged.ready, (
        "the original's location was not recorded, so rollback would find nothing"
    )


def test_the_publish_lock_works_without_write_access(tmp_path: Path) -> None:
    """`flock` needs a descriptor, not write access.

    Simulates the cross-user case that strands an operator: a persistent lock
    file this process cannot open for writing. With `O_RDWR` the export fails
    outright, for a lock it only ever wanted to read.
    """
    import hashlib

    import blastbox.host.imagerun as mod

    if os.geteuid() == 0:
        pytest.skip("root opens anything for writing, so this cannot be provoked here")

    dest = tmp_path / "fc" / "readonly.ext4"
    key = hashlib.sha256(str(dest).encode()).hexdigest()[:16]
    lock = Path(tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"
    lock.write_text("")
    lock.chmod(0o444)  # as a root-created 0644 lock looks to another user
    try:
        with mod._destination_lock(dest):
            pass
    finally:
        lock.chmod(0o644)
        lock.unlink(missing_ok=True)
