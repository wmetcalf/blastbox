"""Execution of a declared image plan.

Every test here is a failure that has actually happened on this fleet. The
runner is a double, so the assertions are about the ARGV and the ORDER — which
is where all of those failures lived — rather than about docker.
"""

from __future__ import annotations

import dataclasses
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
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
from blastbox.host import images as _images
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

    def __init__(
        self, fail: str | None = None, stdout: str = "", moves: bool = False
    ) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail
        self.stdout = stdout
        # Opt-in, because most tests here use `mv` only as a recorded intention
        # and their staging paths never exist on disk. The publication and
        # rollback tests are the ones that read the destination back, and for
        # those a `mv` that reports success without moving anything turns the
        # assertion into a test of "the artifact could not be identified".
        self.moves = moves

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
        if rc == 0 and self.moves and bare[:2] == ["truncate", "-s"]:
            # Sparse, and real. With `moves` on, the publication that follows
            # actually renames this file -- so a truncate that only recorded its
            # intention would make the publish fail on a missing source and the
            # test would never reach the behaviour it is about.
            size = bare[2]
            mult = {"K": 1024, "M": 1024**2, "G": 1024**3}.get(size[-1].upper(), 1)
            n = int(size.rstrip("KMGkmg")) * mult
            with open(bare[3], "wb") as fh:
                fh.truncate(n)
        if rc == 0 and self.moves and bare[:1] == ["mv"] and len(bare) == 3:
            # Really moves. Publication is a rename and rollback is its inverse,
            # and both are now decided by reading the destination back -- so a
            # double that reports success without moving anything makes every
            # such test exercise "the artifact could not be identified" instead
            # of the branch it was written for.
            try:
                os.replace(bare[1], bare[2])
            except OSError as exc:
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr=str(exc)
                )
        if rc == 0 and bare[:3] == ["stat", "-c", "%d:%i"]:
            # Really stats. Publication records device:inode to tell its own
            # artifact from a newer run's, and rollback refuses to act on one it
            # cannot identify -- so a double that invented or omitted this would
            # turn every rollback test into a test of that refusal.
            try:
                st = Path(bare[3]).stat()
                out = f"{st.st_dev}:{st.st_ino}"
            except OSError:
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr="no such file"
                )
        if rc == 0 and bare[:3] == ["stat", "-c", "%s"]:
            # Really stats: a double that invented a size would make the shrink
            # guard assert on fiction. Absent files exit non-zero, as stat does.
            try:
                out = str(Path(bare[3]).stat().st_size)
            except OSError:
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr="no such file"
                )
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
        "ARG BASE_IMAGE\nARG JDK_BUILD_IMAGE\nARG BLASTBOX_VERSION\n"
        "ARG REGISTRY_TOKEN\nFROM ${BASE_IMAGE}\n"
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

    _resolves_to(monkeypatch)
    from blastbox.host.stamp import StampError

    def refuse(**_kw):
        raise StampError("Dockerfile declares no ARG BASE_IMAGE")

    monkeypatch.setattr(mod, "_stamp_flags", refuse)
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.33",
            run=run,
            log=lambda _: None,
        )
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

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: ["--label", "x=y"])
    run = FakeRunner()
    build_plan(
        _plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None
    )
    pulls = [c[-1] for c in run.verb("docker", "pull")]
    assert pulls == ["upstream:1"]


def test_the_chain_stops_at_the_first_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Continuing would build the next image on a STALE tag of the same name,
    which is how a rebuild ships a mixture of two builds under one tag."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    # The chain is built under a PRIVATE tag, so that is the name a failure has
    # to be injected on -- and the name the second image would be built under.
    staging = _pin_staging(monkeypatch)
    run = FakeRunner(fail=f"demo-base:{staging}")
    with pytest.raises(BuildError):
        build_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.33",
            run=run,
            log=lambda _: None,
        )
    assert run.tagged(f"demo-worker:{staging}") == [], (
        "the chain continued past a failure"
    )


def test_a_plan_that_cannot_be_built_is_refused_before_docker_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Dockerfile that does not declare the base ARG makes docker discard the
    pin silently. Reported before anything is built, not after."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    repo = _repo(tmp_path)
    (repo / "deploy" / "docker" / "Dockerfile.worker").write_text("FROM scratch\n")
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(
            load_plan(repo),
            "t1",
            blastbox_version="0.1.33",
            run=run,
            log=lambda _: None,
        )
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
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/usr/bin/true": "x"}),
            extract_preserves_ownership=True,
        )
    assert "/init" in str(e.value)
    assert live.read_text() == "the working rootfs", "the live artifact was replaced"
    assert run.verb("mkfs.ext4") == [], (
        "an ext4 was built from a rootfs known to be broken"
    )


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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=extract,
        extract_preserves_ownership=True,
    )
    assert run.verb("mkfs.ext4"), "a valid rootfs was not built"


def test_an_unresolved_destination_is_refused(tmp_path: Path, monkeypatch) -> None:
    """`$DEMO_DIR` unset would otherwise write to a path at the filesystem
    root that nobody chose."""
    monkeypatch.delenv("DEMO_DIR", raising=False)
    plan = _plan(tmp_path)
    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=FakeRunner(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
    removed = [c for c in run.calls if c and c[0] in {"rm", "sudo"} and "-rf" in c]
    assert not any(c[-1] in {".", str(Path.cwd())} for c in removed), run.calls


def test_verification_happens_before_anything_is_exported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exporting first would publish an artifact from an image that has not been
    shown to record what built it — the exact state this module exists to make
    impossible."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "fc"))
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])

    def unstamped(image, _runner=None):
        raise RuntimeError(f"{image} carries no stamp")

    monkeypatch.setattr(mod, "_read_stamp", unstamped)
    run = FakeRunner()
    calls: list[str] = []
    with pytest.raises(BuildError) as e:
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.33",
            run=run,
            log=lambda _: None,
            extract=lambda i, d: calls.append(i),
            extract_preserves_ownership=True,
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
        # PEP 440's separators are not decoration. Each of these stopped early
        # under a hand-written pattern and yielded a DIFFERENT release --
        # `0.2.0`, a final release, for a pin naming its release candidate --
        # which is then passed on as an exact build arg.
        #
        # Captured CANONICALLY, because that value is also written to the stamp
        # and compared against `importlib.metadata.version()`, which reports the
        # normalised spelling. Returning the source spelling produced an image
        # that installed correctly and then failed its own verification.
        ('"blastbox==0.2.0-rc1"', "0.2.0rc1"),
        ('"blastbox==0.2.0rc-1"', "0.2.0rc1"),
        ('"blastbox==0.2.0_rev_3"', "0.2.0.post3"),
        ('"blastbox==0.2.0+linux-x86"', "0.2.0+linux.x86"),
        ('"blastbox==0.2.0rc1"', "0.2.0rc1"),
        ('"blastbox==1!0.2.0"', "1!0.2.0"),
        ('"blastbox==0.2.0.post1"', "0.2.0.post1"),
        # An environment marker is an ordinary way for a requirement to end.
        ("\"blastbox==0.1.38; python_version >= '3.11'\"", "0.1.38"),
        # Trailing junk is not a version we understand. Returning the part we
        # DID parse would pass a release nobody declared on as an exact pin, so
        # the whole match is refused instead.
        ('"blastbox==0.2.0maybe"', ""),
        ('"blastbox==0.2.0!!"', ""),
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/usr/bin/true": "x"}),
            extract_preserves_ownership=True,
        )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
    assert [c for c in run.calls if "chmod" in c and "0755" in c], run.calls
    assert [c for c in run.calls if "chown" in c and "root:root" in c], run.calls


@dataclasses.dataclass
class _RootfsStub:
    """The two fields publication reads off a rootfs spec."""

    kind: str
    forbid_setuid: bool = True


class _FakeStamp:
    def __init__(
        self,
        reproducible=True,
        moved="",
        name="base:1",
        ident="sha256:" + "a" * 64,
        resolvable=True,
    ):
        self.reproducible = reproducible
        self._moved = moved
        self._resolvable = resolvable
        self.base_name = name
        self.base_image_id = ident
        self.base_digest = ""
        self.revision = "b" * 40
        self.blastbox = "0.1.34"
        # Which reference each check was redirected to, so a test can assert
        # the alias was used rather than only that verification passed.
        self.asked_as: list[str | None] = []
        # How many times verification asked about the base at all.
        self.checks = 0

    def base_check(self, _runner=None, ref=None):
        # ONE call answering both questions, as the real Stamp now does.
        self.asked_as.append(ref)
        self.checks += 1
        return self._resolvable, self._moved

    def base_moved(self, _runner=None, ref=None):
        self.asked_as.append(ref)
        return self._moved

    def resolvable(self, _runner=None, ref=None):
        self.asked_as.append(ref)
        # A separate question from `base_moved`, which answers "" for a base
        # that is GONE rather than moved. Verification asks both.
        return self._resolvable


_PINNED_STAGING = "t1-blastbox-staging-pinned"


def _pin_staging(monkeypatch, name: str = _PINNED_STAGING) -> str:
    """Make the private build tag predictable for a test.

    The real one carries a random component so two invocations in one process
    cannot collide, which is exactly what a test asserting a specific name
    cannot work with. Pinned through the same seam the code calls.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_staging_tag", lambda tag: name)
    return name


_VERIFIED_ID = "sha256:" + "e" * 64


def _resolves_to(monkeypatch, ident: str = _VERIFIED_ID) -> list[str]:
    """Make tag->id resolution answer without a docker daemon.

    Returns the list every resolution is recorded into, so a test can assert
    WHAT was resolved as well as that it was.
    """
    import blastbox.host.imagerun as mod

    asked: list[str] = []
    monkeypatch.setattr(
        mod, "_image_id", lambda image, run=None: (asked.append(image), ident)[1]
    )
    return asked


def test_an_unstamped_image_does_not_pass_verification(monkeypatch) -> None:
    """`stamp.read()` fills missing labels with the sentinel "unknown", which is
    TRUTHY — so checking `revision` accepted a completely unstamped image and
    exported it. `Stamp.reproducible` is the predicate that answers this."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
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

    _resolves_to(monkeypatch)
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

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(
        mod,
        "_verify_contents",
        lambda i, r=None: (False, "labelled 0.1.34, contains 0.1.31"),
    )
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "contains 0.1.31" in str(e.value)


def test_an_image_with_no_blastbox_at_all_still_passes(monkeypatch) -> None:
    """A pure-JVM worker base has no blastbox to compare against. That is not a
    disagreement, and treating it as one would block a legitimate chain."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(
        mod, "_verify_contents", lambda i, r=None: (None, "no blastbox")
    )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=FakeRunner(),
            log=lambda _: None,
            extract=extract,
            extract_preserves_ownership=True,
        )
    assert "/usr/bin/env" in str(e.value)


@pytest.mark.parametrize("bad", ["init", "/../etc/passwd", "/a/../../b"])
def test_a_requirement_that_is_not_a_confined_guest_path_is_refused(
    tmp_path: Path, monkeypatch, bad: str
) -> None:
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(
        tmp_path, SPEC.replace('requires = ["/init"]', f'requires = ["{bad}"]')
    )
    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=FakeRunner(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
    assert "cannot be checked" in str(e.value)


def test_no_artifact_is_published_when_a_later_one_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """Publishing each as it is built leaves the earlier destinations on the new
    release and the later ones on the old — the warm tiers then run a MIXED
    release even though the command reported failure."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    d = tmp_path / "out"
    d.mkdir()
    (d / "first.ext4").write_text("old-first")
    monkeypatch.setenv("DEMO_DIR", str(d))
    text = SPEC.replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/first.ext4"'
    ) + (
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
        run_plan(
            plan,
            "t1",
            blastbox_version="0.1.34",
            run=run,
            log=lambda _: None,
            extract=extract,
            extract_preserves_ownership=True,
        )
    assert (d / "first.ext4").read_text() == "old-first", (
        "an artifact was published anyway"
    )


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

    _resolves_to(monkeypatch)
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
                    list(argv),
                    0,
                    stdout='["eclipse-temurin@' + digest + '"]',
                    stderr="",
                )
            return super().__call__(argv, **kw)

    run = InspectingRunner()
    build_plan(
        _plan(tmp_path, text),
        "t1",
        blastbox_version="0.1.34",
        run=run,
        log=lambda _: None,
    )
    builds = run.verb("docker", "build")
    assert builds, run.calls
    pinned = [a for a in builds[0] if a.startswith("JDK_BUILD_IMAGE=")]
    assert pinned == [f"JDK_BUILD_IMAGE=eclipse-temurin@{digest}"], pinned
    # the failure this encodes: a bare digest names no repository
    assert not pinned[0].endswith(f"={digest}"), (
        "pinned to a bare digest docker cannot resolve"
    )


def test_a_non_image_build_arg_is_left_alone(tmp_path: Path, monkeypatch) -> None:
    """A version is not an image. Trying to pin one would fail the build for a
    reason that has nothing to do with provenance."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { BLASTBOX_VERSION = "0.1.34" }',
        1,
    )
    run = FakeRunner()
    build_plan(
        _plan(tmp_path, text),
        "t1",
        blastbox_version="0.1.34",
        run=run,
        log=lambda _: None,
    )
    assert run.verb("docker", "inspect") == [], (
        "a plain version was treated as an image"
    )


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


def test_privilege_is_decided_from_the_parent_not_the_destination(
    tmp_path: Path,
) -> None:
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

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    d = tmp_path / "out"
    d.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(d))
    text = SPEC.replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/first.ext4"'
    ) + (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "demo-worker"\n'
        'dest = "$DEMO_DIR/second.ext4"\nsize_mib = 64\nrequires = ["/init"]\n'
    )
    plan = _plan(tmp_path, text)
    run = FakeRunner()
    run_plan(
        plan,
        "t1",
        blastbox_version="0.1.34",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    """ "stamp is incomplete" plus four fields is not actionable.

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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=extract,
            extract_preserves_ownership=True,
        )
    assert "/bin/mount" in str(e.value)
    assert (dest_dir / "demo.ext4").read_text() == "live", (
        "the live artifact was replaced"
    )
    assert run.verb("mkfs.ext4") == [], (
        "an ext4 was built from a rootfs known to be unsafe"
    )


def test_the_setuid_gate_can_be_turned_off_deliberately(
    tmp_path: Path, monkeypatch
) -> None:
    """Turned off in the DECLARATION, where it is reviewable — not by an
    environment variable nobody sees."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(
        tmp_path,
        SPEC.replace(
            'requires = ["/init"]', 'requires = ["/init"]\nforbid_setuid = false'
        ),
    )

    def extract(_image: str, dest: Path) -> None:
        (dest / "init").write_text("x")
        suid = dest / "su"
        suid.write_text("x")
        suid.chmod(0o4755)

    run = FakeRunner()
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=extract,
        extract_preserves_ownership=True,
    )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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

    return stage_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )


def test_the_rootfs_is_extracted_from_the_id_that_was_verified(
    tmp_path: Path, monkeypatch
) -> None:
    """A tag is mutable. Re-resolving it at export time can hand us an image
    nothing checked — verify A, publish B."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    extracted: list[str] = []
    run_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.34",
        run=FakeRunner(),
        log=lambda _: None,
        extract=lambda image, dest: (
            extracted.append(image),
            (dest / "init").write_text("x"),
        )[0],
        extract_preserves_ownership=True,
    )
    assert extracted == ["sha256:" + "e" * 64], extracted


def test_an_unresolved_build_arg_is_refused_before_docker_runs(
    tmp_path: Path, monkeypatch
) -> None:
    """`_expand` leaves `$VAR` visible so the hole is legible; handing that
    literal to docker builds with a placeholder, or fails deep inside the
    Dockerfile at a line unrelated to the missing variable."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.delenv("MISSING_THING", raising=False)
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { BLASTBOX_VERSION = "$MISSING_THING" }',
        1,
    )
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        build_plan(
            _plan(tmp_path, text),
            "t1",
            blastbox_version="0.1.34",
            run=run,
            log=lambda _: None,
        )
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

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    states = iter(["abc123:0000", "def456:0000"])  # HEAD moved under the build
    monkeypatch.setattr(mod, "_source_state", lambda _repo: next(states))
    with pytest.raises(BuildError) as e:
        build_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=FakeRunner(),
            log=lambda _: None,
        )
    assert "changed while it was being built" in str(e.value)


def test_a_stable_source_tree_builds(tmp_path: Path, monkeypatch) -> None:
    """The companion: a tree that does not move must not be reported as moving,
    or the check is just a way to fail every build."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_source_state", lambda _repo: "abc123:0000")
    assert build_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.34",
        run=FakeRunner(),
        log=lambda _: None,
    )


def test_the_setuid_default_is_on_when_the_spec_says_nothing(tmp_path: Path) -> None:
    """Stated once, in the dataclass. Repeating it at the parse site made the
    field's own default dead code that no mutation could reach."""
    plan = _plan(tmp_path)
    assert plan.rootfs[0].forbid_setuid is True


def test_a_non_boolean_setuid_flag_is_refused(tmp_path: Path) -> None:
    """`forbid_setuid = "false"` is a string, and a truthy one — it would keep
    a gate the author meant to turn off."""
    with pytest.raises(PlanError) as e:
        _plan(
            tmp_path,
            SPEC.replace(
                'requires = ["/init"]', 'requires = ["/init"]\nforbid_setuid = "false"'
            ),
        )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=extract,
            extract_preserves_ownership=True,
        )
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
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=SilentMktemp(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    plan = _plan(
        tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"')
    )
    run = FakeRunner()
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
    assert run.verb("mkfs.ext4")


def test_a_size_that_cannot_resolve_fails_before_anything_is_built(
    tmp_path: Path, monkeypatch
) -> None:
    """`resolved_size_mib` raises PlanError, which is NOT a BuildError — left to
    surface from the export it escaped the CLI's handler and ended the command
    in a traceback, after every image had been built and verified."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.delenv("ROOTFS_MIB", raising=False)
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    plan = _plan(tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "$ROOTFS_MIB"'))
    run = FakeRunner()
    with pytest.raises(BuildError) as e:
        run_plan(
            plan,
            "t1",
            blastbox_version="0.1.35",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
    staged = mod.stage_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr="EACCES"
                )
            if bare[:2] == ["test", "-e"]:
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")
            return super().__call__(argv, **kw)

    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=UnreadableStat(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
    plan = _plan(
        tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"')
    )
    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=FakeRunner(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    plan = _plan(
        tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"')
    )
    run = FakeRunner()
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
    plan = _plan(
        tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"')
    )
    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=FakeRunner(),
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
    assert "Refusing to shrink" in str(e.value)


def test_an_override_larger_than_the_existing_artifact_grows_it(
    tmp_path: Path, monkeypatch
) -> None:
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    _sized(dest_dir / "demo.ext4", 100 * 1024 * 1024)
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.setenv("ROOTFS_MIB", "300")
    plan = _plan(
        tmp_path, SPEC.replace("size_mib = 64", 'size_mib = "${ROOTFS_MIB:-64}"')
    )
    run = FakeRunner()
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
    assert "300M" in run.verb("truncate")[0]


def test_sub_mib_growth_still_preserves_the_artifact(
    tmp_path: Path, monkeypatch
) -> None:
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk" }',
        1,
    )
    run = FakeRunner(fail="eclipse-temurin:25-jdk")
    build_plan(
        _plan(tmp_path, text),
        "t1",
        blastbox_version="0.1.36",
        run=run,
        log=lambda _: None,
    )
    builds = run.verb("docker", "build")
    assert builds, run.calls
    passed = [a for a in builds[0] if a.startswith("JDK_BUILD_IMAGE=")]
    assert passed == ["JDK_BUILD_IMAGE=eclipse-temurin:25-jdk"], passed
    assert run.verb("docker", "inspect") == [], "a stale image was resolved anyway"


def test_a_failed_ext4_stage_leaves_no_partial_image(
    tmp_path: Path, monkeypatch
) -> None:
    """`ready` is a SIBLING file, not inside the staging tree, so removing the
    tree alone left a partly-formatted image of the declared size beside the
    destination after every failed attempt."""
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    run = FakeRunner(fail="mkfs.ext4")
    with pytest.raises(BuildError):
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
    removed = [c for c in run.calls if "rm" in c and any(a.endswith(".img") for a in c)]
    assert removed, f"the staged image was not removed: {run.calls}"


def test_publication_rolls_back_when_a_later_artifact_fails(
    tmp_path: Path, monkeypatch
) -> None:
    """A later publish failing left the earlier destinations on the NEW release
    and the rest on the old — the mixed release the staging phase was written to
    prevent, arriving one step later."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    d = tmp_path / "out"
    d.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(d))
    text = SPEC.replace(
        'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/first.ext4"'
    ) + (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "demo-worker"\n'
        'dest = "$DEMO_DIR/second.ext4"\nsize_mib = 64\nrequires = ["/init"]\n'
    )
    plan = _plan(tmp_path, text)

    class FailSecondPublish(FakeRunner):
        # Real moves: this asserts the first artifact was put BACK, which is a
        # question about the filesystem, not about which commands were issued.
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:1] == ["mv"] and bare[-1].endswith("second.ext4"):
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr="EIO"
                )
            return super().__call__(argv, **kw)

    run = FailSecondPublish(moves=True)
    with pytest.raises(BuildError):
        run_plan(
            plan,
            "t1",
            blastbox_version="0.1.36",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )
    # first.ext4 did not exist before this run, so the inverse of publishing it
    # is removing it -- leaving it would be a partial publish of a failed release
    rolled = [
        c for c in run.calls if "rm" in c and any(a.endswith("first.ext4") for a in c)
    ]
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
    run = FakeRunner(moves=True)
    staged = mod.stage_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
    mod.publish_staged(staged, run=run, log=lambda _: None)
    assert staged.had_previous is False, "the destination did not exist before this run"
    run.calls.clear()
    mod._restore_backup(staged, run, lambda _: None)
    # the inverse of publishing into an empty slot is REMOVING, not restoring
    assert [
        c
        for c in run.calls
        if "rm" in c and any("demo.ext4" == a.rsplit("/", 1)[-1] for a in c)
    ], run.calls
    assert not [
        c for c in run.calls if "mv" in c and any(a.endswith(".bak") for a in c)
    ], "a stale backup was resurrected"


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
        spec=_plan(
            tmp_path / "dc2",
            SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
                'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
            ),
        ).rootfs[0],
        image="i:t",
        dest=dest_dir / "rootfs",
        priv=[],
        staging=dest_dir / "stg",
        ready=dest_dir / "stg",
        had_previous=True,
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
    export_rootfs(
        plan,
        plan.rootfs[0],
        "t1",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )
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
        spec=_plan(
            tmp_path / "dc2",
            SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
                'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
            ),
        ).rootfs[0],
        image="i:t",
        dest=dest_dir / "rootfs",
        priv=[],
        staging=dest_dir / "stg",
        ready=dest_dir / "stg",
        had_previous=True,
        restore_from=dest_dir / "does-not-exist",
        # As publication records it. Rollback refuses to act on an artifact it
        # cannot identify, so a hand-built _Staged without this would exercise
        # that refusal instead of the missing-backup one this test is about.
        published_identity=mod._artifact_identity(
            dest_dir / "rootfs", [], mod._default_runner
        ),
    )
    run = mod._default_runner
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
        spec=_plan(
            tmp_path / "dc2",
            SPEC.replace('kind = "ext4"', 'kind = "dir"').replace(
                'dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/rootfs"'
            ),
        ).rootfs[0],
        image="i:t",
        dest=dest_dir / "rootfs",
        priv=[],
        staging=original,
        ready=original,
        had_previous=True,
        restore_from=original,
    )
    run = FakeRunner()
    mod._restore_backup(staged, run, lambda _: None)
    # exchanged from the recorded source, not from a .bak that never existed
    assert not [
        c for c in run.calls if "mv" in c and any(a.endswith(".bak") for a in c)
    ], run.calls


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
        spec=dir_plan.rootfs[0],
        image="i:t",
        dest=dest_dir / "rootfs",
        priv=[],
        staging=dest_dir / "stg",
        ready=dest_dir / "stg",
    )

    class BackupMoveFails(FakeRunner):
        def __call__(self, argv, **kw):
            bare = self._bare(list(argv))
            if bare[:1] == ["mv"] and bare[-1].endswith(".bak"):
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(
                    list(argv), 1, stdout="", stderr="EIO"
                )
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


def test_the_lock_refuses_a_planted_symlink(tmp_path: Path) -> None:
    """The lock path is PREDICTABLE and lives in a world-writable directory.

    Without `O_NOFOLLOW`, an unprivileged user can pre-create it as a symlink
    to a root-owned file, and a root run then follows the link and `fchmod`s
    that file to 0666.
    """
    import hashlib

    import blastbox.host.imagerun as mod

    victim = tmp_path / "victim"
    victim.write_text("do not touch")
    victim.chmod(0o600)
    dest = tmp_path / "fc" / "attacked.ext4"
    key = hashlib.sha256(str(dest).encode()).hexdigest()[:16]
    lock = Path(tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"
    lock.unlink(missing_ok=True)
    lock.symlink_to(victim)
    try:
        with pytest.raises((OSError, BuildError)):
            with mod._destination_lock(dest):
                pass
        assert stat.S_IMODE(victim.stat().st_mode) == 0o600, "the victim was chmodded"
    finally:
        lock.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("pin", "want"),
    [
        ("blastbox==0.2.0rc1", "0.2.0rc1"),
        ("blastbox==1!0.2.0.post2", "1!0.2.0.post2"),
        ("blastbox==0.2.0+g1234abc", "0.2.0+g1234abc"),
        ("blastbox==0.2.0.dev4", "0.2.0.dev4"),
        ("blastbox>=0.1.36,<0.2", "0.1.36"),
    ],
)
def test_the_complete_pep440_version_is_captured(tmp_path: Path, pin, want) -> None:
    """A pin of `0.2.0rc1` was captured as `0.2.0`, and that truncated value is
    passed as the exact build arg — so the image installs, and then truthfully
    verifies, a different release than the repo declared."""
    from blastbox.host.cli import _declared_blastbox_version

    (tmp_path / "pyproject.toml").write_text(f'[project]\ndependencies = ["{pin}"]\n')
    assert _declared_blastbox_version(tmp_path) == want


def test_an_unprivileged_extraction_is_refused(tmp_path: Path, monkeypatch) -> None:
    """An unprivileged tar reassigns every file to the invoking UID and drops
    setuid bits, and the tree is then audited, formatted and published as if it
    faithfully represented the image. The artifact would not be the one that
    was verified."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: [])
    monkeypatch.setattr(mod, "_can_be_root", lambda: False)
    dest_dir = tmp_path / "fc"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    plan = _plan(tmp_path)
    with pytest.raises(BuildError) as e:
        export_rootfs(plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None)
    assert "ownership preserved" in str(e.value)


def test_the_source_state_counts_untracked_files(tmp_path: Path) -> None:
    """A repo or global `status.showUntrackedFiles=no` otherwise hides a build
    input created while docker was reading the context, and the before/after
    comparison sees no change at all. `stamp.git_revision` already forces this."""
    import blastbox.host.imagerun as mod

    repo = tmp_path / "r"
    repo.mkdir()
    for cmd in (
        ["init", "-q"],
        ["config", "user.email", "t@e"],
        ["config", "user.name", "t"],
        ["config", "status.showUntrackedFiles", "no"],
    ):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, capture_output=True)
    (repo / "a").write_text("x")
    subprocess.run(
        ["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "c"], check=True, capture_output=True
    )
    before = mod._source_state(repo)
    (repo / "sneaked-in").write_text("new build input")
    assert mod._source_state(repo) != before, (
        "an untracked file left the state unchanged"
    )


def test_an_epoch_version_survives_the_stamp_validation(tmp_path: Path) -> None:
    """`1!0.2.0` was captured correctly and then rejected downstream: the
    shell-safe pattern excluded `!`, so every epoch-bearing version this
    supports was still impossible to build."""
    from blastbox.host.stamp import _SHELL_SAFE

    assert _SHELL_SAFE.match("1!0.2.0.post2")
    # and the pattern still refuses what it exists to refuse
    assert not _SHELL_SAFE.match("bad;rm -rf /")
    assert not _SHELL_SAFE.match("a$(x)")


def test_a_protected_destination_refuses_before_creating_anything(
    tmp_path: Path, monkeypatch
) -> None:
    """`_ensure_dir`/`_stage_dir` raise a bare PermissionError under a
    protected destination, and the CLI catches only BuildError — so the very
    environment this refusal exists for got a traceback instead of the message.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_root_prefix", lambda: [])
    monkeypatch.setattr(mod, "_can_be_root", lambda: False)
    protected = tmp_path / "protected"
    protected.mkdir()
    protected.chmod(0o555)
    monkeypatch.setenv("DEMO_DIR", str(protected))
    plan = _plan(tmp_path)
    try:
        with pytest.raises(BuildError) as e:
            export_rootfs(
                plan, plan.rootfs[0], "t1", run=FakeRunner(), log=lambda _: None
            )
        assert "ownership preserved" in str(e.value)
        assert not list(protected.iterdir()), "something was created before the refusal"
    finally:
        protected.chmod(0o755)


def test_a_planted_fifo_does_not_hang_publication(tmp_path: Path) -> None:
    """`O_NOFOLLOW` does not cover FIFOs.

    A local user can plant one at the predictable lock path, and opening an
    existing FIFO `O_RDONLY` blocks until a writer appears — so execution never
    reaches the regular-file check and every publication for that destination
    hangs forever. `O_NONBLOCK` is what prevents it.
    """
    import hashlib

    import blastbox.host.imagerun as mod

    dest = tmp_path / "fc" / "fifo-target.ext4"
    canonical = Path(os.path.realpath(dest.parent)) / dest.name
    key = hashlib.sha256(str(canonical).encode()).hexdigest()[:16]
    lock = Path(tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"
    lock.unlink(missing_ok=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(lock)

    # Bounded, so losing the guard FAILS rather than hangs. Without O_NONBLOCK
    # this open blocks forever waiting for a writer, and an unbounded test
    # would wedge the suite instead of reporting the regression.
    class _Blocked(BaseException):
        """Deliberately NOT an OSError.

        `TimeoutError` subclasses `OSError`, so `pytest.raises((OSError, ...))`
        below swallowed the alarm and the test passed with the guard removed --
        the exact failure mode this test exists to catch, reproduced inside it.
        """

    def _too_slow(_signum, _frame):
        raise _Blocked("opening the lock blocked: O_NONBLOCK is missing")

    old = signal.signal(signal.SIGALRM, _too_slow)
    signal.alarm(5)
    try:
        with pytest.raises((OSError, BuildError)):
            with mod._destination_lock(dest):
                pass
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
        lock.unlink(missing_ok=True)


def test_two_spellings_of_one_destination_share_a_lock(tmp_path: Path) -> None:
    """Different spellings would take different locks and concurrently replace
    the same artifact — the lock would exist and serialise nothing."""
    import hashlib

    import blastbox.host.imagerun as mod

    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    a = real / "rootfs.ext4"
    b = tmp_path / "link" / "rootfs.ext4"

    def key_of(d: Path) -> str:
        canonical = Path(os.path.realpath(d.parent)) / d.name
        return hashlib.sha256(str(canonical).encode()).hexdigest()[:16]

    assert key_of(a) == key_of(b), "one artifact, two lock keys"
    # and the lock actually taken uses that key
    with mod._destination_lock(b):
        lock = Path(tempfile.gettempdir()) / f"blastbox-publish-{key_of(a)}.lock"
        assert lock.exists(), "the lock was taken under a different key"
    lock.unlink(missing_ok=True)


def test_a_build_failure_does_not_print_the_secret(tmp_path: Path, monkeypatch) -> None:
    """describe() redacting is not enough: a real build passes the EXPANDED
    value in argv, and this failure message is printed by the CLI — so any
    routine docker failure leaked the token right after a description that
    showed it redacted."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setenv("TOK", "hunter2-super-secret")
    text = SPEC.replace(
        'base = "upstream:1"',
        'base = "upstream:1"\nbuild_args = { REGISTRY_TOKEN = "$TOK" }',
        1,
    )
    run = FakeRunner(fail=f"demo-base:{_pin_staging(monkeypatch)}")
    with pytest.raises(BuildError) as e:
        build_plan(
            _plan(tmp_path, text),
            "t1",
            blastbox_version="0.1.37",
            run=run,
            log=lambda _: None,
        )
    assert "hunter2-super-secret" not in str(e.value), str(e.value)
    assert "REGISTRY_TOKEN=<redacted>" in str(e.value), str(e.value)


def test_every_check_is_asked_of_the_resolved_id_not_the_tag(monkeypatch) -> None:
    """A tag is mutable, and verification asked it several separate times.

    `_read_stamp`, `base_moved` and `_verify_contents` each re-resolved the tag
    independently, so a concurrent retag between two of them let verification
    read image A's stamp and hand image B's id back for export.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    asked: list[str] = []
    monkeypatch.setattr(
        mod, "_read_stamp", lambda i, r=None: (asked.append(i), _FakeStamp())[1]
    )
    monkeypatch.setattr(
        mod, "_verify_contents", lambda i, r=None: (asked.append(i), (True, ""))[1]
    )
    out = verify_built(["demo:t1"], log=lambda _: None)
    assert out == {"demo:t1": _VERIFIED_ID}
    assert asked == [_VERIFIED_ID, _VERIFIED_ID], asked


def test_an_image_whose_recorded_base_is_gone_does_not_verify(monkeypatch) -> None:
    """`base_moved` answers "" when the base is DELETED rather than moved.

    Absence is `resolvable`'s question, and nothing was asking it — so a
    perfectly stamped image that cannot be rebuilt from what it names passed.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(
        mod, "_read_stamp", lambda i, r=None: _FakeStamp(resolvable=False)
    )
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "no longer present" in str(e.value)


def test_an_unresolvable_tag_is_reported_before_anything_else(monkeypatch) -> None:
    """Resolution comes first, so its failure must be its own message."""
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_image_id", lambda image, run=None: "")
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    with pytest.raises(BuildError) as e:
        verify_built(["demo:t1"], log=lambda _: None)
    assert "could not resolve it to an image id" in str(e.value)


def test_a_file_added_inside_an_untracked_directory_changes_the_source_state(
    tmp_path: Path,
) -> None:
    """`_source_state` fingerprints WHAT changed, so it needs per-file detail.

    `--untracked-files=normal` collapses an untracked directory to a single
    `?? generated/` entry, so adding or removing a file inside one leaves the
    before/after fingerprints identical -- and a docker context that changed
    while the build was reading it gets published under a clean-looking state.
    """
    import blastbox.host.imagerun as mod

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), *args], check=True, capture_output=True
        )

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    git("config", "user.email", "t@e.st")
    git("config", "user.name", "t")
    # The setting that hides the detail even when untracked files are shown.
    git("config", "status.showUntrackedFiles", "normal")
    (tmp_path / "tracked.txt").write_text("x")
    git("add", "tracked.txt")
    git("commit", "-qm", "init")

    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "one").write_text("1")
    before = mod._source_state(tmp_path)
    (generated / "two").write_text("2")
    after = mod._source_state(tmp_path)
    assert before and after
    assert before != after, "a new build input inside an untracked dir went unseen"


def test_the_requested_tag_is_not_moved_by_the_build(
    tmp_path: Path, monkeypatch
) -> None:
    """`docker build -t` publishes the moment ONE image succeeds.

    When that tag is the one the fleet dispatches on, a worker can pull an image
    before anything has verified it -- and a failure later in the chain leaves
    the live tags on a mixture of two builds.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    staging = _pin_staging(monkeypatch)
    run = FakeRunner()
    built = build_plan(
        _plan(tmp_path), "t1", blastbox_version="0.1.33", run=run, log=lambda _: None
    )
    assert built == [f"demo-base:{staging}", f"demo-worker:{staging}"], built
    for call in run.calls:
        if call[:2] == ["docker", "build"]:
            assert "demo-base:t1" not in call and "demo-worker:t1" not in call, call


def test_the_tags_are_published_only_after_the_whole_chain_verifies(
    tmp_path: Path, monkeypatch
) -> None:
    """The ordering IS the fix, so it is asserted as an ordering."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    order: list[str] = []
    real_verify = mod.verify_built

    def spy_verify(images, **kw):
        order.append("verify")
        return real_verify(images, **kw)

    monkeypatch.setattr(mod, "verify_built", spy_verify)
    run = FakeRunner()

    def watched(argv, **kw):
        if list(argv)[:2] == ["docker", "tag"]:
            order.append("tag")
        if list(argv)[:2] == ["docker", "build"]:
            order.append("build")
        return run(argv, **kw)

    published = run_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.34",
        run=watched,
        log=lambda _: None,
        extract=lambda image, dest: (dest / "init").write_text("x"),
        extract_preserves_ownership=True,
    )
    assert published == ["demo-base:t1", "demo-worker:t1"], published
    assert order.index("verify") < order.index("tag"), order
    assert order.count("build") == 2 and order.index("build") < order.index("verify")


def _publication_rollback(tmp_path, monkeypatch, previously) -> list[list[str]]:
    """Fail PART WAY through tag publication; return the tag calls it made.

    The rootfs is published first now, so a rootfs failure moves no tags at all
    -- the case that still needs unwinding is a chain whose second tag fails
    after the first has moved.

    Docker's tag table is MODELLED rather than stubbed per-call: publication
    reads what a tag points at, moves it, reads it back, and a rollback decides
    between restoring and removing from those readings. A double that answers
    every inspect with the same id makes all four look identical, and both
    rollback branches then pass whatever the code does.

    ``previously`` is what each FINAL tag points at before the run -- the only
    thing that decides whether a rollback retags or removes.
    """
    import blastbox.host.imagerun as mod

    staging = _pin_staging(monkeypatch)
    tags: dict[str, str] = {
        f"demo-base:{staging}": _VERIFIED_ID,
        f"demo-worker:{staging}": _VERIFIED_ID,
        **previously,
    }
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setattr(
        mod, "_image_state", lambda image, run=None: tags.get(image, "")
    )
    monkeypatch.setattr(mod, "_image_id", lambda image, run=None: tags.get(image, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    seen: list[list[str]] = []
    run = FakeRunner()

    def watched(argv, **kw):
        a = list(argv)
        if a[:2] == ["docker", "tag"]:
            seen.append(a)
            if a[3] == "demo-worker:t1":
                # The second tag of the chain fails, with the first moved.
                return subprocess.CompletedProcess(a, 1, "", "daemon says no")
            tags[a[3]] = tags.get(a[2], a[2])
        elif a[:2] == ["docker", "rmi"]:
            seen.append(a)
            tags.pop(a[-1], None)
        return run(argv, **kw)

    with pytest.raises(BuildError):
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=watched,
            log=lambda _: None,
            extract=lambda image, dest: (dest / "init").write_text("x"),
            extract_preserves_ownership=True,
        )
    return seen


def test_a_failed_publication_removes_tags_that_did_not_exist_before(
    tmp_path: Path, monkeypatch
) -> None:
    """Nothing pointed at these tags before the run.

    Putting them back means removing them -- not leaving one of them on a
    half-published chain, which is what a consumer would then dispatch on.
    """
    seen = _publication_rollback(tmp_path, monkeypatch, previously={})
    removed = [a[-1] for a in seen if a[:2] == ["docker", "rmi"]]
    assert "demo-base:t1" in removed, seen


def test_a_failed_publication_restores_the_image_a_tag_had_before(
    tmp_path: Path, monkeypatch
) -> None:
    """The common case in production: the tag already names the live release."""
    old = "sha256:" + "d" * 64
    seen = _publication_rollback(
        tmp_path,
        monkeypatch,
        previously={"demo-base:t1": old, "demo-worker:t1": old},
    )
    restored = [a for a in seen if a[:3] == ["docker", "tag", old]]
    assert [a[-1] for a in restored] == ["demo-base:t1"], seen
    assert not [a for a in seen if a[:2] == ["docker", "rmi"] and a[-1].endswith(":t1")]


def test_a_rootfs_failure_moves_no_tags_at_all(tmp_path: Path, monkeypatch) -> None:
    """Rootfs publication is the half that actually fails.

    Publishing it first means the common failure never touches a live tag --
    previously every such failure had to unwind production tags, which is more
    moving parts in exactly the situation with the least margin.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    _pin_staging(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setattr(
        mod,
        "publish_staged",
        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    moved: list[list[str]] = []
    run = FakeRunner()

    def watched(argv, **kw):
        if list(argv)[:2] in (["docker", "tag"], ["docker", "rmi"]):
            moved.append(list(argv))
        return run(argv, **kw)

    with pytest.raises(OSError, match="disk full"):
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=watched,
            log=lambda _: None,
            extract=lambda image, dest: (dest / "init").write_text("x"),
            extract_preserves_ownership=True,
        )
    assert not [a for a in moved if a[:2] == ["docker", "tag"]], moved


def test_rollback_leaves_a_concurrent_runs_publication_alone(tmp_path: Path) -> None:
    """`publish_staged` releases the lock when it returns.

    Another run can publish at the same destination before this one fails on a
    LATER artifact. Restoring then replaces its artifact with the release we are
    rolling back FROM -- a silent downgrade of a live tier, performed by the
    recovery path itself.
    """
    import blastbox.host.imagerun as mod

    dest = tmp_path / "rootfs.ext4"
    dest.write_text("ours")
    bak = tmp_path / "rootfs.ext4.bak"
    bak.write_text("previous")
    # The REAL runner: these assertions are about what ends up on disk, and a
    # double that returns rc=0 without moving anything would make both of them
    # pass no matter what the rollback did.
    run = mod._default_runner
    staged = mod._Staged(
        spec=None,
        image="demo:t1",
        dest=dest,
        priv=[],
        staging=tmp_path / "stg",
        ready=tmp_path / "stg.img",
        had_previous=True,
        restore_from=bak,
        published_identity=mod._artifact_identity(dest, [], run),
    )
    # A concurrent run publishes the way publication actually works: a rename
    # of a different object over the path. (Unlink-then-recreate is not the
    # same test -- the filesystem hands back the same inode and the destination
    # would still look like ours.)
    theirs = tmp_path / "theirs.new"
    theirs.write_text("theirs")
    os.replace(theirs, dest)
    assert mod._artifact_identity(dest, [], run) != staged.published_identity

    said: list[str] = []
    mod._restore_backup(staged, run, said.append)
    assert dest.read_text() == "theirs", "a newer publication was clobbered"
    assert bak.exists(), "the backup was consumed by a rollback that did nothing"
    assert any("NOT rolling back" in s for s in said), said


def test_rollback_still_restores_its_own_publication(tmp_path: Path) -> None:
    """The check must not turn every rollback into a no-op."""
    import blastbox.host.imagerun as mod

    dest = tmp_path / "rootfs.ext4"
    dest.write_text("ours")
    bak = tmp_path / "rootfs.ext4.bak"
    bak.write_text("previous")
    # The REAL runner: these assertions are about what ends up on disk, and a
    # double that returns rc=0 without moving anything would make both of them
    # pass no matter what the rollback did.
    run = mod._default_runner
    staged = mod._Staged(
        spec=None,
        image="demo:t1",
        dest=dest,
        priv=[],
        staging=tmp_path / "stg",
        ready=tmp_path / "stg.img",
        had_previous=True,
        restore_from=bak,
        published_identity=mod._artifact_identity(dest, [], run),
    )
    mod._restore_backup(staged, run, lambda _: None)
    assert dest.read_text() == "previous", "the rollback did not restore"


def test_publication_records_what_it_put_down(tmp_path: Path) -> None:
    """The ownership check is only as good as the identity it compares against.

    Recorded under the publication lock, from the destination itself -- not
    carried over from staging, which names a different object.
    """
    import blastbox.host.imagerun as mod

    dest = tmp_path / "rootfs.ext4"
    dest.write_text("previous")
    ready = tmp_path / "stage.img"
    ready.write_text("new")
    staging = tmp_path / "stage"
    staging.mkdir()
    staged = mod._Staged(
        spec=None,
        image="demo:t1",
        dest=dest,
        priv=[],
        staging=staging,
        ready=ready,
        size_mib=0,
    )
    # Directory-kind publication is the simple rename path; the identity is
    # recorded for both kinds at the same place.
    staged.spec = _RootfsStub(kind="dir")
    mod.publish_staged(staged, run=mod._default_runner, log=lambda _: None)
    assert staged.published_identity, "nothing was recorded to compare against"
    assert staged.published_identity == mod._artifact_identity(
        dest, [], mod._default_runner
    )


def test_rollback_waits_for_the_destination_lock(tmp_path: Path) -> None:
    """Rollback is a check-and-swap, so it races the thing it checks for.

    Without the lock, a second run can publish between the ownership comparison
    and the exchange that follows it -- the window the comparison alone cannot
    close.
    """
    import threading

    import blastbox.host.imagerun as mod

    dest = tmp_path / "rootfs.ext4"
    dest.write_text("ours")
    bak = tmp_path / "rootfs.ext4.bak"
    bak.write_text("previous")
    staged = mod._Staged(
        spec=None,
        image="demo:t1",
        dest=dest,
        priv=[],
        staging=tmp_path / "stg",
        ready=tmp_path / "stg.img",
        had_previous=True,
        restore_from=bak,
        published_identity=mod._artifact_identity(dest, [], mod._default_runner),
    )

    holding = threading.Event()
    release = threading.Event()
    done = threading.Event()

    def hold() -> None:
        with mod._destination_lock(dest):
            holding.set()
            release.wait(10)

    def roll() -> None:
        mod._restore_backup(staged, mod._default_runner, lambda _: None)
        done.set()

    holder = threading.Thread(target=hold)
    holder.start()
    assert holding.wait(10)
    roller = threading.Thread(target=roll)
    roller.start()
    try:
        assert not done.wait(1.0), "the rollback ran while the destination was locked"
        assert dest.read_text() == "ours"
    finally:
        release.set()
        holder.join(10)
        roller.join(10)
    assert done.is_set()
    assert dest.read_text() == "previous", "the rollback never completed"


def test_the_builder_digests_reach_the_stamp_not_only_the_argv(
    tmp_path: Path, monkeypatch
) -> None:
    """Resolution has to happen BEFORE the stamp is built.

    While it ran afterwards the pins existed only in the build argv, so the same
    plan, revision and base could produce a different image once a builder tag
    moved -- with every label identical.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    pinned = {"JDK_BUILD_IMAGE": "eclipse-temurin@sha256:" + "9" * 64}
    monkeypatch.setattr(mod, "_pin_builder_images", lambda *a, **k: dict(pinned))
    seen: list[dict] = []

    def spy(**kw):
        seen.append(kw)
        return []

    monkeypatch.setattr(mod, "_stamp_flags", spy)
    build_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.38",
        run=FakeRunner(),
        log=lambda _: None,
    )
    assert seen, "the stamp was never built"
    assert all(kw.get("builders") == pinned for kw in seen), seen


def test_a_caller_supplied_extractor_must_attest_that_it_preserves_ownership(
    tmp_path: Path, monkeypatch
) -> None:
    """The presence of a hook says nothing about what the hook DOES.

    An ordinary shutil/tar callback produces an all-caller-owned tree with
    setuid bits dropped. `_normalize_root` only fixes the staging root, so the
    remaining checks pass and an altered filesystem gets published -- while the
    refusal that exists for exactly this was skipped because a hook was present.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    with pytest.raises(BuildError) as e:
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=FakeRunner(),
            log=lambda _: None,
            extract=lambda image, dest: (dest / "init").write_text("x"),
        )
    assert "extract_preserves_ownership=True" in str(e.value)


def test_the_default_extraction_is_still_refused_without_privilege(
    tmp_path: Path, monkeypatch
) -> None:
    """The new refusal must not displace the one it sits beside."""
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_can_be_root", lambda: False)
    monkeypatch.setattr(mod, "_sudo_needed", lambda _d: False)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    with pytest.raises(BuildError) as e:
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=FakeRunner(),
            log=lambda _: None,
        )
    assert "not root and has no passwordless sudo" in str(e.value)


def test_a_verification_failure_leaves_the_images_inspectable(
    tmp_path: Path, monkeypatch
) -> None:
    """The staging tags are the only names these images have.

    Dropping them when verification refuses one would leave a dangling image
    and a question nobody can answer -- so they stay, and the run says so.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    staging = _pin_staging(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(
        mod, "_read_stamp", lambda i, r=None: _FakeStamp(reproducible=False)
    )
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    said: list[str] = []
    removed: list[list[str]] = []
    run = FakeRunner()

    def watched(argv, **kw):
        if list(argv)[:2] == ["docker", "rmi"]:
            removed.append(list(argv))
        return run(argv, **kw)

    with pytest.raises(BuildError):
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=watched,
            log=said.append,
        )
    assert not removed, removed
    assert any(staging in s for s in said), said


def test_a_published_child_names_a_base_that_still_exists(
    tmp_path: Path, monkeypatch
) -> None:
    """The chain builds under private tags that the run then removes.

    Recording those left every child of an internal base stamped with a
    reference deleted by the very run that created it -- `blastbox stamp --read`
    reports STAMPED BUT UNBUILDABLE the moment the build succeeds. Measured on
    toolz3 before this fix, on all three internal-base images.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    recorded: list[str | None] = []

    def spy(**kw):
        recorded.append(kw.get("record_base_as"))
        return []

    monkeypatch.setattr(mod, "_stamp_flags", spy)
    build_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.38",
        run=FakeRunner(),
        log=lambda _: None,
    )
    # demo-base is upstream (nothing to redirect); demo-worker is internal and
    # must name the tag this run publishes, not the tag it was built against.
    assert recorded == [None, "demo-base:t1"], recorded


def test_verification_looks_the_recorded_base_up_under_its_staging_alias(
    tmp_path: Path, monkeypatch
) -> None:
    """The recorded tag does not exist yet while verification runs.

    Publishing it earlier is the bug this staging scheme exists to fix, so the
    lookup is redirected instead -- the record itself is unchanged.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    staging = _pin_staging(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    stamps: list = []

    def make(image, runner=None):
        s = _FakeStamp(name="demo-base:t1")
        stamps.append(s)
        return s

    monkeypatch.setattr(mod, "_read_stamp", make)
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    run_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.34",
        run=FakeRunner(),
        log=lambda _: None,
        extract=lambda image, dest: (dest / "init").write_text("x"),
        extract_preserves_ownership=True,
    )
    asked = [ref for s in stamps for ref in s.asked_as]
    assert asked, "nothing was asked about the base at all"
    assert all(ref == f"demo-base:{staging}" for ref in asked), asked


def test_a_secret_that_looks_like_an_image_is_not_logged(tmp_path, monkeypatch) -> None:
    """`REGISTRY_PASS=hunter:2` looks exactly like an image reference.

    The builder-pin heuristic is deliberately permissive, so such a value
    reaches `docker pull` -- and the failure note carried the expanded
    credential into terminal and CI logs, through the very leniency that exists
    to avoid refusing valid builds.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setenv("REGPASS", "hunter:2secret")
    spec = _images.ImageSpec(
        name="demo",
        dockerfile="Dockerfile",
        base="upstream:1",
        build_args={"REGISTRY_PASS": "$REGPASS"},
    )
    said: list[str] = []
    run = FakeRunner(fail="hunter:2secret")
    out = mod._pin_builder_images(
        spec, {"REGPASS": "hunter:2secret"}, run, said.append, pull=True
    )
    assert out == {}, out
    assert said, "the skip was not reported at all"
    joined = "\n".join(said)
    assert "hunter:2secret" not in joined, joined
    assert "REGISTRY_PASS" in joined, joined


def test_an_already_digested_builder_is_still_recorded_as_provenance(
    tmp_path, monkeypatch
) -> None:
    """A plan may pin its builder itself. It still supplies files to the image.

    Skipping it left a multi-stage build reading back with the same empty
    provenance as an image that has no builder stage at all.
    """
    import blastbox.host.imagerun as mod

    jdk = "eclipse-temurin@sha256:" + "9" * 64
    spec = _images.ImageSpec(
        name="demo",
        dockerfile="Dockerfile",
        base="upstream:1",
        build_args={"JDK_BUILD_IMAGE": jdk},
    )
    out = mod._pin_builder_images(spec, {}, FakeRunner(), lambda _: None, pull=True)
    assert out == {"JDK_BUILD_IMAGE": jdk}, out


def test_publication_refuses_when_a_tags_previous_state_is_unreadable(
    tmp_path: Path, monkeypatch
) -> None:
    """A rollback decides between restoring and REMOVING from this reading.

    `_image_id` collapses every failure to "", which reads as "there was
    nothing here" -- so one transient daemon error made the rollback delete a
    live production tag and lose its only recorded reference. Unknown means
    refuse, before anything has moved.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    _pin_staging(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    monkeypatch.setattr(mod, "_image_state", lambda image, run=None: None)
    monkeypatch.setenv("DEMO_DIR", str(tmp_path / "out"))
    moved: list[list[str]] = []
    run = FakeRunner()

    def watched(argv, **kw):
        if list(argv)[:2] == ["docker", "tag"]:
            moved.append(list(argv))
        return run(argv, **kw)

    with pytest.raises(BuildError, match="cannot determine what"):
        run_plan(
            _plan(tmp_path),
            "t1",
            blastbox_version="0.1.34",
            run=watched,
            log=lambda _: None,
            extract=lambda image, dest: (dest / "init").write_text("x"),
            extract_preserves_ownership=True,
        )
    assert moved == [], moved


def test_a_tag_rollback_leaves_a_newer_publication_alone(tmp_path: Path) -> None:
    """The same argument as the artifact rollback, for the other half.

    Two runs publishing one tag: the first can fail after the second has
    already moved it. Putting the first run's previous image back overwrites
    the newer one and leaves it inconsistent with the newer rootfs.
    """
    import blastbox.host.imagerun as mod

    ours = "sha256:" + "1" * 64
    theirs = "sha256:" + "2" * 64
    old = "sha256:" + "0" * 64
    tags = {"demo:t1": theirs}
    calls: list[list[str]] = []

    def run(argv, **kw):
        a = list(argv)
        calls.append(a)
        if a[:2] == ["docker", "tag"]:
            tags[a[3]] = tags.get(a[2], a[2])
        return subprocess.CompletedProcess(a, 0, "", "")

    monkeypatched = mod._image_state
    try:
        mod._image_state = lambda image, r=None: tags.get(image, "")
        said: list[str] = []
        mod.restore_tags(
            mod.PublishedTags(("demo:t1",), {"demo:t1": old}, {"demo:t1": ours}),
            run=run,
            log=said.append,
        )
    finally:
        mod._image_state = monkeypatched
    assert tags["demo:t1"] == theirs, "a newer publication was overwritten"
    assert any("NOT restoring" in s for s in said), said


def test_a_tag_rollback_that_fails_is_reported(tmp_path: Path) -> None:
    """Silence here reads as success while a live tag stays on a new release."""
    import blastbox.host.imagerun as mod

    ours = "sha256:" + "1" * 64
    old = "sha256:" + "0" * 64

    def run(argv, **kw):
        return subprocess.CompletedProcess(list(argv), 1, "", "daemon says no")

    monkeypatched = mod._image_state
    try:
        mod._image_state = lambda image, r=None: ours
        said: list[str] = []
        mod.restore_tags(
            mod.PublishedTags(("demo:t1",), {"demo:t1": old}, {"demo:t1": ours}),
            run=run,
            log=said.append,
        )
    finally:
        mod._image_state = monkeypatched
    assert any("TAG ROLLBACK INCOMPLETE" in s for s in said), said
    assert not any(s.strip().endswith("restored") for s in said), said


def test_two_invocations_do_not_share_a_staging_tag() -> None:
    """The pid alone is not unique.

    Two `run_plan` calls for one requested tag inside a single process -- a
    fleet tool building several engines, a test suite -- would retag each
    other's images mid-build, and the first to publish would delete tags the
    second still needs.
    """
    import blastbox.host.imagerun as mod

    names = {mod._staging_tag("t1") for _ in range(8)}
    assert len(names) == 8, names
    assert all(n.startswith("t1-blastbox-staging-") for n in names), names
    assert all(len(n) <= 128 for n in names), names


def test_a_rollback_that_cannot_identify_the_artifact_leaves_it_alone(
    tmp_path: Path,
) -> None:
    """Failing OPEN defeats the guard exactly when it is needed.

    A destination that has vanished, or a stat that failed, is precisely when
    this run's artifact cannot be told from a newer one's.
    """
    import blastbox.host.imagerun as mod

    dest = tmp_path / "rootfs.ext4"
    dest.write_text("live")
    bak = tmp_path / "rootfs.ext4.bak"
    bak.write_text("previous")
    staged = mod._Staged(
        spec=None,
        image="demo:t1",
        dest=dest,
        priv=[],
        staging=tmp_path / "stg",
        ready=tmp_path / "stg.img",
        had_previous=True,
        restore_from=bak,
        published_identity="",  # publication could not read it back
    )
    said: list[str] = []
    mod._restore_backup(staged, mod._default_runner, said.append)
    assert dest.read_text() == "live", "rolled back over an unidentifiable artifact"
    assert any("cannot establish" in s for s in said), said


def _images_listing(rows: list[tuple[str, str]]) -> str:
    return "\n".join(f"{ref}\t{created}" for ref, created in rows)


def test_stale_staging_tags_are_swept_but_recent_ones_are_kept() -> None:
    """A refused build KEEPS its staging tags; that must still be bounded.

    Those tags are the only names the rejected images have, so removing them on
    failure would leave a dangling image and a question nobody can answer --
    but repeated failures would otherwise pin every rejected chain on disk.

    The age comes from the TAG's own name. docker's `.CreatedAt` is when the
    IMAGE was created, so a cache hit gives a brand-new staging tag an old
    timestamp -- and a concurrent run's sweep would delete a tag a live build
    still needs. That column is deliberately misleading here to prove it is
    not read.
    """
    import blastbox.host.imagerun as mod

    now = int(time.time())
    old = now - 3 * 86400
    stale = f"demo:t1-blastbox-staging-1-aaaaaaaa-{old}"
    fresh = f"demo:t1-blastbox-staging-2-bbbbbbbb-{now}"
    listing = _images_listing(
        [
            (stale, "2020-01-01 00:00:00 +0000 UTC"),
            # A cache hit: brand-new tag, ancient image timestamp.
            (fresh, "2020-01-01 00:00:00 +0000 UTC"),
            ("demo:t1", "2020-01-01 00:00:00 +0000 UTC"),
            # A legal image name that merely CONTAINS the marker.
            ("demo-blastbox-staging-cache:prod", "2020-01-01 00:00:00 +0000 UTC"),
        ]
    )
    removed: list[str] = []

    def run(argv, **kw):
        a = list(argv)
        if a[:2] == ["docker", "images"]:
            return subprocess.CompletedProcess(a, 0, listing, "")
        if a[:2] == ["docker", "rmi"]:
            removed.append(a[-1])
        return subprocess.CompletedProcess(a, 0, "", "")

    dropped = mod.sweep_stale_staging_tags(run=run, log=lambda _: None)
    assert removed == [stale], removed
    assert dropped == removed
    assert fresh not in removed, "a live run's tag was swept"
    assert "demo-blastbox-staging-cache:prod" not in removed, "not a staging tag"


def test_a_tag_without_the_generated_shape_is_never_swept() -> None:
    """This decides whether to DELETE an image.

    Only the complete generated suffix identifies a tag as private build state;
    anything else is somebody's image.
    """
    import blastbox.host.imagerun as mod

    listing = _images_listing(
        [
            ("demo:t1-blastbox-staging-nope", "2020-01-01 00:00:00 +0000 UTC"),
            (
                "demo:t1-blastbox-staging-1-zzzzzzzz-1700000000",
                "2020-01-01 00:00:00 +0000 UTC",
            ),
            (
                "demo-blastbox-staging-1-aaaaaaaa-1700000000:prod",
                "2020-01-01 00:00:00 +0000 UTC",
            ),
        ]
    )
    removed: list[str] = []

    def run(argv, **kw):
        a = list(argv)
        if a[:2] == ["docker", "images"]:
            return subprocess.CompletedProcess(a, 0, listing, "")
        if a[:2] == ["docker", "rmi"]:
            removed.append(a[-1])
        return subprocess.CompletedProcess(a, 0, "", "")

    assert mod.sweep_stale_staging_tags(run=run, log=lambda _: None) == []
    assert removed == []


def test_a_staging_tag_records_its_own_creation_time() -> None:
    """The sweep reads the age out of the NAME, so the name has to carry it."""
    import blastbox.host.imagerun as mod

    before = int(time.time())
    name = mod._staging_tag("t1")
    match = mod._STAGING_RE.search(name)
    assert match, name
    assert before <= int(match.group(1)) <= int(time.time()) + 1, name


def test_a_destination_with_a_literal_dollar_reaches_the_export(
    tmp_path: Path, monkeypatch
) -> None:
    """Three separate checks guard this, and the WRITE GATE is the last of them.

    Fixing the dry run and the plan validator only moved the refusal later: the
    images were built and verified and the export then refused a path that was
    perfectly resolved.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    _pin_staging(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    odd = tmp_path / "we$rd"
    odd.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(odd))
    published = run_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.34",
        run=FakeRunner(moves=True),
        log=lambda _: None,
        extract=lambda image, dest: (dest / "init").write_text("x"),
        extract_preserves_ownership=True,
    )
    assert published == ["demo-base:t1", "demo-worker:t1"], published
    assert (odd / "demo.ext4").exists(), list(odd.iterdir())


def test_a_repository_named_like_a_staging_tag_is_not_swept() -> None:
    """The marker has to be matched in the TAG, not anywhere in the reference.

    `demo-blastbox-staging-1-aaaaaaaa-<epoch>:prod` is a legal image name, and a
    whole-reference search hands somebody's production tag to `docker rmi`.
    """
    import blastbox.host.imagerun as mod

    old = int(time.time()) - 3 * 86400
    listing = _images_listing(
        [
            (
                f"demo-blastbox-staging-1-aaaaaaaa-{old}:prod",
                "2020-01-01 00:00:00 +0000 UTC",
            )
        ]
    )
    removed: list[str] = []

    def run(argv, **kw):
        a = list(argv)
        if a[:2] == ["docker", "images"]:
            return subprocess.CompletedProcess(a, 0, listing, "")
        if a[:2] == ["docker", "rmi"]:
            removed.append(a[-1])
        return subprocess.CompletedProcess(a, 0, "", "")

    assert mod.sweep_stale_staging_tags(run=run, log=lambda _: None) == []
    assert removed == [], removed


def test_every_tag_in_the_chain_is_locked_for_the_whole_publication() -> None:
    """Taken one at a time, two runs can interleave a chain.

    A publishes the base, B publishes base and worker, A then publishes the
    worker -- a mixed chain although both runs reported success. Proven by
    trying to take the SECOND tag's lock while the FIRST is being moved.
    """
    import fcntl
    import hashlib
    import tempfile as _tempfile

    import blastbox.host.imagerun as mod

    def lock_path(ref: str) -> Path:
        key = hashlib.sha256(f"tag:{ref}".encode()).hexdigest()[:16]
        return Path(_tempfile.gettempdir()) / f"blastbox-publish-{key}.lock"

    def held(ref: str) -> bool:
        fd = os.open(lock_path(ref), os.O_CREAT | os.O_RDONLY, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    observed: list[bool] = []

    def run(argv, **kw):
        a = list(argv)
        if a[:2] == ["docker", "tag"] and a[3] == "demo-base:t1":
            # While the FIRST tag is being moved, the second must already be
            # locked by this same publication.
            observed.append(held("demo-worker:t1"))
        if a[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(a, 1, "", "No such image")
        return subprocess.CompletedProcess(a, 0, _VERIFIED_ID, "")

    mod.publish_tags(
        ["demo-base:stg", "demo-worker:stg"], "t1", run=run, log=lambda _: None
    )
    assert observed == [True], observed


def test_the_base_is_inspected_once_per_image(tmp_path: Path, monkeypatch) -> None:
    """Presence and identity are one question asked of one moment.

    Asked separately, a tag that still points at the recorded image for the
    first call and is retagged before the second reports "present, nothing
    moved" -- and the replacement is never compared with the record at all.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    stamps: list = []

    def make(image, runner=None):
        s = _FakeStamp()
        stamps.append(s)
        return s

    monkeypatch.setattr(mod, "_read_stamp", make)
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    verify_built(["demo:t1"], log=lambda _: None)
    assert [s.checks for s in stamps] == [1], [s.checks for s in stamps]


def test_a_secret_named_builder_is_pinned_but_not_recorded(
    tmp_path: Path, monkeypatch
) -> None:
    """The provenance label is PERMANENT and `stamp --read` prints it.

    An already-digested value is preserved verbatim, and `_redact_argv` cannot
    see a credential nested inside `org.blastbox.builders` -- so a secret-named
    argument that happens to look like a digest reference would be embedded in
    the image forever.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    _pin_staging(monkeypatch)
    secret = "registry.example@sha256:" + "7" * 64
    jdk = "eclipse-temurin@sha256:" + "9" * 64
    monkeypatch.setattr(
        mod,
        "_pin_builder_images",
        lambda *a, **k: {"REGISTRY_PASS": secret, "JDK_BUILD_IMAGE": jdk},
    )
    seen: list[dict] = []

    def spy(**kw):
        seen.append(kw)
        return []

    monkeypatch.setattr(mod, "_stamp_flags", spy)
    said: list[str] = []
    build_plan(
        _plan(tmp_path),
        "t1",
        blastbox_version="0.1.39",
        run=FakeRunner(),
        log=said.append,
    )
    assert seen, "the stamp was never built"
    for kw in seen:
        recorded = kw.get("builders") or {}
        assert "REGISTRY_PASS" not in recorded, recorded
        assert recorded.get("JDK_BUILD_IMAGE") == jdk, recorded
    assert not any(secret in s for s in said), said
    assert any("REGISTRY_PASS" in s and "not recorded" in s for s in said), said


def test_cleanup_cannot_strand_the_publication_record(monkeypatch) -> None:
    """Dropping the private tags is tidy-up, and tidy-up must not lose a record.

    If it propagates, the caller never receives what it published, so its
    rollback restores the rootfs and leaves the live tags on the new release --
    the mixed state the rollback exists to prevent, produced by the cleanup
    that runs after it.
    """
    import blastbox.host.imagerun as mod

    monkeypatch.setattr(mod, "_image_state", lambda image, run=None: "")
    monkeypatch.setattr(mod, "_image_id", lambda image, run=None: _VERIFIED_ID)

    def boom(staged, run):
        raise KeyboardInterrupt("operator gave up during cleanup")

    monkeypatch.setattr(mod, "_drop_staging_tags", boom)
    said: list[str] = []
    pub = mod.publish_tags(
        ["demo-base:stg"],
        "t1",
        run=lambda argv, **kw: subprocess.CompletedProcess(list(argv), 0, "", ""),
        log=said.append,
    )
    assert pub.tags == ("demo-base:t1",), pub
    assert pub.published["demo-base:t1"] == _VERIFIED_ID
    assert any("could not drop the staging tags" in s for s in said), said


def test_an_unresolved_destination_fails_before_anything_is_built(
    tmp_path: Path, monkeypatch
) -> None:
    """`export_rootfs` refuses to write to a path nobody chose -- but it refuses at the END,
    after every image has been built and verified.

    That is the same complaint `_size_problems` exists for, in its own words: "left to surface
    from the export it escaped the CLI's handler and ended the command in a traceback, after
    every image had been built and verified". Sizes were moved to the preflight for that
    reason; destinations were not.

    Not hypothetical: `$REDTUSK_FC_DIR/redtusk-rootfs.ext4` is the one declared destination in
    the fleet with no `${VAR:-default}`, so a RedTusk build with that variable unset pays for
    the whole chain before finding out.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.delenv("DEMO_DIR", raising=False)     # the autouse fixture supplies it
    plan = _plan(tmp_path)
    run = FakeRunner()

    with pytest.raises(BuildError) as e:
        run_plan(
            plan,
            "t1",
            blastbox_version="0.1.35",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )

    assert "cannot be built as declared" in str(e.value)
    assert "$DEMO_DIR/demo.ext4" in str(e.value), "the message must name the destination"
    assert run.calls == [], "docker ran before the destination was known"


def test_the_export_still_refuses_a_destination_the_preflight_did_not_see(
    tmp_path: Path, monkeypatch
) -> None:
    """The preflight is an EARLY warning, not a replacement.

    `export_rootfs` is the check that actually guards the write, and it must keep refusing --
    a caller can reach it directly, and the environment can change between the two.
    """
    monkeypatch.delenv("DEMO_DIR", raising=False)
    plan = _plan(tmp_path)
    run = FakeRunner()

    with pytest.raises(BuildError) as e:
        export_rootfs(
            plan,
            plan.rootfs[0],
            "t1",
            run=run,
            log=lambda _: None,
            extract=_fake_extract({"/init": "x"}),
            extract_preserves_ownership=True,
        )

    assert "refusing to write to a path nobody chose" in str(e.value)


def test_a_destination_naming_the_version_resolves_for_both_the_preflight_and_the_export(
    tmp_path: Path, monkeypatch
) -> None:
    """`blastbox_version` is an ARGUMENT, not something the caller must also put in `env`.

    build_plan injects it into a LOCAL copy of the environment. So a destination naming
    $BLASTBOX_VERSION passed a preflight done there and was then refused by stage_rootfs,
    which received the caller's original env -- the late failure this preflight exists to
    prevent, reintroduced by checking a different mapping than the one that acts (codex, #156).

    One environment now serves the preflight, the build and the export.
    """
    import blastbox.host.imagerun as mod

    _resolves_to(monkeypatch)
    # Same stubs the other full-run tests use: this one is about the ENVIRONMENT reaching the
    # export, not about stamping or content verification.
    monkeypatch.setattr(mod, "_stamp_flags", lambda **_k: [])
    monkeypatch.setattr(mod, "_read_stamp", lambda i, r=None: _FakeStamp())
    monkeypatch.setattr(mod, "_verify_contents", lambda i, r=None: (True, ""))
    dest_dir = tmp_path / "out"
    dest_dir.mkdir()
    monkeypatch.setenv("DEMO_DIR", str(dest_dir))
    monkeypatch.delenv("BLASTBOX_VERSION", raising=False)   # supplied ONLY as the argument
    plan = _plan(
        tmp_path,
        SPEC.replace('dest = "$DEMO_DIR/demo.ext4"', 'dest = "$DEMO_DIR/demo-$BLASTBOX_VERSION.ext4"'),
    )
    run = FakeRunner()

    run_plan(
        plan,
        "t1",
        blastbox_version="0.1.40",
        run=run,
        log=lambda _: None,
        extract=_fake_extract({"/init": "x"}),
        extract_preserves_ownership=True,
    )

    # The runner is a fake, so read the RESOLVED path out of what the export actually ran.
    ran = " ".join(" ".join(str(a) for a in c) for c in run.calls)
    assert "demo-0.1.40.ext4" in ran, (
        "the export never resolved $BLASTBOX_VERSION, so the preflight and the export were "
        f"reading different environments; commands were: {ran[:400]}"
    )
    assert "demo-$BLASTBOX_VERSION.ext4" not in ran, (
        "the export used the unexpanded template as a path"
    )
