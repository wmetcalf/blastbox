"""The rebuild half of `deploy/redeploy-warm.sh` is superseded and gated.

A banner marking it superseded is a shell comment: it does not stop
`ENGINE=redtusk ./deploy/redeploy-warm.sh` from running the drifted preset and
swapping a smaller rootfs into place. These tests cover the executable parts of
that decision -- the mode gate, the shrink refusal, and the rollback paths the
two modes actually leave behind.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "redeploy-warm.sh"

_MIB = 1024 * 1024


# Every knob this script reads. Inherited from the ambient shell, any of them
# silently changes the scenario under test: `REDEPLOY_MODE=legacy-rebuild pytest`
# put the default-mode test into legacy mode, and an inherited
# REDEPLOY_CHECK_ONLY=1 made the execution tests exit before doing anything.
_DEPLOY_KNOBS = (
    "REDEPLOY_MODE",
    "REDEPLOY_CHECK_ONLY",
    "ALLOW_ROOTFS_SHRINK",
    "ENGINE",
    "ROOTFS_MIB",
    "FC_DIR",
    "GVISOR_DIR",
    "FC_BIN_SRC",
    "COMPOSE_DIR",
    "COMPOSE_WRAPPER",
    "COMPOSE_FILES",
    "SMOKE_FILE",
    "BLASTBOX_REF",
    "BASE_IMAGE",
    "COLD_IMAGE",
    "WARM_TAG",
    "IMAGE_ENV",
    "WORKER_IMAGE_ENV",
    "API_URL",
    "SHIM_BASE",
    "VENV_PIP",
    "VENV_PY",
    "IMG_USER",
    "FC_DOCKERFILE",
)


def _clean_env(**env: str) -> dict[str, str]:
    """The ambient environment with every deploy knob stripped, plus ``env``."""
    base = {k: v for k, v in os.environ.items() if k not in _DEPLOY_KNOBS}
    return {**base, **env}


def _run(**env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        text=True,
        env=_clean_env(**env),
        check=False,
    )


def _rootfs(tmp_path: Path, mib: int) -> Path:
    """A sparse stand-in for a live FC rootfs of a given size."""
    fc_dir = tmp_path / "fc"
    fc_dir.mkdir(parents=True, exist_ok=True)
    with (fc_dir / "rootfs.ext4").open("wb") as fh:
        fh.truncate(mib * _MIB)
    return fc_dir


def test_an_unknown_mode_is_refused() -> None:
    p = _run(ENGINE="redtusk", REDEPLOY_MODE="bogus")
    assert p.returncode == 2, p.stderr
    assert "unknown REDEPLOY_MODE" in p.stderr


def test_the_default_mode_does_not_enable_the_rebuild_half() -> None:
    """Superseded means off by default, not merely documented as superseded."""
    p = _run(ENGINE="redtusk", REDEPLOY_CHECK_ONLY="1")
    assert p.returncode == 0, p.stderr
    assert "mode=recreate" in p.stdout
    assert "legacy-rebuild" not in p.stdout.split("mode=recreate")[1]


def test_the_rebuild_half_refuses_to_shrink_a_live_rootfs(tmp_path: Path) -> None:
    """The redtusk preset (1024 MiB) against a live 1536 MiB image.

    This is the concrete footgun the supersession banner named; a comment does
    not prevent it, so the script measures the artifact instead.
    """
    p = _run(
        ENGINE="redtusk",
        REDEPLOY_MODE="legacy-rebuild",
        FC_DIR=str(_rootfs(tmp_path, 1536)),
        REDEPLOY_CHECK_ONLY="1",
    )
    assert p.returncode == 2, f"exit={p.returncode} out={p.stdout} err={p.stderr}"
    assert "would shrink it by 512 MiB" in p.stderr
    assert "ROOTFS_MIB=1536" in p.stderr


def test_a_shrink_is_possible_but_only_when_asked_for(tmp_path: Path) -> None:
    p = _run(
        ENGINE="redtusk",
        REDEPLOY_MODE="legacy-rebuild",
        ALLOW_ROOTFS_SHRINK="1",
        FC_DIR=str(_rootfs(tmp_path, 1536)),
        REDEPLOY_CHECK_ONLY="1",
    )
    assert p.returncode == 0, f"exit={p.returncode} err={p.stderr}"
    assert "WARNING" in p.stdout


def test_a_rebuild_that_does_not_shrink_is_allowed(tmp_path: Path) -> None:
    """The guard is about shrinking, not about the rebuild half being illegal."""
    p = _run(
        ENGINE="redtusk",
        REDEPLOY_MODE="legacy-rebuild",
        FC_DIR=str(_rootfs(tmp_path, 1024)),
        REDEPLOY_CHECK_ONLY="1",
    )
    assert p.returncode == 0, f"exit={p.returncode} err={p.stderr}"
    assert "mode=legacy-rebuild" in p.stdout


def test_check_only_touches_nothing(tmp_path: Path) -> None:
    fc_dir = _rootfs(tmp_path, 1024)
    before = {p.name: p.stat().st_mtime_ns for p in fc_dir.iterdir()}
    p = _run(
        ENGINE="redtusk",
        REDEPLOY_MODE="legacy-rebuild",
        FC_DIR=str(fc_dir),
        REDEPLOY_CHECK_ONLY="1",
    )
    assert p.returncode == 0, p.stderr
    assert {p.name: p.stat().st_mtime_ns for p in fc_dir.iterdir()} == before


def test_recreate_mode_never_reaches_the_rebuild_steps(tmp_path: Path) -> None:
    """Prove the gate by execution, not by reading the branch.

    `git` and `docker` are replaced with recorders. In recreate mode neither may
    be invoked: step 1 checks out a blastbox ref and step 2 builds images, and
    both belong to the half that `blastbox build-images` replaced.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    for tool in ("git", "docker", "curl"):
        stub = bin_dir / tool
        stub.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{calls}"\nexit 0\n')
        stub.chmod(0o755)
    compose = bin_dir / "compose-recorder"
    compose.write_text(f'#!/bin/sh\necho "compose $*" >> "{calls}"\nexit 0\n')
    compose.chmod(0o755)

    compose_dir = tmp_path / "compose"
    compose_dir.mkdir()
    (compose_dir / ".env").write_text("REDTUSK_IMAGE=old\nOTHER=keep\n")

    p = _run(
        ENGINE="redtusk",
        FC_DIR=str(_rootfs(tmp_path, 1024)),
        COMPOSE_DIR=str(compose_dir),
        COMPOSE_WRAPPER=str(compose),
        COMPOSE_FILES="",
        SMOKE_FILE="",
        PATH=f"{bin_dir}:{os.environ['PATH']}",
    )
    assert p.returncode == 0, f"exit={p.returncode} out={p.stdout} err={p.stderr}"
    logged = calls.read_text() if calls.exists() else ""
    assert "git " not in logged, logged
    assert "docker " not in logged, logged
    assert "compose " in logged, logged
    # The compose half is NOT superseded and must still have done its job.
    env_now = (compose_dir / ".env").read_text()
    assert "REDTUSK_IMAGE=redtusk:warmfix" in env_now
    assert "OTHER=keep" in env_now
    assert (compose_dir / ".env.bak-warmfix").exists()


def test_each_mode_advertises_the_rollback_paths_it_actually_leaves(
    tmp_path: Path,
) -> None:
    """`build-images` keeps `<dest>.bak`; the in-script swap keeps `.bak-<tag>`.

    Printing the legacy names after a `build-images` deployment sends an
    operator to files that do not exist, in the one situation where they are
    trying to recover a broken warm tier.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("git", "docker", "curl"):
        stub = bin_dir / tool
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    compose = bin_dir / "compose-recorder"
    compose.write_text("#!/bin/sh\nexit 0\n")
    compose.chmod(0o755)
    compose_dir = tmp_path / "compose"
    compose_dir.mkdir()
    (compose_dir / ".env").write_text("REDTUSK_IMAGE=old\n")

    p = _run(
        ENGINE="redtusk",
        FC_DIR=str(_rootfs(tmp_path, 1024)),
        GVISOR_DIR=str(tmp_path / "gv"),
        COMPOSE_DIR=str(compose_dir),
        COMPOSE_WRAPPER=str(compose),
        COMPOSE_FILES="",
        SMOKE_FILE="",
        PATH=f"{bin_dir}:{os.environ['PATH']}",
    )
    assert p.returncode == 0, p.stderr
    assert "rootfs.ext4.bak " in p.stdout
    assert "rootfs.ext4.bak-warmfix" not in p.stdout
    assert "rootfs.bak " in p.stdout


def _stub_bin(tmp_path: Path) -> Path:
    """Stubs for everything the script and its printed rollback shell out to."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for tool in ("git", "docker", "curl"):
        stub = bin_dir / tool
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    # `sudo` appears in the printed rollback and must not want a password here.
    sudo = bin_dir / "sudo"
    sudo.write_text('#!/bin/sh\nexec "$@"\n')
    sudo.chmod(0o755)
    compose = bin_dir / "compose-recorder"
    compose.write_text("#!/bin/sh\nexit 0\n")
    compose.chmod(0o755)
    return bin_dir


def _printed_rollback(stdout: str) -> str:
    """The rollback commands the script told the operator to run."""
    _, _, tail = stdout.partition("ROLLBACK if needed:")
    assert tail.strip(), "no rollback block was printed"
    return tail


def _deploy(tmp_path: Path, bin_dir: Path, fc_dir: Path, gv_dir: Path):
    compose_dir = tmp_path / "compose"
    compose_dir.mkdir(exist_ok=True)
    (compose_dir / ".env").write_text("REDTUSK_IMAGE=old\nKEEP=1\n")
    return _run(
        ENGINE="redtusk",
        FC_DIR=str(fc_dir),
        GVISOR_DIR=str(gv_dir),
        COMPOSE_DIR=str(compose_dir),
        COMPOSE_WRAPPER=str(bin_dir / "compose-recorder"),
        COMPOSE_FILES="",
        SMOKE_FILE="",
        PATH=f"{bin_dir}:{os.environ['PATH']}",
    )


def test_the_printed_rollback_never_destroys_what_it_cannot_replace(
    tmp_path: Path,
) -> None:
    """The rollback block is RUN, not read.

    `blastbox build-images` does not always leave a `.bak`: a first publication
    has nothing to keep, and preserving the old tree after an atomic exchange is
    best effort. The printed block used to `rm -rf` the live gVisor tree and
    only then discover there was nothing to restore -- pasted, by definition, by
    someone whose warm tier is already broken.

    Asserting the TEXT would prove nothing; this executes it against a
    destination with no backup and checks the live tree survived.
    """
    bin_dir = _stub_bin(tmp_path)
    fc_dir = _rootfs(tmp_path, 1024)
    gv_dir = tmp_path / "gv"
    (gv_dir / "rootfs").mkdir(parents=True)
    (gv_dir / "rootfs" / "init").write_text("the live guest")

    p = _deploy(tmp_path, bin_dir, fc_dir, gv_dir)
    assert p.returncode == 0, p.stderr
    assert not (gv_dir / "rootfs.bak").exists()  # first publication

    ran = subprocess.run(
        ["bash", "-c", _printed_rollback(p.stdout)],
        capture_output=True,
        text=True,
        env=_clean_env(PATH=f"{bin_dir}:{os.environ['PATH']}"),
        check=False,
    )
    assert (gv_dir / "rootfs" / "init").read_text() == "the live guest", (
        "the live gVisor tree was destroyed with nothing to restore\n"
        f"{ran.stdout}\n{ran.stderr}"
    )
    assert "NO gVISOR BACKUP" in ran.stdout, ran.stdout
    # The FC half was never destructive -- `mv` with no source just fails -- so
    # its guard buys a legible message instead of `mv: cannot stat ...` in front
    # of an operator who is already having a bad night. That is what is asserted
    # here; nothing stronger is claimed for it.
    assert (fc_dir / "rootfs.ext4").exists(), ran.stderr
    assert "NO FC BACKUP" in ran.stdout, ran.stdout


def test_the_printed_rollback_does_restore_when_a_backup_exists(tmp_path: Path) -> None:
    """Refusing to destroy must not become refusing to roll back."""
    bin_dir = _stub_bin(tmp_path)
    fc_dir = _rootfs(tmp_path, 1024)
    (fc_dir / "rootfs.ext4.bak").write_text("previous fc")
    gv_dir = tmp_path / "gv"
    (gv_dir / "rootfs").mkdir(parents=True)
    (gv_dir / "rootfs" / "init").write_text("the new guest")
    (gv_dir / "rootfs.bak").mkdir()
    (gv_dir / "rootfs.bak" / "init").write_text("the previous guest")

    p = _deploy(tmp_path, bin_dir, fc_dir, gv_dir)
    assert p.returncode == 0, p.stderr
    subprocess.run(
        ["bash", "-c", _printed_rollback(p.stdout)],
        capture_output=True,
        text=True,
        env=_clean_env(PATH=f"{bin_dir}:{os.environ['PATH']}"),
        check=False,
    )
    assert (gv_dir / "rootfs" / "init").read_text() == "the previous guest"
    assert (fc_dir / "rootfs.ext4").read_text() == "previous fc"
