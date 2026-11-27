"""Run agent/install.sh against a fake release dir (no network, no real cosign)."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

INSTALL = Path(__file__).resolve().parents[1] / "agent" / "install.sh"
GOOS = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system())
GOARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
    platform.machine()
)
pytestmark = pytest.mark.skipif(not (GOOS and GOARCH), reason="unsupported platform")
SECRET = "S3CR3T-DO-NOT-PRINT"


def make_release(root: Path, content: bytes = b"#!/bin/sh\necho agent\n") -> tuple[Path, str]:
    rel = root / "release"
    rel.mkdir()
    name = f"blastbox-agent-{GOOS}-{GOARCH}"
    (rel / name).write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    (rel / "SHA256SUMS").write_text(f"{sha}  {name}\n")
    (rel / "SHA256SUMS.sigstore.json").write_text("{}")
    return rel, sha


def run(args, env_extra=None, path=None):
    env = {"PATH": path or os.environ["PATH"], "HOME": "/nonexistent", "BLASTBOX_SECRET": SECRET}
    env.update(env_extra or {})
    return subprocess.run(
        [shutil.which("sh") or "/bin/sh", str(INSTALL), *args], capture_output=True, text=True, env=env, timeout=60
    )


def install(rel, sha, prefix, version="1.0.0", *extra):
    return run(["--version", version, "--sha256", sha, "--from", str(rel),
                "--prefix", str(prefix), *extra])


def stripped_path(tmp: Path, with_cosign: str | None = None) -> str:
    """A PATH holding only coreutils, so cosign is guaranteed absent."""
    d = tmp / "bin"
    d.mkdir(exist_ok=True)
    for tool in ("uname", "id", "mkdir", "mktemp", "cp", "mv", "ln", "rm", "chmod", "cat",
                 "cut", "tr", "wc", "grep", "readlink", "sha256sum", "shasum", "curl", "dirname"):
        src = shutil.which(tool)
        if src and not (d / tool).exists():
            (d / tool).symlink_to(src)
    if with_cosign:
        c = d / "cosign"
        c.write_text(with_cosign)
        c.chmod(c.stat().st_mode | stat.S_IXUSR)
    return str(d)


def test_sha_mismatch_refused(tmp_path):
    rel, _ = make_release(tmp_path)
    p = install(rel, "0" * 64, tmp_path / "pfx", "1.0.0", "--no-cosign")
    assert p.returncode != 0
    assert "sha256 mismatch" in p.stderr
    assert not (tmp_path / "pfx" / "1.0.0").exists()
    assert not (tmp_path / "pfx" / "current").exists()


def test_good_install_and_rollback(tmp_path):
    rel, sha = make_release(tmp_path, b"v1 binary")
    pfx = tmp_path / "pfx"
    p = install(rel, sha, pfx, "1.0.0", "--no-cosign")
    assert p.returncode == 0, p.stderr
    assert "WARNING" in p.stderr and "weaker" in p.stderr
    binp = pfx / "1.0.0" / "blastbox-agent"
    assert binp.read_bytes() == b"v1 binary"
    assert stat.S_IMODE(binp.stat().st_mode) == 0o755
    assert (pfx / "current").is_symlink()
    assert os.readlink(pfx / "current") == "1.0.0"
    assert not list(pfx.glob(".stage.*")) and not list(pfx.glob(".current.tmp.*"))

    shutil.rmtree(rel)
    rel2, sha2 = make_release(tmp_path, b"v2 binary")
    p = install(rel2, sha2, pfx, "2.0.0", "--no-cosign")
    assert p.returncode == 0, p.stderr
    assert os.readlink(pfx / "current") == "2.0.0"
    # current is a symlink to a dir: the flip must not have nested a link inside it
    assert not list(pfx.glob("*/.current.tmp*")) and not list(pfx.glob("*/current"))
    assert not list(pfx.glob("*/1.0.0")) and not list(pfx.glob("*/2.0.0"))
    assert (pfx / ".previous").read_text().strip() == "1.0.0"

    p = run(["--rollback", "--prefix", str(pfx)])
    assert p.returncode == 0, p.stderr
    assert os.readlink(pfx / "current") == "1.0.0"
    assert (pfx / "current" / "blastbox-agent").read_bytes() == b"v1 binary"
    # rollback again swaps forward
    assert run(["--rollback", "--prefix", str(pfx)]).returncode == 0
    assert os.readlink(pfx / "current") == "2.0.0"


def test_rollback_without_previous_refused(tmp_path):
    p = run(["--rollback", "--prefix", str(tmp_path / "pfx")])
    assert p.returncode != 0 and "no previous" in p.stderr


def test_cosign_absent_refused_without_flag(tmp_path):
    rel, sha = make_release(tmp_path)
    pfx = tmp_path / "pfx"
    p = run(["--version", "1.0.0", "--sha256", sha, "--from", str(rel), "--prefix", str(pfx)],
            path=stripped_path(tmp_path))
    assert p.returncode != 0
    assert "cosign not found" in p.stderr
    assert not (pfx / "current").exists()


def test_cosign_called_with_pinned_identity(tmp_path):
    rel, sha = make_release(tmp_path)
    log = tmp_path / "cosign.log"
    fake = f'#!/bin/sh\nprintf "%s\\n" "$@" > {log}\nexit 0\n'
    pfx = tmp_path / "pfx"
    p = run(["--version", "1.2.3", "--sha256", sha, "--from", str(rel), "--prefix", str(pfx)],
            path=stripped_path(tmp_path, fake))
    assert p.returncode == 0, p.stderr
    args = log.read_text().split("\n")
    assert args[:2] == ["verify-blob", "--bundle"]
    assert "SHA256SUMS.sigstore.json" in args
    assert ("https://github.com/wmetcalf/blastbox/.github/workflows/agent-release.yml"
            "@refs/tags/agent-v1.2.3") in args
    assert "https://token.actions.githubusercontent.com" in args
    assert args[-2] == "SHA256SUMS"
    assert os.readlink(pfx / "current") == "1.2.3"


def test_cosign_not_invoked_on_sha_mismatch(tmp_path):
    rel, _ = make_release(tmp_path)
    log = tmp_path / "cosign.log"
    fake = f'#!/bin/sh\necho called > {log}\nexit 0\n'
    p = run(["--version", "1.0.0", "--sha256", "0" * 64, "--from", str(rel),
             "--prefix", str(tmp_path / "pfx")], path=stripped_path(tmp_path, fake))
    assert p.returncode != 0 and "sha256 mismatch" in p.stderr
    assert not log.exists()


def test_cosign_failure_blocks_install(tmp_path):
    rel, sha = make_release(tmp_path)
    pfx = tmp_path / "pfx"
    p = run(["--version", "1.0.0", "--sha256", sha, "--from", str(rel), "--prefix", str(pfx)],
            path=stripped_path(tmp_path, "#!/bin/sh\nexit 1\n"))
    assert p.returncode != 0 and "cosign verification failed" in p.stderr
    assert not (pfx / "1.0.0").exists()


def test_sums_line_must_match(tmp_path):
    rel, sha = make_release(tmp_path)
    (rel / "SHA256SUMS").write_text(f"{'1' * 64}  blastbox-agent-{GOOS}-{GOARCH}\n")
    p = install(rel, sha, tmp_path / "pfx", "1.0.0", "--no-cosign")
    assert p.returncode != 0 and "no matching line" in p.stderr
    assert not (tmp_path / "pfx" / "1.0.0").exists()


def test_args_validated(tmp_path):
    rel, sha = make_release(tmp_path)
    assert install(rel, sha, tmp_path / "p", "1.0", "--no-cosign").returncode != 0
    assert install(rel, sha, tmp_path / "p", "../1.0.0", "--no-cosign").returncode != 0
    assert run(["--version", "1.0.0", "--no-cosign"]).returncode != 0  # sha required
    assert run(["--sha256", sha]).returncode != 0  # version required


def test_no_env_or_secrets_printed(tmp_path):
    rel, sha = make_release(tmp_path)
    for args in (("--no-cosign",), ()):
        p = install(rel, sha, tmp_path / "pfx", "1.0.0", *args)
        assert SECRET not in p.stdout + p.stderr
    p = install(rel, "0" * 64, tmp_path / "pfx2", "1.0.0", "--no-cosign")
    assert SECRET not in p.stdout + p.stderr


def test_static_no_curl_pipe_sh():
    text = INSTALL.read_text()
    assert "| sh" not in text and "|sh" not in text and "| bash" not in text
    assert "--proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL" in text
    assert text.startswith("#!/bin/sh") and "set -eu" in text


def _two_versions(tmp_path):
    pfx = tmp_path / "pfx"
    for v in ("1.0.0", "2.0.0"):
        rel, sha = make_release(tmp_path, f"bin {v}".encode())
        assert install(rel, sha, pfx, v, "--no-cosign").returncode == 0
        shutil.rmtree(rel)
    return pfx


def test_previous_unwritable_does_not_flip(tmp_path):
    # .previous must be recorded before current moves, or a failed write leaves them inconsistent
    pfx = _two_versions(tmp_path)
    (pfx / ".previous").unlink()
    (pfx / ".previous").mkdir()
    rel, sha = make_release(tmp_path, b"bin 3.0.0")
    p = install(rel, sha, pfx, "3.0.0", "--no-cosign")
    assert p.returncode != 0
    assert os.readlink(pfx / "current") == "2.0.0"
    assert not list(pfx.glob(".previous/*"))


def test_current_real_directory_refused(tmp_path):
    pfx = tmp_path / "pfx"
    (pfx / "current").mkdir(parents=True)
    rel, sha = make_release(tmp_path)
    p = install(rel, sha, pfx, "1.0.0", "--no-cosign")
    assert p.returncode != 0 and "not a symlink" in p.stderr
    assert not list((pfx / "current").iterdir())
    assert not (pfx / "1.0.0").exists()  # refused before anything is staged or copied


def test_non_version_current_target_not_recorded(tmp_path):
    pfx = tmp_path / "pfx"
    rel, sha = make_release(tmp_path, b"bin 1")
    assert install(rel, sha, pfx, "1.0.0", "--no-cosign").returncode == 0
    shutil.rmtree(rel)
    (pfx / "current").unlink()
    (pfx / "current").symlink_to(pfx / "1.0.0")  # absolute, hand-made
    rel, sha = make_release(tmp_path, b"bin 2")
    assert install(rel, sha, pfx, "2.0.0", "--no-cosign").returncode == 0
    prev = pfx / ".previous"
    assert not prev.exists() or prev.read_text().strip() == "1.0.0"


def test_uninstalled_current_target_does_not_clobber_previous(tmp_path):
    pfx = _two_versions(tmp_path)  # .previous = 1.0.0, current -> 2.0.0
    (pfx / "current").unlink()
    (pfx / "current").symlink_to("9.9.9")  # dangling, version-shaped
    rel, sha = make_release(tmp_path, b"bin 3.0.0")
    assert install(rel, sha, pfx, "3.0.0", "--no-cosign").returncode == 0
    assert (pfx / ".previous").read_text().strip() == "1.0.0"


def test_failed_previous_write_leaves_no_temp(tmp_path):
    pfx = _two_versions(tmp_path)
    (pfx / ".previous").unlink()
    (pfx / ".previous").mkdir()
    rel, sha = make_release(tmp_path, b"bin 3.0.0")
    assert install(rel, sha, pfx, "3.0.0", "--no-cosign").returncode != 0
    assert not list(pfx.glob(".previous.tmp.*")) and not list(pfx.glob(".current.tmp.*"))


def test_dirs_readable_under_restrictive_umask(tmp_path):
    rel, sha = make_release(tmp_path)
    pfx = tmp_path / "pfx"
    p = subprocess.run(
        ["sh", "-c", 'umask 077; exec sh "$@"', "sh", str(INSTALL), "--version", "1.0.0",
         "--sha256", sha, "--from", str(rel), "--prefix", str(pfx), "--no-cosign"],
        capture_output=True, text=True, env={"PATH": os.environ["PATH"], "HOME": "/nonexistent"},
    )
    assert p.returncode == 0, p.stderr
    for d in (pfx, pfx / "1.0.0"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o755, d


@pytest.mark.parametrize("break_it", ["sha", "sums", "missing"])
def test_failed_install_leaves_no_stage(tmp_path, break_it):
    rel, sha = make_release(tmp_path)
    pfx = tmp_path / "pfx"
    if break_it == "sha":
        sha = "0" * 64
    elif break_it == "sums":
        (rel / "SHA256SUMS").write_text("")
    else:
        (rel / "SHA256SUMS").unlink()
    assert install(rel, sha, pfx, "1.0.0", "--no-cosign").returncode != 0
    assert not list(pfx.glob(".stage.*")) and not list(pfx.glob(".current.tmp.*"))
    assert not list(pfx.glob(".previous.tmp.*"))


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck():
    assert subprocess.run(["shellcheck", str(INSTALL)]).returncode == 0
