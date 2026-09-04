"""Generic detonation engine: run an allow-listed tool, seal the output.

These unit-test the engine logic by running the tool directly through the harness
(no worker). In production the dispatcher runs this engine inside a disposable
hardened worker, which provides the isolation.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from blastbox.engines.detonate import DetonateEngine
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation

pytestmark = pytest.mark.skipif(
    not (shutil.which("tr") and shutil.which("cat")),
    reason="coreutils tr/cat required",
)


def _run(
    tmp_path: Path, engine: DetonateEngine, data: bytes, limits: Limits | None = None
) -> tuple[int, dict, Path]:
    indir = tmp_path / "in"
    outdir = tmp_path / "out"
    indir.mkdir()
    outdir.mkdir()
    inp = indir / "input.bin"
    inp.write_bytes(data)
    rc = run_detonation(
        engine, input_path=inp, output_dir=outdir, limits=limits or Limits()
    )
    meta = json.loads((outdir / "metadata.json").read_text())
    return rc, meta, outdir


def test_stdin_mode_transforms_input(tmp_path: Path) -> None:
    # No {input} token -> the input bytes are fed to the tool on stdin.
    rc, meta, outdir = _run(tmp_path, DetonateEngine(["tr", "a-z", "A-Z"]), b"blob:evil_c2")
    assert rc == 0
    assert meta["status"] == "ok", meta
    assert (outdir / "stdout.bin").read_bytes() == b"BLOB:EVIL_C2"
    assert any(a["id"] == "stdout" for a in meta["artifacts"]), meta["artifacts"]


def test_input_path_token(tmp_path: Path) -> None:
    # {input} is replaced by the input file path; cat echoes it back.
    _rc, meta, outdir = _run(tmp_path, DetonateEngine(["cat", "{input}"]), b"raw-bytes-here")
    assert meta["status"] == "ok", meta
    assert (outdir / "stdout.bin").read_bytes() == b"raw-bytes-here"


def test_tool_not_found_is_engine_error(tmp_path: Path) -> None:
    rc, meta, _ = _run(tmp_path, DetonateEngine(["definitely-not-a-real-tool-xyz"]), b"x")
    assert rc == 0  # engine_error is a sealed outcome, not a harness failure
    assert meta["status"] == "engine_error", meta


def test_unset_argv_is_engine_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No injected argv and no env -> the engine raises, the harness seals engine_error.
    monkeypatch.delenv("BLASTBOX_DETONATE_ARGV", raising=False)
    rc, meta, _ = _run(tmp_path, DetonateEngine(), b"x")
    assert rc == 0
    assert meta["status"] == "engine_error", meta


def test_output_truncated_to_cap(tmp_path: Path) -> None:
    rc, meta, outdir = _run(
        tmp_path, DetonateEngine(["tr", "a-z", "A-Z"]), b"abcdef", Limits(max_artifact_bytes=4)
    )
    assert rc == 0
    assert meta["status"] == "ok", meta
    assert (outdir / "stdout.bin").read_bytes() == b"ABCD"
