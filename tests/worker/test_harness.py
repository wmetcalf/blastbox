"""TDD tests for blastbox.worker.harness (tests 1, 3, 4, 5, 6 from plan).

Test 2 (the round-trip keystone) lives in test_roundtrip.py.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from blastbox.contract import (
    ArtifactRef,
    DeclaredArtifact,
    Detection,
    Dimensions,
    Page,
    Record,
)
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult
from blastbox.worker.harness import main, run_detonation

# ---------------------------------------------------------------------------
# Shared test double
# ---------------------------------------------------------------------------

_ENGINE_NAME = "test-noop"


class _NoopEngine:
    """Happy-path engine: writes a real page-001.png, returns valid result."""

    name: str = _ENGINE_NAME
    formats: frozenset[str] = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        img_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56  # minimal PNG-ish bytes
        (outdir / "page-001.png").write_bytes(img_data)
        return DetonationResult(
            payload=Page(
                index=0,
                dims=Dimensions(width=100.0, height=100.0, unit="px"),
                image=ArtifactRef(id="a0"),
            ),
            artifacts=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")],
            detected=Detection(
                label="docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                confidence=0.99,
                source="test",
            ),
        )


class _RaisingEngine:
    """Engine whose detonate() raises with a secret path in the message."""

    name: str = "raising-engine"
    formats: frozenset[str] = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        raise RuntimeError("boom /secret/path/to/config.yaml")


class _MissingArtifactEngine:
    """Engine that declares an artifact it never writes."""

    name: str = "missing-art-engine"
    formats: frozenset[str] = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        return DetonationResult(
            payload=Record(fields={"note": "no file"}),
            artifacts=[DeclaredArtifact(id="ghost", path="ghost.png", kind="image")],
            detected=Detection(label="unknown", mime="application/octet-stream",
                               confidence=0.0, source="test"),
        )


class _TraversalArtifactEngine:
    """Engine that declares an artifact with a path-traversal path."""

    name: str = "traversal-engine"
    formats: frozenset[str] = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        return DetonationResult(
            payload=Record(fields={}),
            artifacts=[DeclaredArtifact(id="escape", path="../escape.bin", kind="image")],
            detected=Detection(label="unknown", mime="application/octet-stream",
                               confidence=0.0, source="test"),
        )


def _limits() -> Limits:
    return Limits(
        max_metadata_bytes=4 * 1024 * 1024,
        max_artifact_bytes=50 * 1024 * 1024,
        max_total_artifact_bytes=500 * 1024 * 1024,
        max_artifacts=1000,
    )


# ---------------------------------------------------------------------------
# Test 1: happy path
# ---------------------------------------------------------------------------


def test_happy_path_writes_metadata_and_real_hash(tmp_path: Path) -> None:
    """run_detonation writes metadata.json; sha256 is the real file hash; returns 0."""
    input_file = tmp_path / "in" / "doc.docx"
    input_file.parent.mkdir()
    content = b"fake docx content for test"
    input_file.write_bytes(content)
    expected_input_sha = hashlib.sha256(content).hexdigest()

    outdir = tmp_path / "out"
    outdir.mkdir()

    noop = _NoopEngine()
    rc = run_detonation(noop, input_path=input_file, output_dir=outdir, limits=_limits())

    assert rc == 0, "exit code must be 0"

    meta_path = outdir / "metadata.json"
    assert meta_path.exists(), "metadata.json must be written"

    from blastbox.contract import envelope_from_json
    env = envelope_from_json(meta_path.read_bytes())

    assert env.engine == _ENGINE_NAME
    assert env.status == "ok"
    assert env.input_sha256 == expected_input_sha, "input_sha256 must be stamped from the real file"
    assert len(env.artifacts) == 1
    # sha256 must match the real on-disk file, not something made up
    real_sha = hashlib.sha256((outdir / "page-001.png").read_bytes()).hexdigest()
    assert env.artifacts[0].sha256 == real_sha
    assert env.artifacts[0].bytes == (outdir / "page-001.png").stat().st_size


# ---------------------------------------------------------------------------
# Test 3: engine raises → engine_error envelope, scrubbed, returns 0
# ---------------------------------------------------------------------------


def test_engine_raises_writes_engine_error_envelope(tmp_path: Path) -> None:
    """Engine raising RuntimeError → status=engine_error, path scrubbed, rc=0."""
    input_file = tmp_path / "in" / "malformed.bin"
    input_file.parent.mkdir()
    input_file.write_bytes(b"garbage")

    outdir = tmp_path / "out"
    outdir.mkdir()

    engine = _RaisingEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())

    assert rc == 0, "engine error must still return 0"

    meta_path = outdir / "metadata.json"
    assert meta_path.exists()

    from blastbox.contract import envelope_from_json
    env = envelope_from_json(meta_path.read_bytes())

    assert env.status == "engine_error"
    assert env.engine == engine.name
    # The secret path must be scrubbed from warning messages
    assert len(env.warnings) >= 1
    for w in env.warnings:
        assert "/secret/path" not in w.message, "secret path must be scrubbed from warning"
    # Payload must be a Record with an "error" field
    assert isinstance(env.payload, Record)
    assert "error" in env.payload.fields
    # The error value must also be scrubbed
    err_val = env.payload.fields["error"]
    assert "/secret/path" not in str(err_val), "secret path must be scrubbed from payload"


# ---------------------------------------------------------------------------
# Test 4: engine declares missing artifact → seal fails → engine_error, no crash
# ---------------------------------------------------------------------------


def test_missing_declared_artifact_falls_back_to_engine_error(tmp_path: Path) -> None:
    """seal_envelope raises because file is missing → engine_error envelope, rc=0."""
    input_file = tmp_path / "in" / "doc.bin"
    input_file.parent.mkdir()
    input_file.write_bytes(b"data")

    outdir = tmp_path / "out"
    outdir.mkdir()

    engine = _MissingArtifactEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())

    assert rc == 0

    from blastbox.contract import envelope_from_json
    env = envelope_from_json((outdir / "metadata.json").read_bytes())

    assert env.status == "engine_error"
    # engine_error envelope has no artifacts (the missing ones are not included)
    assert env.artifacts == []


# ---------------------------------------------------------------------------
# Test 5: engine declares traversal path → seal fails → engine_error, no crash
# ---------------------------------------------------------------------------


def test_traversal_path_falls_back_to_engine_error(tmp_path: Path) -> None:
    """seal_envelope rejects ../escape path → engine_error envelope, rc=0."""
    input_file = tmp_path / "in" / "doc.bin"
    input_file.parent.mkdir()
    input_file.write_bytes(b"data")

    outdir = tmp_path / "out"
    outdir.mkdir()

    engine = _TraversalArtifactEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())

    assert rc == 0

    from blastbox.contract import envelope_from_json
    env = envelope_from_json((outdir / "metadata.json").read_bytes())

    assert env.status == "engine_error"
    assert env.artifacts == []


# ---------------------------------------------------------------------------
# Test 6: main() argparse + env-var paths
# ---------------------------------------------------------------------------


def test_main_happy_path_via_args(tmp_path: Path) -> None:
    """main() with --input-dir / --output-dir → exit 0, metadata.json written."""
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    (input_dir / "sample.docx").write_bytes(b"docx content")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    noop = _NoopEngine()
    rc = main(noop, argv=[
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir),
    ])

    assert rc == 0
    assert (output_dir / "metadata.json").exists()


def test_main_happy_path_via_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() reads BLASTBOX_INPUT_DIR / BLASTBOX_OUTPUT_DIR from env."""
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    (input_dir / "sample.docx").write_bytes(b"docx content env")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    monkeypatch.setenv("BLASTBOX_INPUT_DIR", str(input_dir))
    monkeypatch.setenv("BLASTBOX_OUTPUT_DIR", str(output_dir))

    noop = _NoopEngine()
    rc = main(noop, argv=[])

    assert rc == 0
    assert (output_dir / "metadata.json").exists()


def test_main_zero_files_in_input_dir_returns_nonzero(tmp_path: Path) -> None:
    """0 files in input-dir → non-zero exit code."""
    input_dir = tmp_path / "in"
    input_dir.mkdir()

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    noop = _NoopEngine()
    rc = main(noop, argv=[
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir),
    ])

    assert rc != 0


def test_main_multiple_files_in_input_dir_returns_nonzero(tmp_path: Path) -> None:
    """More than 1 file in input-dir → non-zero exit code."""
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    (input_dir / "a.docx").write_bytes(b"file a")
    (input_dir / "b.docx").write_bytes(b"file b")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    noop = _NoopEngine()
    rc = main(noop, argv=[
        "--input-dir", str(input_dir),
        "--output-dir", str(output_dir),
    ])

    assert rc != 0
