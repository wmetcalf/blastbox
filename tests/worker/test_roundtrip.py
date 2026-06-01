"""Test 2 (keystone): harness output → host.trust.validate_worker_output round-trip.

Proves that a metadata.json written by run_detonation is accepted verbatim by
the host's trust validator, and that a wrong input_sha256 is rejected.
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
)
from blastbox.errors import OutputTrustError
from blastbox.host.trust import validate_worker_output
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult
from blastbox.worker.harness import run_detonation

_ENGINE_NAME = "roundtrip-engine"


class _NoopEngine:
    """Writes a real PNG-ish file and returns a valid DetonationResult."""

    name: str = _ENGINE_NAME
    formats: frozenset[str] = frozenset({"*"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        img_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 56
        (outdir / "page-001.png").write_bytes(img_data)
        return DetonationResult(
            payload=Page(
                index=0,
                dims=Dimensions(width=210.0, height=297.0, unit="mm"),
                image=ArtifactRef(id="page0"),
            ),
            artifacts=[DeclaredArtifact(id="page0", path="page-001.png", kind="image")],
            detected=Detection(
                label="docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                confidence=0.99,
                source="roundtrip-test",
            ),
        )


def _limits() -> Limits:
    return Limits(
        max_metadata_bytes=4 * 1024 * 1024,
        max_artifact_bytes=50 * 1024 * 1024,
        max_total_artifact_bytes=500 * 1024 * 1024,
        max_artifacts=1000,
    )


def test_harness_output_accepted_by_host_trust(tmp_path: Path) -> None:
    """Harness-written output_dir is accepted verbatim by validate_worker_output."""
    input_file = tmp_path / "in" / "test.docx"
    input_file.parent.mkdir()
    content = b"some docx bytes for round-trip test"
    input_file.write_bytes(content)
    real_input_sha = hashlib.sha256(content).hexdigest()

    outdir = tmp_path / "out"
    outdir.mkdir()

    # Run harness
    engine = _NoopEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())
    assert rc == 0, "harness must succeed"

    # Host validates the output — must NOT raise
    env = validate_worker_output(
        output_dir=outdir,
        input_sha256=real_input_sha,
        engine=_ENGINE_NAME,
        limits=_limits(),
    )

    # Sanity-check the returned envelope
    assert env.engine == _ENGINE_NAME
    assert env.status == "ok"
    assert env.input_sha256 == real_input_sha
    assert len(env.artifacts) == 1
    # sha256 from the host-trusted envelope must match the real on-disk file
    real_img_sha = hashlib.sha256((outdir / "page-001.png").read_bytes()).hexdigest()
    assert env.artifacts[0].sha256 == real_img_sha


def test_wrong_input_sha_causes_host_to_reject(tmp_path: Path) -> None:
    """If input_sha256 passed to host differs from what harness stamped → OutputTrustError."""
    input_file = tmp_path / "in" / "test.docx"
    input_file.parent.mkdir()
    content = b"some docx bytes for round-trip integrity check"
    input_file.write_bytes(content)

    outdir = tmp_path / "out"
    outdir.mkdir()

    engine = _NoopEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())
    assert rc == 0

    # Pass a WRONG sha256 to the host
    wrong_sha = "b" * 64

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=wrong_sha,
            engine=_ENGINE_NAME,
            limits=_limits(),
        )


def test_engine_error_envelope_accepted_by_host_trust(tmp_path: Path) -> None:
    """engine_error envelope (from a raising engine) is accepted by host trust validator."""

    class _RaisingEngine:
        name: str = "raising-rt-engine"
        formats: frozenset[str] = frozenset({"*"})

        def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
            raise RuntimeError("something exploded /internal/secret/file.cfg")

    input_file = tmp_path / "in" / "bad.bin"
    input_file.parent.mkdir()
    content = b"malformed content"
    input_file.write_bytes(content)
    real_input_sha = hashlib.sha256(content).hexdigest()

    outdir = tmp_path / "out"
    outdir.mkdir()

    engine = _RaisingEngine()
    rc = run_detonation(engine, input_path=input_file, output_dir=outdir, limits=_limits())
    assert rc == 0

    # Host must accept engine_error envelopes
    env = validate_worker_output(
        output_dir=outdir,
        input_sha256=real_input_sha,
        engine="raising-rt-engine",
        limits=_limits(),
    )

    assert env.status == "engine_error"
    assert env.artifacts == []
