"""TDD tests for blastbox.host.trust.validate_worker_output.

11 test cases per the plan at docs/plans/2026-05-31-host-trust.md.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from blastbox.errors import OutputTrustError
from blastbox.host.trust import validate_worker_output
from blastbox.limits import Limits

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENGINE = "clippyshot"
_INPUT_SHA = "a" * 64


def _limits(**overrides) -> Limits:
    """Return a Limits instance with generous defaults, accepting **overrides."""
    defaults = dict(
        max_metadata_bytes=4 * 1024 * 1024,
        max_artifact_bytes=50 * 1024 * 1024,
        max_total_artifact_bytes=500 * 1024 * 1024,
        max_artifacts=1000,
    )
    defaults.update(overrides)
    return Limits(**defaults)


def _make_output_dir(
    tmp_path: Path,
    *,
    engine: str = _ENGINE,
    input_sha256: str = _INPUT_SHA,
    artifact_content: bytes = b"PNG_DATA_HERE",
    artifact_id: str = "page-001",
    artifact_path: str = "page-001.png",
    artifact_kind: str = "image",
    # Tamper knobs: override what metadata.json says about sha256/bytes
    meta_artifact_sha: str | None = None,
    meta_artifact_bytes: int | None = None,
    extra_artifacts: list[dict] | None = None,
    write_metadata: bool = True,
) -> tuple[Path, bytes]:
    """Create a valid output_dir with one artifact file and a metadata.json.

    Returns (output_dir, real_artifact_sha256_hex).
    """
    outdir = tmp_path / "output"
    outdir.mkdir()

    # Write the real artifact
    (outdir / artifact_path).write_bytes(artifact_content)
    real_sha = hashlib.sha256(artifact_content).hexdigest()

    # Build the metadata.json — possibly with tampered sha/bytes
    reported_sha = meta_artifact_sha if meta_artifact_sha is not None else real_sha
    reported_bytes = meta_artifact_bytes if meta_artifact_bytes is not None else len(artifact_content)

    artifacts = [
        {
            "id": artifact_id,
            "path": artifact_path,
            "kind": artifact_kind,
            "sha256": reported_sha,
            "bytes": reported_bytes,
        }
    ]
    if extra_artifacts:
        artifacts.extend(extra_artifacts)

    envelope = {
        "engine": engine,
        "status": "ok",
        "input_sha256": input_sha256,
        "detected": {
            "label": "docx",
            "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "confidence": 0.99,
            "source": "magika",
        },
        "artifacts": artifacts,
        "warnings": [],
        "payload": {
            "type": "extracted_text",
            "text": "hello world",
            "char_count": 11,
        },
    }

    if write_metadata:
        (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    return outdir, real_sha


# ---------------------------------------------------------------------------
# Test 1: happy path
# ---------------------------------------------------------------------------


def test_happy_path_returns_envelope_with_real_hash(tmp_path):
    """Valid output → returns Envelope; artifacts[0].sha256 is the real file hash."""
    content = b"PNG_DATA_REAL"
    outdir, real_sha = _make_output_dir(tmp_path, artifact_content=content)

    env = validate_worker_output(
        output_dir=outdir,
        input_sha256=_INPUT_SHA,
        engine=_ENGINE,
        limits=_limits(),
    )

    assert env.engine == _ENGINE
    assert env.input_sha256 == _INPUT_SHA
    assert len(env.artifacts) == 1
    # The returned sha256 MUST be the real computed hash, not whatever was in metadata.json
    assert env.artifacts[0].sha256 == real_sha
    assert env.artifacts[0].bytes == len(content)


# ---------------------------------------------------------------------------
# Test 2: tampered bytes/sha in metadata → re-seal recomputes real values
# ---------------------------------------------------------------------------


def test_tampered_sha_and_bytes_are_recomputed(tmp_path):
    """Worker reports wrong sha256/bytes; re-seal must return the real values."""
    content = b"REAL FILE CONTENT THAT IS BIGGER"
    real_sha = hashlib.sha256(content).hexdigest()
    fake_sha = "b" * 64
    assert fake_sha != real_sha

    outdir, _ = _make_output_dir(
        tmp_path,
        artifact_content=content,
        meta_artifact_sha=fake_sha,
        meta_artifact_bytes=1,  # lies about size
    )

    env = validate_worker_output(
        output_dir=outdir,
        input_sha256=_INPUT_SHA,
        engine=_ENGINE,
        limits=_limits(),
    )

    # Must use real sha, not the worker's lie
    assert env.artifacts[0].sha256 == real_sha
    assert env.artifacts[0].bytes == len(content)


def test_tampered_bytes_triggers_cap_rejection(tmp_path):
    """Worker lies about size; if real size exceeds cap, validation must reject."""
    content = b"x" * 200  # 200 bytes
    outdir, _ = _make_output_dir(
        tmp_path,
        artifact_content=content,
        meta_artifact_bytes=1,  # worker claims tiny — re-seal uses real 200 bytes
    )

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(max_artifact_bytes=100),  # 100 < 200 real bytes
        )


# ---------------------------------------------------------------------------
# Test 3: metadata.json missing
# ---------------------------------------------------------------------------


def test_metadata_missing_raises(tmp_path):
    """Absent metadata.json → OutputTrustError."""
    outdir, _ = _make_output_dir(tmp_path, write_metadata=False)

    with pytest.raises(OutputTrustError, match="metadata"):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 4: metadata is a symlink
# ---------------------------------------------------------------------------


def test_metadata_symlink_rejected(tmp_path):
    """metadata.json that is a symlink → OutputTrustError (regular-file gate)."""
    # Write a valid JSON somewhere else
    real_json = tmp_path / "real_meta.json"
    outdir, _ = _make_output_dir(tmp_path, write_metadata=True)

    # Replace metadata.json with a symlink
    meta = outdir / "metadata.json"
    real_json.write_bytes(meta.read_bytes())
    meta.unlink()
    meta.symlink_to(real_json)

    assert meta.is_symlink()

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 5: metadata over max_metadata_bytes
# ---------------------------------------------------------------------------


def test_metadata_over_size_limit_raises(tmp_path):
    """metadata.json exceeds max_metadata_bytes → OutputTrustError."""
    outdir, _ = _make_output_dir(tmp_path)

    meta = outdir / "metadata.json"
    # Make limits tiny so the existing metadata.json exceeds it
    real_size = meta.stat().st_size

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(max_metadata_bytes=real_size - 1),
        )


# ---------------------------------------------------------------------------
# Test 6: engine mismatch
# ---------------------------------------------------------------------------


def test_engine_mismatch_raises(tmp_path):
    """parsed.engine != engine arg → OutputTrustError."""
    outdir, _ = _make_output_dir(tmp_path, engine="clippyshot")

    with pytest.raises(OutputTrustError, match="engine"):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine="different-engine",
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 7: input_sha mismatch
# ---------------------------------------------------------------------------


def test_input_sha_mismatch_raises(tmp_path):
    """metadata's input_sha256 ≠ what we pass → OutputTrustError."""
    outdir, _ = _make_output_dir(tmp_path, input_sha256="a" * 64)

    with pytest.raises(OutputTrustError, match="input"):
        validate_worker_output(
            output_dir=outdir,
            input_sha256="b" * 64,  # different from what's in metadata
            engine=_ENGINE,
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 8: artifact path traversal / symlink escape
# ---------------------------------------------------------------------------


def test_path_traversal_in_artifact_raises(tmp_path):
    """Declared artifact path '../x' → OutputTrustError (re-seal confinement)."""
    outdir = tmp_path / "output"
    outdir.mkdir()

    # Write the real escape target outside outdir
    escape_file = tmp_path / "escape.bin"
    escape_file.write_bytes(b"escaped")

    # Build metadata.json with a traversal path
    envelope = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {
            "label": "docx",
            "mime": "text/plain",
            "confidence": 1.0,
            "source": "magika",
        },
        "artifacts": [
            {
                "id": "evil",
                "path": "../escape.bin",
                "kind": "image",
                "sha256": "a" * 64,
                "bytes": 7,
            }
        ],
        "warnings": [],
        "payload": {"type": "extracted_text", "text": "x", "char_count": 1},
    }
    (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


def test_symlink_escape_in_artifact_raises(tmp_path):
    """Artifact file that is a symlink pointing outside outdir → OutputTrustError."""
    outdir = tmp_path / "output"
    outdir.mkdir()

    # Create an outside target
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"sensitive data")

    # Create a symlink inside outdir pointing outside
    symlink = outdir / "page.png"
    symlink.symlink_to(outside)

    # Build metadata.json pointing at the symlink path
    real_sha = hashlib.sha256(b"sensitive data").hexdigest()
    envelope = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {
            "label": "docx",
            "mime": "text/plain",
            "confidence": 1.0,
            "source": "magika",
        },
        "artifacts": [
            {
                "id": "page0",
                "path": "page.png",
                "kind": "image",
                "sha256": real_sha,
                "bytes": 14,
            }
        ],
        "warnings": [],
        "payload": {"type": "extracted_text", "text": "x", "char_count": 1},
    }
    (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 9: unresolved ArtifactRef in payload
# ---------------------------------------------------------------------------


def test_unresolved_artifact_ref_raises(tmp_path):
    """Payload references an ArtifactRef id not in declared artifacts → OutputTrustError."""
    outdir = tmp_path / "output"
    outdir.mkdir()

    # Write one real artifact
    (outdir / "page-001.png").write_bytes(b"PNG")
    real_sha = hashlib.sha256(b"PNG").hexdigest()

    # Payload references 'nonexistent-id', not declared
    envelope = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {
            "label": "docx",
            "mime": "text/plain",
            "confidence": 1.0,
            "source": "magika",
        },
        "artifacts": [
            {
                "id": "page-001",
                "path": "page-001.png",
                "kind": "image",
                "sha256": real_sha,
                "bytes": 3,
            }
        ],
        "warnings": [],
        # Page payload references 'nonexistent-id' via ArtifactRef
        "payload": {
            "type": "page",
            "index": 0,
            "dims": {"width": 100, "height": 100, "unit": "px"},
            "image": {"id": "nonexistent-id"},  # not in artifacts!
        },
    }
    (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


# ---------------------------------------------------------------------------
# Test 10: over caps
# ---------------------------------------------------------------------------


def test_too_many_artifacts_raises(tmp_path):
    """More artifacts than max_artifacts → OutputTrustError."""
    # Build output dir with 3 artifacts
    outdir = tmp_path / "output"
    outdir.mkdir()

    arts = []
    for i in range(3):
        content = f"data{i}".encode()
        fname = f"art{i}.bin"
        (outdir / fname).write_bytes(content)
        arts.append({
            "id": f"art{i}",
            "path": fname,
            "kind": "data",
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        })

    envelope = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {"label": "docx", "mime": "text/plain", "confidence": 1.0, "source": "magika"},
        "artifacts": arts,
        "warnings": [],
        "payload": {"type": "extracted_text", "text": "x", "char_count": 1},
    }
    (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(max_artifacts=2),  # only 2 allowed, 3 declared
        )


def test_artifact_over_max_artifact_bytes_raises(tmp_path):
    """Single artifact exceeds max_artifact_bytes → OutputTrustError."""
    content = b"x" * 500  # 500 bytes
    outdir, _ = _make_output_dir(tmp_path, artifact_content=content)

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(max_artifact_bytes=100),  # 100 < 500
        )


def test_total_over_max_total_artifact_bytes_raises(tmp_path):
    """Sum of artifact sizes exceeds max_total_artifact_bytes → OutputTrustError."""
    outdir = tmp_path / "output"
    outdir.mkdir()

    arts = []
    for i in range(3):
        content = b"x" * 100  # 100 bytes each = 300 total
        fname = f"art{i}.bin"
        (outdir / fname).write_bytes(content)
        arts.append({
            "id": f"art{i}",
            "path": fname,
            "kind": "data",
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        })

    envelope = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {"label": "docx", "mime": "text/plain", "confidence": 1.0, "source": "magika"},
        "artifacts": arts,
        "warnings": [],
        "payload": {"type": "extracted_text", "text": "x", "char_count": 1},
    }
    (outdir / "metadata.json").write_bytes(json.dumps(envelope).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(max_total_artifact_bytes=200),  # 200 < 300
        )


# ---------------------------------------------------------------------------
# Test 11: malformed JSON / non-dict / missing payload
# ---------------------------------------------------------------------------


def test_malformed_json_raises(tmp_path):
    """Malformed JSON in metadata.json → OutputTrustError, not an uncaught crash."""
    outdir = tmp_path / "output"
    outdir.mkdir()
    (outdir / "metadata.json").write_bytes(b"{NOT VALID JSON!!!")

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


def test_non_dict_json_raises(tmp_path):
    """JSON array at top-level → OutputTrustError."""
    outdir = tmp_path / "output"
    outdir.mkdir()
    (outdir / "metadata.json").write_bytes(b'["not", "an", "object"]')

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


def test_missing_payload_raises(tmp_path):
    """metadata.json missing 'payload' field → OutputTrustError."""
    outdir = tmp_path / "output"
    outdir.mkdir()

    # Valid-ish envelope but no 'payload'
    bad = {
        "engine": _ENGINE,
        "status": "ok",
        "input_sha256": _INPUT_SHA,
        "detected": {"label": "docx", "mime": "text/plain", "confidence": 1.0, "source": "magika"},
        "artifacts": [],
        "warnings": [],
        # payload intentionally omitted
    }
    (outdir / "metadata.json").write_bytes(json.dumps(bad).encode())

    with pytest.raises(OutputTrustError):
        validate_worker_output(
            output_dir=outdir,
            input_sha256=_INPUT_SHA,
            engine=_ENGINE,
            limits=_limits(),
        )


def test_a_host_io_failure_reading_metadata_is_not_a_trust_verdict(tmp_path, monkeypatch):
    """OutputTrustError conflated "the output is bad" with "we could not read it".

    An OSError here (EMFILE, EIO, ENOMEM) is this dispatcher's failure, not proof the worker
    produced anything invalid — and a host I/O outage hits every job at once, so convicting on it
    burns out the whole warm set. OutputTrustUnknown subclasses OutputTrustError, so the job still
    fails closed; only the ATTRIBUTION changes.
    """
    from blastbox.errors import OutputTrustError, OutputTrustUnknown

    out = tmp_path / "out"
    out.mkdir()

    def _boom(*a, **kw):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr("blastbox.host.trust.read_confined_regular_bytes", _boom)

    with pytest.raises(OutputTrustUnknown) as ei:
        validate_worker_output(output_dir=out, input_sha256=_INPUT_SHA, engine=_ENGINE,
                               limits=_limits())
    assert isinstance(ei.value, OutputTrustError), "must still fail the job closed"


def test_a_malformed_metadata_file_is_still_a_trust_verdict(tmp_path, monkeypatch):
    """The carve-out must stay narrow: a ValueError IS a verdict about the worker's output."""
    from blastbox.errors import OutputTrustUnknown

    out = tmp_path / "out"
    out.mkdir()

    def _bad(*a, **kw):
        raise ValueError("not a regular file inside the output dir")

    monkeypatch.setattr("blastbox.host.trust.read_confined_regular_bytes", _bad)

    with pytest.raises(OutputTrustError) as ei:
        validate_worker_output(output_dir=out, input_sha256=_INPUT_SHA, engine=_ENGINE,
                               limits=_limits())
    assert not isinstance(ei.value, OutputTrustUnknown), (
        "a worker writing a non-regular file is a real verdict"
    )


def test_host_io_during_reseal_is_also_not_a_verdict(tmp_path, monkeypatch):
    """The unknown classification must survive the RE-SEAL, not just the metadata read.

    seal_envelope opens, stats and hashes every declared artifact, so a host-wide EMFILE/EIO
    incident surfaces there too — and wrapping it as a plain OutputTrustError convicted every
    worker at once, exactly what the distinction drawn one step earlier exists to prevent.
    """
    from blastbox.errors import OutputTrustError, OutputTrustUnknown

    out, _ = _make_output_dir(tmp_path, artifact_content=b"payload")

    def _boom(**kw):
        raise OSError(24, "Too many open files")

    monkeypatch.setattr("blastbox.host.trust.seal_envelope", _boom)

    with pytest.raises(OutputTrustUnknown) as ei:
        validate_worker_output(output_dir=out, input_sha256=_INPUT_SHA, engine=_ENGINE,
                               limits=_limits())
    assert isinstance(ei.value, OutputTrustError), "must still fail the job closed"


def test_a_genuine_reseal_violation_is_still_a_verdict(tmp_path, monkeypatch):
    """The carve-out stays narrow: a non-OSError from the re-seal is real evidence."""
    from blastbox.errors import OutputTrustUnknown

    out, _ = _make_output_dir(tmp_path, artifact_content=b"payload")

    def _bad(**kw):
        raise ValueError("declared artifact hash mismatch")

    monkeypatch.setattr("blastbox.host.trust.seal_envelope", _bad)

    with pytest.raises(OutputTrustError) as ei:
        validate_worker_output(output_dir=out, input_sha256=_INPUT_SHA, engine=_ENGINE,
                               limits=_limits())
    assert not isinstance(ei.value, OutputTrustUnknown)
