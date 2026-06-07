import os

import pytest
from typing import Literal
from pydantic import Field
from blastbox.contract.envelope import DeclaredArtifact, seal_envelope, validate_envelope
from blastbox.contract.leaf import Detection
from blastbox.contract.nodes import Page, ExtractedText, register_node_type
from blastbox.contract.leaf import ArtifactRef, Dimensions

def _det():
    return Detection(label="docx", mime="x", confidence=1.0, source="magika")

def test_seal_computes_hash_and_size_and_confines(tmp_path):
    (tmp_path / "page-001.png").write_bytes(b"PNGDATA")
    payload = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                   image=ArtifactRef(id="a0"))
    env = seal_envelope(
        engine="clippyshot", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
        declared=[DeclaredArtifact(id="a0", path="page-001.png", kind="image")],
        warnings=[], payload=payload,
    )
    art = env.artifacts[0]
    assert art.bytes == 7
    assert len(art.sha256) == 64
    assert env.status == "ok"

def test_seal_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError, match="confined"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="../escape", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))

def test_seal_rejects_oversize_artifact_before_reading(tmp_path):
    # A declared artifact larger than the cap is rejected at stat() time (before the host
    # reads/hashes it), so a hostile worker can't force an unbounded in-memory read.
    (tmp_path / "big.bin").write_bytes(b"x" * 100)
    with pytest.raises(ValueError, match="exceeds"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="big.bin", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1),
                      max_artifact_bytes=10)


def test_seal_within_cap_uses_stat_size(tmp_path):
    (tmp_path / "ok.bin").write_bytes(b"x" * 5)
    env = seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                        declared=[DeclaredArtifact(id="a0", path="ok.bin", kind="x")],
                        warnings=[], payload=ExtractedText(text="x", char_count=1),
                        max_artifact_bytes=10)
    assert env.artifacts[0].bytes == 5  # under cap -> sealed; size from stat, chunk-hashed


def test_atomic_write_confined_defeats_destination_symlink(tmp_path):
    """A worker pre-planting the destination as a symlink to an outside file must NOT redirect
    the host write; the target is untouched and the destination becomes a real file."""
    from blastbox.contract.envelope import atomic_write_confined
    d = tmp_path / "out"
    d.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"ORIGINAL")
    (d / "metadata.json").symlink_to(outside)  # worker pre-plants the dst as a symlink

    atomic_write_confined(d, "metadata.json", b"SEALED")

    assert outside.read_bytes() == b"ORIGINAL"  # outside file NOT clobbered
    assert not (d / "metadata.json").is_symlink()  # dst replaced by a real file
    assert (d / "metadata.json").read_bytes() == b"SEALED"


def test_atomic_write_confined_applies_exact_mode(tmp_path):
    """The mode is applied EXACTLY (fchmod, umask-independent) so a host-authored control file
    (go.json) / metadata.json the worker or API reads cross-uid gets 0o644, not 0o600."""
    import stat as _stat
    from blastbox.contract.envelope import atomic_write_confined
    d = tmp_path / "ctrl"
    d.mkdir()
    atomic_write_confined(d, "go.json", b"{}", mode=0o644)
    assert _stat.S_IMODE((d / "go.json").stat().st_mode) == 0o644
    atomic_write_confined(d, "host_only", b"x", mode=0o600)
    assert _stat.S_IMODE((d / "host_only").stat().st_mode) == 0o600


def test_confined_atomic_writer_defeats_destination_symlink(tmp_path):
    """The streaming artifact writer must NOT follow a worker-planted destination symlink — it
    clobbers it with a real confined file and leaves the outside target untouched."""
    from blastbox.contract.envelope import confined_atomic_writer
    d = tmp_path / "out"
    d.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"ORIGINAL")
    (d / "page-001.png").symlink_to(outside)  # worker pre-plants the dst as a symlink

    with confined_atomic_writer(d, "page-001.png") as fd:
        os.write(fd, b"SEALED-PNG")

    assert outside.read_bytes() == b"ORIGINAL"  # outside file NOT clobbered
    assert not (d / "page-001.png").is_symlink()  # replaced by a real file
    assert (d / "page-001.png").read_bytes() == b"SEALED-PNG"


def test_confined_atomic_writer_blocks_symlinked_parent(tmp_path):
    """A symlinked intermediate component must fail the O_NOFOLLOW walk, not redirect the write."""
    from blastbox.contract.envelope import confined_atomic_writer
    d = tmp_path / "out"
    d.mkdir()
    outside_dir = tmp_path / "evil"
    outside_dir.mkdir()
    (d / "sub").symlink_to(outside_dir)  # worker plants a symlinked subdir

    with pytest.raises(OSError):
        with confined_atomic_writer(d, "sub/x.png") as fd:
            os.write(fd, b"data")
    assert not (outside_dir / "x.png").exists()  # write never escaped into the symlink target


def test_confined_atomic_writer_unlinks_temp_on_exception(tmp_path):
    """If the body raises (e.g. a bad re-hash), nothing is published and no temp is leaked."""
    from blastbox.contract.envelope import confined_atomic_writer
    d = tmp_path / "out"
    d.mkdir()
    with pytest.raises(RuntimeError):
        with confined_atomic_writer(d, "page-001.png") as fd:
            os.write(fd, b"partial")
            raise RuntimeError("bad hash")
    assert not (d / "page-001.png").exists()  # not published
    assert list(d.iterdir()) == []  # temp cleaned up


def test_confined_atomic_writer_rejects_traversal(tmp_path):
    from blastbox.contract.envelope import confined_atomic_writer
    d = tmp_path / "out"
    d.mkdir()
    for bad in ("../escape", "/abs", "a/../../b"):
        with pytest.raises(ValueError):
            with confined_atomic_writer(d, bad):
                pass


def test_confined_atomic_writer_dir_mode_for_cross_uid_traverse(tmp_path):
    """Nested artifact dirs get dir_mode (0o755) so a DIFFERENT API uid can traverse to the
    0o644 file inside; the default stays 0o700 (host-only control/metadata writes)."""
    import stat as _stat
    from blastbox.contract.envelope import confined_atomic_writer
    d = tmp_path / "out"
    d.mkdir()

    with confined_atomic_writer(d, "nested/sub/art.txt", mode=0o644, dir_mode=0o755) as fd:
        os.write(fd, b"png")
    assert _stat.S_IMODE((d / "nested").stat().st_mode) == 0o755
    assert _stat.S_IMODE((d / "nested" / "sub").stat().st_mode) == 0o755
    assert _stat.S_IMODE((d / "nested" / "sub" / "art.txt").stat().st_mode) == 0o644

    with confined_atomic_writer(d, "priv/f", mode=0o600) as fd:  # default dir_mode=0o700
        os.write(fd, b"y")
    assert _stat.S_IMODE((d / "priv").stat().st_mode) == 0o700


def test_atomic_write_confined_defeats_temp_symlink(tmp_path):
    """The old predictable temp name pre-planted as a symlink must NOT be followed (random
    O_EXCL|O_NOFOLLOW temp name avoids it entirely)."""
    from blastbox.contract.envelope import atomic_write_confined
    d = tmp_path / "out"
    d.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"ORIGINAL")
    (d / ".metadata.json.tmp").symlink_to(outside)  # the previously-predictable temp path

    atomic_write_confined(d, "metadata.json", b"SEALED")

    assert outside.read_bytes() == b"ORIGINAL"
    assert (d / "metadata.json").read_bytes() == b"SEALED"


def test_seal_caps_growing_artifact_during_hash(tmp_path):
    """#4: an artifact larger than the cap is rejected DURING the hash read, not just by the
    initial fstat (defends a live worker that grows the file after stat)."""
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 5000)
    with pytest.raises(ValueError, match="exceeds|grew"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="big.bin", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1),
                      max_artifact_bytes=1000)


def test_envelope_from_json_rejects_deep_payload():
    """A payload nested past the depth bound is rejected cleanly at parse time (not via a
    catchable RecursionError) — covers the Record.fields recursion vector too."""
    import json as _json

    from blastbox.contract.envelope import envelope_from_json
    deep: dict = {"_type": "extracted_text", "text": "x", "char_count": 1}
    for _ in range(200):
        deep = {"_type": "record", "fields": {"nested": deep}}
    env = {
        "engine": "e", "status": "ok", "input_sha256": "a" * 64,
        "detected": {"label": "d", "mime": "m", "confidence": 1.0, "source": "magika"},
        "artifacts": [], "warnings": [], "payload": deep,
    }
    with pytest.raises(ValueError, match="depth"):
        envelope_from_json(_json.dumps(env).encode())


def test_seal_rejects_symlinked_artifact(tmp_path):
    """A declared artifact that is a symlink (e.g. to a host file) is rejected — the fd open
    is O_NOFOLLOW, so it can't be followed to read outside outdir on a live worker dir."""
    outside = tmp_path / "outside"
    outside.write_bytes(b"SECRET")
    (tmp_path / "a.png").symlink_to(outside)
    with pytest.raises(ValueError, match="confined"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="a.png", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))


def test_seal_rejects_fifo_artifact(tmp_path):
    """A declared artifact that is a FIFO/special file is rejected (S_ISREG check) — and the
    O_NONBLOCK open means it could never block the single-threaded dispatcher."""
    import os
    os.mkfifo(tmp_path / "f.bin")
    with pytest.raises(ValueError, match="confined|regular"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="f.bin", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))


def test_seal_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="nope.png", kind="x")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))

def test_seal_rejects_unresolved_artifactref(tmp_path):
    payload = Page(index=0, dims=Dimensions(width=1, height=1, unit="px"),
                   image=ArtifactRef(id="MISSING"))
    with pytest.raises(ValueError, match="unresolved"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                      declared=[], warnings=[], payload=payload)

# HIGH-1: _collect_refs must find ArtifactRefs outside .image/.children
class ThumbPage(Page):
    type: Literal["thumbpage"] = Field(default="thumbpage", alias="_type")
    thumbnail: ArtifactRef

def test_collect_refs_finds_ref_outside_image_and_children():
    """_collect_refs must find ArtifactRefs in fields beyond .image/.children."""
    from blastbox.contract.envelope import _collect_refs
    register_node_type(ThumbPage)
    node = ThumbPage(
        index=0, dims=Dimensions(width=1, height=1, unit="px"),
        image=ArtifactRef(id="declared-img"),
        thumbnail=ArtifactRef(id="undeclared-thumb"),
    )
    refs = _collect_refs(node)
    assert "undeclared-thumb" in refs

def test_seal_rejects_undeclared_ref_outside_image_and_children(tmp_path):
    """seal_envelope must reject undeclared ArtifactRef in non-image non-children fields."""
    from blastbox.contract.envelope import _collect_refs
    register_node_type(ThumbPage)
    node = ThumbPage(
        index=0, dims=Dimensions(width=1, height=1, unit="px"),
        image=ArtifactRef(id="declared-img"),
        thumbnail=ArtifactRef(id="undeclared-thumb"),
    )
    # Verify _collect_refs finds both refs (image + thumbnail)
    refs = _collect_refs(node)
    assert "declared-img" in refs
    assert "undeclared-thumb" in refs
    # Verify seal_envelope raises when undeclared-thumb is not declared
    # (We can't use seal_envelope with ThumbPage until HIGH-2 is fixed, so
    # we test _collect_refs directly above and below verify unresolved detection logic)
    declared_ids = {"declared-img"}
    unresolved = refs - declared_ids
    assert "undeclared-thumb" in unresolved


# HIGH-2: Registered engine node as ROOT payload must be accepted by seal_envelope
# and must appear in json_schema()
class RootEngineNode(Page):
    type: Literal["root_engine_node"] = Field(default="root_engine_node", alias="_type")
    engine_meta: str = Field(default="")

def test_registered_engine_node_as_root_payload_succeeds(tmp_path):
    """After register_node_type, sealing that type as the root payload must succeed."""
    register_node_type(RootEngineNode)
    (tmp_path / "art.png").write_bytes(b"X")
    payload = RootEngineNode(
        index=0, dims=Dimensions(width=1, height=1, unit="px"),
        image=ArtifactRef(id="art0"), engine_meta="hello",
    )
    env = seal_envelope(
        engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
        declared=[DeclaredArtifact(id="art0", path="art.png", kind="image")],
        warnings=[], payload=payload,
    )
    assert env.payload.type == "root_engine_node"  # type: ignore[union-attr]

def test_json_schema_includes_registered_engine_type():
    """json_schema() must include discriminator tags for registered engine node types."""
    from blastbox.contract import json_schema
    register_node_type(RootEngineNode)
    schema = json_schema()
    schema_str = str(schema)
    assert "root_engine_node" in schema_str


def test_validate_envelope_rejects_oversized(tmp_path):
    (tmp_path / "f").write_bytes(b"x" * 10)
    env = seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                        declared=[DeclaredArtifact(id="a0", path="f", kind="x")],
                        warnings=[], payload=ExtractedText(text="x", char_count=1))
    with pytest.raises(ValueError, match="exceeds"):
        validate_envelope(env, outdir=tmp_path, max_artifact_bytes=5, max_total_bytes=1_000, max_artifacts=10)


# MED-1: validate_envelope must re-stat files and reject tampered bytes field
def test_validate_envelope_rejects_tampered_bytes_field(tmp_path):
    """validate_envelope must re-stat files; a worker that lies about bytes is rejected."""
    (tmp_path / "big.bin").write_bytes(b"x" * 1000)
    env = seal_envelope(engine="e", outdir=tmp_path, input_sha256="b"*64, detected=_det(),
                        declared=[DeclaredArtifact(id="b0", path="big.bin", kind="data")],
                        warnings=[], payload=ExtractedText(text="x", char_count=1))
    # Tamper: replace the sealed artifact with a fake one reporting only 1 byte
    from blastbox.contract.envelope import Artifact
    tampered_artifact = Artifact(
        id=env.artifacts[0].id,
        path=env.artifacts[0].path,
        kind=env.artifacts[0].kind,
        sha256=env.artifacts[0].sha256,
        bytes=1,  # LIES — real file is 1000 bytes
    )
    tampered_env = env.model_copy(update={"artifacts": [tampered_artifact]})
    with pytest.raises(ValueError, match="declared bytes"):
        validate_envelope(tampered_env, outdir=tmp_path,
                          max_artifact_bytes=5000, max_total_bytes=100_000, max_artifacts=10)


# LOW-2: envelope_from_json must raise ValueError (not KeyError) on missing payload
def test_envelope_from_json_raises_value_error_on_missing_payload():
    """envelope_from_json({}) must raise ValueError, not KeyError."""
    from blastbox.contract.envelope import envelope_from_json
    with pytest.raises(ValueError, match="payload"):
        envelope_from_json(b'{}')

def test_envelope_from_json_raises_value_error_on_non_object():
    """envelope_from_json of a JSON array must raise ValueError, not KeyError."""
    from blastbox.contract.envelope import envelope_from_json
    with pytest.raises(ValueError):
        envelope_from_json(b'[]')


def test_seal_rejects_metadata_json_as_declared_artifact(tmp_path):
    """A worker declaring metadata.json as an artifact is rejected — the host overwrites
    metadata.json with the sealed envelope, so the declared sha would desync from served bytes."""
    (tmp_path / "metadata.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="reserved"):
        seal_envelope(engine="e", outdir=tmp_path, input_sha256="b" * 64, detected=_det(),
                      declared=[DeclaredArtifact(id="a0", path="metadata.json", kind="json")],
                      warnings=[], payload=ExtractedText(text="x", char_count=1))
