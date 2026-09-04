import pytest
from pydantic import ValidationError
from blastbox.contract.leaf import Hash, Detection, ArtifactRef, Dimensions

def test_hash_accepts_valid_sha256():
    h = Hash(algo="sha256", value="a" * 64)
    assert h.value == "a" * 64

@pytest.mark.parametrize("algo,value", [
    ("sha256", "a" * 63),       # too short
    ("sha256", "g" * 64),       # non-hex
    ("phash", "xyz"),           # non-hex
])
def test_hash_rejects_malformed(algo, value):
    with pytest.raises(ValidationError):
        Hash(algo=algo, value=value)

def test_artifactref_is_id_only():
    r = ArtifactRef(id="a5")
    assert r.id == "a5"

def test_artifactref_rejects_pathlike():
    with pytest.raises(ValidationError):
        ArtifactRef(id="../etc/passwd")

def test_detection_confidence_bounds():
    Detection(label="docx", mime="application/...", confidence=1.0, source="magika")
    with pytest.raises(ValidationError):
        Detection(label="docx", mime="x", confidence=1.5, source="magika")

def test_dimensions_positive():
    Dimensions(width=1.0, height=2.0, unit="mm")
    with pytest.raises(ValidationError):
        Dimensions(width=0, height=2.0, unit="mm")
