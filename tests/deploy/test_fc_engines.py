"""Tests for the example FC rootfs engines (deploy/firecracker/engines.py).

The module lives outside the package (it is COPY'd into the rootfs), so it is
loaded by path via importlib. The pdftoppm-backed test is gated on poppler.
"""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
from pathlib import Path

import pytest

from blastbox.contract import EmbeddedResource, Page
from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation

_ENGINES_PATH = (
    Path(__file__).resolve().parents[2] / "deploy" / "firecracker" / "engines.py"
)
_HAS_POPPLER = shutil.which("pdftoppm") is not None


def _load_engines():
    spec = importlib.util.spec_from_file_location("fc_engines", _ENGINES_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_eng = _load_engines()


def test_get_engine_factory():
    assert _eng.get_engine("probe").__class__.__name__ == "ProbeEngine"
    assert _eng.get_engine("pdf").__class__.__name__ == "PdfRasterizeEngine"
    assert _eng.get_engine("pdfrasterize").__class__.__name__ == "PdfRasterizeEngine"
    # Unknown → safe default.
    assert _eng.get_engine("nope").__class__.__name__ == "ProbeEngine"


def test_get_engine_module_class_path():
    """Adopter engines load via module:Class (how the clippyshot rootfs selects
    clippyshot.engine:ClippyShotEngine without this file depending on it)."""
    from collections import OrderedDict

    obj = _eng.get_engine("collections:OrderedDict")
    assert isinstance(obj, OrderedDict)


def test_build_sample_pdf_is_valid_pdf():
    data = _eng.build_sample_pdf("X", pages=2)
    assert data.startswith(b"%PDF")
    assert b"%%EOF" in data
    assert b"/Count 2" in data


def test_probe_engine_roundtrip(tmp_path):
    src = tmp_path / "in.bin"
    src.write_bytes(b"hello")
    out = tmp_path / "out"
    out.mkdir()
    rc = run_detonation(_eng.ProbeEngine(), input_path=src, output_dir=out, limits=Limits())
    assert rc == 0
    assert (out / "echo.txt").exists()
    assert (out / "metadata.json").exists()


def test_pdf_rejects_non_pdf(tmp_path):
    eng = _eng.PdfRasterizeEngine()
    assert eng.detect(_write(tmp_path, "x.bin", b"not a pdf")).label == "unknown"
    out = tmp_path / "out"
    out.mkdir()
    result = eng.detonate(_write(tmp_path, "y.bin", b"still not pdf"), out, Limits())
    assert result.status == "rejected"
    assert result.artifacts == []


@pytest.mark.skipif(not _HAS_POPPLER, reason="pdftoppm (poppler-utils) not installed")
def test_pdf_rasterize_multipage_trust_validated(tmp_path):
    from blastbox.host.trust import validate_worker_output

    pdf = _eng.build_sample_pdf("BLASTBOX", pages=3)
    src = tmp_path / "doc.pdf"
    src.write_bytes(pdf)
    sha = hashlib.sha256(pdf).hexdigest()
    out = tmp_path / "out"
    out.mkdir()

    rc = run_detonation(_eng.PdfRasterizeEngine(), input_path=src, output_dir=out, limits=Limits())
    assert rc == 0

    # Payload is the document (EmbeddedResource) holding 3 Page children.
    env = validate_worker_output(
        output_dir=out, input_sha256=sha, engine="pdfrasterize", limits=Limits()
    )
    assert env.status == "ok"
    assert env.input_sha256 == sha
    assert len(env.artifacts) == 3
    # Every artifact hash was recomputed from disk by the trust gate.
    for art in env.artifacts:
        disk = (out / art.path).read_bytes()
        assert hashlib.sha256(disk).hexdigest() == art.sha256

    # The in-memory payload tree shape (pre-seal) is a document → pages.
    out2 = tmp_path / "out2"
    out2.mkdir()
    result = _eng.PdfRasterizeEngine().detonate(src, out2, Limits())
    assert isinstance(result.payload, EmbeddedResource)
    assert len(result.payload.children) == 3
    assert all(isinstance(c, Page) for c in result.payload.children)
    assert all(c.dims.width > 0 and c.dims.height > 0 for c in result.payload.children)


def _write(d: Path, name: str, data: bytes) -> Path:
    p = d / name
    p.write_bytes(data)
    return p
