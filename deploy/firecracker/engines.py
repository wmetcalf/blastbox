"""Example engines baked into the blastbox FC worker rootfs.

These are EXAMPLE engines for the Firecracker warm-tier demo, not part of the
blastbox core (real adopters write their own — ClippyShot's LibreOffice, etc.).
The rootfs picks one at build time via BLASTBOX_FC_ENGINE.

- ProbeEngine     — hashes input → one text artifact (no external tools).
- PdfRasterizeEngine — a REAL detonation: rasterizes an untrusted PDF to per-page
  PNGs with poppler's ``pdftoppm``, producing image artifacts the host re-hashes
  from the output disk and validates through the trust gate.
"""
from __future__ import annotations

import hashlib
import logging
import subprocess
import time
from pathlib import Path

from blastbox.contract import (
    ArtifactRef,
    DeclaredArtifact,
    Detection,
    Dimensions,
    EmbeddedResource,
    Page,
    Record,
    Warning,
)
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

_log = logging.getLogger("blastbox.fc.engines")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def png_dims(path: Path) -> tuple[int, int]:
    """Read a PNG's pixel dimensions from its IHDR (no image library needed)."""
    with open(path, "rb") as fh:
        head = fh.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        return 0, 0
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def build_sample_pdf(text: str = "BLASTBOX FC", pages: int = 1) -> bytes:
    """Build a minimal valid multi-page PDF (correct xref) for tests/demos."""
    objects: dict[int, str] = {}
    next_num = 3
    kids: list[int] = []
    page_pairs: list[tuple[int, int]] = []
    for _ in range(pages):
        page_num, content_num = next_num, next_num + 1
        next_num += 2
        kids.append(page_num)
        page_pairs.append((page_num, content_num))
    font_num = next_num

    objects[1] = "<</Type /Catalog /Pages 2 0 R>>"
    kids_str = " ".join(f"{k} 0 R" for k in kids)
    objects[2] = f"<</Type /Pages /Kids [{kids_str}] /Count {pages}>>"
    for i, (page_num, content_num) in enumerate(page_pairs):
        objects[page_num] = (
            f"<</Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            f"/Contents {content_num} 0 R /Resources <</Font <</F1 {font_num} 0 R>>>>>>"
        )
        stream = f"BT /F1 24 Tf 30 100 Td ({text} {i + 1}) Tj ET"
        objects[content_num] = f"<</Length {len(stream)}>>\nstream\n{stream}\nendstream"
    objects[font_num] = "<</Type /Font /Subtype /Type1 /BaseFont /Helvetica>>"

    out = b"%PDF-1.4\n"
    offsets: dict[int, int] = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += f"{num} 0 obj\n{objects[num]}\nendobj\n".encode()
    xref_pos = len(out)
    count = max(objects) + 1
    out += f"xref\n0 {count}\n".encode()
    out += b"0000000000 65535 f \n"
    for num in range(1, count):
        out += f"{offsets[num]:010d} 00000 n \n".encode()
    out += f"trailer\n<</Size {count} /Root 1 0 R>>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return out


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------


class ProbeEngine:
    """Smallest real engine: hashes the input and emits one text artifact."""

    name = "probe"
    formats = frozenset({"*"})

    def _detection(self) -> Detection:
        return Detection(
            label="probe", mime="application/octet-stream", confidence=1.0, source="probe"
        )

    def detect(self, input: Path) -> Detection:
        return self._detection()

    def warmup(self) -> None:
        _log.info("probe.warmup")
        time.sleep(0.2)

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        data = Path(input).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        (Path(outdir) / "echo.txt").write_text(
            f"sha256={sha}\nbytes={len(data)}\n", encoding="utf-8"
        )
        return DetonationResult(
            payload=Record(fields={"input_sha256": sha, "input_bytes": str(len(data))}),
            artifacts=[DeclaredArtifact(id="echo", path="echo.txt", kind="text")],
            detected=self._detection(),
        )


class PdfRasterizeEngine:
    """Rasterize an untrusted PDF to per-page PNGs with poppler's pdftoppm."""

    name = "pdfrasterize"
    formats = frozenset({"pdf"})
    DPI = 100
    MAX_PAGES = 50

    def _detection(self, is_pdf: bool) -> Detection:
        return Detection(
            label="pdf" if is_pdf else "unknown",
            mime="application/pdf" if is_pdf else "application/octet-stream",
            confidence=0.99 if is_pdf else 0.1,
            source="pdfrasterize",
        )

    def detect(self, input: Path) -> Detection:
        return self._detection(Path(input).read_bytes()[:5].startswith(b"%PDF"))

    def warmup(self) -> None:
        # Load the pdftoppm binary + shared libs into cache pre-input.
        subprocess.run(["pdftoppm", "-h"], capture_output=True)

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        outdir = Path(outdir)
        is_pdf = Path(input).read_bytes()[:5].startswith(b"%PDF")
        if not is_pdf:
            return DetonationResult(
                payload=Record(fields={"reason": "not_a_pdf"}),
                artifacts=[],
                detected=self._detection(False),
                warnings=[Warning(code="not_pdf", message="input is not a PDF")],
                status="rejected",
            )

        prefix = str(outdir / "page")
        subprocess.run(
            ["pdftoppm", "-png", "-r", str(self.DPI), "-l", str(self.MAX_PAGES),
             str(input), prefix],
            check=True,
            capture_output=True,
            timeout=max(10, int(limits.timeout_s)),
        )
        pngs = sorted(outdir.glob("page*.png"))
        if not pngs:
            raise RuntimeError("pdftoppm produced no pages")

        pages: list[Page] = []
        artifacts: list[DeclaredArtifact] = []
        for i, png in enumerate(pngs):
            w, h = png_dims(png)
            aid = f"p{i}"
            artifacts.append(DeclaredArtifact(id=aid, path=png.name, kind="image"))
            pages.append(
                Page(
                    index=i,
                    dims=Dimensions(width=float(w or 1), height=float(h or 1), unit="px"),
                    image=ArtifactRef(id=aid),
                )
            )
        payload = EmbeddedResource(
            embedded_path=Path(input).name,
            content_type="application/pdf",
            depth=0,
            metadata=Record(fields={"page_count": str(len(pages))}),
            children=pages,
        )
        _log.info("pdfrasterize.detonate pages=%d", len(pages))
        return DetonationResult(
            payload=payload, artifacts=artifacts, detected=self._detection(True)
        )


_ENGINES = {"probe": ProbeEngine, "pdfrasterize": PdfRasterizeEngine, "pdf": PdfRasterizeEngine}


def get_engine(name: str) -> object:
    """Return an engine instance from BLASTBOX_FC_ENGINE.

    A built-in example name (``probe`` / ``pdf``), or an adopter engine given as
    ``module.path:ClassName`` (e.g. ``clippyshot.engine:ClippyShotEngine``) which
    is imported + instantiated — so a rootfs can bake in any engine without this
    file depending on it.
    """
    name = name.strip()
    if ":" in name:
        import importlib

        mod_name, _, cls_name = name.partition(":")
        cls = getattr(importlib.import_module(mod_name), cls_name)
        return cls()
    return _ENGINES.get(name.lower(), ProbeEngine)()
