"""Icon extraction: PE RT_GROUP_ICON, .ico/.icns files, APK launcher icons -> PNG."""

from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

MAX_DIM = 1024
MAX_READ = 16 * 1024 * 1024
_PNG = b"\x89PNG\r\n\x1a\n"
_APK_ICON = re.compile(r"^res/(?:mipmap|drawable)[^/]*/ic_launcher[^/]*\.png$")


def _read_capped(path: Path) -> bytes | None:
    with path.open("rb") as f:
        data = f.read(MAX_READ + 1)
    return data if len(data) <= MAX_READ else None


MAX_GROUPS = 64
MAX_TOTAL_READ = 64 * 1024 * 1024
MAX_APK_CANDIDATES = 32


def _declared_ok(data: bytes) -> bool:
    """Check the REAL dimensions in the headers (PNG IHDR / DIB / ICO entries) before decoding.

    ICO directory entries can declare 16x16 while the payload is a huge PNG or DIB, so
    Pillow's size selection cannot be trusted to bound the decode.
    """
    if data.startswith(_PNG):
        if len(data) < 24:
            return False
        w, h = struct.unpack(">II", data[16:24])
        return 0 < w <= MAX_DIM and 0 < h <= MAX_DIM
    if data[:4] == b"\x00\x00\x01\x00":
        if len(data) < 6:
            return False
        count = struct.unpack_from("<H", data, 4)[0]
        for k in range(min(count, 256)):
            off = 6 + 16 * k
            if off + 16 > len(data):
                return False
            size, pos = struct.unpack_from("<II", data, off + 8)
            blob = data[pos : pos + min(size, 40)]
            if blob.startswith(_PNG):
                if not _declared_ok(blob):
                    return False
            elif len(blob) >= 12 and struct.unpack_from("<I", blob, 0)[0] >= 40:  # BITMAPINFOHEADER
                w, h = struct.unpack_from("<ii", blob, 4)
                if not (0 < w <= MAX_DIM and 0 < abs(h) <= 2 * MAX_DIM):
                    return False
            else:
                return False
        return True
    return True


def _to_png(data: bytes, dest: Path) -> bool:
    """Decode ``data`` (png/ico/icns/...) and write the largest <=MAX_DIM image as PNG."""
    import warnings

    from PIL import Image

    if len(data) > MAX_READ or not _declared_ok(data):
        return False
    old = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_DIM * MAX_DIM
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as opened:
                im: Any = opened  # size/scale tweaks below are plugin features the stubs lack
                sizes = im.info.get("sizes")
                if sizes:
                    cands = [(s[0] * s[1], s) for s in sizes if s[0] <= MAX_DIM and s[1] <= MAX_DIM]
                    if not cands:
                        return False
                    best = max(cands, key=lambda c: c[0])[1]
                    im.size = (best[0], best[1])
                    if im.format == "ICNS" and len(best) == 3:
                        im.load(scale=best[2])
                    else:
                        im.load()
                else:
                    if im.width > MAX_DIM or im.height > MAX_DIM:  # header only, nothing decoded yet
                        return False
                    im.load()
                dest.parent.mkdir(parents=True, exist_ok=True)
                im.convert("RGBA").save(dest, "PNG")
        return True
    except Exception:  # noqa: BLE001 - Pillow raises many types on hostile input
        dest.unlink(missing_ok=True)
        return False
    finally:
        Image.MAX_IMAGE_PIXELS = old


def _pe_icons(sample: Path, outdir: Path, max_icons: int) -> list[Path]:
    import pefile  # type: ignore[import-untyped]

    try:
        pe = pefile.PE(str(sample), fast_load=True)
    except Exception:  # noqa: BLE001
        return []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        return _pe_icons_parsed(pe, outdir, max_icons)
    except Exception:  # noqa: BLE001 - hostile PE: any parse/offset error means "no icons"
        return []
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass


def _pe_icons_parsed(pe: Any, outdir: Path, max_icons: int) -> list[Path]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return []

    def leaves(entry: Any) -> list[tuple[int, int, int]]:
        """(resource id, rva, size) only; bytes are fetched lazily."""
        res: list[tuple[int, int, int]] = []
        for e in entry.directory.entries:
            if hasattr(e, "directory"):
                for lang in e.directory.entries:
                    d = getattr(lang, "data", None)
                    if d is not None and 0 < d.struct.Size <= MAX_READ:
                        res.append((e.id or 0, d.struct.OffsetToData, d.struct.Size))
        return res

    groups: list[tuple[int, int, int]] = []
    icons: dict[int, tuple[int, int]] = {}
    for t in root.entries:
        if t.id == 14:
            groups += leaves(t)[:MAX_GROUPS]
        elif t.id == 3:
            for i, rva, size in leaves(t):
                icons.setdefault(i, (rva, size))
    budget = MAX_TOTAL_READ
    written: list[Path] = []
    for _gid, grva, gsize in groups[:MAX_GROUPS]:
        if len(written) >= max_icons or gsize > budget:
            break
        budget -= gsize
        g = pe.get_data(grva, gsize)
        if len(g) < 6:
            continue
        _res, typ, count = struct.unpack_from("<HHH", g, 0)
        if typ != 1:
            continue
        best: tuple[int, int, int] | None = None  # (area, bits, id)
        for k in range(min(count, 256)):
            off = 6 + 14 * k
            if off + 14 > len(g):
                break
            w, h, _c, _r, _pl, bits, _sz, rid = struct.unpack_from("<BBBBHHIH", g, off)
            key = ((w or 256) * (h or 256), bits, rid)
            if rid in icons and (best is None or key[:2] > best[:2]):
                best = key
        if best is None:
            continue
        area, bits, rid = best
        rva, size = icons[rid]
        if size > budget:
            break
        budget -= size
        data = pe.get_data(rva, size)
        if not data.startswith(_PNG):
            # Wrap the raw DIB in a one-image ICO so Pillow can decode it.
            side = int(area**0.5)
            data = (
                struct.pack("<HHH", 0, 1, 1)
                + struct.pack("<BBBBHHII", side & 0xFF, side & 0xFF, 0, 0, 1, bits, len(data), 22)
                + data
            )
        dest = outdir / f"icon-{len(written)}.png"
        if _to_png(data, dest):
            written.append(dest)
    return written


def _apk_icon(sample: Path, outdir: Path) -> list[Path]:
    from PIL import Image

    try:
        with zipfile.ZipFile(sample) as z:
            best: tuple[int, bytes] | None = None
            seen = 0
            for info in z.infolist():
                if not _APK_ICON.match(info.filename) or info.file_size > MAX_READ:
                    continue
                seen += 1
                if seen > MAX_APK_CANDIDATES:
                    break
                with z.open(info) as f:
                    data = f.read(MAX_READ + 1)
                if len(data) > MAX_READ:
                    continue
                try:
                    with Image.open(io.BytesIO(data)) as im:
                        w, h = im.size
                except Exception:  # noqa: BLE001
                    continue
                if w > MAX_DIM or h > MAX_DIM:
                    continue
                if best is None or w * h > best[0]:
                    best = (w * h, data)
    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError):
        return []
    if best is None:
        return []
    dest = outdir / "icon-0.png"
    return [dest] if _to_png(best[1], dest) else []


def extract_icons(sample: Path, outdir: Path, *, max_icons: int = 8) -> list[Path]:
    """Write up to ``max_icons`` PNGs (``icon-<n>.png``) to ``outdir``; never raises on bad input."""
    if max_icons <= 0:
        return []
    try:
        with sample.open("rb") as f:
            head = f.read(8)
    except OSError:
        return []
    if head[:2] == b"MZ":
        return _pe_icons(sample, outdir, max_icons)
    if head[:4] == b"\x00\x00\x01\x00" or head[:4] == b"icns":
        data = _read_capped(sample)
        dest = outdir / "icon-0.png"
        return [dest] if data is not None and _to_png(data, dest) else []
    if head[:2] == b"PK":
        return _apk_icon(sample, outdir)
    return []
