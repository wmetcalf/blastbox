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


def _to_png(data: bytes, dest: Path) -> bool:
    """Decode ``data`` (png/ico/icns/...) and write the largest <=MAX_DIM image as PNG."""
    from PIL import Image

    if len(data) > MAX_READ:
        return False
    try:
        with Image.open(io.BytesIO(data)) as opened:
            im: Any = opened  # size/scale tweaks below are plugin features the stubs lack
            sizes = im.info.get("sizes")
            if sizes:
                cands = []
                for s in sizes:
                    w, h = s[0], s[1]
                    if w <= MAX_DIM and h <= MAX_DIM:
                        cands.append((w * h, s))
                if not cands:
                    return False
                best = max(cands, key=lambda c: c[0])[1]
                if im.format == "ICNS" and len(best) == 3:
                    im.size = (best[0], best[1])
                    im.load(scale=best[2])
                else:
                    im.size = (best[0], best[1])
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


def _pe_icons(sample: Path, outdir: Path, max_icons: int) -> list[Path]:
    import pefile  # type: ignore[import-untyped]

    try:
        pe = pefile.PE(str(sample), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:  # noqa: BLE001
        return []
    try:
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if root is None:
            return []

        def leaves(entry: object) -> list[tuple[int | None, bytes]]:
            res: list[tuple[int | None, bytes]] = []
            for e in getattr(entry, "directory").entries:
                if hasattr(e, "directory"):
                    # name/id level then language level
                    for lang in e.directory.entries:
                        d = getattr(lang, "data", None)
                        if d is not None and d.struct.Size <= MAX_READ:
                            res.append((e.id, pe.get_data(d.struct.OffsetToData, d.struct.Size)))
            return res

        groups: list[bytes] = []
        icons: dict[int, bytes] = {}
        for t in root.entries:
            if t.id == 14:
                groups += [b for _i, b in leaves(t)]
            elif t.id == 3:
                for i, b in leaves(t):
                    if i is not None:
                        icons.setdefault(i, b)
        written: list[Path] = []
        for g in groups:
            if len(written) >= max_icons:
                break
            if len(g) < 6:
                continue
            _res, typ, count = struct.unpack_from("<HHH", g, 0)
            if typ != 1:
                continue
            best: tuple[int, int] | None = None  # (area, id)
            best_bits = 32
            for k in range(min(count, 256)):
                off = 6 + 14 * k
                if off + 14 > len(g):
                    break
                w, h, _c, _r, _pl, bits, _sz, rid = struct.unpack_from("<BBBBHHIH", g, off)
                area = (w or 256) * (h or 256)
                key = (area, bits)
                if rid in icons and (best is None or key > (best[0], best[1])):
                    best = (area, rid)
                    best_bits = bits
            if best is None:
                continue
            rid = best[1]
            data = icons[rid]
            if not data.startswith(_PNG):
                # Wrap the raw DIB in a one-image ICO so Pillow can decode it.
                w, h = (best[0] ** 0.5), 0
                side = int(w)
                data = struct.pack("<HHH", 0, 1, 1) + struct.pack(
                    "<BBBBHHII", side & 0xFF, side & 0xFF, 0, 0, 1, best_bits, len(data), 22
                ) + data
            dest = outdir / f"icon-{len(written)}.png"
            if _to_png(data, dest):
                written.append(dest)
        return written
    finally:
        pe.close()


def _apk_icon(sample: Path, outdir: Path) -> list[Path]:
    from PIL import Image

    try:
        with zipfile.ZipFile(sample) as z:
            best: tuple[int, bytes] | None = None
            for info in z.infolist():
                if not _APK_ICON.match(info.filename) or info.file_size > MAX_READ:
                    continue
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
