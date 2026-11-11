""".NET ManifestResource scan for the sweep: what a decoy UI hides in its resources.

Live, .NET carriers (Formbook, NanoCore) were described by their visible app (an "air-traffic
simulator", a "weather utility") and even called benign, while the malware sat in a large
encrypted resource. This scan lists every embedded ManifestResource (name, size, Shannon
entropy; for a ``.resources`` container its entries with size, entropy and type), flags hidden
payloads and notes whether the managed code references the APIs that load one.

A resource or container entry is a hidden payload when
- it is at least ``HIDDEN_MIN_BYTES`` with entropy at least ``HIDDEN_MIN_ENTROPY`` and is not a
  recognised media file. 7.2 bits/byte is the triage packer threshold: compressed or encrypted
  data sits at 7.9+, while code, text, string tables and uncompressed bitmaps sit well below 7;
  the observed Formbook blob was 7.69. 64 KiB keeps small compressed assets (icons, cursors,
  short gzip'd configs) out; or
- it is, or plainly decodes to, a PE (:func:`decode`: gzip, zlib, raw deflate, base64, a
  single-byte XOR whose key turns the first byte into ``M``, or a repeating XOR key of up to
  ``MAX_XOR_KEY`` bytes that turns the first 60 bytes into the standard DOS header); or
- it is a lossless image (PNG or BMP, also one serialized inside a ``System.Drawing.Bitmap``)
  whose PIXELS are a payload (:func:`image_payload`). The carriers seen live (Formbook,
  AgentTesla and NanoCore from MalwareBazaar, one crypter) keep a loader DLL in a small bitmap
  read column by column as R,G,B, and the next stage in a larger PNG read column by column as
  little-endian ARGB integers behind a 4-byte length and a 3-byte XOR key, drawn in the top-left
  corner of a canvas whose remainder is transparent padding and a second, opaque block. So each
  diagonal block of the image is read in both pixel orders and five channel orders, with and
  without a length prefix, through :func:`decode`. A block that decodes to nothing but whose
  pixels are statistically noise (:func:`pixel_noise`: byte entropy AND entropy of the
  differences between horizontal neighbours both at least ``NOISE_MIN_ENTROPY``, which no
  picture reaches because neighbouring pixels of a picture resemble each other) is flagged as an
  encrypted carrier. Lossy formats (JPEG) cannot carry exact bytes in pixels and are skipped.

A recovered .NET stage is described (``stage``: module name, type and method counts, the loader
APIs it references) and scanned in turn (``MAX_DEPTH`` levels), its findings listed under
``<module>!<resource>``.

dnfile does not materialise the bytes of user-typed ``.resources`` entries (Bitmap, Icon: it
hands ``None``), which is how the carriers above were first missed: those are sliced out of the
container's data section by the entries' own offsets.

THIS FILE RUNS AS A STANDALONE SCRIPT under the capa venv's python (which carries the
hash-locked ``dnfile`` already pinned for capa), as a bounded subprocess
(``runner.run_dotnet_resources``: ``ulimit -v``/``-f``, timeout, stdout cap), because dnfile
parses hostile metadata. It imports only the standard library and dnfile:
``python -I dotnet_resources.py <sample> <outdir>`` prints one JSON document and writes each
hidden payload (``hidden-<n>.bin``) and decoded PE (``decoded-<n>.bin``) into ``outdir``.

JSON: ``{"resources_total", "resources": [{"name", "size", "entropy", "container"[, "format"]
[, "entries_total", "entries": [{"name", "size", "entropy", "type"}]]}], "loader_refs": [...],
"hidden": [{"resource"[, "entry"], "size", "entropy"[, "file"][, "image"][, "noise"]
[, "decoded", "decoded_file"][, "stage"]}][, "items_unread"][, "error"]}``. ``decoded`` is a
:func:`decode` method, prefixed ``image:<col|row>-<channels>[+len]/`` when the bytes came from
pixels. Counts, names and bytes written are capped.

The caps on resources and entries bound what is LISTED. Every resource and every entry is read
for a payload, while ``SCAN_BUDGET_S`` and ``MAX_HIDDEN`` last: a carrier placed behind 64 dull
resources is found like any other. ``items_unread`` counts what the scan did not read: items past
that budget or that cap, items that broke a parser, and images of a kind the scanner reads that
were over ``MAX_IMAGE_PIXELS`` or past ``IMAGE_BUDGET_S``. Any of them may be a payload, so the
verdict rule does not call a program benign while the count is not zero.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import struct
import sys
import time
import zlib
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HIDDEN_MIN_BYTES = 64 * 1024
HIDDEN_MIN_ENTROPY = 7.2
MAX_RESOURCES = 64  # listed; every resource is read for a payload
MAX_ENTRIES = 64  # listed per .resources container; every entry is read
MAX_HIDDEN = 16
SCAN_BUDGET_S = 60.0  # reading items for payloads; the sweep gives the whole scan 90 s
MAX_NAME = 200
MAX_ENTROPY_BYTES = 4 * 1024 * 1024
MAX_DECODED_BYTES = 64 * 1024 * 1024
MAX_WRITE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MIN_BASE64 = 64
MAX_XOR_KEY = 30  # half the known DOS header, so every key byte is confirmed at least once
MAX_DEPTH = 3  # stages scanned inside a recovered stage
MIN_IMAGE_PIXELS = 1024
MAX_IMAGE_PIXELS = 4 * 1024 * 1024
IMAGE_BUDGET_S = 40.0  # pixel decoding is pure Python: all images of one scan share this
MAX_UNFILTER_BYTES = 16 * 1024 * 1024  # PNG rows un-filtered in pure Python, per image
MAX_IMAGE_BLOCKS = 4
MAX_IMAGE_SCAN = 512  # an image file starts within this many bytes of a serialized Bitmap
NOISE_MIN_ENTROPY = 7.2
NOISE_SAMPLE_BYTES = 1024 * 1024
BLOCK_PROBE = 8  # leading rows/columns that give a block's extent

# (type, member) pairs a resource-borne loader needs; rendered "Type.Member".
LOADER_MEMBERS = frozenset({
    ("Assembly", "Load"), ("Assembly", "LoadFrom"), ("Assembly", "LoadFile"), ("AppDomain", "Load"),
    ("Assembly", "GetManifestResourceStream"), ("Assembly", "get_EntryPoint"), ("MethodBase", "Invoke"),
    ("Type", "InvokeMember"), ("Activator", "CreateInstance"), ("ResourceManager", ".ctor"),
    ("ResourceManager", "GetObject"), ("SymmetricAlgorithm", "CreateDecryptor"),
    ("Convert", "FromBase64String"), ("GZipStream", ".ctor"), ("DeflateStream", ".ctor"),
    ("Bitmap", "GetPixel"), ("Bitmap", "LockBits"), ("CryptoStream", ".ctor"),
    ("AesCryptoServiceProvider", ".ctor"), ("RijndaelManaged", ".ctor"), ("Aes", "Create"),
})
_MEDIA = ((b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
          (b"\x00\x00\x01\x00", "ico"), (b"RIFF", "riff"), (b"wOFF", "woff"), (b"wOF2", "woff2"))
_B64 = re.compile(rb"[A-Za-z0-9+/=\r\n]+")
_PNG = b"\x89PNG\r\n\x1a\n"
# The DOS header every mainstream linker emits, up to (not including) e_lfanew.
_DOS = bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000"
                     "000000000000000000000000000000000000000000000000")


def entropy(data: bytes) -> float:
    data = data[:MAX_ENTROPY_BYTES]
    if not data:
        return 0.0
    n = len(data)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(data).values()))


def media_format(data: bytes) -> str | None:
    """A media file's format by magic, also one serialized inside a Bitmap/Icon (first 512 bytes)."""
    for magic, name in _MEDIA:
        if data.startswith(magic):
            return name
    head = data[:512]
    for magic, name in _MEDIA[:4]:
        if magic in head:
            return name
    return None


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    (off,) = struct.unpack_from("<I", data, 0x3C)
    return 0x40 <= off <= len(data) - 4 and data[off:off + 4] == b"PE\x00\x00"


def _inflate(data: bytes, wbits: int, limit: int | None = None) -> bytes | None:
    limit = MAX_DECODED_BYTES if limit is None else limit
    try:
        z = zlib.decompressobj(wbits)
        out = z.decompress(data, limit + 1)
    except zlib.error:
        return None
    return out if len(out) <= limit else None


def decode(data: bytes) -> tuple[str, bytes] | None:
    """``(method, PE bytes)`` when ``data`` is a PE or one plain transform away from one."""
    if is_pe(data):
        return "plain", data
    if data[:2] == b"\x1f\x8b":
        out = _inflate(data, 16 + zlib.MAX_WBITS)
        if out is not None and is_pe(out):
            return "gzip", out
    if len(data) >= 2 and data[0] == 0x78 and (data[0] << 8 | data[1]) % 31 == 0:
        out = _inflate(data, zlib.MAX_WBITS)
        if out is not None and is_pe(out):
            return "zlib", out
    out = _inflate(data, -zlib.MAX_WBITS)
    if out is not None and is_pe(out):
        return "deflate", out
    if len(data) >= MIN_BASE64 and len(data) <= MAX_DECODED_BYTES * 2 and _B64.fullmatch(data):
        try:
            out = base64.b64decode(data, validate=False)
        except (binascii.Error, ValueError):
            out = b""
        if is_pe(out):
            return "base64", out
    if len(data) >= 0x40:
        key = data[0] ^ 0x4D
        if key and data[1] ^ key == 0x5A:
            table = bytes(b ^ key for b in range(256))
            out = data[:MAX_DECODED_BYTES].translate(table)
            if is_pe(out):
                return f"xor:{key:#04x}", out
    if len(data) >= len(_DOS) + 4:
        stream = bytes(a ^ b for a, b in zip(data, _DOS))
        for period in range(2, MAX_XOR_KEY + 1):
            if stream == (stream[:period] * len(_DOS))[:len(_DOS)]:
                out = _xor(data[:MAX_DECODED_BYTES], stream[:period])
                if is_pe(out):
                    return "xor:0x" + stream[:period].hex(), out
                break
    return None


def _xor(data: bytes, key: bytes) -> bytes:
    pad = (key * (len(data) // len(key) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(pad, "little")).to_bytes(len(data), "little")


def _pe_end(data: bytes) -> int:
    """The offset a PE's headers say its file content ends at (sections, certificate table); 0 when
    the headers cannot be read. It may lie past ``len(data)``."""
    try:
        (off,) = struct.unpack_from("<I", data, 0x3C)
        count, opt = struct.unpack_from("<H", data, off + 6)[0], struct.unpack_from("<H", data, off + 20)[0]
        table = off + 24 + opt
        end = table + 40 * count
        for i in range(min(count, 96)):
            size, ptr = struct.unpack_from("<II", data, table + 40 * i + 16)
            if ptr:
                end = max(end, ptr + size)
        (magic,) = struct.unpack_from("<H", data, off + 24)
        dirs = off + 24 + (112 if magic == 0x20B else 96)
        if dirs + 8 * 5 <= table:
            cert, cert_size = struct.unpack_from("<II", data, dirs + 8 * 4)
            if cert:
                end = max(end, cert + cert_size)
    except struct.error:
        return 0
    return end


def pe_extent(data: bytes) -> int:
    """Where a PE's file content ends within ``data``, or ``len(data)``."""
    end = _pe_end(data)
    return end if 0x40 < end <= len(data) else len(data)


def trim_pe(data: bytes) -> bytes:
    """``data`` without the zero padding a carrier leaves after the PE it holds."""
    end = pe_extent(data)
    return data[:end] if end < len(data) and not data[end:].strip(b"\x00") else data


class Image:
    """A decoded lossless image: one ``bytes`` plane per channel, row-major from the top row.
    ``a`` is ``None`` when the file has no alpha channel."""

    def __init__(self, fmt: str, w: int, h: int, r: bytes, g: bytes, b: bytes, a: bytes | None) -> None:
        self.fmt, self.w, self.h, self.r, self.g, self.b, self.a = fmt, w, h, r, g, b, a
        self.spare_w = self.spare_h = 0  # all-zero columns / rows cut off a block: maybe its own zeros

    def planes(self) -> list[bytes]:
        return [self.r, self.g, self.b] + ([self.a] if self.a is not None else [])

    def crop(self, x0: int, y0: int, w: int, h: int) -> Image:
        def cut(plane: bytes | None) -> Any:
            if plane is None:
                return None
            return b"".join(plane[y * self.w + x0:y * self.w + x0 + w] for y in range(y0, y0 + h))
        return Image(self.fmt, w, h, cut(self.r), cut(self.g), cut(self.b), cut(self.a))


def _unfilter(raw: bytes, h: int, stride: int, bpp: int) -> bytes | None:
    """PNG scanlines without their filter bytes (filters 0-4 undone)."""
    line_len = stride + 1
    if len(raw) < h * line_len:
        return None
    if not raw[0:h * line_len:line_len].strip(b"\x00"):  # every row unfiltered: what noise compresses best with
        return b"".join(raw[y * line_len + 1:(y + 1) * line_len] for y in range(h))
    if h * stride > MAX_UNFILTER_BYTES:
        return None
    out = bytearray(h * stride)
    prev = bytearray(stride)
    for y in range(h):
        kind = raw[y * line_len]
        line = bytearray(raw[y * line_len + 1:(y + 1) * line_len])
        if kind == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 255
        elif kind == 2:
            line = bytearray((a + b) & 255 for a, b in zip(line, prev))
        elif kind == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 255
        elif kind == 4:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                up = prev[i]
                corner = prev[i - bpp] if i >= bpp else 0
                pa, pb, pc = abs(up - corner), abs(left - corner), abs(left + up - 2 * corner)
                line[i] = (line[i] + (left if pa <= pb and pa <= pc else up if pb <= pc else corner)) & 255
        elif kind != 0:
            return None
        out[y * stride:(y + 1) * stride] = line
        prev = line
    return bytes(out)


class _TooLarge(Exception):
    """A PNG or BMP of a kind the scanner reads, with more than ``MAX_IMAGE_PIXELS`` pixels."""


def _png(data: bytes, start: int, pixels: bool = True) -> Image | None:
    pos = start + len(_PNG)
    header: tuple[int, ...] | None = None
    idat: list[bytes] = []
    while pos + 8 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, pos)
        if kind == b"IHDR" and length == 13:
            if pos + 21 > len(data):
                return None  # the header chunk is cut short
            header = struct.unpack_from(">IIBBBBB", data, pos + 8)
        elif kind == b"IDAT":
            idat.append(data[pos + 8:pos + 8 + length] if pixels else b"")
        elif kind == b"IEND":
            break
        pos += 12 + length
    if header is None or not idat:
        return None
    w, h, depth, colour, _, _, interlace = header
    if depth != 8 or colour not in (2, 6) or interlace or not w or not h:
        return None
    if w * h > MAX_IMAGE_PIXELS:
        raise _TooLarge
    bpp = 4 if colour == 6 else 3
    if not pixels:
        return Image("png", w, h, b"", b"", b"", None)
    raw = _inflate(b"".join(idat), zlib.MAX_WBITS, limit=h * (w * bpp + 1))
    if raw is None:
        return None
    px = _unfilter(raw, h, w * bpp, bpp)
    if px is None:
        return None
    return Image("png", w, h, px[0::bpp], px[1::bpp], px[2::bpp], px[3::4] if bpp == 4 else None)


def _bmp(data: bytes, start: int, pixels: bool = True) -> Image | None:
    try:
        offset, dib, w, h, planes, bits, compression = struct.unpack_from("<IIiiHHI", data, start + 10)
    except struct.error:
        return None
    if dib not in (40, 52, 56, 108, 124) or planes != 1 or bits not in (24, 32) or compression not in (0, 3):
        return None
    rows = abs(h)
    if w <= 0 or not rows:
        return None
    if w * rows > MAX_IMAGE_PIXELS:
        raise _TooLarge
    bpp = bits // 8
    stride = (w * bpp + 3) & ~3
    if len(data) - (start + offset) < stride * rows:
        return None
    if not pixels:
        return Image("bmp", w, rows, b"", b"", b"", None)
    body = data[start + offset:start + offset + stride * rows]
    order = range(rows) if h < 0 else range(rows - 1, -1, -1)  # a positive height is stored bottom-up
    px = b"".join(body[y * stride:y * stride + w * bpp] for y in order)
    return Image("bmp", w, rows, px[2::bpp], px[1::bpp], px[0::bpp], px[3::4] if bpp == 4 else None)


def _load_image(data: bytes, pixels: bool = True) -> Image | None:
    """:func:`load_image`, raising :class:`_TooLarge` when the only image found is over the limit.
    ``pixels=False`` reads the headers alone and gives the image without its channel planes."""
    head = data[:MAX_IMAGE_SCAN]
    start = head.find(_PNG)
    if start >= 0:
        return _png(data, start, pixels)
    too_large = False
    start = head.find(b"BM")
    while start >= 0:
        try:
            image = _bmp(data, start, pixels)
        except _TooLarge:
            image, too_large = None, True
        if image is not None:
            return image
        start = head.find(b"BM", start + 1)
    if too_large:
        raise _TooLarge
    return None


def _readable_image(data: bytes) -> bool:
    """Whether ``data`` is an image of a kind the scanner reads, whatever its size, by its headers."""
    try:
        return _load_image(data, pixels=False) is not None
    except _TooLarge:
        return True


def load_image(data: bytes) -> Image | None:
    """The PNG or BMP that ``data`` is, or that a serialized Bitmap wraps, as channel planes."""
    try:
        return _load_image(data)
    except _TooLarge:
        return None


def _blank(image: Image, start: int, stop: int, step: int) -> bool:
    return not any(plane[start:stop:step].strip(b"\x00") for plane in image.planes())


def blocks(image: Image) -> list[Image]:
    """The image as the diagonal run of blocks a padded carrier canvas is made of: each block's
    extent is where its rows and columns stop being all-zero pixels (a block shares no row or
    column with the next, so its own rows and columns bound it). A picture is one block."""
    out: list[Image] = []
    x0 = y0 = 0
    w, h = image.w, image.h
    while x0 < w and y0 < h and len(out) < MAX_IMAGE_BLOCKS:
        while x0 < w and _blank(image, y0 * w + x0, h * w, w):  # leading empty columns
            x0 += 1
        while y0 < h and _blank(image, y0 * w + x0, (y0 + 1) * w, 1):  # leading empty rows
            y0 += 1
        if x0 >= w or y0 >= h:
            break
        bw = bh = 0
        for plane in image.planes():
            for y in range(y0, min(y0 + BLOCK_PROBE, h)):
                bw = max(bw, len(plane[y * w + x0:(y + 1) * w].rstrip(b"\x00")))
            for x in range(x0, min(x0 + BLOCK_PROBE, w)):
                bh = max(bh, len(plane[y0 * w + x:h * w:w].rstrip(b"\x00")))
        if not bw or not bh:
            break
        for _ in range(2):  # the probe under-reads an edge that is zero there: widen over the whole block
            bw = max(len(plane[y * w + x0:(y + 1) * w].rstrip(b"\x00"))
                     for plane in image.planes() for y in range(y0, y0 + bh))
            bh = max(len(plane[y0 * w + x:h * w:w].rstrip(b"\x00"))
                     for plane in image.planes() for x in range(x0, x0 + bw))
        if (x0, y0, bw, bh) == (0, 0, w, h):
            return [image]
        block = image.crop(x0, y0, bw, bh)
        block.spare_w, block.spare_h = w - x0 - bw, h - y0 - bh
        out.append(block)
        x0, y0 = x0 + bw, y0 + bh
    return out or [image]


def _alpha(image: Image) -> bytes | None:
    """The alpha plane when it carries anything (it is not one constant value)."""
    a = image.a
    return a if a and a.count(a[:1]) != len(a) else None


def pixel_streams(image: Image) -> Iterator[tuple[str, bytes]]:
    """``(layout, bytes)`` for every way a loader plausibly reads the pixels: column- or row-major,
    in each channel order (4-channel orders only when the alpha channel carries anything)."""
    n = image.w * image.h
    alpha = _alpha(image)
    orders = ["rgb", "bgr"] + (["bgra", "rgba", "argb"] if alpha is not None else [])
    for major in ("col", "row"):
        planes: dict[str, bytes] = {"r": image.r, "g": image.g, "b": image.b}
        if alpha is not None:
            planes["a"] = alpha
        if major == "col":
            planes = {k: b"".join(v[x::image.w] for x in range(image.w)) for k, v in planes.items()}
        for order in orders:
            buf = bytearray(n * len(order))
            for i, ch in enumerate(order):
                buf[i::len(order)] = planes[ch]
            yield f"{major}-{order}", bytes(buf)


def pixel_noise(image: Image) -> float | None:
    """How noise-like the pixels are: the lower of the byte entropy and the entropy of the
    differences between horizontal neighbours, over the colour channels (and a varying alpha).
    ``None`` when there are too few bytes to carry a payload."""
    planes = [image.r, image.g, image.b]
    alpha = _alpha(image)
    if alpha is not None:
        planes.append(alpha)
    if image.w * image.h * len(planes) < HIDDEN_MIN_BYTES:
        return None
    lowest = 8.0
    for plane in planes:
        sample = plane[:NOISE_SAMPLE_BYTES // len(planes)]
        delta = bytes((a - b) & 255 for a, b in zip(sample[1:], sample))
        lowest = min(lowest, entropy(sample), entropy(delta))
    return lowest


def _carve(stream: bytes, spare: int) -> tuple[str, bytes] | None:
    """:func:`decode` of a pixel stream, bare or behind a 4-byte length. ``spare`` zero bytes may
    follow the stream: a block is cut where its pixels turn all-zero, which a payload's own
    trailing zeros (section padding) do too."""
    found = decode(stream)
    if found is not None:
        method, pe = found
        short = _pe_end(pe) - len(pe)
        if 0 < short <= spare and (method == "plain" or method.startswith("xor:")):
            found = decode(stream + bytes(short)) or found
        return found[0], trim_pe(found[1])
    if len(stream) > 8:
        (length,) = struct.unpack_from("<I", stream, 0)
        if 0x40 <= length <= len(stream) - 4 + spare:
            body = stream[4:4 + length]
            found = decode(body + bytes(length - len(body)))
            if found is not None:
                return "+len/" + found[0], found[1]
    return None


def image_payload(image: Image) -> tuple[str, bytes] | None:
    """``("image:<layout>[+len]/<method>", PE bytes)`` when a block's pixels decode to a PE."""
    for block in blocks(image):
        if block.w * block.h < MIN_IMAGE_PIXELS:
            continue
        for layout, stream in pixel_streams(block):
            lost = block.spare_w * block.h if layout.startswith("col") else block.spare_h * block.w
            found = _carve(stream, min(lost * (len(layout) - 4), MAX_DECODED_BYTES))
            if found is not None:
                method = found[0] if found[0].startswith("+len/") else "/" + found[0]
                return f"image:{layout}{method}", found[1]
    return None


def image_noise(image: Image) -> float | None:
    """The highest :func:`pixel_noise` among the image's blocks that reach ``NOISE_MIN_ENTROPY``."""
    best: float | None = None
    for block in blocks(image):
        noise = pixel_noise(block)
        if noise is not None and noise >= NOISE_MIN_ENTROPY and (best is None or noise > best):
            best = noise
    return best


def _name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        try:
            text = str(value)  # dnfile hands heap strings as objects with a __str__
        except Exception:
            return ""
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:MAX_NAME]


def _entry_bytes(entry: Any) -> bytes:
    value = getattr(entry, "value", None)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    data = getattr(entry, "data", None)
    return bytes(data) if isinstance(data, (bytes, bytearray)) else b""


def _entry_spans(container: Any, entries: list[Any]) -> dict[int, tuple[int, int]]:
    """Where each entry's serialized bytes lie in the container's ``_data``, by position: from its
    offset in the data section to the next entry's. dnfile leaves these unread for user types
    (Bitmap, Icon). Spans, not bytes: entries that share an offset share one slice."""
    raw = getattr(container, "_data", None)
    base = getattr(getattr(container, "struct", None), "DataSectionOffset", None)
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(base, int) or base < 0:
        return {}
    starts: dict[int, int] = {}
    for i, e in enumerate(entries):
        off = getattr(getattr(e, "struct", None), "DataOffset", None)
        if isinstance(off, int) and 0 <= off and base + off < len(raw):
            starts[i] = base + off
    bounds = sorted(set(starts.values())) + [len(raw)]
    end = dict(zip(bounds, bounds[1:]))
    return {i: (o, end[o]) for i, o in starts.items()}


def _loader_refs(pe: Any) -> list[str]:
    refs: set[str] = set()
    try:
        table = pe.net.mdtables.MemberRef
        rows = table.rows if table is not None else []
    except AttributeError:
        return []
    for row in rows:
        try:
            cls = row.Class.row
            pair = (str(getattr(cls, "TypeName", "") or ""), str(row.Name or ""))
        except AttributeError:
            continue
        if pair in LOADER_MEMBERS:
            refs.add(f"{pair[0]}.{pair[1]}")
    return sorted(refs)


class _Writer:
    def __init__(self, outdir: Path | None) -> None:
        self.outdir = outdir
        self.written = 0
        self.n = 0

    def write(self, prefix: str, data: bytes) -> str | None:
        if self.outdir is None or len(data) > MAX_FILE_BYTES or self.written + len(data) > MAX_WRITE_BYTES:
            return None
        name = f"{prefix}-{self.n}.bin"
        self.n += 1
        fd = os.open(self.outdir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.written += len(data)
        return name


def _stage(pe: Any) -> dict[str, Any]:
    """What a recovered PE is: for a .NET stage its module name, size in types and methods and the
    loader APIs it references."""
    net = getattr(pe, "net", None)
    tables = getattr(net, "mdtables", None)
    if tables is None:
        return {"dotnet": False}
    out: dict[str, Any] = {"dotnet": True, "loader_refs": _loader_refs(pe)}
    try:
        out["module"] = _name(tables.Module.rows[0].Name)
        out["types"] = len(tables.TypeDef.rows)
        out["methods"] = len(tables.MethodDef.rows)
    except (AttributeError, IndexError, TypeError):
        pass
    return out


class _Scan:
    """One scan's state: the hidden payloads found so far and the files written for them."""

    def __init__(self, outdir: Path | None) -> None:
        self.hidden: list[dict[str, Any]] = []
        self.writer = _Writer(outdir)
        self.items_unread = 0  # see the module docstring: any of them may be a payload
        self._deadline = time.monotonic() + SCAN_BUDGET_S
        self._image_deadline = time.monotonic() + IMAGE_BUDGET_S

    def image(self, data: bytes) -> Image | None:
        """``data`` as an image, while the scan's image time budget lasts.

        An image of a kind the scanner reads that it did not read, for time or because it is over
        ``MAX_IMAGE_PIXELS``, is counted in ``items_unread``.
        """
        if time.monotonic() < self._image_deadline:
            try:
                return _load_image(data)
            except _TooLarge:
                self.items_unread += 1
                return None
        if _readable_image(data):
            self.items_unread += 1
        return None

    def consider(self, data: bytes, ent: float | None, resource: str, entry: str | None, depth: int) -> None:
        """Read one resource or entry for a hidden payload (``ent``: its entropy when the caller
        has it). An item not read, or one that breaks a parser, is counted, never fatal."""
        if len(self.hidden) >= MAX_HIDDEN or time.monotonic() >= self._deadline:
            self.items_unread += 1
            return
        try:
            self._consider(data, entropy(data) if ent is None else ent, resource, entry, depth)
        except Exception:  # a parser bug on hostile bytes costs this item, not the scan
            self.items_unread += 1

    def _consider(self, data: bytes, ent: float, resource: str, entry: str | None, depth: int) -> None:
        decoded = decode(data)
        image = self.image(data) if decoded is None else None
        noise: float | None = None
        if image is not None:
            decoded = image_payload(image)
            noise = image_noise(image) if decoded is None else None
        big = (image is None and len(data) >= HIDDEN_MIN_BYTES and ent >= HIDDEN_MIN_ENTROPY
               and media_format(data) is None)
        if decoded is None and noise is None and not big:
            return
        item: dict[str, Any] = {"resource": resource, "size": len(data), "entropy": round(ent, 3)}
        if entry is not None:
            item["entry"] = entry
        if image is not None:
            item["image"] = f"{image.fmt} {image.w}x{image.h}"
        if noise is not None:
            item["noise"] = round(noise, 3)
        raw = self.writer.write("hidden", data)
        if raw is not None:
            item["file"] = raw
        self.hidden.append(item)
        if decoded is None:
            return
        method, payload = decoded
        item["decoded"] = method
        if method != "plain":
            out = self.writer.write("decoded", payload)
            if out is not None:
                item["decoded_file"] = out
        self.stage(item, payload, depth)

    def stage(self, item: dict[str, Any], payload: bytes, depth: int) -> None:
        """Describe a recovered PE and, when it is .NET, scan its own resources one level down."""
        try:
            import dnfile

            pe = dnfile.dnPE(data=payload)
        except Exception:  # dnfile/pefile raise many types on hostile input
            return
        try:
            item["stage"] = _stage(pe)
            if item["stage"]["dotnet"] and depth < MAX_DEPTH:
                self.resources(pe, None, _name(item["stage"].get("module") or "stage") + "!", depth + 1)
        finally:
            _close(pe)

    def resources(self, pe: Any, doc: dict[str, Any] | None, prefix: str, depth: int) -> None:
        """Walk ``pe``'s ManifestResources: list them into ``doc`` (the submitted assembly only)
        and consider each, and each container entry, as a hidden payload."""
        try:
            resources = list(pe.net.resources or [])
        except Exception:
            resources = []
            if doc is not None:
                doc["error"] = "resources_unreadable"
        if doc is not None:
            doc["resources_total"] = len(resources)
        for n, res in enumerate(resources):
            rows = doc["resources"] if doc is not None and n < MAX_RESOURCES else None
            try:
                self.resource(res, rows, prefix, depth)
            except Exception:  # dnfile reads lazily: a resource it cannot give is one item unread
                self.items_unread += 1

    def resource(self, res: Any, rows: list[dict[str, Any]] | None, prefix: str, depth: int) -> None:
        """Read one ManifestResource, and each entry of a container, for a hidden payload; describe
        it in ``rows`` when it is one of those the document lists."""
        name = prefix + _name(getattr(res, "name", ""))
        data = getattr(res, "data", None)
        if isinstance(data, (bytes, bytearray)):
            raw = bytes(data)
            ent = entropy(raw) if rows is not None else None
            if rows is not None and ent is not None:
                row: dict[str, Any] = {"name": name, "size": len(raw), "entropy": round(ent, 3), "container": False}
                fmt = media_format(raw)
                if fmt:
                    row["format"] = fmt
                rows.append(row)
            self.consider(raw, ent, name, None, depth)
            return
        entries = list(getattr(data, "entries", None) or [])
        raw_container = getattr(data, "_data", b"")
        listed: list[dict[str, Any]] = []
        if rows is not None:
            size = getattr(res, "size", 0)
            whole = entropy(bytes(raw_container)) if isinstance(raw_container, (bytes, bytearray)) else 0.0
            rows.append({"name": name, "size": size if isinstance(size, int) else 0, "entropy": round(whole, 3),
                         "container": True, "entries_total": len(entries), "entries": listed})
        spans = _entry_spans(data, entries)
        read: set[tuple[int, int]] = set()  # entries at one offset share a slice: it is read once
        for i, e in enumerate(entries):
            blob = _entry_bytes(e)
            again = False
            if not blob and i in spans:
                again = spans[i] in read
                read.add(spans[i])
                blob = bytes(raw_container[spans[i][0]:spans[i][1]])
            ename = _name(getattr(e, "name", ""))
            ent = None
            if rows is not None and i < MAX_ENTRIES:
                ent = entropy(blob)
                listed.append({"name": ename, "size": len(blob), "entropy": round(ent, 3),
                               "type": _name(getattr(e, "type_name", "") or "")})
            if not again:
                self.consider(blob, ent, name, ename, depth)


def _close(pe: Any) -> None:
    try:
        pe.close()
    except Exception:
        pass


def scan(sample: Path, outdir: Path | None) -> dict[str, Any]:
    """The resource document for ``sample`` (see the module docstring); never raises on bad input."""
    doc: dict[str, Any] = {"resources_total": 0, "resources": [], "loader_refs": [], "hidden": []}
    try:
        import dnfile  # the capa venv's hash-locked copy in the worker image
    except ImportError:
        doc["error"] = "dnfile_missing"
        return doc
    try:
        pe = dnfile.dnPE(str(sample))
    except Exception:  # dnfile/pefile raise many types on hostile input
        doc["error"] = "parse_failed"
        return doc
    try:
        if getattr(pe, "net", None) is None:
            doc["error"] = "not_dotnet"
            return doc
        doc["loader_refs"] = _loader_refs(pe)
        state = _Scan(outdir)
        doc["hidden"] = state.hidden
        state.resources(pe, doc, "", 0)
        if state.items_unread:
            doc["items_unread"] = state.items_unread
    finally:
        _close(pe)
    return doc


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: dotnet_resources.py <sample> <outdir>", file=sys.stderr)
        return 2
    outdir = Path(argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    sys.stdout.write(json.dumps(scan(Path(argv[1]), outdir)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
