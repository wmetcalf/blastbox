""".NET ManifestResource scan for the sweep: what a decoy UI hides in its resources.

Live, .NET carriers (Formbook, NanoCore) were described by their visible app (an "air-traffic
simulator", a "weather utility") and even called benign, while the malware sat in a large
encrypted resource. This scan lists every embedded ManifestResource (name, size, Shannon
entropy; for a ``.resources`` container its entries with size, entropy and type), flags hidden
payloads and notes whether the managed code references the APIs that load one.

A resource or container entry is a hidden payload when
- it is at least ``HIDDEN_MIN_BYTES`` with entropy at least ``HIDDEN_MIN_ENTROPY`` and is not a
  whole media file (:func:`media_extent`: the format's own framing has to hold from its magic
  to its end, so a magic in front of a payload excuses nothing, and whatever follows the end of
  a media file is read as an item of its own). 7.2 bits/byte is the triage packer threshold:
  compressed or encrypted
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

``.resources`` containers are read by this file's own parser (:func:`_container`), not
dnfile's: dnfile gives no bytes for user-typed entries (Bitmap, Icon), which is how the carriers
above were first missed, and one malformed container made it refuse the whole assembly
(:func:`_open` keeps it from parsing them). Each entry is the bytes its type says it has, or, for
a type with no length of its own, the bytes up to the next entry's offset. Entries that share an
offset are read once. Bytes of the container that no entry covers (:func:`_gaps`) are read as
items too. A container this parser cannot follow is read whole, as one blob, and counted unread.

One item is read as up to ``MAX_PARTS`` stretches: an image or media file, then what follows its
end, and for a BMP the bytes between its header and its pixels. Of the image headers in an
item's first ``MAX_IMAGE_SCAN`` bytes, the first one that holds decides: a small valid picture
placed after an oversize one does not stand in for it. An image cut short by the next entry's
offset is read again from the bytes that follow in the container, since a decoy entry can point
into the middle of a bitmap.

THIS FILE RUNS AS A STANDALONE SCRIPT under the capa venv's python (which carries the
hash-locked ``dnfile`` already pinned for capa), as a bounded subprocess
(``runner.run_dotnet_resources``: ``ulimit -v``/``-f``, timeout, stdout cap), because dnfile
parses hostile metadata. It imports only the standard library and dnfile:
``python -I dotnet_resources.py <sample> <outdir> [<seconds>]`` prints one JSON document and
writes each hidden payload (``hidden-<n>.bin``) and decoded PE (``decoded-<n>.bin``) into
``outdir``. ``<seconds>`` is the time for reading items, counted from the start of the process
(default ``SCAN_BUDGET_S``); the runner gives two thirds of its timeout, so that a scan short of
time answers with a count of what it did not read and is not killed with nothing.

JSON: ``{"resources_total", "resources": [{"name", "size", "entropy", "container"[, "format"]
[, "entries_total", "entries": [{"name", "size", "entropy", "type"}]]}], "loader_refs": [...],
"hidden": [{"resource"[, "entry"], "size", "entropy"[, "file"][, "image"][, "noise"]
[, "decoded", "decoded_file"][, "stage"]}][, "items_unread"][, "error"]}``. ``decoded`` is a
:func:`decode` method, prefixed ``image:<col|row>-<channels>[+len]/`` when the bytes came from
pixels. Counts, names and bytes written are capped.

The caps on resources and entries bound what is LISTED. Every resource and every entry is read
for a payload, while the time budget and ``MAX_HIDDEN`` last: a carrier placed behind 64 dull
resources is found like any other. ``items_unread`` counts what the scan did not read: items past
that budget or that cap, items that broke a parser, items of more than ``MAX_PARTS`` stretches,
resource rows whose bytes lie outside the file (dnfile drops those; ``resources_total`` counts
them), and images of a kind the scanner reads that were over ``MAX_IMAGE_PIXELS`` or past
``IMAGE_BUDGET_S``. Any of them may be a payload, so the verdict rule does not call a program
benign while the count is not zero.

What this scan does NOT see, by design. It is a set of heuristics for the carriers observed, not
a proof that nothing is hidden:
- an encoding :func:`decode` does not know (it is tried at the start of a stretch only), or a
  payload under ``HIDDEN_MIN_BYTES`` or ``HIDDEN_MIN_ENTROPY`` that does not decode;
- a payload inside media whose framing holds: in PNG chunks other than the pixels, in a JPEG's
  segments or scan data, in an ICO, RIFF or WOFF body (their framing is one length field);
- an image whose header is past the first ``MAX_IMAGE_SCAN`` bytes of its item, a palette or
  interlaced PNG, a compressed BMP;
- a resource kept in another file of a multi-file assembly;
- a hidden plain PE counts as a ground for the verdict only when the code references a loader
  API (``loader_refs``).
The cost of reading strictly: a truncated or damaged media file of ``HIDDEN_MIN_BYTES`` or more
with high entropy is reported as a hidden payload.
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
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, NamedTuple

HIDDEN_MIN_BYTES = 64 * 1024
HIDDEN_MIN_ENTROPY = 7.2
MAX_RESOURCES = 64  # listed; every resource is read for a payload
MAX_ENTRIES = 64  # listed per .resources container; every entry is read
MAX_CONTAINER_ENTRIES = 65536  # read per container
MAX_CONTAINER_TYPES = 65536
MAX_GAPS = 16  # stretches of one container outside its entries that are read
MIN_PART = 64  # bytes outside an entry, or left over by an image, worth reading
MAX_PARTS = 4  # stretches of one item read on their own: the item, then what images in it leave
MAX_HIDDEN = 16
SCAN_BUDGET_S = 60.0  # the most a scan spends: the caller gives less when it has less (main)
_T0 = time.monotonic()  # as a script, the scan's time counts from here: dnfile's parse is in it
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


def _media_at(data: bytes) -> tuple[str, int] | None:
    """The media format ``data`` starts with, or wraps as a serialized Bitmap/Icon (first 512
    bytes), and where its file begins."""
    for magic, name in _MEDIA:
        if data.startswith(magic):
            return name, 0
    head = data[:MAX_IMAGE_SCAN]
    found = [(at, name) for magic, name in _MEDIA[:4] if (at := head.find(magic)) >= 0]
    if not found:
        return None
    at, name = min(found)
    return name, at


def media_format(data: bytes) -> str | None:
    """A media file's format by magic, also one serialized inside a Bitmap/Icon (first 512 bytes)."""
    hit = _media_at(data)
    return hit[0] if hit is not None else None


def _png_end(data: bytes, at: int) -> int | None:
    pos, first = at + len(_PNG), True
    while pos + 12 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, pos)
        if not kind.isalpha() or (first and (kind, length) != (b"IHDR", 13)):
            return None
        pos, first = pos + 12 + length, False
        if kind == b"IEND":
            return pos
    return None


def _jpeg_end(data: bytes, at: int) -> int | None:
    pos = at + 2
    while pos + 2 <= len(data):
        marker = data[pos + 1]
        if data[pos] != 0xFF:
            return None
        if marker == 0xD9:
            return pos + 2
        if marker == 0xFF:  # a fill byte
            pos += 1
        elif marker == 0x01 or 0xD0 <= marker <= 0xD7:  # markers with no length
            pos += 2
        else:
            (length,) = struct.unpack_from(">H", data, pos + 2)
            if length < 2:
                return None
            pos += 2 + length
            if marker == 0xDA:  # a scan: entropy-coded data up to the next marker
                found = _JPEG_MARKER.search(data, pos)
                if found is None:
                    return None
                pos = found.start()
    return None


def _gif_end(data: bytes, at: int) -> int | None:
    def table(flags: int) -> int:
        return 3 << ((flags & 7) + 1) if flags & 0x80 else 0

    pos = at + 13 + table(data[at + 10])
    while pos < len(data):
        kind = data[pos]
        if kind == 0x3B:
            return pos + 1
        if kind == 0x2C:  # an image: descriptor, colour table, code size, data blocks
            pos += 11 + table(data[pos + 9])
        elif kind == 0x21:  # an extension: label, data blocks
            pos += 2
        else:
            return None
        while data[pos]:
            pos += 1 + data[pos]
        pos += 1
    return None


def _ico_end(data: bytes, at: int) -> int | None:
    (count,) = struct.unpack_from("<H", data, at + 4)
    end = images = at + 6 + 16 * count
    for i in range(count):
        size, offset = struct.unpack_from("<II", data, at + 14 + 16 * i)
        if at + offset < images or not size:
            return None
        end = max(end, at + offset + size)
    return end if count else None


_JPEG_MARKER = re.compile(rb"\xff[^\x00\xff\xd0-\xd7]")
_MEDIA_END: dict[str, Callable[[bytes, int], int | None]] = {
    "png": _png_end, "jpeg": _jpeg_end, "gif": _gif_end, "ico": _ico_end,
    "riff": lambda data, at: at + 8 + struct.unpack_from("<I", data, at + 4)[0],
    "woff": lambda data, at: at + struct.unpack_from(">I", data, at + 8)[0],
    "woff2": lambda data, at: at + struct.unpack_from(">I", data, at + 8)[0],
}


def media_extent(data: bytes) -> int | None:
    """Where the media file that ``data`` is, or wraps, stops, when its framing holds to its own
    end; ``None`` for bytes that only start like one. The file's content is not judged."""
    hit = _media_at(data)
    if hit is None:
        return None
    name, at = hit
    try:
        end = _MEDIA_END[name](data, at)
    except (struct.error, IndexError):
        return None
    return end if end is not None and at < end <= len(data) else None


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
        self.end = 0  # where the image file stops in the bytes it was read from
        self.slack = b""  # bytes between a bitmap's headers and its pixels

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


class _Cut(Exception):
    """A PNG or BMP whose headers or pixel data run past the bytes given."""


def _png(data: bytes, start: int, pixels: bool = True) -> Image | None:
    pos = start + len(_PNG)
    header: tuple[int, ...] | None = None
    idat: list[bytes] = []
    end = 0  # just past the IEND chunk, when the file has one
    while pos + 8 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, pos)
        if kind == b"IHDR" and length == 13:
            if pos + 21 > len(data):
                raise _Cut  # the header chunk is cut short
            header = struct.unpack_from(">IIBBBBB", data, pos + 8)
        elif kind == b"IDAT":
            idat.append(data[pos + 8:pos + 8 + length] if pixels else b"")
        elif kind == b"IEND":
            end = min(pos + 12 + length, len(data))
            break
        pos += 12 + length
    if header is None:
        if end:
            return None
        raise _Cut
    w, h, depth, colour, _, _, interlace = header
    if depth != 8 or colour not in (2, 6) or interlace or not w or not h:
        return None
    if end and not idat:
        return None  # a whole file with no pixel data
    if w * h > MAX_IMAGE_PIXELS:
        raise _TooLarge
    image: Image | None = None
    bpp = 4 if colour == 6 else 3
    if idat and not pixels:
        image = Image("png", w, h, b"", b"", b"", None)
    elif idat:
        raw = _inflate(b"".join(idat), zlib.MAX_WBITS, limit=h * (w * bpp + 1))
        px = _unfilter(raw, h, w * bpp, bpp) if raw is not None else None
        if px is not None:
            image = Image("png", w, h, px[0::bpp], px[1::bpp], px[2::bpp], px[3::4] if bpp == 4 else None)
    if image is None:
        if end:
            return None  # the file is whole and its pixel data is broken
        raise _Cut
    image.end = end or len(data)
    return image


def _bmp(data: bytes, start: int, pixels: bool = True) -> Image | None:
    try:
        offset, dib, w, h, planes, bits, compression = struct.unpack_from("<IIiiHHI", data, start + 10)
    except struct.error:
        raise _Cut from None
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
        raise _Cut
    image = Image("bmp", w, rows, b"", b"", b"", None)
    if pixels:
        body = data[start + offset:start + offset + stride * rows]
        order = range(rows) if h < 0 else range(rows - 1, -1, -1)  # a positive height is stored bottom-up
        px = b"".join(body[y * stride:y * stride + w * bpp] for y in order)
        image = Image("bmp", w, rows, px[2::bpp], px[1::bpp], px[0::bpp], px[3::4] if bpp == 4 else None)
    image.end = start + offset + stride * rows
    image.slack = data[start + 14 + dib:start + offset]
    return image


def _load_image(data: bytes, pixels: bool = True) -> Image | None:
    """:func:`load_image`, raising :class:`_TooLarge` or :class:`_Cut` when the image found is over
    the pixel limit or runs past ``data``. ``pixels=False`` reads the headers alone and gives the
    image without its channel planes.

    The first image header that holds decides, in file order: a later one may be a small picture
    planted inside a carrier's header to be read in its place.
    """
    head = data[:MAX_IMAGE_SCAN]
    png = head.find(_PNG)
    start = head.find(b"BM")
    while start >= 0 or png >= 0:
        if png >= 0 and not 0 <= start < png:
            image, png = _png(data, png, pixels), -1
        else:
            image = _bmp(data, start, pixels)
            start = head.find(b"BM", start + 1)
        if image is not None:
            return image
    return None


def load_image(data: bytes) -> Image | None:
    """The PNG or BMP that ``data`` is, or that a serialized Bitmap wraps, as channel planes."""
    try:
        return _load_image(data)
    except (_TooLarge, _Cut):
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


_RES_MAGIC = b"\xce\xca\xef\xbe"
_FIXED = {2: 1, 3: 2, 4: 1, 5: 1, 6: 2, 7: 2, 8: 4, 9: 4, 0xA: 8, 0xB: 8, 0xC: 4, 0xD: 8, 0xE: 16, 0xF: 8, 0x10: 8}
_TYPES = {
    0: "Null", 1: "System.String", 2: "System.Boolean", 3: "System.Char", 4: "System.Byte", 5: "System.SByte",
    6: "System.Int16", 7: "System.UInt16", 8: "System.Int32", 9: "System.UInt32", 0xA: "System.Int64",
    0xB: "System.UInt64", 0xC: "System.Single", 0xD: "System.Double", 0xE: "System.Decimal",
    0xF: "System.DateTime", 0x10: "System.TimeSpan", 0x20: "System.ByteArray", 0x21: "System.Stream",
}


class _Broken(Exception):
    """A ``.resources`` container whose header does not parse, or a resource with no bytes."""


class _Entry(NamedTuple):
    name: str
    type: str
    start: int  # of the entry in the container: its type code
    body: int  # of its value
    end: int
    open: bool  # the format does not say where it ends: it runs to the next entry


class _Container(NamedTuple):
    total: int  # entries the header declares
    base: int  # where the data section starts
    entries: list[_Entry]
    unread: int  # 1 when the header declares entries that are not in ``entries``


def _u32(raw: bytes, pos: int) -> int:
    if pos < 0 or pos + 4 > len(raw):
        raise _Broken
    return int.from_bytes(raw[pos:pos + 4], "little")


def _leb(raw: bytes, pos: int) -> tuple[int, int]:
    """The 7-bit encoded int at ``pos`` and the position after it."""
    value = 0
    for shift in range(0, 35, 7):
        if not 0 <= pos < len(raw):
            raise _Broken
        value |= (raw[pos] & 0x7F) << shift
        pos += 1
        if raw[pos - 1] < 0x80:
            return value, pos
    raise _Broken


def _lstr(raw: bytes, pos: int) -> tuple[bytes, int]:
    n, pos = _leb(raw, pos)
    if pos + n > len(raw):
        raise _Broken
    return raw[pos:pos + n], pos + n


def _extent(raw: bytes, start: int, version: int, types: list[str]) -> tuple[str, int, int | None]:
    """An entry's type name, where its value starts, and where it ends when its type says so.

    A user type (a serialized Bitmap or Icon), a code the format does not define, a value that
    runs past the container and every entry of a version 1 container have no stated end.
    """
    try:
        code, body = _leb(raw, start)
        if version == 1:
            return (types[code] if code < len(types) else ""), start, None
        kind, end = _TYPES.get(code, ""), None
        if code == 0:
            end = body
        elif code == 1:
            n, body = _leb(raw, body)
            end = body + n
        elif code in _FIXED:
            end = body + _FIXED[code]
        elif code in (0x20, 0x21):
            end = body + 4 + _u32(raw, body)
            body += 4
        elif code >= 0x40:
            kind = types[code - 0x40] if code - 0x40 < len(types) else ""
        if end is None:
            return kind, start, None
        return kind, body, (end if end <= len(raw) else None)
    except _Broken:
        return "", start, None


def _container(raw: bytes) -> _Container:
    """Parse a ``.resources`` container the way .NET's ResourceReader walks it; ``_Broken`` when
    its header does not parse. An entry whose name or offset cannot be read is left out."""
    if raw[:4] != _RES_MAGIC:
        raise _Broken
    if _u32(raw, 4) > 1:
        pos = 12 + _u32(raw, 8)
    else:  # the reader's and the resource set's type names
        _, pos = _lstr(raw, 12)
        _, pos = _lstr(raw, pos)
    version, total, ntypes = _u32(raw, pos), _u32(raw, pos + 4), _u32(raw, pos + 8)
    pos += 12
    if version not in (1, 2) or ntypes > MAX_CONTAINER_TYPES or total > (len(raw) - pos) // 8:
        raise _Broken
    types = []
    for _ in range(ntypes):
        text, pos = _lstr(raw, pos)
        types.append(_name(text.split(b",")[0].strip()))
    table = ((pos + 7) & ~7) + 4 * total  # the name positions, after the name hashes
    names = table + 4 * total + 4
    base = _u32(raw, names - 4)
    if base > len(raw):
        raise _Broken
    unread = 1 if total > MAX_CONTAINER_ENTRIES else 0
    found: list[tuple[str, int]] = []
    for i in range(min(total, MAX_CONTAINER_ENTRIES)):
        try:
            text, at = _lstr(raw, names + _u32(raw, table + 4 * i))
            found.append((_name(text.decode("utf-16-le", "replace")), min(base + _u32(raw, at), len(raw))))
        except _Broken:
            unread = 1
    bounds = sorted({start for _, start in found} | {len(raw)})
    after = dict(zip(bounds, bounds[1:]))
    entries = []
    for name, start in found:
        kind, body, end = _extent(raw, start, version, types)
        stop = max(body, after.get(start, len(raw))) if end is None else end
        entries.append(_Entry(name, kind, start, body, stop, end is None))
    return _Container(total, base, entries, unread)


def _gaps(box: _Container, size: int) -> list[tuple[int, int]]:
    """The stretches of a container of at least ``MIN_PART`` bytes that no entry covers: in its
    data section, and everything before it when that alone could hold a payload."""
    out = [(0, box.base)] if box.base >= HIDDEN_MIN_BYTES else []
    cur = box.base
    for start, end in sorted({(e.start, e.end) for e in box.entries}):
        if start - cur >= MIN_PART:
            out.append((cur, start))
        cur = max(cur, end)
    if size - cur >= MIN_PART:
        out.append((cur, size))
    return out


def _open(dnfile: Any, *args: Any, **kwargs: Any) -> Any:
    """``dnfile.dnPE`` with every resource left as its bytes.

    dnfile parses each ``.resources`` container while it opens the assembly and lets some errors
    of a malformed one out, which cost the scan the whole assembly. The scanner reads containers
    itself (``_container``), so dnfile's parse is switched off for the call.
    """
    cls = getattr(getattr(dnfile, "resource", None), "InternalResource", None)
    parse = getattr(cls, "parse", None)
    if cls is None or parse is None:
        return dnfile.dnPE(*args, **kwargs)
    cls.parse = lambda self: None
    try:
        pe = dnfile.dnPE(*args, **kwargs)
        try:
            getattr(getattr(pe, "net", None), "resources", None)  # read now, while they stay bytes
        except Exception:
            pass
        return pe
    finally:
        cls.parse = parse


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


def _rest(raw: bytes, at: int) -> Callable[[], bytes]:
    return lambda: raw[at:]


class _Scan:
    """One scan's state: the hidden payloads found so far and the files written for them."""

    def __init__(self, outdir: Path | None, budget_s: float | None = None, since: float | None = None) -> None:
        self.hidden: list[dict[str, Any]] = []
        self.writer = _Writer(outdir)
        self.items_unread = 0  # see the module docstring: any of them may be a payload
        budget = SCAN_BUDGET_S if budget_s is None else budget_s
        start = time.monotonic() if since is None else since
        self._deadline = start + budget
        self._image_deadline = start + min(IMAGE_BUDGET_S, budget * 2 / 3)

    def image(self, data: bytes, wider: Callable[[], bytes] | None = None) -> tuple[Image | None, bytes]:
        """``data`` as an image, while the scan's image time budget lasts, and the bytes it was
        read from: ``wider()`` when the image's own headers say it runs past ``data``.

        An image of a kind the scanner reads that it did not read, for time or because it is over
        ``MAX_IMAGE_PIXELS``, is counted in ``items_unread``.
        """
        late = time.monotonic() >= self._image_deadline
        source = data
        try:
            try:
                image = _load_image(source, pixels=not late)
            except _Cut:
                if wider is None:
                    return None, data
                source = wider()
                image = _load_image(source, pixels=not late)
        except _TooLarge:
            self.items_unread += 1
            return None, data
        except _Cut:
            return None, data
        if late and image is not None:
            self.items_unread += 1
            return None, data
        return image, source

    def consider(self, data: bytes, ent: float | None, resource: str, entry: str | None, depth: int,
                 wider: Callable[[], bytes] | None = None) -> None:
        """Read one resource or entry for a hidden payload (``ent``: its entropy when the caller
        has it; ``wider``: the bytes from where it starts to the end of what holds it, for an
        entry whose end is only inferred). An item not read, or one that breaks a parser, is
        counted, never fatal."""
        if len(self.hidden) >= MAX_HIDDEN or time.monotonic() >= self._deadline:
            self.items_unread += 1
            return
        before = self.items_unread
        try:
            self._consider(data, entropy(data) if ent is None else ent, resource, entry, depth, wider)
        except Exception:  # a parser bug on hostile bytes costs this item, not the scan
            self.items_unread = before + 1  # once, whatever was counted before it broke

    def _consider(self, data: bytes, ent: float, resource: str, entry: str | None, depth: int,
                  wider: Callable[[], bytes] | None) -> None:
        """Read an item part by part: what an image or media file in it does not cover is read
        as a part of its own, so a picture in front does not excuse what follows it."""
        parts = [(data, ent, wider)]
        for done in range(MAX_PARTS + 1):
            if not parts:
                return
            if done == MAX_PARTS or len(self.hidden) >= MAX_HIDDEN:
                break
            part, bits, more = parts.pop(0)
            rest = self._part(part, bits, resource, entry, depth, more)
            parts += [(left, entropy(left), None) for left in rest if len(left) >= MIN_PART]
        self.items_unread += 1  # some of this item was not read

    def _part(self, data: bytes, ent: float, resource: str, entry: str | None, depth: int,
              wider: Callable[[], bytes] | None) -> list[bytes]:
        """Report ``data`` when it is a hidden payload; return the stretches of it still unread."""
        decoded = decode(data)
        image: Image | None = None
        rest: list[bytes] = []
        big = False
        if decoded is None:
            image, source = self.image(data, wider)
        if image is not None:
            rest = [image.slack]
            if len(source) > len(data):
                data = source[:image.end]  # the picture, not the part of it the offsets gave
                ent = entropy(data)
            else:
                rest.append(data[image.end:])
        elif decoded is None:
            end = media_extent(data)
            rest = [data[end:]] if end is not None else []
            big = end is None and len(data) >= HIDDEN_MIN_BYTES and ent >= HIDDEN_MIN_ENTROPY
        noise: float | None = None
        if image is not None:
            decoded = image_payload(image)
            noise = image_noise(image) if decoded is None else None
        if decoded is None and noise is None and not big:
            return rest
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
            return rest
        method, payload = decoded
        item["decoded"] = method
        if method != "plain":
            out = self.writer.write("decoded", payload)
            if out is not None:
                item["decoded_file"] = out
        self.stage(item, payload, depth)
        return rest

    def stage(self, item: dict[str, Any], payload: bytes, depth: int) -> None:
        """Describe a recovered PE and, when it is .NET, scan its own resources one level down."""
        try:
            import dnfile

            pe = _open(dnfile, data=payload)
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
        lost = _unreadable_rows(pe)
        self.items_unread += lost
        if doc is not None:
            doc["resources_total"] = len(resources) + lost
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
        if not isinstance(data, (bytes, bytearray)):
            data = getattr(data, "_data", None)  # a parser's object over the container's bytes
        if not isinstance(data, (bytes, bytearray)):
            raise _Broken  # one item unread, counted by the caller
        raw = bytes(data)
        box = None
        if raw.startswith(_RES_MAGIC):
            try:
                box = _container(raw)
            except _Broken:
                self.items_unread += 1  # read below as one blob, which is not reading its entries
        if box is None:
            ent = entropy(raw) if rows is not None else None
            if rows is not None and ent is not None:
                row: dict[str, Any] = {"name": name, "size": len(raw), "entropy": round(ent, 3), "container": False}
                fmt = media_format(raw)
                if fmt:
                    row["format"] = fmt
                rows.append(row)
            self.consider(raw, ent, name, None, depth)
            return
        self.items_unread += box.unread
        listed: list[dict[str, Any]] = []
        if rows is not None:
            rows.append({"name": name, "size": len(raw), "entropy": round(entropy(raw), 3), "container": True,
                         "entries_total": box.total, "entries": listed})
        seen: dict[tuple[int, int], tuple[int, float] | None] = {}  # entries at one place: read once
        for e in box.entries:
            key = (e.body, e.end)
            if key not in seen and time.monotonic() >= self._deadline:
                seen[key] = None  # not copied out of the container just to be counted
                self.items_unread += 1
            elif key not in seen:
                blob = raw[e.body:e.end]
                bits = entropy(blob)
                seen[key] = (len(blob), bits)
                if blob:
                    self.consider(blob, bits, name, e.name, depth, _rest(raw, e.body) if e.open else None)
            was = seen[key]
            if was is not None and rows is not None and len(listed) < MAX_ENTRIES:
                listed.append({"name": e.name, "size": was[0], "entropy": round(was[1], 3), "type": e.type})
        gaps = _gaps(box, len(raw))
        for lo, hi in gaps[:MAX_GAPS]:
            self.consider(raw[lo:hi], None, name, f"(bytes outside entries at {lo:#x})", depth)
        if len(gaps) > MAX_GAPS:
            self.items_unread += 1


def _close(pe: Any) -> None:
    try:
        pe.close()
    except Exception:
        pass


def _unreadable_rows(pe: Any) -> int:
    """How many embedded ManifestResource rows of ``pe`` dnfile gave no resource for: it drops,
    with only a warning, a row whose offset or size runs outside the file. A row of size 0 has
    nothing in it to read, and one kept in another file is not in this one."""
    try:
        net = pe.net
        base = net.struct.ResourcesRva
        if base <= 0:
            return 0  # no resources directory: nothing the runtime could read either
        rows = [row for row in net.mdtables.ManifestResource.rows if row.Implementation is None]
        empty = 0
        for row in rows:
            try:
                head = pe.get_data(base + row.Offset, 4)
            except Exception:
                continue
            empty += len(head) == 4 and not any(head)
        return max(0, len(rows) - len(net.resources or []) - empty)
    except Exception:  # no such table, or a fake of an assembly without one
        return 0


def scan(sample: Path, outdir: Path | None, budget_s: float | None = None,
         since: float | None = None) -> dict[str, Any]:
    """The resource document for ``sample`` (see the module docstring); never raises on bad input.

    ``budget_s`` is the time for reading items, counted from ``since`` (a ``time.monotonic()``
    value; default now). Past it items are counted unread, not read."""
    doc: dict[str, Any] = {"resources_total": 0, "resources": [], "loader_refs": [], "hidden": []}
    try:
        import dnfile  # the capa venv's hash-locked copy in the worker image
    except ImportError:
        doc["error"] = "dnfile_missing"
        return doc
    try:
        pe = _open(dnfile, str(sample))
    except Exception:  # dnfile/pefile raise many types on hostile input
        doc["error"] = "parse_failed"
        return doc
    try:
        if getattr(pe, "net", None) is None:
            doc["error"] = "not_dotnet"
            return doc
        doc["loader_refs"] = _loader_refs(pe)
        state = _Scan(outdir, budget_s, since)
        doc["hidden"] = state.hidden
        state.resources(pe, doc, "", 0)
        if state.items_unread:
            doc["items_unread"] = state.items_unread
    finally:
        _close(pe)
    return doc


def main(argv: list[str]) -> int:
    budget = None
    try:
        if len(argv) == 4:
            budget = float(argv[3])
        if len(argv) not in (3, 4) or (budget is not None and not 0 < budget < float("inf")):
            raise ValueError
    except ValueError:
        print("usage: dotnet_resources.py <sample> <outdir> [<seconds>]", file=sys.stderr)
        return 2
    outdir = Path(argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    sys.stdout.write(json.dumps(scan(Path(argv[1]), outdir, budget, _T0)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
