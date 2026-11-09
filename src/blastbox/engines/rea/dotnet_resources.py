""".NET ManifestResource scan for the sweep: what a decoy UI hides in its resources.

Live, .NET carriers (Formbook, NanoCore) were described by their visible app (an "air-traffic
simulator", a "weather utility") and even called benign, while the malware sat in a large
encrypted resource. This scan lists every embedded ManifestResource (name, size, Shannon
entropy; for a ``.resources`` container its entries with size, entropy and type), flags hidden
payloads and notes whether the managed code references the APIs that load one.

A resource or container entry is a hidden payload when either
- it is at least ``HIDDEN_MIN_BYTES`` with entropy at least ``HIDDEN_MIN_ENTROPY`` and is not a
  recognised media file. 7.2 bits/byte is the triage packer threshold: compressed or encrypted
  data sits at 7.9+, while code, text, string tables and uncompressed bitmaps sit well below 7;
  the observed Formbook blob was 7.69. 64 KiB keeps small compressed assets (icons, cursors,
  short gzip'd configs) out. Images (PNG/JPEG/GIF/ICO, also inside a serialized Bitmap) are
  high-entropy by nature and are skipped, which leaves steganographic bitmap carriers to the
  model (their size and type are still listed); or
- it is, or plainly decodes to, a PE (:func:`decode`: gzip, zlib, raw deflate, base64 or a
  single-byte XOR whose key turns the first byte into ``M``). Nothing further is tried.

THIS FILE RUNS AS A STANDALONE SCRIPT under the capa venv's python (which carries the
hash-locked ``dnfile`` already pinned for capa), as a bounded subprocess
(``runner.run_dotnet_resources``: ``ulimit -v``/``-f``, timeout, stdout cap), because dnfile
parses hostile metadata. It imports only the standard library and dnfile:
``python -I dotnet_resources.py <sample> <outdir>`` prints one JSON document and writes each
hidden payload (``hidden-<n>.bin``) and decoded PE (``decoded-<n>.bin``) into ``outdir``.

JSON: ``{"resources_total", "resources": [{"name", "size", "entropy", "container"[, "format"]
[, "entries_total", "entries": [{"name", "size", "entropy", "type"}]]}], "loader_refs": [...],
"hidden": [{"resource"[, "entry"], "size", "entropy"[, "file"][, "decoded", "decoded_file"]}]
[, "error"]}``. Counts, names and bytes written are capped.
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
import zlib
from collections import Counter
from pathlib import Path
from typing import Any

HIDDEN_MIN_BYTES = 64 * 1024
HIDDEN_MIN_ENTROPY = 7.2
MAX_RESOURCES = 64
MAX_ENTRIES = 64  # per .resources container
MAX_HIDDEN = 16
MAX_NAME = 200
MAX_ENTROPY_BYTES = 4 * 1024 * 1024
MAX_DECODED_BYTES = 64 * 1024 * 1024
MAX_WRITE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MIN_BASE64 = 64

# (type, member) pairs a resource-borne loader needs; rendered "Type.Member".
LOADER_MEMBERS = frozenset({
    ("Assembly", "Load"), ("Assembly", "LoadFrom"), ("Assembly", "LoadFile"), ("AppDomain", "Load"),
    ("Assembly", "GetManifestResourceStream"), ("Assembly", "get_EntryPoint"), ("MethodBase", "Invoke"),
    ("Type", "InvokeMember"), ("Activator", "CreateInstance"), ("ResourceManager", ".ctor"),
    ("ResourceManager", "GetObject"), ("SymmetricAlgorithm", "CreateDecryptor"),
    ("Convert", "FromBase64String"), ("GZipStream", ".ctor"), ("DeflateStream", ".ctor"),
})
_MEDIA = ((b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
          (b"\x00\x00\x01\x00", "ico"), (b"RIFF", "riff"), (b"wOFF", "woff"), (b"wOF2", "woff2"))
_B64 = re.compile(rb"[A-Za-z0-9+/=\r\n]+")


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


def _inflate(data: bytes, wbits: int) -> bytes | None:
    try:
        z = zlib.decompressobj(wbits)
        out = z.decompress(data, MAX_DECODED_BYTES + 1)
    except zlib.error:
        return None
    return out if len(out) <= MAX_DECODED_BYTES else None


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
    return None


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


def _consider(hidden: list[dict[str, Any]], writer: _Writer, data: bytes, ent: float, resource: str,
              entry: str | None) -> None:
    if len(hidden) >= MAX_HIDDEN:
        return
    decoded = decode(data)
    big = len(data) >= HIDDEN_MIN_BYTES and ent >= HIDDEN_MIN_ENTROPY and media_format(data) is None
    if decoded is None and not big:
        return
    item: dict[str, Any] = {"resource": resource, "size": len(data), "entropy": round(ent, 3)}
    if entry is not None:
        item["entry"] = entry
    raw = writer.write("hidden", data)
    if raw is not None:
        item["file"] = raw
    if decoded is not None:
        method, pe = decoded
        item["decoded"] = method
        if method != "plain":
            out = writer.write("decoded", pe)
            if out is not None:
                item["decoded_file"] = out
    hidden.append(item)


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
        try:
            resources = list(pe.net.resources or [])
        except Exception:
            resources = []
            doc["error"] = "resources_unreadable"
        doc["resources_total"] = len(resources)
        doc["loader_refs"] = _loader_refs(pe)
        writer = _Writer(outdir)
        for res in resources[:MAX_RESOURCES]:
            name = _name(getattr(res, "name", ""))
            data = getattr(res, "data", None)
            if isinstance(data, (bytes, bytearray)):
                raw = bytes(data)
                ent = entropy(raw)
                row: dict[str, Any] = {"name": name, "size": len(raw), "entropy": round(ent, 3),
                                       "container": False}
                fmt = media_format(raw)
                if fmt:
                    row["format"] = fmt
                doc["resources"].append(row)
                _consider(doc["hidden"], writer, raw, ent, name, None)
                continue
            entries = list(getattr(data, "entries", None) or [])
            size = getattr(res, "size", 0)
            row = {"name": name, "size": size if isinstance(size, int) else 0, "entropy": 0.0, "container": True,
                   "entries_total": len(entries), "entries": []}
            raw_container = getattr(data, "_data", b"")
            if isinstance(raw_container, (bytes, bytearray)):
                row["entropy"] = round(entropy(bytes(raw_container)), 3)
            for e in entries[:MAX_ENTRIES]:
                blob = _entry_bytes(e)
                ent = entropy(blob)
                ename = _name(getattr(e, "name", ""))
                row["entries"].append({"name": ename, "size": len(blob), "entropy": round(ent, 3),
                                       "type": _name(getattr(e, "type_name", "") or "")})
                _consider(doc["hidden"], writer, blob, ent, name, ename)
            doc["resources"].append(row)
    finally:
        try:
            pe.close()
        except Exception:
            pass
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
