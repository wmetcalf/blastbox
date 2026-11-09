"""Generate the dotnet fixture's embedded resources (deterministic; stdlib only).

usage: python3 -I make_resources.py <sample.exe> <outdir>

blob.bin            72 KiB of hash-chain bytes: a high-entropy raw resource (hidden payload)
payload.gz          gzip of sample.exe: decodes to a PE
x.dat               sample.exe's first 1 KiB (its headers) XOR 0x5A: decodes to a PE header
b64.txt             base64 of the same 1 KiB: decodes to a PE header
logo.png            a PNG signature + 80 KiB of hash-chain bytes: high entropy, but media
Resources.resources a v2 .resources container: "AppTitle" (string), "Blob" (66 KiB byte[] of
                    hash-chain bytes, a hidden payload) and "Pad" (2 KiB of zeros, byte[])
"""

import base64
import gzip
import hashlib
import struct
import sys
from pathlib import Path


def chain(seed: bytes, n: int) -> bytes:
    out = bytearray()
    h = seed
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:n])


def enc7(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def sstr(s: str) -> bytes:
    b = s.encode()
    return enc7(len(b)) + b


def name_hash(name: str) -> int:
    h = 5381
    for ch in name:
        h = (((h << 5) + h) ^ ord(ch)) & 0xFFFFFFFF
    return h


def resources(entries: list[tuple[str, int, bytes]]) -> bytes:
    """A v2 ResourceReader file: (name, type code, encoded value)."""
    reader = sstr("System.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, "
                  "PublicKeyToken=b77a5c561934e089") + sstr("System.Resources.RuntimeResourceSet")
    head = struct.pack("<III", 0xBEEFCACE, 1, len(reader)) + reader
    head += struct.pack("<III", 2, len(entries), 0)
    head += b"PAD"[: (-len(head)) % 8].ljust((-len(head)) % 8, b"P")
    data = bytearray()
    names = bytearray()
    rows = []
    for name, code, value in entries:
        rows.append((name_hash(name), len(names)))
        nb = name.encode("utf-16-le")
        names += enc7(len(nb)) + nb + struct.pack("<I", len(data))
        data += enc7(code) + value
    order = sorted(range(len(rows)), key=lambda i: rows[i][0])
    head += b"".join(struct.pack("<I", rows[i][0]) for i in order)
    head += b"".join(struct.pack("<I", rows[i][1]) for i in order)
    data_off = len(head) + 4 + len(names)
    return head + struct.pack("<I", data_off) + bytes(names) + bytes(data)


def main() -> None:
    sample, out = Path(sys.argv[1]).read_bytes(), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    (out / "blob.bin").write_bytes(chain(b"blob", 72 * 1024))
    (out / "payload.gz").write_bytes(gzip.compress(sample, mtime=0))
    (out / "x.dat").write_bytes(bytes(b ^ 0x5A for b in sample[:1024]))
    (out / "b64.txt").write_bytes(base64.b64encode(sample[:1024]))
    (out / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + chain(b"png", 80 * 1024))
    blob = chain(b"res", 66 * 1024)
    (out / "Resources.resources").write_bytes(resources([
        ("AppTitle", 0x01, sstr("Air Traffic Simulator")),
        ("Blob", 0x20, struct.pack("<I", len(blob)) + blob),
        ("Pad", 0x20, struct.pack("<I", 2048) + b"\x00" * 2048),
    ]))


if __name__ == "__main__":
    main()
