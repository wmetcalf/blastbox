#!/usr/bin/env python3
"""Rebuild the D4 golden tar with tarfile, byte for byte (USTAR, sorted, mode 0644, uid/gid 0,
no names, mtime 0, no dirs, two zero end blocks and NO record padding). Prints sha256."""
import hashlib, tarfile, io
tree = {
    "metadata.json": b'{"a":1}',
    "art/z.bin": b"zz",
    "art/a.txt": b"hello\n",
    "B.txt": b"",
    "deep/er/path/f": b"x" * 1000,
    "a-" + "n" * 90 + "/" + "m" * 90: b"split into ustar prefix",
}
out = bytearray()
for name in sorted(tree, key=lambda s: s.encode()):
    data = tree[name]
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname, ti.mtime = len(data), 0o644, 0, 0, "", "", 0
    ti.type = tarfile.REGTYPE
    h = bytearray(ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape"))
    # Go's archive/tar always writes devmajor/minor as "0000000\0"; newer tarfile leaves them
    # NUL for regular files. Pin the Go spelling, then recompute the checksum.
    h[329:337] = b"0000000\0"; h[337:345] = b"0000000\0"
    h[148:156] = b"        "
    h[148:156] = b"%06o\0 " % sum(h)
    out += h
    out += data + b"\0" * (-len(data) % 512)
out += b"\0" * 1024
import sys
open(sys.argv[1],"wb").write(bytes(out)) if len(sys.argv)>1 else print(hashlib.sha256(bytes(out)).hexdigest())
