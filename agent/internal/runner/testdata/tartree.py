#!/usr/bin/env python3
"""Build the writer tar for a JSON tree {name: hex body} given on stdin, exactly as
scripts/gen_conformance.py go_writer_tar does (USTAR), and print its sha256. A name USTAR
cannot hold gets tarfile's PAX form instead (a path record, then the USTAR header), with the
same devmajor/devminor pinning in both headers."""
import hashlib, json, sys, tarfile


def pin(h):
    h[329:337] = b"0000000\0"; h[337:345] = b"0000000\0"
    h[148:156] = b"        "
    h[148:156] = b"%06o\0 " % sum(h)


tree = {k: bytes.fromhex(v) for k, v in json.load(sys.stdin).items()}
out = bytearray()
for name in sorted(tree, key=lambda s: s.encode()):
    data = tree[name]
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname, ti.mtime = len(data), 0o644, 0, 0, "", "", 0
    ti.type = tarfile.REGTYPE
    try:
        h = bytearray(ti.tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape"))
        pin(h)
    except ValueError:
        h = bytearray(ti.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
        first, last = h[:512], h[-512:]
        pin(first); pin(last)
        h = first + h[512:-512] + last
    out += h
    out += data + b"\0" * (-len(data) % 512)
out += b"\0" * 1024
print(hashlib.sha256(bytes(out)).hexdigest())
