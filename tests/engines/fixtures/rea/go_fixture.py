"""A minimal Go-shaped ELF64 built from the real bytes of deploy/rea/corpus-build's benign_go.elf.

benign_go.elf (sha256 c7c6c885...eb02, ``go build -trimpath`` of hello.go, Go 1.23) packs its
string literals with no terminator. The windows below are copied byte for byte from it, at
their real virtual addresses, with their packed neighbours on both sides:

- ``http://loadout-go-fixture.example.org/ping`` (42 bytes) at 0x4b823d, followed by the
  strconv digits ``1734723475976807094411...``; static header ``{0x4b823d, 42}`` at 0x4d6700;
- ``198.51.100.23`` (13 bytes) at 0x4b22f5, followed by ``3814697265625wakeable...``; static
  header ``{0x4b22f5, 13}`` at 0x4d6710;
- ``hello loadout go %d\\n`` (20 bytes) at 0x4b3911, with no static header: main.main passes it
  to fmt.Printf as ``LEA RCX, [rip+0x227ac]; MOV EDI, 0x14`` at 0x49115e (real code bytes).
"""

from __future__ import annotations

import struct

URL = "http://loadout-go-fixture.example.org/ping"
IP = "198.51.100.23"
FORMAT = "hello loadout go %d\n"
# What the live G2 pass sealed as a "verified" IOC (2026-11-03), and the sweep-shaped variant.
URL_OVERRUN = URL + "1734723475976807094411"

WINDOWS = {  # virtual address of the window start -> real bytes (the literal starts 24 bytes in)
    0x4b823d - 24: b") failed to return pidfdhttp://loadout-go-fixture.example.org/ping"
                   b"173472347597680709441192448139",
    0x4b22f5 - 24: b"randautoseedtlsunsafeekm198.51.100.233814697265625wakeableSleepprofMemActive",
    0x4b3911 - 24: b"losedmultipartmaxheadershello loadout go %d\n37252902984619140625floating point error",
}
CODE_VA = 0x49115e
CODE = bytes.fromhex("488d0dac270200bf14000000488d74243841b8010000004d")

_TEXT = (0x1000, 0x491000, 0x200, 5)     # file off, va, size, flags R+X
_RODATA = (0x2000, 0x4b2000, 0x7000, 4)  # R
_DATA = (0x9000, 0x4d6000, 0x1000, 6)    # R+W


def go_elf(*, headers: bool = True, magic: bool = True) -> bytes:
    size = _DATA[0] + _DATA[2]
    buf = bytearray(size)
    buf[0:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", buf, 16, 2, 62, 1, CODE_VA, 0x40, 0, 0, 64, 56, 3, 64, 0, 0)
    for k, (off, va, n, flags) in enumerate((_TEXT, _RODATA, _DATA)):
        struct.pack_into("<IIQQQQQQ", buf, 0x40 + 56 * k, 1, flags, off, va, va, n, n, 0x1000)
    at = _TEXT[0] + CODE_VA - _TEXT[1]
    buf[at:at + len(CODE)] = CODE
    for va, data in WINDOWS.items():
        at = _RODATA[0] + va - _RODATA[1]
        buf[at:at + len(data)] = data
    if headers:
        struct.pack_into("<QQQQ", buf, _DATA[0] + 0x700, 0x4b823d, 42, 0x4b22f5, 13)
    if magic:
        buf[_DATA[0] + 0x800:_DATA[0] + 0x800 + 14] = b"\xff Go buildinf:"
    return bytes(buf)
