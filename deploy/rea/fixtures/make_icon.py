"""Write a deterministic 16x16 32-bpp .ico (stdlib only) for the PE fixture.

The pattern is a green border with a diagonal, so a decoded icon is visibly
non-blank and an icon perceptual hash has some structure to work with.
"""

import struct
import sys

SIZE = 16


def pixel(x: int, y: int) -> bytes:
    if x in (0, SIZE - 1) or y in (0, SIZE - 1):
        return bytes((0x77, 0xFF, 0x22, 0xFF))  # BGRA phosphor green
    if x == y or x == SIZE - 1 - y:
        return bytes((0xE5, 0xFF, 0xD9, 0xFF))
    return bytes((0x03, 0x04, 0x02, 0xFF))


def build() -> bytes:
    # BMP rows are stored bottom-up; the AND mask is all zero (fully opaque).
    xor = b"".join(pixel(x, y) for y in reversed(range(SIZE)) for x in range(SIZE))
    and_mask = bytes(4 * SIZE)  # 16 bits per row padded to 32 bits
    header = struct.pack(
        "<IiiHHIIiiII",
        40,
        SIZE,
        SIZE * 2,
        1,
        32,
        0,
        len(xor) + len(and_mask),
        0,
        0,
        0,
        0,
    )
    image = header + xor + and_mask
    icondir = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", SIZE, SIZE, 0, 0, 1, 32, len(image), 6 + 16)
    return icondir + entry + image


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as fh:
        fh.write(build())
