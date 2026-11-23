"""Write stage.h for unpack.c: the encrypted next stage, shellcode and strings (benign fixture).

usage: python3 -I make_stage.py <stage.exe> <stage.h>

The stage is a benign PE (the REA fixture sample.exe). Everything is XORed with an xorshift32
keystream, so the stub's data section is high-entropy and the strings are not in the file.
Deterministic: same input, same header.
"""

import sys

SEED_STAGE = 0x1D872B41
SEED_SC = 0x7F4A7C15
SEED_STR = 0x2545F491
# x64: 48 nops, then mov eax, 42; ret. Executed from a fresh RX allocation.
SHELLCODE = b"\x90" * 48 + b"\xb8\x2a\x00\x00\x00\xc3"
STRINGS = {
    "URL": b"http://stage.loadout.example/next.bin\x00",
    "AGENT": b"LoadoutFixture/1.0\x00",
}


def keystream(seed: int, n: int) -> bytes:
    s, out = seed, bytearray()
    for _ in range(n):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        out.append(s & 0xFF)
    return bytes(out)


def enc(data: bytes, seed: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(seed, len(data))))


def carray(name: str, data: bytes) -> str:
    body = ",".join(str(b) for b in data)
    return f"static const unsigned char {name}[{len(data)}] = {{{body}}};\n#define {name.upper()}_LEN {len(data)}u\n"


def main() -> None:
    stage = open(sys.argv[1], "rb").read()
    out = [f"#define SEED_STAGE {SEED_STAGE:#x}u\n#define SEED_SC {SEED_SC:#x}u\n#define SEED_STR {SEED_STR:#x}u\n",
           carray("stage_enc", enc(stage, SEED_STAGE)), carray("sc_enc", enc(SHELLCODE, SEED_SC))]
    out += [carray(f"str_{k.lower()}", enc(v, SEED_STR)) for k, v in STRINGS.items()]
    open(sys.argv[2], "w").write("".join(out))


main()
