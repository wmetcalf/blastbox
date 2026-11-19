#!/usr/bin/env python3
"""Create the model gateway's X25519 private key and print its public key.

    python3 keygen.py secret/gateway.key

Writes the private key (base64url, no padding, of 32 raw bytes) to the given path with mode
0400, refusing to overwrite an existing file, and prints ONLY the base64url public key: that
value is Loadout's ``LOADOUT_REA_GATEWAY_PUBKEY``. The private key is never printed. Needs
``cryptography``.
"""
from __future__ import annotations

import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: keygen.py PRIVATE_KEY_PATH", file=sys.stderr)
        return 2
    path = argv[1]
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except FileExistsError:
        print(f"refusing to overwrite {path}", file=sys.stderr)
        return 1
    with os.fdopen(fd, "w") as fh:
        fh.write(b64u(raw) + "\n")
    print(b64u(pub))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
