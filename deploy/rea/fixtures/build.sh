#!/bin/sh
# Rebuild the REA fixtures (sample.exe, sample.elf) from the sources here.
# Run it through the Dockerfile's `rea-fixtures` stage so the toolchain matches
# the one that produced the committed binaries:
#   docker build -f deploy/docker/Dockerfile.rea-cold-worker --target rea-fixtures \
#     --output type=local,dest=<dir> .
# Reproducibility: fixed build dir, no PE link timestamp, no debug info.
# Symbols are kept so Ghidra can find `main`.
# usage: build.sh <outdir>
set -eu
src=$(cd "$(dirname "$0")" && pwd)
out=$1
work="$out/.build"
rm -rf "$work" && mkdir -p "$work"
cp "$src/hello.c" "$src/sample.rc" "$work/"
python3 -I "$src/make_icon.py" "$work/sample.ico"
cd "$work"
x86_64-w64-mingw32-windres -O coff -o sample.res.o sample.rc
x86_64-w64-mingw32-gcc -O2 -Wl,-S -Wl,--no-insert-timestamp -o "$out/sample.exe" hello.c sample.res.o
gcc -O2 -Wl,-S -o "$out/sample.elf" hello.c
cd "$out" && rm -rf "$work"
sha256sum sample.exe sample.elf
