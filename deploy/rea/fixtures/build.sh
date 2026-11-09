#!/bin/sh
# Rebuild the REA fixtures (sample.exe, sample.elf, installer.exe) from the sources here.
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
# installer.exe: a benign NSIS installer around sample.exe (installer.nsi says why each member).
cp "$src/installer.nsi" "$out/sample.exe" "$work/"
mv sample.exe payload.exe
cp payload.exe helper.dll && head -c 262144 /dev/zero >> helper.dll
printf 'Loadout REA fixture.\n' > readme.txt
makensis -V2 -NOCD installer.nsi && mv installer.exe "$out/installer.exe"
cd "$out" && rm -rf "$work"
sha256sum sample.exe sample.elf installer.exe
