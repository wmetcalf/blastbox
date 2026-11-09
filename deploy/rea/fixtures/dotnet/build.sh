#!/bin/sh
# Rebuild deploy/rea/fixtures/dotnet.dll (benign; see Program.cs and make_resources.py).
# The SDK image has no python, so the resources are generated first, on any host:
#   python3 -I deploy/rea/fixtures/dotnet/make_resources.py deploy/rea/fixtures/sample.exe <gen>
#   docker run --rm --network none -v "$PWD/deploy/rea/fixtures:/fx" -v "<gen>:/gen:ro" \
#     mcr.microsoft.com/dotnet/sdk@sha256:341aa6e8bbaceb1194732328ca27c15bfa9c531687db83a66af3c0c1833f5534 \
#     sh /fx/dotnet/build.sh /fx /gen
set -eu
fx=$1
gen=$2
work=$(mktemp -d)
cp "$fx/dotnet/Program.cs" "$fx/dotnet/fixture.csproj" "$work/"
cp -r "$gen" "$work/gen"
cd "$work"
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet build -c Release -o out --nologo -v q
cp out/fixture.dll "$fx/dotnet.dll"
cd / && rm -rf "$work"
sha256sum "$fx/dotnet.dll"
