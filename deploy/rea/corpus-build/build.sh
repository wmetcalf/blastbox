#!/bin/sh
# Benign corpus builder for the REA gate (deploy/rea/CORPUS.md). Copy this directory to
# ~/rea-build/t8/build on the docker host and run it there; samples land in ~/rea-build/t8/samples.
# benign_pe.exe must already be in the samples dir (cp ../fixtures/sample.exe samples/benign_pe.exe).
# Needs network for the toolchain images (golang, dotnet/sdk, ubuntu:22.04, debian:bookworm).
set -eux
B=$HOME/rea-build/t8/build; S=$HOME/rea-build/t8/samples; mkdir -p "$S"
# Go (static, symbols kept for Go build-info)
[ -f "$S/benign_go.elf" ] || docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -e GOCACHE=/tmp/gc -e GOPATH=/tmp/gp -e CGO_ENABLED=0 -v "$B":/b -w /b golang:1.23-bookworm \
  sh -c 'go mod init loadout/fixture >/dev/null 2>&1 || true; go build -trimpath -o /b/out-go hello.go'
cp "$B/out-go" "$S/benign_go.elf"
# .NET class library
rm -rf "$B/dn"; mkdir -p "$B/dn"; cp "$B/Fixture.cs" "$B/Fixture.csproj" "$B/dn/"
docker run --rm -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -v "$B/dn":/b -w /b mcr.microsoft.com/dotnet/sdk:8.0 \
  sh -c 'dotnet build -c Release -o /b/out && chown -R '$(id -u):$(id -g)' /b'
cp "$B/dn/out/LoadoutFixture.dll" "$S/benign_dotnet.dll"
# APK (Ubuntu jammy packaged Android build tools; platform 23 android.jar)
docker run --rm -v "$B/apk":/b -w /b ubuntu:22.04 sh -c '
  set -eux; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    aapt zipalign apksigner dalvik-exchange android-sdk-platform-23 default-jdk-headless >/dev/null
  J=/usr/lib/android-sdk/platforms/android-23/android.jar
  rm -rf obj bin; mkdir -p obj bin
  javac -source 8 -target 8 -bootclasspath $J -d obj src/org/loadout/fixture/Main.java
  dalvik-exchange --dex --output=bin/classes.dex obj
  aapt package -f -M AndroidManifest.xml -I $J -F bin/unsigned.apk
  (cd bin && aapt add unsigned.apk classes.dex)
  zipalign -f 4 bin/unsigned.apk bin/aligned.apk
  keytool -genkeypair -keystore bin/k.jks -storepass loadout -keypass loadout -alias fx -keyalg RSA -keysize 2048 \
    -validity 3650 -dname "CN=Loadout Fixture" >/dev/null 2>&1
  apksigner sign --ks bin/k.jks --ks-pass pass:loadout --key-pass pass:loadout --out bin/fixture.apk bin/aligned.apk
  apksigner verify --print-certs bin/fixture.apk | head -3
  chown -R '$(id -u):$(id -g)' /b'
cp "$B/apk/bin/fixture.apk" "$S/benign.apk"
# ZIP, password ZIP (ZipCrypto, password "infected"), truncated PE
python3 - "$S" <<'PY'
import sys, zipfile, os
s = sys.argv[1]
readme = b"Benign Loadout REA fixture archive.\nSee http://loadout-zip-fixture.example.org/readme and 203.0.113.7\n"
with zipfile.ZipFile(os.path.join(s, "benign.zip"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("readme.txt", readme)
    z.write(os.path.join(s, "benign_pe.exe"), "bin/hello.exe")
pe = open(os.path.join(s, "benign_pe.exe"), "rb").read()
open(os.path.join(s, "truncated_pe.exe"), "wb").write(pe[:20000])
PY
docker run --rm -v "$S":/s -w /tmp debian:bookworm sh -c '
  set -eux; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends zip >/dev/null
  mkdir -p m && printf "Benign protected member. http://loadout-pzip-fixture.example.org/x\n" > m/secret.txt && cp /s/benign_pe.exe m/hello.exe
  (cd m && zip -q -P infected /s/protected.zip secret.txt hello.exe)
  chown '$(id -u):$(id -g)' /s/protected.zip'
ls -la "$S"; sha256sum "$S"/*
