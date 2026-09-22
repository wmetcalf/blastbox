#!/usr/bin/env bash
# Install the firecracker binary (+ best-effort guest kernel) into ~/.local for
# LOCAL FC testing.  NO sudo — firecracker is a static binary; the only privilege
# it needs is /dev/kvm access (kvm group; see test-fc.sh).
#
# Honest caveat: a *guest kernel* URL drifts between firecracker releases. If the
# kernel download below fails, fetch one per the firecracker getting-started guide
# and point BLASTBOX_FC_KERNEL at it — or just run the FC test on toolz2, which
# already has firecracker + a kernel + KVM.
set -euo pipefail
DEST="${BLASTBOX_FC_HOME:-$HOME/.local/share/blastbox/fc}"
BIN_DIR="$HOME/.local/bin"
ARCH="$(uname -m)"   # expect x86_64
mkdir -p "$DEST" "$BIN_DIR"

echo ">> resolving latest firecracker release"
api="https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest"
ver="$(curl -fsSL "$api" | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | grep -oE 'v[0-9][^"]+')"
[[ -n "$ver" ]] || { echo "ERROR: could not resolve latest firecracker version"; exit 1; }
tgz="firecracker-${ver}-${ARCH}.tgz"
url="https://github.com/firecracker-microvm/firecracker/releases/download/${ver}/${tgz}"

echo ">> downloading $url"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$tgz"
tar -xzf "$tmp/$tgz" -C "$tmp"
install -m755 "$tmp/release-${ver}-${ARCH}/firecracker-${ver}-${ARCH}" "$BIN_DIR/firecracker"
echo ">> installed firecracker $ver -> $BIN_DIR/firecracker"
"$BIN_DIR/firecracker" --version 2>/dev/null | head -1 || true

# best-effort guest kernel; override with BLASTBOX_FC_KERNEL.
# Must be >= 5.18 (VMGenID) for the warm-SNAPSHOT tier: restoring a snapshot clones
# the base VM's kernel CRNG, and only a VMGenID-aware guest reseeds it on restore
# (otherwise restored clones can repeat random output). 5.10 is too old and the
# snapshot-runtime selector now refuses it; fetch a 6.1 CI kernel instead.
# THE QUICKSTART KERNEL IS NOT AN ACCEPTABLE FALLBACK, and it used to be the second
# entry in this list. That URL serves the 5.10 image from 2021, which is the kernel the
# paragraph above says the snapshot selector refuses -- and against a current firecracker
# (tested on v1.16.0) it does not merely lack VMGenID, it cannot boot at all:
#
#   VFS: Cannot open root device "vda" or unknown-block(0,0): error -6
#   Kernel panic - not syncing: VFS: Unable to mount root fs
#
# The microVM then dies in ~0.5 s, so the symptom an operator sees is "guest never
# signalled READY within 45s" from a test that looks like a blastbox bug. Measured
# 2026-09-22: the first URL below 404s (the drift this script's header warns about), the
# fallback quietly installed that 5.10 kernel, and every live FC test failed for a reason
# nothing in the output named. A missing kernel is a clear error; a kernel that panics is
# a wild goose chase.
kern="$DEST/vmlinux"
if [[ ! -s "$kern" ]]; then
  echo ">> fetching a guest kernel (>= 5.18 required for VMGenID)"
  for u in \
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/${ARCH}/vmlinux-6.1.128" \
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/${ARCH}/vmlinux-6.1.102" \
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${ARCH}/vmlinux-6.1.102" ; do
    if curl -fsSL "$u" -o "$kern" 2>/dev/null && [[ -s "$kern" ]]; then
      echo "   kernel -> $kern  (from $u)"; break
    fi
    rm -f "$kern"
  done
fi
# VERIFY WHAT IS ON DISK, whether we fetched it or found it already there: an operator who
# ran this script months ago has whatever the URLs served THEN.
if [[ -s "$kern" ]]; then
  kver="$(strings "$kern" 2>/dev/null | grep -oE 'Linux version [0-9]+\.[0-9]+' | head -1 | awk '{print $3}')"
  if [[ -n "$kver" ]]; then
    kmaj="${kver%%.*}"; kmin="${kver#*.}"
    if (( kmaj < 5 || (kmaj == 5 && kmin < 18) )); then
      echo "!! $kern is Linux $kver, which is too old: the warm-snapshot tier needs >= 5.18 for"
      echo "   VMGenID, and against a current firecracker it panics on boot (no root device),"
      echo "   which surfaces much later as 'guest never signalled READY'. Refusing to leave it"
      echo "   in place. Move it aside and re-run, or set BLASTBOX_FC_KERNEL to a 6.1 image."
      exit 1
    fi
    echo "   guest kernel: Linux $kver"
  fi
else
  echo "!! kernel download failed — every published URL 404'd (they drift between firecracker"
  echo "   releases). Fetch a >= 5.18 vmlinux per the firecracker getting-started guide and set"
  echo "   BLASTBOX_FC_KERNEL, or run the FC test on a host that already has one."
fi

echo
echo "Next:  scripts/test-fc.sh    # builds a blastbox probe rootfs + runs the live FC round-trip"
