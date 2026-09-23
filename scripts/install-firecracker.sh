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

# Guest kernel: selected, fetched and VERIFIED by scripts/lib/fc-kernel.sh (a function so it
# can be tested on its own -- see that file for why it needed to be).
# shellcheck source=lib/fc-kernel.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/fc-kernel.sh"
fc_kernel_setup

echo
echo "Next:  scripts/test-fc.sh    # builds a blastbox probe rootfs + runs the live FC round-trip"
