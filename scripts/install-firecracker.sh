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

# best-effort guest kernel; override with BLASTBOX_FC_KERNEL
kern="$DEST/vmlinux"
if [[ ! -s "$kern" ]]; then
  echo ">> fetching a guest kernel (best-effort)"
  for u in \
    "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/${ARCH}/vmlinux-5.10.bin" \
    "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${ARCH}/kernels/vmlinux.bin" ; do
    if curl -fsSL "$u" -o "$kern" 2>/dev/null && [[ -s "$kern" ]]; then
      echo "   kernel -> $kern  (from $u)"; break
    fi
  done
  [[ -s "$kern" ]] || echo "!! kernel download failed — set BLASTBOX_FC_KERNEL to a firecracker-compatible vmlinux (see firecracker getting-started), or run the FC test on toolz2."
fi

echo
echo "Next:  scripts/test-fc.sh    # builds a blastbox probe rootfs + runs the live FC round-trip"
