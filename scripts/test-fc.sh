#!/usr/bin/env bash
# blastbox local tests — TIER 2 (Firecracker): real-microVM warm round-trip.
#
# This is the ONLY test that exercises a real guest decoding the host's *streamed*
# input frame (send_frame_from_file) — a wire-format change won't show up in the
# mocked unit tests. It boots a real microVM, warms it, streams a fixture in, and
# asserts the host-re-sealed metadata.json is trust-validated.
#
# NO sudo IF you can access /dev/kvm: firecracker is a KVM hypervisor, NOT a userns
# sandbox, so Ubuntu 24.04's apparmor_restrict_unprivileged_userns does NOT apply.
# Grant access once with:  sudo usermod -aG kvm "$USER"  (then re-login). Otherwise
# this script falls back to sudo. Easiest of all: run it on toolz2 (FC + kernel + KVM
# already present) — `ENGINE=probe deploy/firecracker/build-rootfs.sh` there too.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
VENV="$REPO/.venv"
FCHOME="${BLASTBOX_FC_HOME:-$HOME/.local/share/blastbox/fc}"

# --- firecracker binary + guest kernel ----------------------------------
FC_BIN="${BLASTBOX_FC_BIN:-$(command -v firecracker || true)}"
[[ -x "$FC_BIN" ]] || FC_BIN="$HOME/.local/bin/firecracker"
if [[ ! -x "$FC_BIN" ]]; then
  echo ">> firecracker not found — running scripts/install-firecracker.sh"
  "$REPO/scripts/install-firecracker.sh"
  FC_BIN="$HOME/.local/bin/firecracker"
fi
KERNEL="${BLASTBOX_FC_KERNEL:-$FCHOME/vmlinux}"
[[ -s "$KERNEL" ]] || { echo "ERROR: no guest kernel. Set BLASTBOX_FC_KERNEL=/path/to/vmlinux (see install-firecracker.sh)."; exit 1; }

if [[ ! -x "$VENV/bin/pytest" ]]; then
  python3 -m venv "$VENV"; "$VENV/bin/pip" install -q -e ".[dev]"
fi

# --- build a blastbox-format probe rootfs (no root: mke2fs -d) -----------
DOCKER=docker
docker info >/dev/null 2>&1 || DOCKER="sudo docker"
ROOTFS="${BLASTBOX_FC_ROOTFS:-$FCHOME/blastbox-probe-rootfs.ext4}"
echo ">> building blastbox-format probe rootfs -> $ROOTFS"
ENGINE=probe DOCKER="$DOCKER" "$REPO/deploy/firecracker/build-rootfs.sh" "$ROOTFS"

# --- run the live round-trip (no sudo if /dev/kvm is accessible) ---------
SEL='-k FirecrackerLiveBoot'
TEST="tests/host/runtime/test_firecracker.py"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  echo ">> /dev/kvm accessible — running WITHOUT sudo"
  env BLASTBOX_FC_BIN="$FC_BIN" BLASTBOX_FC_KERNEL="$KERNEL" BLASTBOX_FC_ROOTFS="$ROOTFS" \
    "$VENV/bin/pytest" "$TEST" -v $SEL "$@"
else
  echo ">> /dev/kvm not accessible to you — running under sudo (or: sudo usermod -aG kvm $USER; re-login)"
  sudo -E env BLASTBOX_FC_BIN="$FC_BIN" BLASTBOX_FC_KERNEL="$KERNEL" BLASTBOX_FC_ROOTFS="$ROOTFS" \
    "$VENV/bin/pytest" "$TEST" -v $SEL "$@"
fi
