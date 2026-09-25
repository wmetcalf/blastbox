#!/usr/bin/env bash
# Build a blastbox FC worker rootfs (ext4) from the Docker image.
#
# No mount, no root: we `docker export` the image to a directory and let
# `mke2fs -d` populate the ext4 image directly — mirroring the host-side rdump
# discipline (never mount an untrusted/handled disk).
#
# Usage:  deploy/firecracker/build-rootfs.sh [output.ext4]
# Env:    ROOTFS_MIB (default 768)   DOCKER (default: docker)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
IMG="${1:-$HERE/rootfs.ext4}"
SIZE_MIB="${ROOTFS_MIB:-1024}"
DOCKER="${DOCKER:-docker}"
ENGINE="${ENGINE:-probe}"   # probe | pdf | pdfrasterize — baked into the rootfs
DOCKERFILE="${DOCKERFILE:-deploy/firecracker/Dockerfile.worker}"
TAG="blastbox-fc-worker:${ENGINE}"

command -v mkfs.ext4 >/dev/null || { echo "need mkfs.ext4 (e2fsprogs)"; exit 1; }
command -v truncate  >/dev/null || { echo "need truncate (coreutils)"; exit 1; }

cd "$REPO"
echo ">> docker build $TAG (engine=$ENGINE, dockerfile=$DOCKERFILE)"
build_args="--build-arg ENGINE=$ENGINE"
[ -n "${BASE_IMAGE:-}" ] && build_args="$build_args --build-arg BASE_IMAGE=$BASE_IMAGE"
# shellcheck disable=SC2086
"$DOCKER" build $build_args -f "$DOCKERFILE" -t "$TAG" .

# Hardening audit: the rootfs must have NO setuid/setgid binaries.
echo ">> audit: setuid/setgid binaries (expect none)"
suid="$("$DOCKER" run --rm --entrypoint find "$TAG" / -xdev -type f -perm /6000 2>/dev/null || true)"
if [ -n "$suid" ]; then
    echo "!! setuid/setgid binaries remain in the rootfs:" >&2
    echo "$suid" >&2
    exit 1
fi
echo "   clean — no setuid/setgid binaries"

cid="$("$DOCKER" create "$TAG")"
rootdir="$(mktemp -d)"
cleanup() { "$DOCKER" rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$rootdir"; }
trap cleanup EXIT

echo ">> export rootfs -> $rootdir"
"$DOCKER" export "$cid" | tar -x -C "$rootdir"

# STAMP it, as `blastbox build-images` does: the warm tiers check this file against their
# host and refuse a mismatched guest. Unstamped, the tier only warns and boots it -- and this
# script is the hotfix path, where host/guest drift is most likely. BLASTBOX_PY names a python
# that can import blastbox (default: python3).
echo ">> stamp rootfs (image provenance)"
# Verified by the FILE, not the exit status: a blastbox older than this CLI imports the module
# and exits 0 having written nothing.
if ! "${BLASTBOX_PY:-python3}" -m blastbox.host.rootfs_stamp write "$rootdir" "$TAG" firecracker \
   || [ ! -s "$rootdir/opt/blastbox/rootfs-stamp.json" ]; then
    echo "!! could not stamp the rootfs (is blastbox importable by ${BLASTBOX_PY:-python3}?)." >&2
    echo "!! It will boot UNCHECKED against its host; rebuild with \`blastbox build-images\`." >&2
fi

echo ">> mke2fs -d (no mount, no root) -> $IMG (${SIZE_MIB} MiB)"
rm -f "$IMG"
truncate -s "${SIZE_MIB}M" "$IMG"
# -F force (regular file), -q quiet, -d populate from directory.
mkfs.ext4 -F -q -d "$rootdir" "$IMG"

echo ">> done: $IMG"
ls -lh "$IMG"
