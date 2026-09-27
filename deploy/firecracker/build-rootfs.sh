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
# The IMMUTABLE image this container was created from: the stamp must describe what was
# exported, and "$TAG" can be retagged by another build before the stamp step runs.
img_id="$("$DOCKER" inspect --format '{{.Image}}' "$cid")"

echo ">> export rootfs -> $rootdir"
"$DOCKER" export "$cid" | tar -x -C "$rootdir"

# STAMP it, as `blastbox build-images` does: the warm tiers check this file against their
# host and refuse a mismatched guest. Unstamped, the tier only warns and boots it -- and this
# script is the hotfix path, where host/guest drift is most likely. BLASTBOX_PY names a python
# that can import blastbox (default: python3).
echo ">> stamp rootfs (image provenance)"
PY="${BLASTBOX_PY:-python3}"
stamp_file="$rootdir/opt/blastbox/rootfs-stamp.json"
if "$PY" -c 'import blastbox.host.rootfs_stamp' 2>/dev/null; then
    # Never publish a stamp baked into the IMAGE: it would pass for this export's own.
    "$PY" -m blastbox.host.rootfs_stamp clear "$rootdir" \
        || { echo "!! refusing to package: could not clear a stamp baked into the image" >&2; exit 1; }
    # The source revision, marked "-dirty" (the same suffix `blastbox stamp` uses) when tracked
    # or untracked changes could have entered the image: a clean commit must not claim a build
    # it cannot reproduce.
    src_rev="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || true)"
    if [ -n "$src_rev" ] && [ -n "$(git -C "$REPO" status --porcelain --untracked-files=all 2>/dev/null)" ]; then
        src_rev="${src_rev}-dirty"
    fi
    # Verified by the FILE, not the exit status: a blastbox older than this CLI imports the
    # module and exits 0 having written nothing. A REFUSAL (an unverifiable guest) fails the
    # build: publishing it unstamped would boot it with no check at all.
    if ! "$PY" -m blastbox.host.rootfs_stamp write "$rootdir" "$img_id" firecracker "$src_rev" \
       || [ ! -s "$stamp_file" ]; then
        "$PY" -m blastbox.host.rootfs_stamp clear "$rootdir" || true
        echo "!! refusing to package: the rootfs could not be stamped (see above)." >&2
        exit 1
    fi
else
    # No importable blastbox: the documented fallback -- publish UNSTAMPED (the tiers warn and
    # boot it). Any stamp inherited from the image is still removed, without following a link
    # the image controls: every component on the path must be a real directory/file.
    for p in "$rootdir/opt" "$rootdir/opt/blastbox" "$stamp_file"; do
        if [ -L "$p" ]; then echo "!! refusing to package: $p is a symlink inside the image" >&2; exit 1; fi
    done
    if [ -e "$stamp_file" ] && [ ! -f "$stamp_file" ]; then
        echo "!! refusing to package: $stamp_file is not a regular file" >&2; exit 1
    fi
    rm -f -- "$stamp_file"
    echo "!! blastbox is not importable by $PY: the rootfs is published UNSTAMPED and will boot" >&2
    echo "!! unchecked against its host. Set BLASTBOX_PY, or rebuild with \`blastbox build-images\`." >&2
fi

echo ">> mke2fs -d (no mount, no root) -> $IMG (${SIZE_MIB} MiB)"
rm -f "$IMG"
truncate -s "${SIZE_MIB}M" "$IMG"
# -F force (regular file), -q quiet, -d populate from directory.
mkfs.ext4 -F -q -d "$rootdir" "$IMG"

echo ">> done: $IMG"
ls -lh "$IMG"
