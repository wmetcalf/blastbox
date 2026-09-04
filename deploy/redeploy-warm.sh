#!/usr/bin/env bash
#
# ============================================================================
# THE REBUILD/EXPORT HALF OF THIS SCRIPT IS SUPERSEDED -- AND NOW REFUSES TO
# RUN UNLESS YOU ASK FOR IT BY NAME.
#
# Every adopter engine declares its image chain in `blastbox-images.toml` and
# builds it with:
#
#     blastbox build-images <repo> --tag <tag>        # --dry-run to inspect
#
# That replaces steps 3-4 (rootfs build + staged swap). It stamps and VERIFIES
# every image before exporting, checks the rootfs contains what the engine
# declares it needs, refuses to publish a sandbox rootfs carrying setuid
# binaries, takes a per-destination lock so a concurrent run cannot corrupt the
# swap, and KEEPS THE SIZE ALREADY IN PLACE unless explicitly overridden.
#
# What `build-images` does NOT do, and why this file still exists:
#
#   * It does not check out a blastbox ref or force-install a dev wheel over
#     the engine's shipped blastbox (steps 1-2). For an UNRELEASED hotfix --
#     a fix branch not yet on PyPI -- that derivation is still the way in, so
#     it is kept behind REDEPLOY_MODE=legacy-rebuild. For a released blastbox,
#     bump the engine's pin and use `build-images`.
#   * It does not swap the Firecracker BINARY. The image plan covers images and
#     rootfs artifacts only, so FC_BIN_SRC is handled here, in BOTH modes.
#   * It does not touch compose. Steps 5-6 (.env image vars, recreate, smoke)
#     and the rollback block are not superseded.
#
# MODES
#
#   REDEPLOY_MODE=recreate        (default) steps 5-6 + the optional FC binary
#                                 swap. Assumes the images and rootfs are
#                                 already published by `blastbox build-images`.
#   REDEPLOY_MODE=legacy-rebuild  the original steps 1-6. Explicit opt-in.
#   REDEPLOY_CHECK_ONLY=1         validate mode + presets + guards, print the
#                                 plan, change nothing.
#
# The presets in this file have DRIFTED from what is deployed:
#
#     redtusk    ROOTFS_MIB=1024   live: 1536 (toolz2), 3072 (toolz3)
#     clippyshot ROOTFS_MIB=7000   live: 6144 (both hosts)
#
# Running the redtusk preset as written would SHRINK that rootfs by 512 MiB on
# toolz2 and 2 GiB on toolz3. A comment does not stop that, so legacy-rebuild
# now measures the live artifact and refuses to shrink it unless the operator
# sets ALLOW_ROOTFS_SHRINK=1.
# ============================================================================
#
# Redeploy an adopter engine's blastbox.host stack onto a patched blastbox,
# rebuilding BOTH warm-snapshot worker rootfs (Firecracker + gVisor) so a
# blastbox fix (e.g. the warm-tier restore clock-jump) actually reaches the
# warm workers — not just the dispatcher image.
#
# This captures, reproducibly, the chain that was run by hand for the RedTusk and
# ClippyShot stacks on toolz2 during the 2026-06-19 warm-tier-outage fix:
#
#   1. build a blastbox wheel from a git ref (the fix branch / a tag),
#   2. derive <image>:warmfix from the live :dev images by force-reinstalling that
#      wheel over whatever blastbox they shipped (PyPI/older),
#   3. rebuild the FC rootfs (build-rootfs.sh; installs blastbox from THIS repo's
#      source, so check out the same ref here) and the gVisor rootfs
#      (Dockerfile.shim, which inherits blastbox from <image>:warmfix),
#   4. stage both rootfs + the patched firecracker binary with .bak-<suffix>,
#   5. bump the compose .env image vars + recreate the api/dispatchers (NOT pg),
#   6. smoke a benign job and confirm a warm tier returns status=done.
#
# Everything is reversible: see the printed ROLLBACK block at the end.
#
# Usage:  ENGINE=clippyshot ./deploy/redeploy-warm.sh         (reads the preset below)
#         ENGINE=redtusk    ./deploy/redeploy-warm.sh
#         ...or export every VAR yourself and run with ENGINE=custom.
#
# Run it ON the deploy host (toolz2), from the blastbox repo root, with docker +
# (for the gVisor rootfs export) passwordless sudo for `tar -x`/`mv` of root-owned
# rootfs files. NOTHING runs against production until the recreate step; the build
# + stage steps only produce *.warmfix artifacts alongside the live ones.
set -euo pipefail

ENGINE="${ENGINE:?set ENGINE=clippyshot|redtusk|custom}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# --- per-engine presets (the values verified on toolz2 2026-06-19) -------------
case "$ENGINE" in
  clippyshot)
    : "${BLASTBOX_REF:=fix/fc-warm-entropy}"
    : "${BASE_IMAGE:=clippyshot:dev}"        ; : "${COLD_IMAGE:=clippyshot-cold-worker:dev}"
    : "${WARM_TAG:=warmfix}"
    : "${VENV_PIP:=/opt/clippyshot/bin/pip}" ; : "${VENV_PY:=/opt/clippyshot/bin/python}"
    : "${IMG_USER:=clippy}"
    : "${FC_DOCKERFILE:=deploy/firecracker/Dockerfile.clippyshot}" ; : "${ROOTFS_MIB:=7000}"
    : "${FC_DIR:=/home/coz/clippyshot-fc}"   ; : "${GVISOR_DIR:=/home/coz/clippyshot-gvisor}"
    : "${SHIM_BASE:=clippyshot:dev}"          # Dockerfile.shim --build-arg BASE (we pass :warmfix)
    : "${COMPOSE_DIR:=/home/coz/clippyshot/deploy/docker}"
    : "${COMPOSE_WRAPPER:=./clippyshot-compose}"
    : "${COMPOSE_FILES:=-f docker-compose.yml -f docker-compose.firecracker.yml -f docker-compose.gvisor.yml}"
    : "${IMAGE_ENV:=CLIPPYSHOT_IMAGE}"       ; : "${WORKER_IMAGE_ENV:=CLIPPYSHOT_WORKER_IMAGE}"
    : "${API_URL:=http://127.0.0.1:8001}"    ; : "${SMOKE_FILE:=}"
    ;;
  redtusk)
    : "${BLASTBOX_REF:=fix/fc-warm-entropy}"
    : "${BASE_IMAGE:=redtusk:0115}"          ; : "${COLD_IMAGE:=redtusk-cold-worker:0122}"
    : "${WARM_TAG:=warmfix}"
    : "${VENV_PIP:=/opt/redtusk/bin/pip}"    ; : "${VENV_PY:=/opt/redtusk/bin/python}"
    : "${IMG_USER:=10001:10001}"
    : "${FC_DOCKERFILE:=deploy/firecracker/Dockerfile.redtusk}" ; : "${ROOTFS_MIB:=1024}"
    : "${FC_DIR:=/home/coz/redtusk-bb-fc}"   ; : "${GVISOR_DIR:=/var/lib/redtusk-gvisor}"
    : "${SHIM_BASE:=redtusk:0115}"
    : "${COMPOSE_DIR:=/home/coz/redtusk-bb/deploy/docker}"
    : "${COMPOSE_WRAPPER:=docker compose}"
    : "${COMPOSE_FILES:=-f docker-compose.yml -f docker-compose.firecracker.yml -f docker-compose.gvisor.yml}"
    : "${IMAGE_ENV:=REDTUSK_IMAGE}"          ; : "${WORKER_IMAGE_ENV:=REDTUSK_WORKER_IMAGE}"
    : "${API_URL:=http://127.0.0.1:8003}"    ; : "${SMOKE_FILE:=}"
    ;;
  custom) : ;;   # require the caller to export every VAR
  *) echo "unknown ENGINE=$ENGINE (clippyshot|redtusk|custom)" >&2; exit 2 ;;
esac

WARM_IMAGE="${BASE_IMAGE%:*}:${WARM_TAG}"
WARM_COLD_IMAGE="${COLD_IMAGE%:*}:${WARM_TAG}"
SUF="bak-${WARM_TAG}"
FC_BIN_SRC="${FC_BIN_SRC:-}"   # optional: path to a patched firecracker (>=1.15.1) to swap in
log(){ printf '\033[1;36m[redeploy-warm]\033[0m %s\n' "$*"; }

log "engine=$ENGINE ref=$BLASTBOX_REF -> $WARM_IMAGE / $WARM_COLD_IMAGE"

MODE="${REDEPLOY_MODE:-recreate}"
case "$MODE" in
  recreate|legacy-rebuild) ;;
  *) echo "unknown REDEPLOY_MODE=$MODE (recreate|legacy-rebuild)" >&2; exit 2 ;;
esac

# The rebuild half is opt-in, and the opt-in still does not license a shrink.
# `build-images` preserves the size already in place; these presets do not, and
# the drift above is real, so measure the artifact rather than trusting a
# comment nobody reads at 3am.
if [ "$MODE" = legacy-rebuild ] && [ -f "$FC_DIR/rootfs.ext4" ]; then
  live_mib=$(( $(stat -c %s "$FC_DIR/rootfs.ext4") / 1048576 ))
  if [ "$ROOTFS_MIB" -lt "$live_mib" ]; then
    if [ "${ALLOW_ROOTFS_SHRINK:-0}" = 1 ]; then
      log "WARNING: rebuilding $FC_DIR/rootfs.ext4 at ${ROOTFS_MIB} MiB over a live ${live_mib} MiB image (ALLOW_ROOTFS_SHRINK=1)"
    else
      echo "refusing to rebuild $FC_DIR/rootfs.ext4 at ${ROOTFS_MIB} MiB: the live" >&2
      echo "image is ${live_mib} MiB, and this preset would shrink it by $(( live_mib - ROOTFS_MIB )) MiB." >&2
      echo "Use \`blastbox build-images\`, which keeps the existing size, or set" >&2
      echo "ROOTFS_MIB=$live_mib, or ALLOW_ROOTFS_SHRINK=1 if the shrink is intended." >&2
      exit 2
    fi
  fi
fi

if [ "$MODE" = legacy-rebuild ]; then
  log "mode=legacy-rebuild: steps 1-6 (superseded rebuild half is ENABLED)"
else
  log "mode=recreate: steps 5-6 + optional FC binary swap; rootfs/images must"
  log "  already be published by \`blastbox build-images <repo> --tag $WARM_TAG\`"
fi

if [ "${REDEPLOY_CHECK_ONLY:-0}" = 1 ]; then
  log "check-only: nothing was changed"
  exit 0
fi

if [ "$MODE" = legacy-rebuild ]; then
# --- 1. blastbox wheel from BLASTBOX_REF --------------------------------------
log "checkout $BLASTBOX_REF + build wheel (via $BASE_IMAGE pip, no-cache so a PyPI wheel isn't served)"
git -C "$REPO" fetch --quiet origin "$BLASTBOX_REF" && git -C "$REPO" checkout --quiet "$BLASTBOX_REF"
SRC=$(mktemp -d); WHEELS=$(mktemp -d)
cp -r "$REPO"/. "$SRC"/ ; rm -rf "$SRC/.git" "$SRC/build" "$SRC/src/"*.egg-info 2>/dev/null || true
docker run --rm -u root -v "$SRC":/src -v "$WHEELS":/out --entrypoint "$VENV_PIP" "$BASE_IMAGE" \
  wheel /src --no-deps --no-cache-dir --no-binary :all: -w /out >/dev/null
WHEEL=$(ls "$WHEELS"/blastbox-*.whl | head -1); log "wheel: $(basename "$WHEEL")"

# --- 2. derive :warmfix images (force the wheel over shipped blastbox) ---------
derive() {  # $1 = source image, $2 = destination :warmfix image
  local src="$1" dst="$2" d wn
  d=$(mktemp -d); cp "$WHEEL" "$d/"; wn=$(basename "$WHEEL")
  cat > "$d/Dockerfile" <<DOCKER
FROM ${src}
USER root
COPY ${wn} /tmp/${wn}
RUN ${VENV_PIP} install --force-reinstall --no-deps --no-index --no-cache-dir /tmp/${wn} && rm /tmp/${wn}
USER ${IMG_USER}
DOCKER
  log "build $dst FROM $src"
  docker build -q -f "$d/Dockerfile" -t "$dst" "$d" >/dev/null; rm -rf "$d"
  docker run --rm --entrypoint "$VENV_PY" "$dst" -c \
    "from blastbox.worker import warm; assert hasattr(warm,'_RestoreAwareDeadline'); print('  fix present:', '$dst')"
}
derive "$BASE_IMAGE" "$WARM_IMAGE"
derive "$COLD_IMAGE" "$WARM_COLD_IMAGE"

# --- 3. rebuild both warm rootfs (to *.warmfix staging) -----------------------
log "FC rootfs -> $FC_DIR/rootfs.ext4.${WARM_TAG}"
ENGINE="$ENGINE" ROOTFS_MIB="$ROOTFS_MIB" DOCKERFILE="$FC_DOCKERFILE" BASE_IMAGE="$WARM_COLD_IMAGE" \
  "$REPO/deploy/firecracker/build-rootfs.sh" "$FC_DIR/rootfs.ext4.${WARM_TAG}"
log "gVisor rootfs -> $GVISOR_DIR/rootfs.${WARM_TAG}"
docker build -q --build-arg BASE="$WARM_IMAGE" -f "$REPO/deploy/gvisor/Dockerfile.shim" \
  -t "${WARM_IMAGE%:*}-warm:gvisor-${WARM_TAG}" "$REPO" >/dev/null
cid=$(docker create "${WARM_IMAGE%:*}-warm:gvisor-${WARM_TAG}")
sudo rm -rf "$GVISOR_DIR/rootfs.${WARM_TAG}"; sudo mkdir -p "$GVISOR_DIR/rootfs.${WARM_TAG}"
docker export "$cid" | sudo tar -x -C "$GVISOR_DIR/rootfs.${WARM_TAG}"; docker rm "$cid" >/dev/null

# --- 4. stage swaps (with backups) + optional FC binary -----------------------
log "stage rootfs (backups -> *.$SUF)"
mv "$FC_DIR/rootfs.ext4" "$FC_DIR/rootfs.ext4.$SUF"; mv "$FC_DIR/rootfs.ext4.${WARM_TAG}" "$FC_DIR/rootfs.ext4"
sudo mv "$GVISOR_DIR/rootfs" "$GVISOR_DIR/rootfs.$SUF"; sudo mv "$GVISOR_DIR/rootfs.${WARM_TAG}" "$GVISOR_DIR/rootfs"
fi

# --- 4b. optional Firecracker binary swap (BOTH modes) ------------------------
# `build-images` publishes images and rootfs; the FC binary is not in the plan,
# so this stays here and stays reachable without the rebuild half.
if [ -n "$FC_BIN_SRC" ]; then
  log "swap firecracker binary <- $FC_BIN_SRC"
  cp -a "$FC_DIR/firecracker" "$FC_DIR/firecracker.$SUF"
  cp -f "$FC_BIN_SRC" "$FC_DIR/firecracker.new" && mv -f "$FC_DIR/firecracker.new" "$FC_DIR/firecracker"
  "$FC_DIR/firecracker" --version | head -1
fi

# --- 5. .env image vars + recreate (NOT postgres) -----------------------------
cd "$COMPOSE_DIR"
cp .env ".env.$SUF"
# `grep -v` exits 1 when it selects NO lines -- an .env holding only the two
# image vars is exactly that -- and under `set -e` the redeploy would abort
# here, after the backup and before the rewrite. Only status 2 is an error.
grep -vE "^(${IMAGE_ENV}|${WORKER_IMAGE_ENV})=" .env > .env.tmp || [ $? -eq 1 ]
echo "${IMAGE_ENV}=${WARM_IMAGE}"        >> .env.tmp
echo "${WORKER_IMAGE_ENV}=${WARM_COLD_IMAGE}" >> .env.tmp
mv .env.tmp .env
log "recreate api + dispatchers"
$COMPOSE_WRAPPER $COMPOSE_FILES up -d --force-recreate api dispatcher dispatcher-fc dispatcher-gvisor

# --- 6. smoke: a benign job must reach a warm tier ----------------------------
if [ -n "$SMOKE_FILE" ] && [ -f "$SMOKE_FILE" ]; then
  log "smoke: warm-pool build (~75s) then submit $SMOKE_FILE"
  sleep 75
  jid=$(curl -sS -F "file=@$SMOKE_FILE" -F "engine=$ENGINE" "$API_URL/v1/jobs" | python3 -c 'import sys,json;print(json.load(sys.stdin)["job_id"])')
  for _ in $(seq 1 40); do st=$(curl -sS "$API_URL/v1/jobs/$jid" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("status"),d.get("worker_runtime"))'); case "$st" in done*) break;; failed*|error*|rejected*) echo "SMOKE FAILED: $st"; exit 1;; esac; sleep 3; done
  log "smoke: $jid -> $st"
fi

[ "$MODE" = legacy-rebuild ] && rm -rf "$SRC" "$WHEELS"
if [ "$MODE" = legacy-rebuild ]; then
cat <<ROLLBACK

[redeploy-warm] DONE (legacy-rebuild). ROLLBACK if needed:
  cd $COMPOSE_DIR && cp .env.$SUF .env
  mv $FC_DIR/rootfs.ext4.$SUF $FC_DIR/rootfs.ext4
  sudo rm -rf $GVISOR_DIR/rootfs && sudo mv $GVISOR_DIR/rootfs.$SUF $GVISOR_DIR/rootfs
  [ -f $FC_DIR/firecracker.$SUF ] && mv $FC_DIR/firecracker.$SUF $FC_DIR/firecracker
  $COMPOSE_WRAPPER $COMPOSE_FILES up -d --force-recreate api dispatcher dispatcher-fc dispatcher-gvisor
ROLLBACK
else
cat <<ROLLBACK

[redeploy-warm] DONE (recreate). ROLLBACK if needed:
  cd $COMPOSE_DIR && cp .env.$SUF .env
  # rootfs published by \`blastbox build-images\` keeps the PREVIOUS artifact at
  # <dest>.bak -- not the .bak-$WARM_TAG names the superseded in-script swap used:
  mv $FC_DIR/rootfs.ext4.bak $FC_DIR/rootfs.ext4
  sudo rm -rf $GVISOR_DIR/rootfs && sudo mv $GVISOR_DIR/rootfs.bak $GVISOR_DIR/rootfs
  [ -f $FC_DIR/firecracker.$SUF ] && mv $FC_DIR/firecracker.$SUF $FC_DIR/firecracker
  $COMPOSE_WRAPPER $COMPOSE_FILES up -d --force-recreate api dispatcher dispatcher-fc dispatcher-gvisor
ROLLBACK
fi
