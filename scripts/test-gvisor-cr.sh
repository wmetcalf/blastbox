#!/usr/bin/env bash
# blastbox local tests — TIER 2 (gVisor): the C/R warm-snapshot round-trip.  NEEDS sudo.
#
# This is THE test that validates the warm-snapshot headline end-to-end:
# runsc checkpoint -> restore -> file-trigger control plane -> probe detonation ->
# host re-seal -> metadata.json status=="ok", with the claim_id/CAS ownership fence
# exercised by a real runtime (not the mocked unit tests).
#
# Why sudo: the gVisor backend drives runsc in ROOTFUL mode (no --rootless path),
# and root also bypasses Ubuntu 24.04's apparmor_restrict_unprivileged_userns=1.
# A soffice-free `probe` engine is baked in, so no LibreOffice is needed.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
VENV="$REPO/.venv"
ROOTFS="${BLASTBOX_GVISOR_ROOTFS:-/tmp/bb-gvisor-rootfs}"
IMG="blastbox-warm-probe:test"

# --- prereqs -------------------------------------------------------------
RUNSC="$(command -v runsc || true)"
[[ -n "$RUNSC" ]] || { echo "ERROR: runsc not found on PATH"; exit 1; }
"$RUNSC" help 2>&1 | grep -qiE 'checkpoint' || { echo "ERROR: this runsc lacks checkpoint/restore"; exit 1; }

DOCKER=docker
docker info >/dev/null 2>&1 || DOCKER="sudo docker"

if [[ ! -x "$VENV/bin/pytest" ]]; then
  python3 -m venv "$VENV"; "$VENV/bin/pip" install -q -e ".[dev]"
fi
"$VENV/bin/python" -c 'import build' 2>/dev/null || "$VENV/bin/pip" install -q build

# --- build the probe-engine warm rootfs ---------------------------------
echo ">> building probe wheel + warm image (no soffice; quick smoke)"
rm -rf /tmp/bb-w && "$VENV/bin/python" -m build --wheel -o /tmp/bb-w "$REPO" >/dev/null
BUILD=/tmp/bb-warm-build; rm -rf "$BUILD"; mkdir -p "$BUILD"
cp "$REPO/deploy/gvisor/run_warm.py" "$REPO/deploy/firecracker/engines.py" /tmp/bb-w/blastbox-*.whl "$BUILD/"
cat > "$BUILD/Dockerfile" <<'EOF'
FROM python:3.12-slim
COPY *.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl
COPY run_warm.py /opt/blastbox/run_warm.py
COPY engines.py /opt/blastbox/engines.py
RUN printf 'probe' > /opt/blastbox/engine
EOF
$DOCKER build -t "$IMG" "$BUILD" >/dev/null

echo ">> exporting rootfs -> $ROOTFS  (Docker ENV is dropped; engine is baked in a FILE)"
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS"
cid="$($DOCKER create "$IMG")"; $DOCKER export "$cid" | tar -C "$ROOTFS" -xf -; $DOCKER rm "$cid" >/dev/null

# --- run the round-trip AS ROOT -----------------------------------------
echo ">> running gVisor C/R round-trip AS ROOT (you'll be prompted for sudo)"
sudo -E env \
  BLASTBOX_GVISOR_ROOTFS="$ROOTFS" \
  BLASTBOX_GVISOR_RUNSC="$RUNSC" \
  "$VENV/bin/pytest" tests/integration/test_gvisor_snapshot_roundtrip.py -v "$@"
