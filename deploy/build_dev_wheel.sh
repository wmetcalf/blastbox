#!/usr/bin/env bash
# Build a blastbox wheel that SAYS it is not the released one.
#
# Why this exists: the host image pins `blastbox[s3]==0.1.26` from PyPI, but a fleet running a
# pre-release fix has local source with the SAME 0.1.26 in pyproject.toml. Everything then
# reports "blastbox 0.1.26" -- `pip show`, `blastbox.__version__`, deploy_inventory.sh -- while
# the code is materially different. Drift detection is exactly what that inventory is for, and
# a same-version-different-code artifact defeats it silently.
#
# So stamp a PEP 440 LOCAL version identifier (`0.1.26+g<sha>[.dirty]`) at build time. It sorts
# above the release, installs over it without a pin change, and is impossible to mistake for
# PyPI in any inventory. Nothing in the repo's version is committed or changed.
#
# Usage: deploy/build_dev_wheel.sh [outdir]    (default: dist/)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$REPO/dist}"
cd "$REPO"

BASE="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)"
[ -n "$BASE" ] || { echo "could not read version from pyproject.toml" >&2; exit 1; }
SHA="$(git rev-parse --short HEAD)"
DIRTY=""
git diff --quiet && git diff --cached --quiet || DIRTY=".dirty"
LOCAL="${BASE}+g${SHA}${DIRTY}"

# Build from a COPY so the working tree's pyproject.toml is never edited -- a build that leaves
# a modified version behind is one `git commit -a` away from shipping a fake release number.
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
git ls-files -z | xargs -0 -I{} cp --parents {} "$WORK"/
# Untracked-but-needed files would break the build loudly, not silently -- pyproject + src are
# both tracked, so the archive is complete by construction.
sed -i "s/^version = \"${BASE}\"/version = \"${LOCAL}\"/" "$WORK/pyproject.toml"

echo ">> building blastbox ${LOCAL}"
( cd "$WORK" && python3 -m build --wheel --outdir "$OUT" ) >/dev/null
WHEEL="$(ls -t "$OUT"/blastbox-*"+g${SHA}"*.whl | head -1)"
echo "$WHEEL"
