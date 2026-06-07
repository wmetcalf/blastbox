#!/usr/bin/env bash
# blastbox local tests — TIER 1: unit + lint + types.  NO sudo, NO runtimes.
#
# Runs anywhere. subprocess/runsc/redis/sockets are mocked; SQLite/fakeredis/
# filesystem/seal are real. This is what you run on every change.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
VENV="$REPO/.venv"

if [[ ! -x "$VENV/bin/pytest" ]]; then
  echo ">> creating venv + installing .[dev]"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -e ".[dev]"
fi

echo ">> pytest tests   (gated integration/docker tests self-skip without prereqs)"
"$VENV/bin/pytest" tests "$@"
echo ">> ruff check src tests"
"$VENV/bin/ruff" check src tests
echo ">> mypy src"
"$VENV/bin/mypy" src
echo "OK: unit + lint + types"
