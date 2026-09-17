#!/usr/bin/env bash
# PROVE THE ENFORCEMENT MATRIX HAS TEETH.
#
# The node-grants gate was twice found to be disableable with the whole suite green,
# because every test written for it asserted on `inspect.getsource()` substrings. A
# passing test suite is not evidence that a control works; a suite that goes RED when the
# control is removed is. This script removes it, one arm at a time, and requires
# tests/host/test_grants_enforcement_matrix.py to fail each time.
#
# Runs against a COPY under /tmp. It never mutates the repo.
#
#   scripts/ci/prove-grants-enforcement.sh
#
# Exit 0 only if every mutation was caught.
set -uo pipefail
REPO="$(git -C "$(dirname "$0")/../.." rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -a "$REPO" "$WORK/bb"
cd "$WORK/bb" || exit 1
PY="$REPO/.venv/bin/python"
MATRIX=tests/host/test_grants_enforcement_matrix.py

# name|file|python-replacement. Each disables ONE arm of the control.
MUTATIONS=(
  "the whole gate (refuse always permits)|src/blastbox/host/placement.py|s=s.replace('    def refuse(self, *, engine: str, personality) -> str | None:','    def refuse(self, *, engine: str, personality) -> str | None:\n        return None   # MUTANT',1)"
  "the engine arm|src/blastbox/host/placement.py|s=s.replace('    if not grants.allows_engine(engine):','    if False:',1)"
  "the tier arm|src/blastbox/host/placement.py|s=s.replace('    if tier is not None and not grants.allows_tier(tier):','    if False:',1)"
  "the credentials arm|src/blastbox/host/placement.py|s=s.replace('    if require_credentials and not grants.credentials:','    if False:',1)"
  "the unverifiable-certificate refusal|src/blastbox/host/placement.py|s=s.replace('    if grants is None:','    if False:',1)"
  "the cold-path call site|src/blastbox/host/dispatch.py|s=s.replace('            if why is not None:','            if why is not None and not True:',1)"
  "the VM-path call site|src/blastbox/host/runtime/vm_dispatch.py|s=s.replace('        if why is not None:','        if why is not None and not True:',1)"
  "the VM tier resolution|src/blastbox/host/runtime/vm_dispatch.py|s=s.replace('        registry = self._net_policy_registry()','        return type(\"_P\", (), {\"exit_driver\": \"none\"})()   # MUTANT',1)"
  "release-not-fail (cold)|src/blastbox/host/dispatch.py|s=s.replace('                self._requeue_claimed(\n                    job, defer=True, defer_s=shared_defer,','                self._fail_job(job, \"mutant\"); return\n                self._requeue_claimed(\n                    job, defer=True, defer_s=shared_defer,',1)"
  "release-not-fail (VM)|src/blastbox/host/runtime/vm_dispatch.py|s=s.replace('                status=JobStatus.QUEUED, claim_id=None, started_at=None,','                status=JobStatus.FAILED, claim_id=None, started_at=None,',1)"
)

pass=0; fail=0
printf '%-44s %s\n' "MUTATION" "MATRIX"
printf '%-44s %s\n' "--------" "------"
for m in "${MUTATIONS[@]}"; do
  name="${m%%|*}"; rest="${m#*|}"; file="${rest%%|*}"; repl="${rest#*|}"
  cp "$REPO/$file" "$file"
  if ! "$PY" - "$file" <<PYEOF
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(); before = s
$repl
if s == before:
    print("ANCHOR MISSING", file=sys.stderr); raise SystemExit(2)
p.write_text(s)
PYEOF
  then
    printf '%-44s \033[31mANCHOR MISSING (mutation did not apply)\033[0m\n' "$name"
    fail=$((fail+1)); cp "$REPO/$file" "$file"; continue
  fi
  if "$PY" -m pytest "$MATRIX" -q -p no:randomly >/dev/null 2>&1; then
    printf '%-44s \033[31mNOT CAUGHT — the matrix passes without this\033[0m\n' "$name"
    fail=$((fail+1))
  else
    printf '%-44s \033[32mcaught\033[0m\n' "$name"
    pass=$((pass+1))
  fi
  cp "$REPO/$file" "$file"          # restore before the next mutation
done

echo
echo "  ${pass} caught, ${fail} missed"
[[ $fail -eq 0 ]] || {
  echo "  A control the tests cannot notice the absence of is not a tested control." >&2
  exit 1
}
echo "  Every arm of the grants gate is covered by a test that fails without it."
