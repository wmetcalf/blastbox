#!/usr/bin/env bash
# Mutation-check the consolidation. A patch that fails to apply, or applies without changing
# anything, is an ERROR -- never a surviving mutant. (An earlier harness reported SURVIVED for two
# mutants it had never applied.)
set -uo pipefail
# Resolve the repo from THIS SCRIPT's location, and abort if that fails. The first version
# hardcoded one absolute path with no `set -e` and no check on the cd, so in any other checkout it
# carried on against the CALLER's working directory -- a harness that rewrites source files and
# reverts them from a snapshot, pointed at whatever repo you happened to be standing in. The
# blast radius of that is worse than anything it was written to catch.
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd) || {
  echo "mutation_check_park: cannot resolve the repository root" >&2; exit 2; }
cd -- "$REPO" || { echo "mutation_check_park: cannot cd to $REPO" >&2; exit 2; }
[ -f src/blastbox/host/runtime/aws_worker.py ] || {
  echo "mutation_check_park: $REPO does not look like the blastbox checkout" >&2; exit 2; }
[ -x .venv/bin/python ] || {
  echo "mutation_check_park: $REPO/.venv/bin/python is missing" >&2; exit 2; }
# The snapshot is the ONLY thing that undoes a mutation, so nothing below may run until it is
# known-good. Previously mktemp and the copy were both unchecked while `set -e` was off, and the
# EXIT trap assumed both had succeeded -- so a failure here left mutated source in the checkout and
# the trap silently copied nothing over it.
SNAP=$(mktemp -d) || { echo "mutation_check_park: mktemp failed" >&2; exit 2; }
cp src/blastbox/host/pool.py src/blastbox/host/runtime/aws_worker.py "$SNAP/" || {
  echo "mutation_check_park: could not snapshot the sources" >&2; rm -rf "$SNAP"; exit 2; }
[ -s "$SNAP/pool.py" ] && [ -s "$SNAP/aws_worker.py" ] || {
  echo "mutation_check_park: snapshot is incomplete" >&2; rm -rf "$SNAP"; exit 2; }
restore() {
  if cp "$SNAP/pool.py" src/blastbox/host/pool.py \
     && cp "$SNAP/aws_worker.py" src/blastbox/host/runtime/aws_worker.py; then
    return 0
  fi
  # MUST report failure. With `cp ... || echo ...` the function exit status was echo's, i.e. 0,
  # so mut() would happily patch on top of an already-mutated tree and report a meaningless result.
  echo "mutation_check_park: RESTORE FAILED — sources may be mutated, snapshot at $SNAP" >&2
  return 1
}
trap restore EXIT

FAILURES=0

mut() {
  local name="$1" patch="$2" test="$3" rc
  # A failed restore is FATAL, not something to carry on from: the next patch would be applied on
  # top of whatever mutation the previous case left behind and every result after it is fiction.
  if ! restore; then
    echo "  FATAL    $name (baseline restore failed; sources may be mutated)"
    FAILURES=$((FAILURES + 1)); exit 1
  fi
  if ! .venv/bin/python -c "$patch" 2>/dev/null; then
    echo "  ERROR    $name (patch failed)"; FAILURES=$((FAILURES + 1)); return
  fi
  if git diff --quiet src/; then
    echo "  ERROR    $name (changed nothing)"; FAILURES=$((FAILURES + 1)); return
  fi
  # Distinguish a KILLED mutant from an infrastructure failure. pytest exits 1 for a real test
  # failure -- that is a kill -- but 2/3/4/5 for collection errors, usage errors and internal
  # faults, and 124 for a timeout. Counting those as kills reported a mutant as caught by a test
  # run that never actually ran it.
  timeout 300 .venv/bin/python -m pytest "$test" -q -p no:cacheprovider >/dev/null 2>&1
  rc=$?
  case "$rc" in
    0) echo "  SURVIVED $name"; FAILURES=$((FAILURES + 1)) ;;
    1) echo "  killed   $name" ;;
    *) echo "  ERROR    $name (pytest rc=$rc -- not a verdict)"; FAILURES=$((FAILURES + 1)) ;;
  esac
}

T=tests/host/runtime/test_aws_worker.py
P=tests/host/test_pool.py

mut "stopping closer stops crediting" '
import pathlib;p=pathlib.Path("src/blastbox/host/runtime/aws_worker.py");s=p.read_text()
o="""            # of 310s while logging "stuck for 310s". The ledger removed the dependency entirely.
            self._thaw_park(sid, now)"""
assert s.count(o)==1
p.write_text(s.replace(o,"            self._park_unknown_since.pop(sid, None)",1))
' "$T::test_recovery_observing_stopping_credits_the_brownout_like_every_other_closer"

mut "claim gate ignores an unresolved park" '
import pathlib;p=pathlib.Path("src/blastbox/host/runtime/aws_worker.py");s=p.read_text()
o="        if slot.slot_id in self._park_unknown_since:"
assert s.count(o)==1
p.write_text(s.replace(o,"        if False:",1))
' "$T::test_an_unresolved_park_attempt_makes_the_slot_unclaimable"

mut "timeout markers removed from the no-verdict list" '
import pathlib;p=pathlib.Path("src/blastbox/host/runtime/aws_worker.py");s=p.read_text()
o="    \"requesttimeout\",                  # RequestTimeout / RequestTimeoutException"
assert s.count(o)==1
p.write_text(s.replace(o,"",1))
' "$T::test_a_server_side_timeout_is_a_non_answer_not_a_refusal"

mut "maintain_idle stops freezing the park clock" '
import pathlib;p=pathlib.Path("src/blastbox/host/runtime/aws_worker.py");s=p.read_text()
o="""                    if isinstance(exc, AwsNoVerdict) and slot.slot_id in self._park_since:
                        self._freeze_park(slot.slot_id, self._clock())"""
assert s.count(o)==1
p.write_text(s.replace(o,"                    pass",1))
' "$T::test_the_maintenance_door_freezes_the_park_clock_too"

mut "freeze becomes unbounded again" '
import pathlib;p=pathlib.Path("src/blastbox/host/runtime/aws_worker.py");s=p.read_text()
o="        credited = min(self._park_credit.get(sid, 0.0) + live, self.cfg.hibernate_timeout_s)"
assert s.count(o)==1
p.write_text(s.replace(o,"        credited = self._park_credit.get(sid, 0.0) + live",1))
' "$T::test_an_indefinite_freeze_still_expires"

mut "restore uses the credit ledger again" '
import pathlib;p=pathlib.Path("src/blastbox/host/pool.py");s=p.read_text()
o="""                                         if slot.slot_id in self._never_ready"""
assert s.count(o)==2
p.write_text(s.replace(o,"                                         if slot.slot_id in self._warming_unknown_credit"))
' "$P::test_a_proven_slot_is_restored_to_idle_not_warming"

mut "promotion stops clearing never_ready" '
import pathlib;p=pathlib.Path("src/blastbox/host/pool.py");s=p.read_text()
o="""                        self._never_ready.discard(slot.slot_id)
                        self._warming_unknown_credit.pop(slot.slot_id, None)"""
assert s.count(o)==1
p.write_text(s.replace(o,"                        self._warming_unknown_credit.pop(slot.slot_id, None)",1))
' "$P::test_a_proven_slot_is_restored_to_idle_not_warming"

# EXIT NONZERO on any surviving mutant, patch error or infrastructure failure. Every branch above
# used to end on a successful echo, so the script exited 0 for EVERY outcome -- an automated caller
# got a green check even when mutants survived or were never tested. A harness whose whole purpose
# is refusing to call an untested thing "verified" must not do that itself.
# Restore EXPLICITLY and check it, before printing any verdict. The EXIT trap also restores, but
# bash preserves the script's own exit status through a trap -- a trap returning 1 does NOT make
# the script exit 1 -- so the LAST mutation's restore was the one thing here with no check at all,
# and a failure there reported success while leaving that mutation in the source tree.
if ! restore; then
  echo "  == BASELINE NOT RESTORED — the last mutation may still be in the tree (snapshot: $SNAP)"
  exit 2
fi
if [ "$FAILURES" -ne 0 ]; then
  echo "  == $FAILURES mutant(s) survived or could not be evaluated"
  exit 1
fi
echo "  == all mutants killed, baseline restored"
