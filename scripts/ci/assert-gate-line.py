#!/usr/bin/env python3
"""Assert a forwarder log matches the SAME regex the dispatcher's health gate uses.

The gate-success string lives in four hand-copied places — deploy/egress-forwarder/
entrypoint.sh (the source of truth), ``egress.GATE_OK_PATTERN``, literals in the unit
tests, and scripts/test-egress-leak.sh — with nothing tying them together. CI only ever
exercised the FAILURE path, so rewording the success line kept every test and the whole
job green while `forwarder_health` reported every global-mode node as "has not logged a
successful overlay probe" and the dispatcher deferred 100% of egress jobs fleet-wide.

Imported, never retyped: a second literal spelling here would move the drift, not remove
it.

    python3 scripts/ci/assert-gate-line.py <logfile>
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
from blastbox.host.egress import GATE_OK_PATTERN  # noqa: E402

log = pathlib.Path(sys.argv[1]).read_text(errors="replace")
hit = GATE_OK_PATTERN.search(log)
if not hit:
    print(f"::error::the forwarder came up but GATE_OK_PATTERN ({GATE_OK_PATTERN.pattern!r}) "
          "matches nothing it printed — forwarder_health would report every healthy node "
          "as DEGRADED and the dispatcher would defer all egress work")
    print(log)
    raise SystemExit(1)
print(f"gate success line OK: {hit.group(0)!r}")
