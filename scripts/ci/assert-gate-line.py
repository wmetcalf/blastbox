#!/usr/bin/env python3
"""Assert a forwarder log matches the SAME regex the dispatcher's health gate uses.

The gate-success string lives in four hand-copied places — deploy/egress-forwarder/
entrypoint.sh (the source of truth), ``egress.GATE_OK_PATTERN``, literals in the unit
tests, and scripts/test-egress-leak.sh — with nothing tying them together. CI only ever
exercised the FAILURE path, so rewording the success line kept every test and the whole
job green while `forwarder_health` reported every global-mode node as "has not logged a
successful overlay probe" and the dispatcher deferred 100% of egress jobs fleet-wide.

READ, DO NOT IMPORT. The obvious version of this said
``from blastbox.host.egress import GATE_OK_PATTERN``, and that pulls ``blastbox/
__init__.py`` -> the worker engine -> pydantic. The egress-forwarder CI job installs no
Python dependencies (it builds a container and pokes it), so the import died with
ModuleNotFoundError while the forwarder under test had printed exactly the right line.
Lifting the literal out of the module source keeps the single source of truth — the
pattern is still not retyped here — with nothing but the stdlib. A unit test asserts
this extraction yields the same object the module compiles, so the two cannot drift.

    python3 scripts/ci/assert-gate-line.py <logfile>
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EGRESS_PY = ROOT / "src" / "blastbox" / "host" / "egress.py"


def gate_ok_pattern() -> "re.Pattern[str]":
    """The compiled GATE_OK_PATTERN, lifted from the module source without importing it."""
    src = EGRESS_PY.read_text(encoding="utf-8")
    m = re.search(r'^GATE_OK_PATTERN\s*=\s*re\.compile\(\s*r"([^"]*)"\s*\)', src, re.M)
    if not m:
        raise SystemExit(
            f"could not find GATE_OK_PATTERN in {EGRESS_PY}. It was renamed, reformatted "
            "or moved — fix this extraction rather than retyping the pattern, or the CI "
            "check and the dispatcher stop checking the same thing."
        )
    return re.compile(m.group(1))


def main() -> int:
    pattern = gate_ok_pattern()
    log = pathlib.Path(sys.argv[1]).read_text(errors="replace")
    hit = pattern.search(log)
    if not hit:
        print(f"::error::the forwarder came up but GATE_OK_PATTERN ({pattern.pattern!r}) "
              "matches nothing it printed — forwarder_health would report every healthy "
              "node as DEGRADED and the dispatcher would defer all egress work")
        print(log)
        return 1
    print(f"gate success line OK: {hit.group(0)!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
