"""Generic cold-path worker entrypoint.

The reusable equivalent of the FC ``run_guest.py`` / gVisor ``run_warm.py``
loaders, for the plain-docker (runsc/runc) COLD path: load the operator-selected
engine from ``BLASTBOX_ENGINE='module:Class'`` and run it through the harness.

A cold worker image's ENTRYPOINT is ``python -m blastbox.worker.cold``; the engine
is fixed per image (operator-configured, never job-derived). Input/output dirs come
from ``BLASTBOX_INPUT_DIR`` / ``BLASTBOX_OUTPUT_DIR`` (the dispatcher injects them).
"""
from __future__ import annotations

import os
import sys

from blastbox.worker.harness import main as harness_main
from blastbox.worker.load import load_engine


def main(argv: list[str] | None = None) -> int:
    spec = os.environ.get("BLASTBOX_ENGINE", "").strip()
    if not spec:
        sys.stderr.write(
            "BLASTBOX_ENGINE not set — expected 'module:Class' "
            "(e.g. clippyshot.engine:ClippyShotEngine)\n"
        )
        return 4
    try:
        engine = load_engine(spec)
    except Exception as exc:  # noqa: BLE001 — operator-config error, not a programmer bug
        sys.stderr.write(
            f"BLASTBOX_ENGINE={spec!r} could not be loaded (expected 'module:Class'): {exc}\n"
        )
        return 4
    return harness_main(engine, argv)


if __name__ == "__main__":
    raise SystemExit(main())
