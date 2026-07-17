"""Shared node view for dispatcher-side self-sizing.

blastbox splits an engine into a `serve` (ingress) process and a `dispatch` process, and
the warm pool lives in the DISPATCHER — which has no HTTP server. So the node coordinator
can't be an HTTP push to the ingress. Instead each engine's dispatcher publishes its own
demand snapshot to a shared node directory and reads its peers' snapshots back; every
dispatcher then runs the same deterministic allocation over the same node view and sizes
its OWN pool. No cross-process push, no admin endpoint, and it lives exactly where the
pool is.

The share is a directory (bind-mounted into each engine stack on a node): one
`<engine>.json` per engine, written atomically. Snapshots older than a staleness window
are ignored, so a stopped engine drops out of the node view on its own.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class DemandSnapshot:
    """One engine's contribution to the node view."""

    engine: str
    backlog: int                 # QUEUED jobs (leading scale signal)
    assigned: int                # slots in-flight now
    slot_ram_mib: float          # per-slot footprint
    slot_vcpus: float
    min_warm: int
    max_ceiling: int
    weight: float                # static share when balancing is off
    ts: float                    # publish time (for staleness)


class NodeShare(Protocol):
    def publish(self, snap: DemandSnapshot) -> None: ...
    def read_all(self, *, max_age_s: float, now: float) -> list[DemandSnapshot]: ...


class FileNodeShare:
    """Directory-backed share. Each engine owns `<dir>/<engine>.json`."""

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def publish(self, snap: DemandSnapshot) -> None:
        path = self._dir / f"{snap.engine}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(snap)))
        tmp.replace(path)                       # atomic swap; readers never see a partial file

    def read_all(self, *, max_age_s: float, now: float) -> list[DemandSnapshot]:
        out: list[DemandSnapshot] = []
        for f in sorted(self._dir.glob("*.json")):
            try:
                snap = DemandSnapshot(**json.loads(f.read_text()))
            except Exception:
                continue                        # a torn/foreign file just doesn't contribute
            if now - snap.ts <= max_age_s:
                out.append(snap)
        return out
