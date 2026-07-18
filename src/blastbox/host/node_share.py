"""Shared node view for dispatcher-side self-sizing.

blastbox splits an engine into a `serve` (ingress) process and a `dispatch` process, and
the warm pool lives in the DISPATCHER — which has no HTTP server. So the node coordinator
can't be an HTTP push to the ingress. Instead each engine's dispatcher publishes its own
demand snapshot to a shared node directory and reads its peers' snapshots back; every
dispatcher then runs the same deterministic allocation over the same node view and sizes
its OWN pool. No cross-process push, no admin endpoint, and it lives exactly where the
pool is.

The share is a directory (bind-mounted into each engine stack on a node): one file per
PUBLISHING UNIT (a dispatcher process = engine × tier × host × instance), written
atomically. Snapshots older than a staleness window are ignored, so a stopped engine drops
out of the node view on its own; a graceful stop also removes its own file, and read_all
garbage-collects long-abandoned files (a crashed process's remnant).

Trust model
-----------
The share dir is a NODE-LOCAL COORDINATION SURFACE within a SINGLE TRUST DOMAIN — like a
`/var/run` socket dir. It is written ONLY by the dispatcher processes (trusted infra);
untrusted sample code runs in the sealed slots/microVMs (blastbox's isolation boundary) and
never touches this dir. Snapshots are therefore validated for well-formedness + resource
bounds (`_valid`) and pinned to their canonical filename (a file can't claim another unit's
identity), but they are NOT cryptographically authenticated: a shared-secret HMAC among
mutually-distrusting dispatchers would be theater (a compromised dispatcher holds the
secret), so the correct isolation for a deployment that does NOT trust its own dispatchers
equally is FILESYSTEM per-owner write permissions — mount/chmod the dir so each engine
container can write only its own `<identity>.json` to a commonly-readable dir. Do NOT put a
share dir on a surface writable by anything outside the dispatcher trust domain.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
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
    node: str = ""               # publishing host — so a share_dir accidentally shared
                                 # across hosts (NFS) doesn't conflate their demand/budget
    tier: str = ""               # the pool's runtime tier (firecracker/gvisor). Part of the
                                 # identity: ONE engine can run on TWO node-managed tiers on
                                 # one host (separate pools) — without the tier they'd share a
                                 # key and collapse into one, each sizing to the whole budget.
    instance: str = ""           # the publishing PROCESS (pid). Part of the identity so two
                                 # replicas of the same engine/tier/node on one host — e.g.
                                 # briefly overlapping during a rolling deploy — are TWO
                                 # distinct pools that split the budget in plan_sizes, rather
                                 # than colliding on one file and each taking the full ceiling.


class NodeShare(Protocol):
    def publish(self, snap: DemandSnapshot) -> None: ...
    def read_all(self, *, max_age_s: float, now: float) -> list[DemandSnapshot]: ...
    def remove(self, snap: DemandSnapshot) -> None: ...


class FileNodeShare:
    """Directory-backed share. Each publishing unit — a dispatcher process =
    (engine, tier, node, instance) — owns one
    `<dir>/<engine>[@<tier>][@<node>][@<instance>].json`, so distinct pools never collide."""

    # A file untouched for this long past the staleness window belongs to a crashed process
    # (a live dispatcher rewrites its file every tick); read_all GCs it so the dir doesn't
    # accumulate remnants across restarts. Far beyond staleness, so a live unit is never hit.
    _GC_AGE_MULT = 20.0
    _GC_AGE_FLOOR_S = 300.0

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _filename(engine: str, tier: str, node: str, instance: str = "") -> str:
        # The file is keyed by the FULL publishing-unit identity (engine, tier, node,
        # instance), each optional part appended only when set. Each part is load-bearing:
        #   * node — two HOSTS accidentally sharing the dir (NFS/PV) must not both write
        #     `<engine>.json` (last-writer-wins destroys a host's own snapshot → it reads a
        #     foreign node, filters itself out, sizes from an empty view → oversubscription).
        #   * tier — ONE host can run the same engine on firecracker AND gvisor (two pools);
        #     without the tier they'd share `<engine>.json` and each size to the whole budget.
        #   * instance — two REPLICAS of the same engine/tier/node (a rolling deploy's brief
        #     overlap) are two real pools; a shared file would let each take the full ceiling.
        # `@` can't appear in an engine slug, a runtime name, a DNS hostname, or a pid, so the
        # join is unambiguous. Default (all optional parts "") keeps the plain `<engine>.json`.
        parts = [engine, *([tier] if tier else []), *([node] if node else []),
                 *([instance] if instance else [])]
        return "@".join(parts) + ".json"

    def publish(self, snap: DemandSnapshot) -> None:
        name = self._filename(snap.engine, snap.tier, snap.node, snap.instance)
        path = self._dir / name
        # Path-traversal guard: the identity components ARE the filename, so a component with
        # '/', '\\' or '..' (a hostile/typo'd engine name or BLASTBOX_NODE_ID) could escape
        # the share dir and clobber an unrelated file. Refuse anything that isn't a plain
        # basename resolving directly under the dir.
        if os.sep in name or (os.altsep and os.altsep in name) or path.parent != self._dir:
            raise ValueError(f"unsafe snapshot identity {name!r}: path separators not allowed")
        # Write via an UNPREDICTABLE temp file (tempfile.mkstemp uses O_CREAT|O_EXCL, 0600),
        # then atomically rename it in. A predictable `<pool>.json.tmp` could be pre-created by
        # a peer as a symlink so a plain write_text() follows it and truncates a file outside
        # the dir; an unpredictable, exclusively-created temp closes that. os.replace onto the
        # destination replaces a symlink there rather than following it.
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(asdict(snap)))
            os.replace(tmp, path)               # atomic swap; readers never see a partial file
        except BaseException:
            try:
                os.unlink(tmp)                  # don't leave the temp behind on failure
            except OSError:
                pass
            raise

    def remove(self, snap: DemandSnapshot) -> None:
        """Delete this unit's own snapshot — called on a graceful stop so a restart doesn't
        leave a phantom pool lingering in the node view for a whole staleness window."""
        try:
            (self._dir / self._filename(snap.engine, snap.tier, snap.node, snap.instance)).unlink()
        except OSError:
            pass                                # already gone / not ours to worry about

    def read_all(self, *, max_age_s: float, now: float) -> list[DemandSnapshot]:
        out: list[DemandSnapshot] = []
        gc_age = max(self._GC_AGE_FLOOR_S, max_age_s * self._GC_AGE_MULT)
        for f in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                # Drop UNKNOWN keys before constructing: during a rolling upgrade a NEWER
                # peer may add a DemandSnapshot field, and an OLDER reader passing it to the
                # constructor would raise TypeError (unexpected kwarg) → the file is skipped
                # → that peer silently drops out of this node's view → oversubscription. So
                # tolerate extra fields. (The reverse direction — an older writer omitting a
                # field a newer reader needs — is handled by giving new fields defaults, as
                # `node`/`tier` do.) A non-dict payload makes .items() raise → skipped.
                snap = DemandSnapshot(**{k: v for k, v in data.items()
                                         if k in DemandSnapshot.__dataclass_fields__})
                # Anti-impersonation: the filename must be EXACTLY the canonical slug of the
                # snapshot's self-declared (engine, tier, node, instance). A file can't claim
                # another unit's identity, and one unit can't masquerade as another's pool.
                # validate INSIDE the try: an untyped dataclass accepts wrong-typed fields
                # (e.g. slot_ram_mib=null), so `_valid`'s comparisons can raise TypeError —
                # that must skip the poisoned file, not propagate out and kill the sizer.
                # Age bounded BOTH ways: reject a snapshot more than one staleness window in
                # the FUTURE (bad clock / far-future stale file) — otherwise its negative age
                # reads as fresh forever and a stopped engine keeps consuming node budget.
                identity_ok = f.name == self._filename(snap.engine, snap.tier, snap.node,
                                                       snap.instance)
                age = now - snap.ts if math.isfinite(snap.ts) else None
                if identity_ok and age is not None and age > gc_age:
                    f.unlink(missing_ok=True)   # GC a crashed process's long-abandoned remnant
                    continue
                ok = _valid(snap) and identity_ok and age is not None and -max_age_s <= age <= max_age_s
            except Exception:
                continue                        # torn / foreign / type-poisoned → doesn't contribute
            if ok:
                out.append(snap)
        return out


# A snapshot is a request to spend node resources, so validate it — even a stray/hostile
# file can't drive a spawn-storm or an unbounded water-fill (identity/filename agreement is
# checked separately by the caller):
#   * engine/tier/node must be STRINGS (they form the identity + are compared/joined),
#   * footprints must be POSITIVE (a 0 footprint makes plan_sizes' fit() always true →
#     it would water-fill to max_ceiling; also a plain misconfig guard),
#   * counts non-negative, ceiling positive and sanity-capped.
_MAX_CEILING_SANE = 4096
_MAX_SLOT_RAM_MIB = 1024 * 1024        # 1 TiB per slot — no real microVM is bigger
_MAX_COUNT = 1 << 30                   # sane cap on backlog/assigned (a real queue is small)
_MAX_WEIGHT = 1 << 20


def _finite_in(x: object, lo: float, hi: float) -> bool:
    # json parses 1e999→inf and huge integers into arbitrary-precision ints, both of which
    # pass a bare `>= 0`; a NON-FINITE or over-cap value must be rejected, because it later
    # flows into float()/ceil() arithmetic (float(10**400) raises OverflowError and would
    # wedge the whole sizer for as long as the file exists). NB: a huge int must be
    # range-checked WITHOUT float conversion — even math.isfinite(10**400) overflows.
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return False
    if isinstance(x, float) and not math.isfinite(x):
        return False
    return lo <= x <= hi                      # int compare is exact (no float coercion)


def _valid(snap: DemandSnapshot) -> bool:
    return (
        isinstance(snap.engine, str) and isinstance(snap.tier, str)
        and isinstance(snap.node, str) and isinstance(snap.instance, str)
        and _finite_in(snap.slot_ram_mib, 1e-9, _MAX_SLOT_RAM_MIB) and snap.slot_ram_mib > 0
        and _finite_in(snap.slot_vcpus, 1e-9, 1024) and snap.slot_vcpus > 0
        and _finite_in(snap.backlog, 0, _MAX_COUNT)
        and _finite_in(snap.assigned, 0, _MAX_COUNT)
        and _finite_in(snap.max_ceiling, 1, _MAX_CEILING_SANE)
        and _finite_in(snap.min_warm, 0, _MAX_CEILING_SANE)
        and _finite_in(snap.weight, 0, _MAX_WEIGHT)
        and math.isfinite(snap.ts)           # a non-finite ts would never age out
    )
