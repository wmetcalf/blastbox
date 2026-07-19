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
import time as _time
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
    node: str = ""               # publishing host — so a share_dir accidentally shared across
                                 # hosts (NFS) doesn't conflate their demand/budget. INVARIANT:
                                 # every unit sharing a dir MUST use a CONSISTENT node id — all
                                 # "" for a single host's local dir, or each host a DISTINCT id
                                 # when a dir is (accidentally) shared. An untagged reader
                                 # (node="") treats untagged peers as same-node, so mixing a
                                 # tagged host and an untagged host on ONE shared dir conflates
                                 # them → oversubscription. Tag every host, or don't share dirs.
    tier: str = ""               # the pool's runtime tier (firecracker/gvisor). Part of the
                                 # identity: ONE engine can run on TWO node-managed tiers on
                                 # one host (separate pools) — without the tier they'd share a
                                 # key and collapse into one, each sizing to the whole budget.
    refresh_s: float = 0.0       # the publisher's own expected refresh period (interval +
                                 # measured tick cost). A reader ages this snapshot out by the
                                 # LARGER of its own staleness window and this, so a publisher
                                 # whose backlog count is consistently slow (a huge shared-store
                                 # scan) isn't expired by fast peers mid-count → oversubscription.
    instance: str = ""           # the publishing PROCESS's random per-process token (NOT pid —
                                 # containers share pid 1). Part of the identity so two replicas
                                 # of the same engine/tier/node on one host — e.g. briefly
                                 # overlapping during a rolling deploy — are TWO distinct pools
                                 # that split the budget in plan_sizes, rather than colliding on
                                 # one file and each taking the full ceiling.
    balancing: bool = False      # this unit's allocation MODE (backlog-balancing vs static
                                 # weight). Published so every reader derives ONE consensus mode
                                 # for the whole node view — if dispatchers on a node disagreed
                                 # and each applied its OWN mode to the shared snapshots, they'd
                                 # compute different plans and their slices could sum past the
                                 # budget (N-way oversubscription). See DispatcherSizer.tick.
    stale_after_s: float = 0.0   # the publisher's OWN staleness window. Published so EVERY reader
                                 # ages this unit out by the SAME (publisher-declared) horizon —
                                 # if each reader used its own local window, a slow-but-live peer
                                 # could be aged out by fast readers and kept by slow ones, giving
                                 # them different snapshot sets → different plans → oversubscription.
                                 # 0 = unspecified (older peer) → reader falls back to its own value.
    budget_ram_mib: float = 0.0  # this unit's view of the NODE budget (RAM/vCPU), after headroom
    budget_vcpus: float = 0.0    # + adaptive scaling. Published so readers reconcile to ONE
                                 # budget (the elementwise MIN across the view) — dispatchers
                                 # with different headroom/vcpu config or adaptive scale otherwise
                                 # each plan against their OWN budget and pick incompatible slices
                                 # that sum past the true budget. 0.0 = unknown → ignored in the
                                 # consensus (older peer / pre-budget snapshot).


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
        existed = self._dir.exists()
        self._dir.mkdir(parents=True, exist_ok=True)
        if not existed:
            # We just AUTO-created the dir. Dispatchers for different engines can run under
            # DIFFERENT UIDs; each must be able to create its own `<identity>.json`. A dir made
            # under the default umask (0755) would let peers READ but not WRITE, so every
            # other-UID peer's publish would fail and it would fall back to static sizing while
            # THIS process sees only itself and allocates the whole node budget. Make it sticky
            # world-writable (0o1777, /tmp semantics): any peer can create its own file, the
            # sticky bit stops one peer unlinking another's (GC already tolerates a failed
            # unlink), and each owner can always rewrite/remove its own snapshot.
            #
            # If an operator PRE-PROVISIONED the dir (the trust-sensitive path in the module
            # docstring — tight per-owner perms on a mounted dir), we leave its perms untouched.
            try:
                os.chmod(self._dir, 0o1777)
            except OSError:
                pass

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

    def _safe_path(self, snap: DemandSnapshot) -> Path:
        """The snapshot's file path, GUARDED against traversal: the identity components ARE
        the filename, so a component with '/', '\\' or '..' (a hostile/typo'd engine name or
        BLASTBOX_NODE_ID) could escape the share dir and clobber/unlink an unrelated file.
        Refuse anything that isn't a plain basename resolving directly under the dir. Used by
        BOTH publish and remove so neither can be steered outside the dir."""
        name = self._filename(snap.engine, snap.tier, snap.node, snap.instance)
        path = self._dir / name
        if os.sep in name or (os.altsep and os.altsep in name) or path.parent != self._dir:
            raise ValueError(f"unsafe snapshot identity {name!r}: path separators not allowed")
        return path

    def publish(self, snap: DemandSnapshot) -> None:
        path = self._safe_path(snap)
        name = path.name
        # Write via an UNPREDICTABLE temp file (tempfile.mkstemp uses O_CREAT|O_EXCL, 0600),
        # then atomically rename it in. A predictable `<pool>.json.tmp` could be pre-created by
        # a peer as a symlink so a plain write_text() follows it and truncates a file outside
        # the dir; an unpredictable, exclusively-created temp closes that. os.replace onto the
        # destination replaces a symlink there rather than following it.
        fd, tmp = tempfile.mkstemp(dir=self._dir, prefix=f".{name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(asdict(snap)))
            # mkstemp makes the file 0600; make it world-READable so peer dispatchers running
            # under a DIFFERENT uid (each engine container may) can read the node view — else
            # they get PermissionError, drop this pool, and oversubscribe. The payload is
            # non-sensitive demand data (engine/tier/counts). Writable stays owner-only.
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)               # atomic swap; readers never see a partial file
        except BaseException:
            try:
                os.unlink(tmp)                  # don't leave the temp behind on failure
            except OSError:
                pass
            raise

    def remove(self, snap: DemandSnapshot) -> None:
        """Delete this unit's own snapshot — called on a graceful stop so a restart doesn't
        leave a phantom pool lingering in the node view for a whole staleness window. Goes
        through the same traversal guard as publish, so an unsafe identity can't unlink
        outside the dir."""
        try:
            self._safe_path(snap).unlink()
        except (OSError, ValueError):
            pass                                # already gone / unsafe / not ours to worry about

    def read_all(self, *, max_age_s: float, now: float) -> list[DemandSnapshot]:
        out: list[DemandSnapshot] = []
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
                # ts is bounded via _finite_in (NOT bare math.isfinite, which OVERFLOWS on a
                # huge-int ts out of json and would crash-skip — the same reason every other
                # numeric field uses _finite_in). Age bounded BOTH ways: a snapshot more than
                # one staleness window in the FUTURE (bad clock) is rejected too, or its
                # negative age would read as fresh forever.
                # Effective staleness window is PUBLISHER-DECLARED so every reader agrees on when this
                # unit is stale: the LARGER of its refresh period (×2, one missed beat) and its own
                # configured stale_after_s. Both come from the SNAPSHOT, not the reader, so two
                # readers with different local cadence/config can't disagree about a peer's liveness
                # (which would split the node into divergent plans → oversubscription). Falls back
                # to the reader's own max_age_s only when the publisher declared neither (a
                # pre-upgrade snapshot). Capped at the GC floor so a spoofed window can't keep a
                # phantom past the mtime sweep.
                declared = max(
                    snap.refresh_s * 2.0 if _finite_in(snap.refresh_s, 0, _MAX_TS) else 0.0,
                    snap.stale_after_s if _finite_in(snap.stale_after_s, 0, _MAX_TS) else 0.0)
                eff = min(declared, self._GC_AGE_FLOOR_S) if declared > 0 else max_age_s
                ok = (_valid(snap)
                      and f.name == self._filename(snap.engine, snap.tier, snap.node, snap.instance)
                      and _finite_in(snap.ts, -_MAX_TS, _MAX_TS)
                      and -eff <= (now - snap.ts) <= eff)
            except Exception:
                continue                        # torn / foreign / type-poisoned → doesn't contribute
            if ok:
                out.append(snap)
        self._gc(max(self._GC_AGE_FLOOR_S, max_age_s * self._GC_AGE_MULT))
        return out

    def _gc(self, older_than_s: float) -> None:
        """Sweep long-abandoned files by FILESYSTEM mtime — both stale `*.json` snapshots a
        crashed process never gracefully removed AND leaked `*.tmp` temps from a publish
        killed mid-write (which the `*.json` view never enumerates, so they'd accumulate on a
        substrate that gets OOM-killed). mtime (not the parsed ts) is robust to a malformed or
        hostile payload and, re-stat'd here, spares a file an owner just re-published (fresh
        mtime) — closing the read-then-unlink race a ts-based GC had. Best-effort; far beyond
        the staleness window, so a live unit (rewritten every tick) is never hit."""
        now_wall = _time.time()
        try:
            entries = list(self._dir.iterdir())   # iterdir sees dotfiles (mkstemp temps)
        except OSError:
            return
        for f in entries:
            if not (f.name.endswith(".json") or f.name.endswith(".tmp")):
                continue
            try:
                if f.is_file() and now_wall - f.stat().st_mtime > older_than_s:
                    f.unlink()
            except OSError:
                continue                        # gone / racing another reader's GC — fine


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
_MAX_TS = 1 << 40                      # ~year 36812: any unix ts fits; rejects a huge-int ts
                                       # via _finite_in WITHOUT float coercion (float(10**400)
                                       # and even bare math.isfinite(10**400) OverflowError).


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
        and _finite_in(snap.ts, -_MAX_TS, _MAX_TS)   # bounded (NOT bare math.isfinite, which
        and _finite_in(snap.refresh_s, 0, _MAX_TS)   # OverflowErrors on a huge-int ts/refresh)
        # Consensus fields — validate here too, else a poisoned budget_ram_mib="oops" survives
        # read_all and every later tick raises on `s.budget_ram_mib > 0`; because the heartbeat
        # already published, the run loop then retries forever and freezes the pool at a stale
        # allocation instead of just skipping the one bad file. 0 = "unknown budget" (allowed).
        and isinstance(snap.balancing, bool)
        and _finite_in(snap.budget_ram_mib, 0, _MAX_SLOT_RAM_MIB * _MAX_CEILING_SANE)
        and _finite_in(snap.budget_vcpus, 0, 1024 * _MAX_CEILING_SANE)
        and _finite_in(snap.stale_after_s, 0, _MAX_TS)
    )
