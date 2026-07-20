"""Dispatcher-side self-sizer — the transport that fits blastbox's serve/dispatch split.

Runs inside the `dispatch` process (which owns the warm pool). Each tick it publishes its
own demand to the shared node view and reads every peer's, then runs the SAME
deterministic allocation (node_sizer.plan_sizes) over the whole node and resizes ITS OWN
pool. Because every engine's dispatcher runs the identical allocation over the identical
shared view, the node partitions consistently — no central daemon, no HTTP push, no admin
endpoint. Off unless NodeConfig enables resource_management or balancing.

Consistency is EVENTUAL, not instantaneous: dispatchers publish/read on their own clocks
(and adaptive scale is per-process), so two engines can act on slightly divergent views
for one interval and transiently sum above budget. That window is bounded — the staleness
horizon is short, each engine's real RAM use is capped by IDLE-slot reaping + the warm
target tracking demand, and the views reconverge next tick — so it self-corrects rather
than drifting; it is not a hard oversubscription guarantee.
"""

from __future__ import annotations

import logging
import math
import os
import secrets
import threading
import time
from typing import Callable, Optional

from .node_config import EngineNode, NodeConfig, _is_safe_slug
from .node_share import DemandSnapshot, FileNodeShare, NodeShare
from .node_sizer import (
    NodeBudget,
    PoolSize,
    PoolSpec,
    _mem_available_mib,
    manages,
    node_capacity,
    plan_sizes,
)


def _pool_key(engine: str, tier: str, instance: str = "") -> str:
    """Identity of a warm pool within a node view = (engine, tier, instance). The same engine
    on two node-managed tiers on one host is two distinct pools; two REPLICAS of one
    engine/tier (a rolling deploy's brief overlap) are also two distinct pools. Keying by
    engine alone would merge them in the allocation and each would take the whole budget.
    Deterministic + identical across every dispatcher, so all agree on the plan. (node is not
    in the key — the view is already node-filtered.)"""
    return "@".join([engine, *([tier] if tier else []), *([instance] if instance else [])])


class DispatcherSizer:
    def __init__(
        self,
        engine: EngineNode,
        pool: object,                         # the local WarmPool (assigned_count/resize)
        share: NodeShare,
        config: NodeConfig,
        *,
        runtime: str,                         # the pool's runtime NAME (BLASTBOX_POOL_RUNTIME /
                                              # dispatcher tier) — WarmPool.runtime is the
                                              # SlotRuntime OBJECT, not a name, so gating must
                                              # use this string.
        backlog_fn: Callable[[], int],        # this engine's own QUEUED count (total, tier-scoped)
        untargeted_backlog_fn: Optional[Callable[[], int]] = None,  # of that total, the UNTARGETED
                                              # count (target_tier IS NULL). None → no cross-tier
                                              # dedup (all backlog treated as tier-local).
        node: Optional[str] = None,           # physical-node id; default from BLASTBOX_NODE_ID
        instance: Optional[str] = None,       # publishing process id; default os.getpid()
        capacity_fn: Callable[[float, float], NodeBudget] = node_capacity,
        avail_fn: Callable[[], Optional[float]] = _mem_available_mib,
        clock: Callable[[], float] = time.time,
        concurrency_gate: object = None,      # DynamicConcurrencyGate; its live limit tracks
                                              # the pool ceiling so CONCURRENT jobs (warm+cold)
                                              # never exceed the budget-allocated ceiling.
        cold_slot_ram_mib: float = 0.0,       # cold worker footprint (BLASTBOX_WORKER_MEMORY) in
                                              # MiB; prices cold permits. 0 = unknown → warm 1:1.
    ) -> None:
        self._engine = engine
        self._pool = pool
        self._gate = concurrency_gate
        self._cold_slot_ram_mib = max(0.0, float(cold_slot_ram_mib))
        self._share = share
        self._config = config
        self._runtime = (runtime or "").strip().lower()
        self._backlog_fn = backlog_fn
        self._untargeted_backlog_fn = untargeted_backlog_fn
        self._last_untargeted = 0             # last untargeted count (published in the snapshot)
        # The publishing PROCESS identity, so two replicas of this engine/tier/node (a rolling
        # deploy's overlap) publish to DISTINCT files and split the budget instead of
        # colliding. A RANDOM per-process token, NOT os.getpid(): each dispatcher runs in its
        # own container where pid is almost always 1, so pid would collide across replicas.
        # On a graceful stop we remove our own file so a restart leaves no phantom.
        self._instance = str(instance if instance is not None else secrets.token_hex(8))
        # The node id must identify the PHYSICAL HOST, shared by every engine container on
        # it — NOT socket.gethostname(), which inside a container is the container's own
        # name (so each engine would see only itself → no coordination, the common toolz2
        # layout). Default "" means "the share_dir IS the node boundary" (correct when all
        # of a host's engines bind-mount one dir); set BLASTBOX_NODE_ID per physical host
        # only to defend a share_dir accidentally shared ACROSS hosts.
        self._node = node if node is not None else os.environ.get("BLASTBOX_NODE_ID", "").strip()
        # The node id becomes a filename component; a '/'/'\\'/'..' would make every publish
        # raise (traversal guard) and the sizer loop forever without ever publishing → peers
        # oversubscribe. Validate here (engine names are validated in from_env; this is the
        # other identity component that comes from raw env). Empty is fine (the default).
        if self._node and not _is_safe_slug(self._node):
            raise ValueError(
                f"BLASTBOX_NODE_ID {self._node!r} is not a safe slug "
                "(letters/digits/._- only, no path separators or '..')")
        self._capacity_fn = capacity_fn
        self._avail_fn = avail_fn
        self._clock = clock
        self._budget_scale = 1.0              # adaptive correction, persisted across ticks
        self._last_tick_dur = 0.0             # measured, to widen the staleness window
        self._last_backlog = 0                # published as a heartbeat before the (slow) count
        self._stop_event: Optional[threading.Event] = None  # set in run(); fences the update-publish
        self._warned_mixed_nodes = False      # one-shot: warn on an inconsistent node-id view
        self._warned_mixed_modes = False      # one-shot: warn on mixed balancing modes on a node
        self._last_view_ok = 0.0              # clock of the last tick that CONFIRMED we're visible
                                              # (published AND read our own snapshot back) — the
                                              # fail-closed timer, covering both write and read loss
        self._publish_lock = threading.Lock()  # serialize each publish against the CLI's final
                                              # remove/lease — else a publish still in flight past
                                              # the join could os.replace() a removed file back or
                                              # clobber the orphan lease with a short-lived heartbeat
        self._count_thread: Optional[threading.Thread] = None   # the single outstanding backlog
        self._count_result: dict = {}                           # count (a wedged one mustn't spawn
                                                                # a new thread every tick)

    def _cold_only(self) -> bool:
        """A pool-less cold dispatcher: no warm pool to resize, just a gate + a cold reservation.
        Requires BOTH no pool AND the cold tier — so a directly-constructed sizer for some other
        pool-less runtime can't accidentally activate as a managed cold pool."""
        return self._pool is None and self._runtime == "cold"

    def _active(self) -> bool:
        cfg = self._config
        # Mirror NodeConfig.active — adaptive counts too. from_env folds adaptive into
        # resource_management, but a DIRECTLY-constructed NodeConfig(adaptive=True,
        # resource_management=False) would otherwise no-op here despite active=True.
        # A pool-less cold-only sizer is managed too (its docker workers still consume the budget),
        # even though "cold" isn't a warm-managed runtime.
        return (cfg.resource_management or cfg.balancing or cfg.adaptive) and (
            manages(self._runtime) or self._cold_only())

    # Adaptive control loop bounds. Deliberately a DAMPED, asymmetric ramp (shrink faster
    # than grow) rather than a hard MemAvailable cap: a cap that tracks free RAM directly
    # oscillates (shrink pools → free rises → cap rises → grow → free drops → …). Extending
    # this proven-stable loop's range with a low floor lets it shed enough to honour min_free
    # under severe pressure without a second, unstable control loop. It's best-effort host
    # protection — for a HARD OOM guarantee use cgroup memory limits on the engine containers.
    _SCALE_FLOOR = 0.25          # shed up to 75% of the budget under sustained memory pressure
    _SCALE_DOWN = 0.10           # per tick when free < min_free (fast shrink)
    _SCALE_UP = 0.05             # per tick when free > 2·min_free (slow grow — conservative)

    def _adapt(self, budget: "NodeBudget") -> "NodeBudget":
        """Nudge the RAM budget from observed free memory when BLASTBOX_NODE_ADAPTIVE is
        on. Persisted across ticks. The UP-scale is capped so the adapted budget never
        exceeds physical RAM: with headroom_frac h the baseline budget is total·h, so the
        scale is capped at 1/h (times the safety 1.25) — otherwise a high headroom (e.g.
        1.0) × 1.25 would target 125% of node RAM → OOM. The DOWN-scale floors at
        _SCALE_FLOOR so it can shed most of the budget under real memory pressure (the
        1-per-engine baseline still keeps every pool viable)."""
        if not self._config.adaptive:
            return budget
        free = self._avail_fn()
        if free is None:
            return budget
        hi = min(1.25, 1.0 / max(self._config.ram_headroom_frac, 0.05))
        floor = self._config.min_free_mib
        if free < floor:
            self._budget_scale = max(self._SCALE_FLOOR, self._budget_scale - self._SCALE_DOWN)
        elif free > floor * 2:
            self._budget_scale = min(hi, self._budget_scale + self._SCALE_UP)
        self._budget_scale = min(self._budget_scale, hi)   # clamp if headroom changed
        return NodeBudget(ram_mib=budget.ram_mib * self._budget_scale, vcpus=budget.vcpus)

    def _size_to_floor(self) -> "PoolSize":
        """Fail-closed sizing: shrink to the genuinely minimal viable target and never grow. Used
        when the node view is globally inconsistent (mixed node ids) so no local plan can be made
        safe. The floor is ONE slot — the same 1-per-engine baseline plan_sizes uses — NOT the
        configured min_warm: with an inconsistent view a dispatcher can't know how many peers
        exist, so honouring a big min_warm (e.g. 8) would let N dispatchers each resize to 8 and
        oversubscribe the very node this branch is protecting. Ceiling 1 / warm ≤ 1 is the safest
        each can pick independently (matches the undersized-node baseline) until the operator sets
        a consistent BLASTBOX_NODE_ID."""
        e = self._engine
        ceiling = 1
        warm = 0 if self._cold_only() else (1 if e.min_warm >= 1 else 0)
        if hasattr(self._pool, "resize"):
            self._pool.resize(  # type: ignore[attr-defined]
                warm_size=warm, concurrent_ceiling=ceiling)
        # Bound the gate UNCONDITIONALLY — NOT only when there's a warm pool. A cold-only
        # dispatcher has no pool to resize, but its concurrency gate must STILL be floored here
        # (to ceiling−warm = 1 cold worker), or the fail-closed net leaves it admitting the full
        # budgeted ceiling exactly when the node view is inconsistent / unreadable (oversubscription
        # in the case this method exists to prevent). set_limit floors at 1.
        if self._gate is not None:
            self._gate.set_limit(ceiling - warm)  # type: ignore[attr-defined]
        return PoolSize(warm_size=warm, concurrent_ceiling=ceiling)

    def tick(self) -> Optional[PoolSize]:
        """Publish own demand, read the node view, size the local pool. Returns this
        engine's decided size (None when the feature is off or the view is empty)."""
        if not self._active():
            return None
        started = self._clock()
        e = self._engine
        # Two DIFFERENT active-work counts, kept separate on purpose:
        #  * assigned_warm — WARM slots busy now. Drives the WARM target (warm slots to keep hot).
        #    Cold work must NOT inflate this: cold jobs bypass the warm pool, so counting them
        #    would warm VMs they can never use AND shrink the cold headroom (ceiling − warm) to
        #    its floor → an egress batch would run essentially serially.
        #  * assigned (total) — the PUBLISHED reservation (the pool's ceiling SHARE). It is the
        #    MAX of active work and CURRENTLY-RESIDENT slots:
        #      - active work = warm-assigned + cold in flight. Cold jobs have already LEFT the
        #        queued backlog and hold no warm slot, so without them the snapshot under-reports
        #        demand and the planner could shrink this pool while cold work still runs (the gate
        #        can't recall in-flight permits).
        #      - resident slots — resize() only moves setpoints; surplus IDLE/WARMING VMs aren't
        #        reaped until a later pool tick. If demand drops and we advertised the LOWER share
        #        immediately, a peer would spawn into the "freed" budget while our old VMs still
        #        consume it (the cold gate only bounds OUR cold admission, not the peer). Holding
        #        the reservation at current residency until it actually reaps means we shrink FIRST
        #        and peers grow only as fast as we truly free RAM — no cross-pool oversubscription.
        # assigned_warm — WARM slots busy now. Drives the WARM target only. Cold work must NOT
        # inflate this: cold jobs bypass the warm pool, so counting them would warm VMs they can
        # never use AND shrink the cold headroom to its floor (an egress batch would run serially).
        assigned_warm = int(getattr(self._pool, "assigned_count", 0))      # cheap

        # The PUBLISHED reservation (the pool's ceiling SHARE) is re-sampled FRESH at each publish
        # (heartbeat AND the post-count update), not captured once at tick start: the backlog count
        # can be a slow shared-store scan during which the pool grows, and re-publishing a stale
        # reservation with a fresh ts would let a peer treat the just-grown residency as free.
        #   footprint = max(warm-assigned, warm residency) + cold in flight, because:
        #     - resident warm VMs persist until an async reap (resize() only moves setpoints), so
        #       we must keep reserving them until they actually drain — else a peer grows into the
        #       "freed" budget while our VMs still hold it;
        #     - cold workers spawn OUTSIDE the warm pool and COEXIST with warm residency, so they
        #       ADD to it (a max would understate by min(idle_warm, cold_in_flight)); AND they are
        #       priced in WARM-SLOT EQUIVALENTS — the planner values `assigned` at slot_ram_mib, so
        #       a 4 GiB cold worker on a 2 GiB slot must reserve 2 units, not 1, or a peer would
        #       allocate the missing RAM (the same conversion the cold GATE already applies).
        cold_ram = self._cold_slot_ram_mib or e.slot_ram_mib
        cold_units = (cold_ram / e.slot_ram_mib) if e.slot_ram_mib > 0 else 1.0

        def _reservation() -> int:
            aw = int(getattr(self._pool, "assigned_count", 0))
            res = int(getattr(self._pool, "slot_count", 0))
            cif = int(getattr(self._gate, "in_flight", 0)) if self._gate is not None else 0
            return max(aw, res) + math.ceil(cif * cold_units)

        # Compute OUR view of the node budget up front so we can PUBLISH it: readers reconcile to
        # one budget (the elementwise MIN across the view), so a dispatcher with a different
        # headroom/vcpu config or adaptive scale can't plan against a bigger budget than a peer
        # and pick an incompatible slice that oversubscribes the node.
        my_budget = self._adapt(self._capacity_fn(self._config.ram_headroom_frac,
                                                  self._config.vcpu_oversubscription))

        # tell peers our expected refresh period so a slow count doesn't get us aged out
        refresh_s = self._config.interval_s + self._last_tick_dur
        def _snapshot(backlog: int, ts: float) -> DemandSnapshot:
            return DemandSnapshot(
                engine=e.name, backlog=backlog, assigned=_reservation(),
                slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
                min_warm=e.min_warm, max_ceiling=e.max_ceiling, weight=e.weight, ts=ts,
                node=self._node, tier=self._runtime, instance=self._instance,
                refresh_s=refresh_s, balancing=self._config.balancing,
                budget_ram_mib=my_budget.ram_mib, budget_vcpus=my_budget.vcpus,
                stale_after_s=self._config.stale_after_s,
                untargeted_backlog=min(backlog, self._last_untargeted))

        # HEARTBEAT before the (possibly-slow) count: publish a fresh-ts snapshot with the last
        # tick's backlog so peers keep seeing us alive even when THIS count — a huge shared-
        # store scan — runs long; otherwise they age us out mid-count and reallocate our share
        # → oversubscription. (For a count longer than the staleness window, also raise
        # BLASTBOX_NODE_STALE_AFTER_S; see docs.) FENCED on stop like the update below, so a
        # shutdown that already removed our file isn't followed by a heartbeat republish.
        if self._stop_event is not None and self._stop_event.is_set():
            return None
        with self._publish_lock:
            self._share.publish(_snapshot(self._last_backlog, started))
        # Run the (possibly slow) count in a thread and KEEP RE-PUBLISHING the heartbeat while it
        # runs, so a count that unexpectedly exceeds the staleness window doesn't let peers expire
        # us mid-count and reallocate our still-live pool. A snapshot's advertised refresh_s reflects
        # the PRIOR tick, so it can't cover an unobserved slow query — an active heartbeat can.
        #
        # Keep at most ONE outstanding count: if a prior tick's count is STILL wedged, do NOT spawn
        # another (that would accumulate a daemon thread + a store connection every tick until the
        # process OOMs). Skip the count this tick and use the last-known backlog; the single
        # outstanding thread's result is picked up whenever it finishes.
        if self._count_thread is not None and self._count_thread.is_alive():
            backlog = self._last_backlog
        else:
            # CONSUME a prior count that finished AFTER its deadline (between ticks) before starting
            # a replacement — otherwise a query that's consistently just over the deadline would
            # have every sample discarded and _last_backlog would never advance (stuck at the floor
            # despite queued work).
            if self._count_thread is not None and "v" in self._count_result:
                self._last_backlog = self._count_result["v"]
                if "u" in self._count_result:
                    self._last_untargeted = self._count_result["u"]
            self._count_result = {}
            holder = self._count_result

            def _count() -> None:
                try:
                    holder["v"] = max(0, int(self._backlog_fn()))
                    # of the total, the UNTARGETED portion — for cross-tier dedup (an engine's
                    # untargeted queue is drained by ALL its tiers, so count it once). Clamp to the
                    # total (the two counts run in one thread but aren't a single snapshot).
                    if self._untargeted_backlog_fn is not None:
                        holder["u"] = min(holder["v"], max(0, int(self._untargeted_backlog_fn())))
                except Exception:
                    holder["v"] = self._last_backlog
            self._count_thread = threading.Thread(target=_count, name="node-sizer-count",
                                                  daemon=True)
            self._count_thread.start()
            # BOUND the wait: if count() wedges, don't hang here forever — the synchronous startup
            # tick would never return (dispatch never begins) and a running loop would never read
            # the node view again (a new peer could split the budget while we hold a stale ceiling)
            # nor reach the fail-closed check. Past the deadline, proceed with the last-known
            # backlog and let the (single) daemon thread finish in the background.
            deadline = self._clock() + max(self._config.stale_after_s, self._config.interval_s * 3)
            heartbeat_s = max(0.5, self._config.interval_s)
            while self._count_thread.is_alive() and self._clock() < deadline:
                self._count_thread.join(timeout=heartbeat_s)
                if self._stop_event is not None and self._stop_event.is_set():
                    break
                if self._count_thread.is_alive() and holder.get("v") is None:
                    with self._publish_lock:
                        self._share.publish(_snapshot(self._last_backlog, self._clock()))
            backlog = holder.get("v", self._last_backlog)
            self._last_untargeted = min(backlog, holder.get("u", self._last_untargeted))
        self._last_backlog = backlog
        now = self._clock()
        # UPDATED publish with the FRESH backlog so the node converges in one tick (not lagged).
        # FENCED on the stop event: on shutdown the CLI sets stop, times out the join while we
        # were mid-count, and removes our file — this guard means we don't then republish a
        # phantom after the count returns.
        if self._stop_event is None or not self._stop_event.is_set():
            with self._publish_lock:
                self._share.publish(_snapshot(backlog, now))
        # Effective staleness widens by the measured tick cost: the real publish period is
        # interval + tick_time, so a slow count (huge shared store) must not age peers out
        # and collapse every engine to "sees only itself" → node oversubscription. Use the
        # LARGER of the previous tick's duration and THIS tick's count latency (now - started):
        # a first tick, or a suddenly-slow count, would otherwise size against a window built
        # from a stale-fast previous duration and drop a live peer this very tick.
        this_tick_cost = max(0.0, now - started)
        max_age = max(self._config.stale_after_s,
                      (self._config.interval_s + max(self._last_tick_dur, this_tick_cost)) * 2.0)
        # Node filter, SYMMETRIC so a partial config (some engines set BLASTBOX_NODE_ID,
        # some not, on one host) still coordinates instead of each thinking it's alone
        # (→ oversubscription): include a peer if either side is untagged, or the tags
        # match. A set-vs-different-set pair (real cross-host isolation) is excluded.
        snaps = [s for s in self._share.read_all(max_age_s=max_age, now=now)
                 if s.node == "" or self._node == "" or s.node == self._node]
        self._last_tick_dur = max(0.0, self._clock() - started)
        # CONFIRM we're visible to the node: we published our snapshot moments ago, so a working
        # view MUST read it back. Seeing ourselves proves BOTH the write AND the read/list path
        # work — the fail-closed timer in run() keys on this, so a dispatcher that can still PUBLISH
        # but has lost the ability to READ the share (so it never notices peers reclaiming its
        # share) still shrinks instead of holding a stale ceiling that later bursts.
        mine_key = _pool_key(e.name, self._runtime, self._instance)
        if any(_pool_key(s.engine, s.tier, s.instance) == mine_key for s in snaps):
            self._last_view_ok = now
        if not snaps:
            return None
        # The node filter is symmetric (so a single host's partial node-id config still
        # coordinates), which makes an untagged reader see tagged peers too. But a view that
        # MIXES distinct node ids gives every process a DIFFERENT planner view (tagged A sees
        # {A, untagged}, tagged B sees {B, untagged}, untagged sees all three) → each plans from
        # a divergent subset and their slices sum PAST the budget. No local decision can fix a
        # globally-inconsistent view, so FAIL CLOSED: size to the warm floor only (never grow) and
        # warn. Every affected dispatcher does the same, so none over-allocates; the pool still
        # serves at its min_warm floor until the operator gives every co-located dispatcher a
        # CONSISTENT BLASTBOX_NODE_ID (all "" for one host, or one shared tag).
        if len({s.node for s in snaps}) > 1:
            if not self._warned_mixed_nodes:
                self._warned_mixed_nodes = True
                logging.getLogger("blastbox.node_sizer").warning(
                    "node view for %s mixes distinct node ids %s — refusing to grow (sizing to the "
                    "warm floor) to avoid oversubscribing from divergent views; set a CONSISTENT "
                    "BLASTBOX_NODE_ID on every co-located dispatcher (all \"\" for one host, or one "
                    "shared tag). See docs/CONFIGURATION.md.",
                    self._engine.name, sorted({s.node for s in snaps}))
            return self._size_to_floor()

        # CONSENSUS allocation mode across the node view. The demand basis (live backlog vs
        # static weight) must be identical for EVERY dispatcher on the node — otherwise each
        # applies its own mode to the same snapshots, computes a different plan, and their
        # self-slices can sum past the budget (e.g. a static unit takes its weight share while a
        # balancing neighbour with all the backlog takes a big share → 14 slots from a 10-slot
        # node). Derive ONE mode deterministically from the shared view so all readers agree:
        # balancing is on only if THIS unit AND every peer opts in (unanimous). A lone
        # misconfigured unit therefore can't silently flip the node's basis or oversubscribe it;
        # the node falls back to static (the conservative floor) and we warn once so an operator
        # aligns BLASTBOX_NODE_BALANCING. `all()` over the view already includes our own
        # published snapshot, but AND-ing the local flag is robust even if it isn't in view yet.
        peer_modes = {bool(getattr(s, "balancing", False)) for s in snaps}
        balancing = self._config.balancing and all(peer_modes)
        if len(peer_modes) > 1 and not self._warned_mixed_modes:
            self._warned_mixed_modes = True
            logging.getLogger("blastbox.node_sizer").warning(
                "node view for %s mixes BLASTBOX_NODE_BALANCING modes across dispatchers %s — "
                "using STATIC allocation for all (the safe consensus) to avoid oversubscribing "
                "the node budget; set a CONSISTENT balancing mode on every dispatcher of a node.",
                self._engine.name, sorted(peer_modes))
        # REPLICAS of the same (engine, tier) drain the SAME tier-scoped queue, so each reports the
        # WHOLE backlog as its own — 10 queued jobs across 2 replicas look like demand 20, doubling
        # that engine's share vs unrelated pools and warming each replica for all 10. Split the
        # shared backlog across the replicas draining it (by identical engine+tier), so the engine's
        # TOTAL backlog demand is counted once. Failover-safe: if a replica drops, the next tick
        # sees fewer replicas and each recomputes a larger share. (assigned is per-pool — the
        # replica's own residency — so it is NOT divided.)
        # SORTED instance lists per (engine, tier) so every dispatcher distributes a shared
        # quantity — and its integer remainder — IDENTICALLY across the same-queue replicas.
        replica_insts: dict[tuple[str, str], list[str]] = {}
        for s in snaps:
            replica_insts.setdefault((s.engine, s.tier), []).append(s.instance)
        for _lst in replica_insts.values():
            _lst.sort()

        def _share(total: float, engine: str, tier: str) -> float:
            return total / max(1, len(replica_insts.get((engine, tier), [None])))

        def _int_share(total: int, engine: str, tier: str, instance: str) -> int:
            # divide an integer quantity across same-queue replicas, handing the REMAINDER to the
            # lowest-ranked instances — so N replicas' shares still SUM to `total` (flooring alone
            # would give every replica 0 when total < N, stranding jobs in warm-only mode).
            insts = replica_insts.get((engine, tier), [instance])
            n = max(1, len(insts))
            base, rem = divmod(max(0, total), n)
            rank = insts.index(instance) if instance in insts else n
            return base + (1 if rank < rem else 0)

        # UNTARGETED jobs (target_tier IS NULL) are drained by EVERY tier of the engine, so their
        # demand is counted ONCE across ALL the engine's pools (fc + gvisor + replicas), not per
        # tier. TARGETED jobs stay tier-scoped (split across same-(engine,tier) replicas only).
        engine_pools: dict[str, int] = {}
        engine_insts: dict[str, list[tuple[str, str]]] = {}
        for s in snaps:
            engine_pools[s.engine] = engine_pools.get(s.engine, 0) + 1
            engine_insts.setdefault(s.engine, []).append((s.tier, s.instance))
        for _elst in engine_insts.values():
            _elst.sort()

        def _split(s) -> tuple[int, int]:
            """(targeted-to-this-tier, untargeted) from a snapshot's backlog."""
            u = max(0, min(s.backlog, int(getattr(s, "untargeted_backlog", 0))))
            return s.backlog - u, u

        def _backlog_demand(s) -> float:
            targeted, untargeted = _split(s)
            return (_share(targeted, s.engine, s.tier)                  # tier-scoped, per replica
                    + untargeted / max(1, engine_pools.get(s.engine, 1)))  # engine-wide, per pool

        def _engine_int_share(total: int, engine: str, tier: str, instance: str) -> int:
            # like _int_share, but over ALL of the engine's pools (every tier) — for splitting the
            # UNTARGETED count so the shares still SUM to it across the engine's tiers + replicas.
            lst = engine_insts.get(engine, [(tier, instance)])
            n = max(1, len(lst))
            base, rem = divmod(max(0, total), n)
            rank = lst.index((tier, instance)) if (tier, instance) in lst else n
            return base + (1 if rank < rem else 0)

        specs = [
            PoolSpec(
                # key each pool by (engine, tier, instance): the same engine on two node-
                # managed tiers, or two replicas of one engine/tier (rolling-deploy overlap),
                # are distinct pools competing for the budget — keying by engine alone would
                # collapse them and each would size to the whole budget. `_pool_key` matches
                # what THIS dispatcher looks up for itself below.
                name=_pool_key(s.engine, s.tier, s.instance),
                slot_ram_mib=s.slot_ram_mib, slot_vcpus=s.slot_vcpus,
                # ceiling water-fill: live backlog (balancing) or the static WEIGHT share — split
                # across same-queue replicas (and, for backlog, untargeted split engine-wide across
                # tiers) so a rolling overlap OR a multi-tier engine doesn't double its node share.
                demand=(_backlog_demand(s) + s.assigned) if balancing
                else _share(s.weight, s.engine, s.tier),
                # PER-ENGINE floor + cap are also split across same-queue replicas — else two
                # replicas of a cap-8 engine could each be allocated 8 (aggregate 16) and a floor
                # of 4 becomes an aggregate 8. Deterministic remainder so the shares sum to the
                # configured value; max_ceiling floored at 1 (a pool needs a runnable slot).
                min_warm=_int_share(s.min_warm, s.engine, s.tier, s.instance),
                # cap = the split share, but NEVER below this pool's own reservation — else
                # splitting a joining replica's cap would clip the INCUMBENT's hard `reserved`
                # floor (plan_sizes seats min(reserved, max_ceiling)) and a newcomer could grow
                # into slots the incumbent's still-resident VMs occupy (residency > budget until
                # they reap). Keeping cap >= reserved lets the incumbent hold its residency and
                # starves the newcomer's growth until the incumbent actually drains.
                max_ceiling=max(1, _int_share(s.max_ceiling, s.engine, s.tier, s.instance),
                                s.assigned),
                # the pool's published reservation (resident warm + cold in flight) is a HARD
                # ceiling floor — a peer must not be handed slots this pool is still running.
                reserved=s.assigned,
            )
            for s in snaps
        ]
        # CONSENSUS budget: reconcile to the elementwise MINIMUM budget across the view (our own
        # + every peer that published one). Dispatchers with a different headroom/vcpu config or a
        # different per-process adaptive scale otherwise each plan against their OWN budget and
        # pick incompatible slices that sum past the true node budget. Taking the min is the
        # conservative consensus: every reader computes the same (tightest) budget → the same plan
        # → Σ ≤ min ≤ everyone's actual, so the node is never oversubscribed. A peer that hasn't
        # published a budget yet (0.0 = unknown) is ignored rather than collapsing the budget to 0.
        peer_budget_ram = [s.budget_ram_mib for s in snaps if s.budget_ram_mib > 0]
        peer_budget_vcpus = [s.budget_vcpus for s in snaps if s.budget_vcpus > 0]
        budget = NodeBudget(
            ram_mib=min([my_budget.ram_mib, *peer_budget_ram]),
            vcpus=min([my_budget.vcpus, *peer_budget_vcpus]))
        plan = plan_sizes(specs, budget)  # type: ignore[arg-type]
        mine = plan.get(_pool_key(e.name, self._runtime, self._instance))
        if mine is not None and hasattr(self._pool, "resize"):
            # WARM tracks THIS engine's WARM-eligible demand (not the weight, a ceiling-share
            # ratio only; and not cold in-flight, which bypasses the warm pool) so static mode
            # doesn't hold idle engines hot: a big weight buys a big ceiling to burst into, but
            # few hot slots when idle. (A backlog of egress jobs still counts here — the sizer
            # can't cheaply tell which queued jobs resolve to egress; run a predominantly-egress
            # engine on the cold tier, not a warm-managed one, since warm-tier networking is a
            # future phase and those jobs bypass the warm pool anyway.)
            # Split the shared backlog across same-queue replicas HERE too (not just in the ceiling
            # demand): otherwise two overlapping replicas would each warm for the WHOLE queue —
            # 8 VMs for 4 jobs. Use the deterministic remainder split so the replicas' warm targets
            # still SUM to the backlog even when it's smaller than the replica count (a plain floor
            # would give every replica 0 and strand the job in warm-only mode).
            # split THIS pool's warm backlog: targeted per same-tier replica, untargeted engine-wide
            # across tiers — so a multi-tier engine doesn't warm each tier for the whole untargeted
            # queue. Both use the deterministic remainder split so the shares still SUM to the count.
            # Two intentional, SAFE-DIRECTION approximations here (never over-warm / oversubscribe):
            #  (a) COLD tiers are in `engine_insts` (they publish snapshots and DO claim untargeted
            #      target_tier-IS-NULL jobs via cold detonation), so they take a share of the
            #      untargeted WARM split too — a cold-only pool warms 0, letting its share fall to
            #      cold detonation rather than pre-warming it on the warm tiers. That under-warms the
            #      warm tiers by cold's share (latency onto the cold path), which is exactly a cold-
            #      only dispatcher's purpose; it reserves its own cold-footprint budget separately.
            #  (b) the untargeted warm target uses _engine_int_share's (tier,instance)-rank remainder
            #      bias while the ceiling water-fill breaks ties by snaps order, so under a tight
            #      budget + non-divisible untargeted one warmable job can stay QUEUED a tick (served
            #      when a slot frees or via cold). No job loss, Σwarm ≤ Σceiling ≤ budget always.
            my_targeted = max(0, backlog - min(backlog, self._last_untargeted))
            my_backlog = (_int_share(my_targeted, e.name, self._runtime, self._instance)
                          + _engine_int_share(min(backlog, self._last_untargeted),
                                              e.name, self._runtime, self._instance))
            # the warm FLOOR is also split across same-queue replicas — else two overlapping
            # replicas each hold the full min_warm hot (aggregate 2× the configured floor).
            my_min_warm = _int_share(e.min_warm, e.name, self._runtime, self._instance)
            warm = min(mine.concurrent_ceiling, max(my_min_warm, my_backlog + assigned_warm))
            mine = PoolSize(warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
            self._pool.resize(  # type: ignore[attr-defined]
                warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
            # Drive the dispatcher's COLD-admission gate to the budget's COLD HEADROOM. Cold
            # workers spawn OUTSIDE the warm pool, so headroom is (ceiling − warm RESIDENCY). Base
            # it on the LARGER of the new warm target and the slots RESIDENT right now: resize()
            # only moves setpoints, and surplus IDLE/WARMING slots are not reaped until a later
            # pool tick — so when a tick LOWERS warm (say 8→1), using the target alone would open
            # ceiling−1 cold permits while 8 VMs are still resident (≈2× the budget). Reserving
            # max(target, resident) holds the cold limit down until the surplus actually drains,
            # and also reserves for warm that is still SPAWNING UP toward a raised target. The gate
            # floors the limit at 1 (see set_limit) so cold (egress / warm-miss) never fully starves
            # under sustained warm load — a DELIBERATE liveness choice: for a forensics node an
            # egress detonation is often the important analysis, so we accept ≤1 unbudgeted cold
            # worker per warm-saturated engine (a bounded overshoot: Σ ≤ budget + (such engines)).
            # For a strict hard cap instead, size BLASTBOX_WORKER_MEMORY ≤ the slot RAM, or put a
            # cgroup memory limit on the engine containers. Only RAM is priced here — cold vCPU
            # isn't gated (CPU is compressible and the budget already oversubscribes vCPU by design).
            resident = int(getattr(self._pool, "slot_count", warm))
            headroom_slots = mine.concurrent_ceiling - max(warm, resident)
            if self._gate is not None:
                # PRICE cold permits by the COLD worker footprint, which can EXCEED the warm slot's
                # (BLASTBOX_WORKER_MEMORY defaults to 4g while a warm slot's RAM_MIB defaults to
                # 2048): the headroom is (headroom_slots × warm-slot RAM); dividing by the cold
                # worker RAM gives how many cold workers actually FIT. Converting slots→permits 1:1
                # would let a pool priced for 2g slots admit 4g cold workers = ≈2× its RAM. cold=0
                # / unknown → fall back to the warm footprint (1:1, prior behaviour).
                cold_ram = self._cold_slot_ram_mib or e.slot_ram_mib
                cold_permits = (int(headroom_slots * e.slot_ram_mib / cold_ram)
                                if cold_ram > 0 else headroom_slots)
                # set_limit floors at 1, so cold never fully starves even when headroom ≤ 0.
                self._gate.set_limit(cold_permits)  # type: ignore[attr-defined]
        elif mine is not None and self._cold_only():
            # COLD-ONLY dispatcher: no warm pool to resize. The pool's "slot" IS a docker cold
            # worker (footprint already the cold worker RAM), so the whole budget-allocated ceiling
            # is the cold-admission limit — drive the gate to it directly (no warm residency to
            # subtract, no warm→cold footprint conversion). warm_size is 0 (nothing to keep hot).
            mine = PoolSize(warm_size=0, concurrent_ceiling=mine.concurrent_ceiling)
            if self._gate is not None:
                self._gate.set_limit(mine.concurrent_ceiling)  # type: ignore[attr-defined]
        return mine

    def publish_orphan_lease(self, warm_orphans: int, cold_inflight: int = 0) -> None:
        """On shutdown with UNREAPED resources (a warm VM whose destroy failed, or a cold worker
        the bounded join abandoned), re-publish a FINAL snapshot reserving what's still running with
        an EXTENDED lifetime, so peers keep honoring the reservation well past the normal staleness
        window. A managed Firecracker guest has NO idle TTL (it waits for the host reaper), so a
        failed reap can consume RAM long after 20s; leasing to the reader's GC floor (~5 min, the
        max a reader will honor) shrinks that oversubscription window. Best-effort — a truly
        permanent orphan needs an external reaper / runtime watchdog (a tracked follow-on).

        Cold workers are priced in WARM-SLOT EQUIVALENTS (the same conversion _reservation() uses),
        since a hung 4 GiB cold worker on a 2 GiB slot must reserve 2 units or peers reallocate the
        missing RAM for the whole lease."""
        e = self._engine
        cold_ram = self._cold_slot_ram_mib or e.slot_ram_mib
        cold_units = (cold_ram / e.slot_ram_mib) if e.slot_ram_mib > 0 else 1.0
        reserved = max(0, int(warm_orphans)) + math.ceil(max(0, int(cold_inflight)) * cold_units)
        # Cap the lease's max_ceiling (and min_warm) AT the reservation so plan_sizes reserves
        # exactly what's still running and can't demand-fill spare budget INTO a dead pool — an
        # equal-weight orphan holding 1 slot on a 16-slot node would otherwise still be planned ~8
        # slots, throttling the live pools for the whole lease.
        capped = max(1, reserved)
        # Under the publish lock (bounded) so an in-flight run-loop publish still finishing past the
        # join can't os.replace() a normal short-lived heartbeat over this extended lease afterward.
        snap = DemandSnapshot(
            engine=e.name, backlog=0, assigned=reserved,
            slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
            min_warm=min(e.min_warm, capped), max_ceiling=capped, weight=e.weight,
            ts=self._clock(), node=self._node, tier=self._runtime, instance=self._instance,
            refresh_s=0.0, balancing=self._config.balancing,
            stale_after_s=FileNodeShare._GC_AGE_FLOOR_S)
        self._locked_final(lambda: self._share.publish(snap))

    def _locked_final(self, fn: Callable[[], None]) -> None:
        """Run a FINAL cleanup publish/remove UNDER the publish lock, so no in-flight run-loop
        publish clobbers it afterward. Bounded acquire (a wedged publish mustn't hang shutdown).
        If the lock can't be taken, a publish is still in progress — do NOT run fn() anyway: racing
        it would let that publish's os.replace() recreate a removed snapshot or overwrite the orphan
        lease afterward. Skip and let the in-flight publish + staleness govern (best-effort)."""
        if not self._publish_lock.acquire(timeout=10.0):
            logging.getLogger("blastbox.node_sizer").warning(
                "node self-sizer for %s: publish still in progress at shutdown — skipping final "
                "snapshot cleanup to avoid racing it", self._engine.name)
            return
        try:
            fn()
        except Exception:
            pass
        finally:
            self._publish_lock.release()

    def remove_own_snapshot(self) -> None:
        """Remove this unit's published snapshot. Idempotent — the run() loop's finally also
        does this, but the CLI calls it directly after join(timeout): if the join times out
        because a tick is mid slow-count, the finally may not run before the process exits,
        so this guarantees the file is gone and no phantom pool lingers on restart. Taken under
        the publish lock so a publish still in flight past the join can't os.replace() the file
        back AFTER we remove it (peers would then see a phantom pool for a staleness window)."""
        self._locked_final(lambda: self._share.remove(self._identity()))

    def _identity(self) -> DemandSnapshot:
        """A minimal snapshot carrying only THIS unit's identity — for removing our own file
        on stop (the metric fields are irrelevant to the filename)."""
        e = self._engine
        return DemandSnapshot(
            engine=e.name, backlog=0, assigned=0, slot_ram_mib=e.slot_ram_mib,
            slot_vcpus=e.slot_vcpus, min_warm=e.min_warm, max_ceiling=e.max_ceiling,
            weight=e.weight, ts=0.0, node=self._node, tier=self._runtime,
            instance=self._instance)

    def run(self, *, stop: Optional[threading.Event] = None, max_ticks: Optional[int] = None,
            sleep: Callable[[float], None] = time.sleep) -> None:
        self._stop_event = stop               # so tick() can fence its update-publish on stop
        self._last_view_ok = self._clock()     # grace baseline: assume visible until proven otherwise
        warned_invisible = False
        n = 0
        try:
            while not (stop is not None and stop.is_set()):
                try:
                    self.tick()
                except Exception:  # a sizing hiccup must never take down the dispatcher
                    logging.getLogger("blastbox.node_sizer").warning(
                        "node self-sizer tick failed for %s (continuing)", self._engine.name,
                        exc_info=True)
                # FAIL CLOSED if we can no longer confirm we're VISIBLE to the node — either the
                # PUBLISH fails (permission change, broken bind mount, full disk) OR the READ/list
                # fails (we can still write but no longer see the share, so we'd never notice peers
                # reclaiming our share). Once we haven't read our own snapshot back for longer than
                # the staleness window, peers have reallocated our share while our pool is still
                # live — shrink to the floor so we stop oversubscribing. Recovers automatically: the
                # next tick that reads itself back clears the timer and re-sizes from the live view.
                if self._clock() - self._last_view_ok > self._config.stale_after_s:
                    if not warned_invisible:
                        warned_invisible = True
                        logging.getLogger("blastbox.node_sizer").warning(
                            "node self-sizer for %s could not confirm visibility (publish or read) "
                            "for > the staleness window — peers may have reclaimed our share; "
                            "shrinking the pool to its floor until it recovers.", self._engine.name)
                    self._size_to_floor()
                else:
                    warned_invisible = False
                n += 1
                if max_ticks is not None and n >= max_ticks:
                    return
                # Sleep on the stop event (when present) so a shutdown wakes us IMMEDIATELY —
                # otherwise a plain sleep(interval) delays the finally's file-removal by up to
                # interval_s (60s+), long past the dispatcher's shutdown/join window, and the
                # graceful cleanup degrades to the crash path (a phantom pool for a staleness
                # window). stop.wait returns True when set → break to the finally.
                if stop is not None:
                    if stop.wait(self._config.interval_s):
                        break
                else:
                    sleep(self._config.interval_s)
        finally:
            # NB: removal of our snapshot is the CALLER's job (cli calls remove_own_snapshot()
            # AFTER pool.stop() has reaped the slots), so the reservation stays advertised until
            # our RAM is actually released — removing it here on thread-exit would free it too
            # early (peers reallocate our share while our slots are still being reaped). A
            # standalone caller that doesn't remove relies on staleness + the mtime GC.
            pass

    def start_thread(self, stop: threading.Event) -> threading.Thread:
        """Start the loop in a daemon thread (for use alongside the dispatcher loop)."""
        t = threading.Thread(target=self.run, kwargs={"stop": stop},
                             name=f"node-sizer:{self._engine.name}", daemon=True)
        t.start()
        return t
