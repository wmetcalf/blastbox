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
import os
import secrets
import threading
import time
from typing import Callable, Optional

from .node_config import EngineNode, NodeConfig, _is_safe_slug
from .node_share import DemandSnapshot, NodeShare
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
        backlog_fn: Callable[[], int],        # this engine's own QUEUED count
        node: Optional[str] = None,           # physical-node id; default from BLASTBOX_NODE_ID
        instance: Optional[str] = None,       # publishing process id; default os.getpid()
        capacity_fn: Callable[[float, float], NodeBudget] = node_capacity,
        avail_fn: Callable[[], Optional[float]] = _mem_available_mib,
        clock: Callable[[], float] = time.time,
        concurrency_gate: object = None,      # DynamicConcurrencyGate; its live limit tracks
                                              # the pool ceiling so CONCURRENT jobs (warm+cold)
                                              # never exceed the budget-allocated ceiling.
    ) -> None:
        self._engine = engine
        self._pool = pool
        self._gate = concurrency_gate
        self._share = share
        self._config = config
        self._runtime = (runtime or "").strip().lower()
        self._backlog_fn = backlog_fn
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

    def _active(self) -> bool:
        cfg = self._config
        return (cfg.resource_management or cfg.balancing) and manages(self._runtime)

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

    def tick(self) -> Optional[PoolSize]:
        """Publish own demand, read the node view, size the local pool. Returns this
        engine's decided size (None when the feature is off or the view is empty)."""
        if not self._active():
            return None
        started = self._clock()
        e = self._engine
        assigned = int(getattr(self._pool, "assigned_count", 0))      # cheap

        # tell peers our expected refresh period so a slow count doesn't get us aged out
        refresh_s = self._config.interval_s + self._last_tick_dur
        def _snapshot(backlog: int, ts: float) -> DemandSnapshot:
            return DemandSnapshot(
                engine=e.name, backlog=backlog, assigned=assigned,
                slot_ram_mib=e.slot_ram_mib, slot_vcpus=e.slot_vcpus,
                min_warm=e.min_warm, max_ceiling=e.max_ceiling, weight=e.weight, ts=ts,
                node=self._node, tier=self._runtime, instance=self._instance,
                refresh_s=refresh_s, balancing=self._config.balancing)

        # HEARTBEAT before the (possibly-slow) count: publish a fresh-ts snapshot with the last
        # tick's backlog so peers keep seeing us alive even when THIS count — a huge shared-
        # store scan — runs long; otherwise they age us out mid-count and reallocate our share
        # → oversubscription. (For a count longer than the staleness window, also raise
        # BLASTBOX_NODE_STALE_AFTER_S; see docs.) FENCED on stop like the update below, so a
        # shutdown that already removed our file isn't followed by a heartbeat republish.
        if self._stop_event is not None and self._stop_event.is_set():
            return None
        self._share.publish(_snapshot(self._last_backlog, started))
        backlog = max(0, int(self._backlog_fn()))                    # the possibly-slow count
        self._last_backlog = backlog
        now = self._clock()
        # UPDATED publish with the FRESH backlog so the node converges in one tick (not lagged).
        # FENCED on the stop event: on shutdown the CLI sets stop, times out the join while we
        # were mid-count, and removes our file — this guard means we don't then republish a
        # phantom after the count returns.
        if self._stop_event is None or not self._stop_event.is_set():
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
        if not snaps:
            return None
        # Observability: the node filter is intentionally symmetric (so a single host's
        # partial node-id config still coordinates), which makes an untagged reader see
        # tagged peers too. If the view mixes DISTINCT node ids, that usually means a
        # share_dir was accidentally shared ACROSS hosts without consistent tagging — a
        # misconfig that conflates their budgets. Warn once so an operator can spot it
        # (we keep coordinating rather than fail-closed, per the documented invariant).
        if not self._warned_mixed_nodes and len({s.node for s in snaps}) > 1:
            self._warned_mixed_nodes = True
            logging.getLogger("blastbox.node_sizer").warning(
                "node view for %s mixes distinct node ids %s — if this share_dir is shared "
                "across physical hosts, set a DISTINCT BLASTBOX_NODE_ID on every host (see "
                "docs/CONFIGURATION.md); mixing conflates their budgets.",
                self._engine.name, sorted({s.node for s in snaps}))

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
        specs = [
            PoolSpec(
                # key each pool by (engine, tier, instance): the same engine on two node-
                # managed tiers, or two replicas of one engine/tier (rolling-deploy overlap),
                # are distinct pools competing for the budget — keying by engine alone would
                # collapse them and each would size to the whole budget. `_pool_key` matches
                # what THIS dispatcher looks up for itself below.
                name=_pool_key(s.engine, s.tier, s.instance),
                slot_ram_mib=s.slot_ram_mib, slot_vcpus=s.slot_vcpus,
                # ceiling water-fill: by live backlog (balancing) or the static weight share.
                demand=float(s.backlog + s.assigned) if balancing else float(s.weight),
                min_warm=s.min_warm, max_ceiling=s.max_ceiling,
            )
            for s in snaps
        ]
        budget = self._adapt(self._capacity_fn(self._config.ram_headroom_frac,
                                               self._config.vcpu_oversubscription))
        plan = plan_sizes(specs, budget)  # type: ignore[arg-type]
        mine = plan.get(_pool_key(e.name, self._runtime, self._instance))
        if mine is not None and hasattr(self._pool, "resize"):
            # WARM tracks THIS engine's REAL demand (not the weight, which is only a
            # ceiling-share ratio) so static mode doesn't hold idle engines hot: a big
            # weight buys a big ceiling to burst into, but few hot slots when idle.
            warm = min(mine.concurrent_ceiling, max(e.min_warm, backlog + assigned))
            mine = PoolSize(warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
            self._pool.resize(  # type: ignore[attr-defined]
                warm_size=warm, concurrent_ceiling=mine.concurrent_ceiling)
            # Drive the dispatcher's live concurrency to the same ceiling, so CONCURRENT jobs
            # (warm AND cold-fallback) are bounded by the budget-allocated ceiling — the node
            # RAM cap holds even over the cold path, which the warm pool alone can't bound.
            if self._gate is not None:
                self._gate.set_limit(mine.concurrent_ceiling)  # type: ignore[attr-defined]
        return mine

    def remove_own_snapshot(self) -> None:
        """Remove this unit's published snapshot. Idempotent — the run() loop's finally also
        does this, but the CLI calls it directly after join(timeout): if the join times out
        because a tick is mid slow-count, the finally may not run before the process exits,
        so this guarantees the file is gone and no phantom pool lingers on restart."""
        try:
            self._share.remove(self._identity())
        except Exception:
            pass

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
        n = 0
        try:
            while not (stop is not None and stop.is_set()):
                try:
                    self.tick()
                except Exception:  # a sizing hiccup must never take down the dispatcher
                    logging.getLogger("blastbox.node_sizer").warning(
                        "node self-sizer tick failed for %s (continuing)", self._engine.name,
                        exc_info=True)
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
