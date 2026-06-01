# Host Orchestrator — Warm Pool Core Slice

**Goal:** `blastbox.host.pool` — manage a set of **pre-spawned warm worker slots** so a job can be
handed to an already-`warmup()`'d worker instead of paying cold start on the critical path. Engine-
agnostic. Every slot is still **one untrusted doc then destroyed** (warm ≠ reuse) — the pool only
pre-pays startup in the background.

**Scope:** the pool core — slot state machine, spawn/claim/release/reap, warm-size maintenance, the
background spawn loop. **Injectable `SlotRuntime`** (spawn/is-ready/reap a warm worker) so the whole
pool is unit-testable with a fake — no Docker. **Deferred follow-ups:** burst scaling, the health-
check loop, and the dispatcher warm-mode integration (claim a slot → stage input → signal go → wait
done → validate → release). Design the seam so those slot in.

**Tech Stack:** Python 3.12+, stdlib `threading`, `blastbox.errors`, pytest.

**Reference:** RedTusk `/home/coz/Downloads/RedTusk/src/redtusk/pool.py` (the proven slot state machine
+ claim/release/reap + spawn-deficit loop). Generalize; the framework's slots speak the merged warm
protocol (`blastbox.worker.warm.FileWarmControl`: a slot is IDLE when its control dir has `ready`).

## File structure
- `src/blastbox/host/pool.py`
- `tests/host/test_pool.py`

## Public API
```python
class SlotState(str, Enum):
    SPAWNING = "spawning"; WARMING = "warming"; IDLE = "idle"
    ASSIGNED = "assigned"; DRAINING = "draining"

@dataclass
class Slot:
    slot_id: str
    control_dir: Path        # FileWarmControl handshake dir (ready/go.json/done)
    input_dir: Path
    output_dir: Path
    state: SlotState
    container_id: str | None = None
    spawned_at: float = 0.0

class SlotRuntime(Protocol):
    def spawn(self) -> Slot: ...           # launch a warm worker; returns a SPAWNING/WARMING slot
    def is_ready(self, slot: Slot) -> bool: ...   # True once the worker signalled ready (control_dir/ready)
    def is_alive(self, slot: Slot) -> bool: ...   # liveness (container running)
    def reap(self, slot: Slot) -> None: ...       # kill+rm the container, rmtree the slot dirs

class WarmPool:
    def __init__(self, *, runtime: SlotRuntime, warm_size: int = 4, concurrent_ceiling: int = 16,
                 spawn_rate_limit: float = 4.0, clock: Callable[[], float] = time.monotonic): ...
    def start(self) -> None: ...           # begin the background spawn loop
    def stop(self) -> None: ...            # stop loops, reap all slots
    def claim(self, *, timeout_s: float) -> Slot | None: ...  # an IDLE+alive slot → ASSIGNED, or None
    def release(self, slot: Slot) -> None: ...   # ASSIGNED → DRAINING → reap + spawn replacement
    def tick(self) -> None: ...            # one maintenance step (promote WARMING→IDLE, spawn to deficit)
    @property
    def idle_count(self) -> int: ...
    @property
    def slot_count(self) -> int: ...
```

## Behavior
- **State machine**: `spawn()` → SPAWNING; `tick()` promotes a slot to IDLE once `runtime.is_ready(slot)`
  (was WARMING). `claim` picks an IDLE slot, re-checks `runtime.is_alive` (drop+replace if it died in the
  window — the liveness race RedTusk guards), flips to ASSIGNED, returns it. `release` → DRAINING →
  `runtime.reap(slot)` → remove from the pool → the next `tick` spawns a replacement to restore warm_size.
  A slot is **never reused**: release always reaps; there is no ASSIGNED→IDLE path.
- **warm-size maintenance**: `tick` computes `deficit = warm_size - (slots not DRAINING)`, clamped so
  `slot_count` never exceeds `concurrent_ceiling`, and spawns up to the deficit, rate-limited to
  `spawn_rate_limit`/sec (token-bucket on the clock). Spawn failures back off and are logged; repeated
  failures shrink the effective target (don't spin).
- **start/stop**: `start` runs `tick` on a background thread every ~`poll_interval` (e.g. 0.1s); `stop`
  cancels it and reaps every slot. `claim` blocks up to `timeout_s` waiting for an IDLE slot (polling
  the pool), returning None on timeout. Thread-safe (a lock around slot-dict mutations).
- **clock injectable** (`time.monotonic` default) so rate-limit/timeout logic is deterministic in tests.

## Security / correctness (review will check)
- **One job per slot**: `release` ALWAYS reaps; assert there is no code path returning an ASSIGNED slot
  to IDLE. A reaped slot's id never reappears as IDLE.
- **Liveness race**: a slot that dies between becoming IDLE and being claimed must NOT be handed out —
  `claim` re-checks `is_alive` and drops it.
- **No double-claim**: two concurrent `claim` calls never return the same slot (thread-safe).
- `stop` reaps all slots (no orphaned warm containers leak).
- warmup/state captured before any input — the pool never stages input here (that's the dispatcher
  integration follow-up); slots are pristine until assigned.

## Tests (TDD; fake `SlotRuntime` driving ready/alive/reap deterministically + an injected clock)
1. `start` + `tick` spawns up to `warm_size` slots; once the fake marks them ready, `idle_count == warm_size`.
2. `claim` returns an IDLE slot (state ASSIGNED); `claim` with no idle + tiny timeout → None.
3. `release` reaps the slot (fake records reap) and a `tick` spawns a replacement → `idle_count` recovers.
4. **never reused**: after `release`, the same slot_id never returns to IDLE; a second `claim` returns a
   DIFFERENT slot.
5. **liveness race**: a slot marked ready then `is_alive=False` before claim → `claim` skips it (and it's
   dropped/replaced), returns a live one or None.
6. **no double-claim**: N idle slots, M threads each `claim` once → no slot_id claimed twice; surplus get None.
7. `concurrent_ceiling`: with many releases in flight, `slot_count` never exceeds the ceiling.
8. spawn rate-limit: with `spawn_rate_limit=2` and the clock advanced, no more than 2 spawns/sec.
9. `stop` reaps every slot (fake reap called for all; `slot_count == 0`).

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. all prior), mypy + ruff clean. Don't push.
