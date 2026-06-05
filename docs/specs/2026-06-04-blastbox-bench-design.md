# blastbox.bench — performance benchmarking, stats & comparisons

Status: **implemented** · 2026-06-04

## Goal

A first-class, reusable benchmarking capability inside blastbox: measure the
performance of **any** runtime / sandbox / pipeline operation, compute robust
percentile statistics, and produce A/B comparisons — exposed through an **ad-hoc
CLI** (`blastbox bench`) *and* a **CI regression gate**, both driving one shared
core. It replaces the throwaway scripts we keep hand-writing (`bench.py`,
`pctbench.py`, `settle_sweep.py`, the nono `recon.py`) with a maintained harness,
and it would have caught a stale conclusion in our own notes (the nono 0.60→0.61.1
overhead reversal).

## Why runtime-agnostic (the scope decision)

The things worth measuring span tiers, not just the warm-snapshot work:

- **snapshot tier** — warm restore vs cold boot, RAM-vs-disk, settle sweep;
- **sandbox tier** — per-job overhead of `nono` vs `bwrap` vs `nsjail` vs none;
- **conversion pipeline** — latency / throughput across formats.

A snapshot-only design would force a refactor the moment we add a sandbox or
conversion benchmark. So the **core is generic** — "run *a workload* under *a
config*, N times, summarize, compare" — and every measurable is a **registered
scenario**. The snapshot scenarios are simply the first entries; the nono A/B
drops in as a sandbox scenario with no core change.

## Architecture

A new `src/blastbox/bench/` package: an engine-agnostic **core** (stats + the
sampling harness), a **scenario registry** (blastbox-specific, runtime-agnostic),
and **two thin front-ends** that both drive the core.

```
            ┌──────────────── bench/ (one source of truth) ───────────────┐
            │  stats.py   summarize()/compare()  — pure math, no I/O        │
            │  harness.py measure(op, runs, warmup, clock) → samples        │
            │             Report accumulator → table / JSON                 │
            │  scenarios.py  @scenario(name, requires=…) registry           │
            │     snapshot.* | sandbox.overhead | convert.latency | …       │
            │  report.py  human table + stable JSON schema                  │
            └───────┬──────────────────────────────────────────┬──────────┘
                    │                                           │
        `blastbox bench <scenario>` (CLI)        tests/perf/ pytest gate
        p50/p90/p99 table + A/B + --json         asserts RATIO invariants
```

## Components

Each is small, single-purpose, and independently testable.

### `bench/stats.py` — pure statistics (no I/O)

- `summarize(samples: list[float]) -> Stats` — `Stats` is a frozen dataclass
  `(n, p50, p90, p99, mean, min, max, stdev)`. Percentiles use linear
  interpolation between order statistics (the same `pct()` the ad-hoc scripts use).
- `compare(a: Stats, b: Stats) -> Comparison` — `(speedup=a.p50/b.p50,
  p50_delta_pct, p90_delta_pct, …)`. Direction is explicit (baseline vs candidate).
- Edge cases: `n == 0` raises `ValueError("no samples")`; `n == 1` → `stdev = 0.0`.

Fully unit-testable with fixed arrays and known percentiles.

### `bench/harness.py` — the sampler

- `measure(op: Callable[[], object], *, runs: int, warmup: int = 0,
  clock: Callable[[], float] = time.monotonic) -> list[float]` — calls `op`
  `warmup + runs` times, times each **post-warmup** call with `clock`, returns the
  durations. The clock is injectable for deterministic tests.
- An `op` that **raises** drops that sample (logged at debug) rather than aborting
  the run; the durations list only contains successful samples.
- `Report` accumulator: `report.add(label, samples)`,
  `report.compare(label_a, label_b)`, `report.to_table() -> str`,
  `report.to_json() -> dict`. Holds named sample-sets so a scenario can emit
  several (e.g. `none` / `nono` / `bwrap`).

### `bench/scenarios.py` — the runtime-agnostic registry

- `@scenario(name: str, requires: tuple[str, ...] = ())` registers a function
  `Callable[[BenchConfig], ScenarioResult]`. `BenchConfig` carries the knobs
  (`runs`, `warmup`, plus scenario-specific values pulled from env/args).
- `ScenarioResult` = `{report: Report, status: "ok"|"skipped"|"insufficient",
  note: str}`.
- `requires` declares prerequisites by token — e.g. `"fc-host"` (firecracker +
  `/dev/kvm` + kernel + rootfs), `"nono"`, `"bwrap"`, `"soffice"`. A small
  `check_requirement(token) -> bool` probes each; a scenario with an unmet
  requirement returns `status="skipped"` (never crashes — same discipline as the
  `integration`/`docker` markers).
- Registry API: `get_scenario(name)`, `list_scenarios() -> list[ScenarioInfo]`.

**Initial scenarios** (each is just a registry entry — the runtime-agnostic point):

| name | requires | what it measures |
|---|---|---|
| `snapshot.cold-boot-ready` | fc-host | cold boot → warm-ready (the per-slot cost a restore replaces) |
| `snapshot.restore-latency` | fc-host | warm restore (spawn + outdisk copy + load) p50/p90/p99 |
| `snapshot.restore-convert` | fc-host | full per-job (restore + settle + convert) |
| `snapshot.ram-vs-disk` | fc-host | `/dev/shm` vs disk mem backend (build + restore→convert) |
| `snapshot.settle-sweep` | fc-host | success rate vs `settle_s` (the sweep we ran by hand) |
| `sandbox.overhead` | soffice | a representative workload under `{none, bwrap, nsjail, nono}` → overhead % vs none (the nono A/B, promoted) |
| `convert.latency` | soffice | conversion wall-time across a small fixture set (first cut) |

These reuse the existing runtime primitives (`SnapshotSlotRuntime`,
`select_sandbox`, the launcher) — the bench wraps them, it does not reimplement them.

> **Implemented in the first cut:** `sandbox.overhead`, `convert.latency`, and
> `snapshot.restore-latency`. The other four `snapshot.*` scenarios
> (`cold-boot-ready`, `restore-convert`, `ram-vs-disk`, `settle-sweep`) are deferred
> additive follow-ons — same `_impl(cfg, *, primitive)` + `requires=("fc-host",)`
> shape, registered when needed (they're FC-host-gated and not exercised by the
> ratio gate, which uses synthetic samples).

### `bench/report.py` — formatting

- Human table: one row per labelled sample-set, columns `p50 p90 p99 mean n
  overhead-vs-baseline`.
- JSON: a stable schema — the first cut emits `{scenario, results: [{label, stats}]}`
  (`stats` is `null` for an empty-sample label); this is the seam for CI baselines and
  external tracking. Top-level `config` (the run knobs) and precomputed `comparisons`
  are deferred additive fields, not in the first cut.

## Two front-ends

### CLI: `blastbox bench`

Wired into the existing argparse subparser CLI (`host/cli.py`, alongside
`serve`/`dispatch`/`version`):

```
blastbox bench --list                       # list scenarios + their requirements
blastbox bench <name> [--runs N] [--warmup W] [--json out.json] [--compare base.json]
```

- `--json` writes the JSON report; `--compare base.json` prints deltas vs a prior run.
- A scenario whose `requires` are unmet prints a one-line SKIPPED note and exits 0,
  so the command is safe to run on any host.

### CI gate: `tests/perf/`

pytest scenarios gated by a `perf` marker (registered in
`[tool.pytest.ini_options]`), skipped when prerequisites are absent. They assert
**ratio invariants**, never absolute times (see below):

- `warm restore p50` is **≥ K×** faster than `cold-boot-ready p50`.
- `sandbox.overhead` for `nono` is **≤ X%** vs none (and **≤ bwrap's** overhead).

The initial invariants are **seeded from the numbers we already measured, with
generous margin** so they catch real regressions without flaking — e.g. restore is
~13.5× faster than cold boot (gate at ≥ 5×), nono overhead is +1–4% (gate at ≤ 15%).
They live in a small committed `perf_gates` config dict; absolute baselines (JSON)
are optional and informational only.

## The one real subtlety — what CI asserts

Absolute milliseconds vary by host and CI runner, so gating "restore < 600 ms"
would be flaky. The gate therefore asserts **relative invariants** — speedup
ratios and overhead percentages — which are far more host-stable. The **CLI**
reports both absolutes and ratios; **CI gates only the ratios**.

## Data flow

```
scenario(config) → harness.measure(op, runs) → list[float]
                 → stats.summarize → Stats        (per label)
                 → stats.compare(a, b) → Comparison (A/B)
                 → Report → table (CLI) / JSON (--json, CI baseline)
CI: scenario → summarize → assert ratio within tolerance of a committed invariant
```

## Error handling

- **Unmet `requires`** → `status="skipped"` (CLI exit 0 + note; pytest `skip`). No crash.
- **`op` raises mid-measure** → that sample is dropped + logged; if fewer than
  `min_samples` (default 3) succeed, the scenario returns `status="insufficient"`
  with a clear note rather than a bogus statistic.
- **stats** on empty input raises `ValueError`; `n == 1` yields `stdev == 0.0`.
- The bench **never** mutates production state; FC scenarios run in a scratch dir
  and reap what they spawn (reusing the runtime's own cleanup).

## Testing

- `stats` / `harness` / `report` are pure → **full unit coverage**: known-percentile
  fixtures, an injected clock for `measure`, empty / single-sample edge cases,
  table + JSON shape.
- `scenarios`: a couple of **fake-runtime** scenarios (no real FC/nono) exercised
  through the registry + harness — covers `requires`-skip, insufficient-samples, and
  the A/B comparison path. The real FC/sandbox scenarios are `requires`-gated.
- CLI: an in-process `main(["bench", "--list"])` test + a fake scenario run with
  `--json` (no subprocess needed).
- perf gate: one fake-backed ratio-assertion test proving the gate mechanism; the
  real gates carry the `perf` marker.

## Scope / non-goals (YAGNI)

- **No** historical time-series DB, **no** web dashboard, **no** flamegraphs /
  profiling — wall-clock + percentiles only. JSON output is the seam for anyone who
  wants external tracking.
- The perf gate ships with a **small** set of ratio invariants; growing them is
  incremental and additive.
- The bench does not own the runtimes — it wraps `SnapshotSlotRuntime`,
  `select_sandbox`, etc. as they are.

## File structure

| path | responsibility |
|---|---|
| `src/blastbox/bench/__init__.py` | package exports (`measure`, `summarize`, `compare`, `scenario`, `Report`) |
| `src/blastbox/bench/stats.py` | `summarize` / `compare` + `Stats` / `Comparison` |
| `src/blastbox/bench/harness.py` | `measure` + `Report` |
| `src/blastbox/bench/scenarios.py` | `@scenario` registry, `BenchConfig`, `check_requirement`, the initial scenarios |
| `src/blastbox/bench/report.py` | table + JSON formatting |
| `src/blastbox/host/cli.py` | add the `bench` subcommand (`build_parser` + `_bench_cmd`) |
| `tests/bench/test_{stats,harness,report,scenarios,cli_bench}.py` | unit tests |
| `tests/perf/test_perf_gates.py` | `perf`-marked ratio gates |
| `pyproject.toml` | register the `perf` pytest marker |

## Decisions (locked during brainstorming)

| decision | rationale |
|---|---|
| **Runtime-agnostic registry** (not snapshot-only) | the sandbox/conversion benchmarks (the nono A/B) are not snapshot-shaped; a generic core avoids a refactor. |
| **Both front-ends on one core** (CLI + pytest gate) | one source of truth; ad-hoc exploration and CI regression-gating share the harness. |
| **CI gates ratios, not absolute times** | absolute ms are host/runner-dependent → flaky; ratios are host-stable. |
| **`requires`-gated scenarios skip cleanly** | a single command/suite is safe to run anywhere; FC/nono/soffice scenarios no-op when absent. |
| **JSON output, no TSDB/dashboard** (YAGNI) | the seam for external tracking without owning a storage/UI surface. |
