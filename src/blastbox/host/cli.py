"""Command-line interface for the blastbox host orchestrator.

Subcommands:
- ``serve``    — start the FastAPI ingress server via uvicorn.
- ``dispatch`` — run the Dispatcher loop (claim + launch worker containers).
- ``bench``    — run a performance benchmark scenario (or ``--list`` them).
- ``version``  — print version and exit.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

from blastbox import __version__
from blastbox.limits import Limits
from blastbox.observability import configure_logging


def _serve_cmd(args: argparse.Namespace) -> int:
    import uvicorn

    from blastbox.host.ingress.app import build_app
    from blastbox.host.ingress.extension import load_ingress_extension

    allowed: set[str] = set()
    if args.allowed_engines:
        allowed = {e.strip() for e in args.allowed_engines.split(",") if e.strip()}

    extension = load_ingress_extension(os.environ.get("BLASTBOX_INGRESS_EXTENSION"))
    app = build_app(allowed_engines=allowed or None, extension=extension)
    uvicorn.run(app, host=args.host, port=args.port, workers=1)
    return 0


def _parse_default_params(raw: str | None) -> dict[str, str]:
    """Parse ``BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS='KEY=VAL,KEY2=VAL2'`` into a dict.

    Operator-set per-engine defaults applied to any job that doesn't specify the key (the
    dispatcher merges them UNDER job.params; see EngineSpec.default_params). Keys are
    upper-cased (to match the UPPERCASE-only forwardable-key shape — a lowercase default
    would silently never forward); values are kept verbatim. Comma-separated, so a value
    may not contain a comma (fine for the enablement flags this is for). Malformed entries
    (no ``=`` or empty key) are warned about and skipped, mirroring _parse_engine_specs.
    Returns ``{}`` when unset/empty.
    """
    out: dict[str, str] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            print(
                f"warning: ignoring malformed default-param {item!r} (expected KEY=VALUE)",
                file=sys.stderr,
            )
            continue
        key, _, value = item.partition("=")
        key = key.strip().upper()
        if not key:
            print(
                f"warning: ignoring default-param with empty key: {item!r}",
                file=sys.stderr,
            )
            continue
        out[key] = value.strip()
    return out


def _parse_engine_specs(engines_raw: str) -> dict:
    """Parse ``BLASTBOX_ENGINES='NAME=image:tag[,NAME2=image2:tag2]'`` into a
    ``{name: EngineSpec}`` map.

    ``worker_argv`` defaults to ``[]`` — the engine image's ENTRYPOINT is
    self-contained (e.g. ``python -m blastbox.worker.cold``). Malformed entries
    are warned about and skipped.
    """
    from blastbox.host.dispatch import EngineSpec

    engines: dict[str, EngineSpec] = {}
    for spec_str in engines_raw.split(","):
        spec_str = spec_str.strip()
        if not spec_str:
            continue
        if "=" not in spec_str:
            print(
                f"warning: ignoring malformed engine spec {spec_str!r} "
                "(expected NAME=image:tag)",
                file=sys.stderr,
            )
            continue
        name, _, image = spec_str.partition("=")
        name = name.strip()
        image = image.strip()
        if name and image:
            # Optional per-engine forwardable-param allowlist (default-deny once set):
            #   BLASTBOX_ENGINE_<NAME>_PARAM_KEYS='KEY1,KEY2'
            # UNSET preserves the legacy shape+denylist behaviour; SET (even to an empty
            # value) is an explicit allowlist (empty = block all). This is how an operator
            # opens the worker's env namespace to specific client params (e.g. clippyshot's
            # scanner toggles) without exposing every CLIPPYSHOT_* the worker reads
            # (sandbox/limits) to client override.
            # None when UNSET (legacy denylist); a frozenset when SET (even if empty after
            # stripping → blocks all client params, the operator's explicit intent).
            # Env var names can't contain hyphens, so normalize the engine name (test-engine
            # → TEST_ENGINE). Keys are upper-cased to match the UPPERCASE-only client keys
            # (_VALID_ENV_KEY_RE): a lowercase allowlist entry would silently never match
            # (fail-closed); a lowercase RESERVED entry would silently never match and BYPASS
            # the denylist (fail-DANGEROUS) — so normalize on parse, here, for both.
            env_name = name.upper().replace("-", "_")
            keys_raw = os.environ.get(f"BLASTBOX_ENGINE_{env_name}_PARAM_KEYS")
            allowed = (
                None if keys_raw is None
                else frozenset(k.strip().upper() for k in keys_raw.split(",") if k.strip())
            )
            # Optional per-engine RESERVED keys (engine-OWNED denylist):
            #   BLASTBOX_ENGINE_<NAME>_RESERVED_KEYS='KEY1,KEY2'
            # Client params this engine's worker reads that flip its security posture or
            # are code-exec vectors (clippyshot inner-sandbox selector; redtusk JVM
            # binary/jar/opts/library path / CRaC dir). Dropped UNCONDITIONALLY — even if
            # the allowlist is unset/misconfigured. This keeps blastbox core engine-
            # agnostic: the engine names its own dangerous keys, here, in its deploy config.
            reserved_raw = os.environ.get(f"BLASTBOX_ENGINE_{env_name}_RESERVED_KEYS")
            reserved = frozenset(
                k.strip().upper() for k in (reserved_raw or "").split(",") if k.strip()
            )
            # Optional per-engine DEFAULT params (operator policy):
            #   BLASTBOX_ENGINE_<NAME>_DEFAULT_PARAMS='KEY=VAL,KEY2=VAL2'
            # Applied for any key a job doesn't set (job wins), forwarded through the same
            # allowlist/reserved gate as client params. Makes an enablement default a runtime
            # decision (flip + restart, no rebuild) instead of a hardcoded engine value.
            default_params = _parse_default_params(
                os.environ.get(f"BLASTBOX_ENGINE_{env_name}_DEFAULT_PARAMS")
            )
            # Optional per-engine DEFAULT network personality (BLASTBOX_ENGINE_<NAME>_NETPOLICY).
            # A name from the operator's BLASTBOX_NETPOLICY_<NAME> registry; "none" (default) =
            # no egress. Validated/resolved fail-closed at dispatch (netpolicy.resolve).
            net_policy = (
                os.environ.get(f"BLASTBOX_ENGINE_{env_name}_NETPOLICY") or "none"
            ).strip().lower()
            # Optional per-engine dispatcher-TIER allowlist (BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES):
            #   BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES='cold,firecracker,gvisor'
            # Unset OR set-but-empty ⇒ None (any tier) — an empty value is the common `${VAR:-}` compose
            # idiom for "use the default", and unlike the param allowlist an empty set here would be a
            # footgun (an engine permitted on NO tier can never run). Set ⇒ only those tiers; enforced
            # fail-closed at startup (enforce_allowed_runtimes) so a BLASTBOX_POOL_RUNTIME drift can't
            # route the engine onto a tier it wasn't cleared for. An unknown tier name is a config typo —
            # raise, don't silently drop it (a dropped entry could leave the set permitting an unintended tier).
            from blastbox.host.jobs.base import VALID_TIERS

            runtimes_raw = os.environ.get(f"BLASTBOX_ENGINE_{env_name}_ALLOWED_RUNTIMES")
            allowed_runtimes: frozenset[str] | None = None
            if runtimes_raw and runtimes_raw.strip():
                parsed = frozenset(t.strip().lower() for t in runtimes_raw.split(",") if t.strip())
                unknown = parsed - set(VALID_TIERS)
                if unknown:
                    raise ValueError(
                        f"BLASTBOX_ENGINE_{env_name}_ALLOWED_RUNTIMES has unknown tier(s) "
                        f"{sorted(unknown)}; valid tiers: {'/'.join(VALID_TIERS)}"
                    )
                # A value that parses to zero tiers (e.g. ",  ,") is treated as unset (any tier), not
                # an empty "run nowhere" set — same footgun avoidance as the set-but-empty case above.
                allowed_runtimes = parsed or None
            engines[name] = EngineSpec(
                name=name, image=image, worker_argv=[],
                allowed_param_keys=allowed, reserved_param_keys=reserved,
                default_params=default_params,
                net_policy=net_policy,
                allowed_runtimes=allowed_runtimes,
            )
    return engines


def _node_manages_tier(tier: str) -> bool:
    """True if the node autosizer is enabled AND it manages this dispatcher's runtime tier
    (firecracker/gvisor). Fully guarded — a bad BLASTBOX_NODE_* config never crashes dispatch,
    it just reports 'not managed'. Used to make the node budget a HARD cap at startup:
    force warm_only (no uncounted cold spill) and start the pool unspawned until the sizer's
    first allocation (no legacy over-spawn)."""
    try:
        from blastbox.host.node_config import NodeConfig
        from blastbox.host.node_sizer import manages
        return NodeConfig.from_env().active and manages(tier)
    except Exception:
        return False


def _parse_mem_mib(raw: str) -> float:
    """Parse a docker --memory-style size ("4g", "512m", "2048k", bare "2048"=MiB) to MiB.
    Returns 0.0 on anything unparseable (caller falls back to the warm-slot footprint)."""
    s = (raw or "").strip().lower()
    if not s:
        return 0.0
    mult = {"b": 1.0 / (1024 * 1024), "k": 1.0 / 1024, "m": 1.0, "g": 1024.0}
    unit = s[-1]
    try:
        if unit in mult:
            return max(0.0, float(s[:-1]) * mult[unit])
        return max(0.0, float(s))          # bare number → MiB (matches our RAM_MIB convention)
    except ValueError:
        return 0.0


def _start_node_sizer(pool, engines, store, tier, concurrency=1, concurrency_gate=None,
                      cold_slot_ram_mib=0.0):
    """Start the opt-in node self-sizer for this dispatcher's warm pool, or return None.

    Fully guarded (`except Exception`): a bad BLASTBOX_NODE_* config, an unwritable
    share_dir, or any setup error logs and disables sizing — it NEVER crashes dispatch.
    (KeyboardInterrupt/SystemExit deliberately propagate so the caller's finally still
    stops the pool.) Returns the stop Event when started, else None."""
    if pool is None:
        return None
    sizer = None
    try:
        from blastbox.host.node_config import NodeConfig

        node_cfg = NodeConfig.from_env()   # inside the guard: parse errors mustn't crash dispatch
        if not (node_cfg.resource_management or node_cfg.balancing):
            return None
        import threading as _threading

        from blastbox.host.dispatcher_sizer import DispatcherSizer
        from blastbox.host.node_share import _MAX_WEIGHT, FileNodeShare
        from blastbox.host.node_sizer import local_backlog_fn

        # A dispatcher may serve several engines on ONE pool; size on ALL of their combined
        # backlog. The pool has a single per-slot footprint, so use the CONSERVATIVE (max)
        # footprint across the served engines — a slot must fit the biggest of them; using
        # the first/smallest would under-count RAM/vCPU and let the ceiling oversubscribe.
        served = list(engines) if engines else [e for e in [os.environ.get("BLASTBOX_ENGINE", "")] if e]
        declared = {e.name for e in node_cfg.engines}
        mine = [e for e in node_cfg.engines if e.name in served]
        if not mine:
            print(f"node self-sizer: none of this dispatcher's engines {served} are in "
                  f"BLASTBOX_NODE_ENGINES — not sizing (declare one to enable).", file=sys.stderr)
            return None
        missing = [s for s in served if s not in declared]
        if missing:
            # The pool serves ALL of `served`, but the footprint/ceiling are derived only from
            # the DECLARED subset. Sizing on a partial inventory would under-count RAM/vCPU (an
            # omitted engine's slots are invisible) and oversubscribe. Fail closed: require the
            # whole pool declared, or don't size (the pool keeps its static config, no worse
            # than pre-autosizer).
            print(f"node self-sizer: served engines {sorted(missing)} are missing from "
                  f"BLASTBOX_NODE_ENGINES — not sizing (declare EVERY served engine so the "
                  f"pool footprint is complete).", file=sys.stderr)
            return None
        base = mine[0]
        # The shared pool's ceiling is the LARGEST engine's ceiling (not the smallest): taking the
        # min would let a low-cap engine throttle the whole pool — clip(cap 1) + red(cap 32) would
        # cap at 1 even when all queued work is red and the budget permits 32. The busiest engine
        # must be able to reach its own cap. Bounded by the dispatcher's worker concurrency
        # (run_forever runs at most `concurrency` jobs at once, so a higher ceiling is wasted RAM)
        # and, downstream, by the node budget's water-fill — so this never oversubscribes. (A
        # shared pool can't enforce each engine's individual sub-cap without per-engine tracking;
        # the node budget bounds the aggregate, which is what matters for oversubscription.)
        combined_ceiling = max(1, min(max(e.max_ceiling for e in mine), concurrency))
        spec = replace(  # type: ignore[call-arg]
            base,
            slot_ram_mib=max(e.slot_ram_mib for e in mine),
            slot_vcpus=max(e.slot_vcpus for e in mine),
            # The shared pool serves ALL of `mine`, so its warm floor is the SUM of the engines'
            # floors — each engine wants its own min_warm hot. Taking the max discards the other
            # engines' floors (two engines @ MIN_WARM=2 would keep only 2 hot, not 4). Cap by the
            # combined ceiling: you can't warm more than the pool's hard ceiling anyway.
            min_warm=min(sum(e.min_warm for e in mine), combined_ceiling),
            max_ceiling=combined_ceiling,
            # the shared pool represents the COMBINED engines, so its static weight is the
            # SUM of their weights — using only the first engine's understates its share.
            # Clamp to _MAX_WEIGHT: the reader (_valid) rejects a snapshot weight above it, so
            # an unclamped sum would silently self-evict this pool from every node view.
            weight=min(sum(e.weight for e in mine), float(_MAX_WEIGHT)),
        )
        sizer_stop = _threading.Event()
        # `tier` is the pool's runtime NAME (firecracker/gvisor/cold) — WarmPool.runtime is
        # the SlotRuntime object, so gating uses this string.
        sizer = DispatcherSizer(  # noqa: F841 — bound so the except can clean up its snapshot
            spec, pool, FileNodeShare(node_cfg.share_dir), node_cfg,
            runtime=tier,
            # scope backlog to jobs THIS tier can claim (target_tier routing) so
            # the pool isn't sized for work pinned to a tier it can never drain.
            backlog_fn=local_backlog_fn(store, served, claimant_tier=tier),
            concurrency_gate=concurrency_gate,   # sizer drives its live limit on each resize
            cold_slot_ram_mib=cold_slot_ram_mib,  # price cold permits by the cold worker footprint
        )
        # Print the status FIRST, then start the thread LAST — otherwise if this print raises
        # (broken pipe / closed stderr) the except below returns None while the thread is
        # already running, leaking a daemon the caller can never stop or join.
        print(f"node self-sizer: managing {spec.name!r} warm pool (backlog over {served}) "
              f"from {node_cfg.share_dir} "
              f"({'balancing' if node_cfg.balancing else 'static shares'})", file=sys.stderr)
        # ONE synchronous sizing before the periodic thread + before dispatch serves: the pool
        # was started unspawned (warm=0), so this sizes it from the node budget now, closing
        # the startup window where it would otherwise run at its legacy target until the first
        # background tick. If this FAILS (e.g. the share_dir is read-only so publish() raises),
        # the sizer can never work AND the pool is still at warm=0 — so let it propagate to the
        # except below, which returns None → the caller restores the pool to its static config.
        sizer.tick()
        thread = sizer.start_thread(sizer_stop)
        # Return the thread + sizer so the caller can JOIN on shutdown (else the daemon is torn
        # down without its finally, which removes this unit's snapshot → phantom pool on
        # restart) AND directly remove the snapshot after join, guaranteeing removal even if
        # the join times out mid-tick. The run loop sleeps on sizer_stop, so the join is quick.
        return sizer_stop, thread, sizer
    except Exception:
        logging.getLogger("blastbox.node_sizer").warning(
            "node self-sizer setup failed — continuing without it", exc_info=True)
        # The synchronous first tick may have already PUBLISHED a snapshot (the heartbeat succeeds
        # before a later step — the update publish, a read, or start_thread — raises). If we return
        # None now, the caller restores the pool to its legacy size but the phantom snapshot lingers
        # advertising ~0 demand, then ages out permanently → peers reclaim this node's share while
        # the pool runs unmanaged at full size = persistent oversubscription. Remove it on the way out.
        if sizer is not None:
            sizer.remove_own_snapshot()
        return None


def _dispatch_cmd(args: argparse.Namespace) -> int:
    from blastbox.host.dispatch import Dispatcher
    from blastbox.host.jobs.factory import build_job_store_from_env

    # Build engine specs from env or CLI.
    # Format expected: ENGINE_NAME=image:tag[,ENGINE_NAME2=image2:tag2]
    engines_raw = args.engines or os.environ.get("BLASTBOX_ENGINES", "")
    engines = _parse_engine_specs(engines_raw)

    if not engines:
        print("error: no engines configured (set --engines or BLASTBOX_ENGINES)", file=sys.stderr)
        return 1

    limits = Limits.from_env()
    job_root = Path(os.environ.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs"))
    store = build_job_store_from_env()

    # Opt-in warm pool (BLASTBOX_POOL_RUNTIME; default "none" → cold path only).
    from blastbox.host.pool_config import build_warm_pool

    pool = build_warm_pool()   # built, NOT started -- start only after all validation below, so a
    # config error (mixed cascade / multi-engine) can't leak already-spawned cloud slots.

    # Tier identity, derived ALONGSIDE the pool so a misconfig fails fast HERE rather than the
    # dispatcher silently mislabeling/misrouting warm jobs as "cold". A built warm pool MUST
    # have a known warm runtime; no pool ⇒ "cold". (build_warm_pool only builds a pool for a
    # valid runtime, so the raise is a belt-and-suspenders guard against drift.)
    if pool is not None:
        from blastbox.host.jobs.base import WARM_TIERS

        _pool_rt = os.environ.get("BLASTBOX_POOL_RUNTIME", "none").strip().lower()
        if _pool_rt not in WARM_TIERS:
            raise ValueError(
                f"a warm pool was built but BLASTBOX_POOL_RUNTIME={_pool_rt!r} is not a known "
                f"warm tier ({'/'.join(WARM_TIERS)}); cannot derive the dispatcher tier identity"
            )
        tier = _pool_rt
    else:
        tier = "cold"

    warm_only = (os.environ.get("BLASTBOX_DISPATCH_WARM_ONLY", "").strip().lower()
                 in ("1", "true", "yes", "on"))
    node_managed = _node_manages_tier(tier)
    # NB: we deliberately do NOT force warm_only when node-managed. warm_only would break jobs
    # that resolve to an egress network personality (dispatch bypasses the warm pool for
    # egress), and it doesn't actually bound cold RAM. The node budget is bounded instead by
    # DISPATCH concurrency: each in-flight job (warm OR cold) is one slot of RAM. The sizer caps
    # the pool ceiling at BLASTBOX_DISPATCH_CONCURRENCY (below) AND drives a live concurrency gate
    # to that same budget-allocated ceiling, so active jobs ≤ ceiling ≤ budget — a hard NODE cap
    # that holds automatically over the cold path, not just the operator's Σ arithmetic.
    dispatch_concurrency = int(os.environ.get("BLASTBOX_DISPATCH_CONCURRENCY") or "1")
    # When node-managed, a live gate bounds COLD admission to the node budget's cold headroom
    # (ceiling − warm reservation): the cold path spawns footprint outside the warm pool, so the
    # sizer drives the gate each resize to keep warm residency + cold workers within the budget.
    # Warm dispatch is never gated. Best-effort (bounded, self-correcting overshoot), not a hard
    # guarantee. Off (None) when unmanaged — no behavior change.
    from blastbox.host.concurrency_gate import DynamicConcurrencyGate
    concurrency_gate = DynamicConcurrencyGate(dispatch_concurrency) if node_managed else None
    # Cold worker footprint (BLASTBOX_WORKER_MEMORY, docker --memory default "4g"), so the sizer
    # prices cold permits by REAL cold RAM rather than assuming a cold worker == one warm slot.
    cold_slot_ram_mib = _parse_mem_mib(os.environ.get("BLASTBOX_WORKER_MEMORY", "") or "4g")

    # Fail-closed BEFORE pool.start(): refuse to run an engine on ANY tier this dispatcher can execute
    # it on — the advertised tier PLUS the cold-fallback/egress-bypass ("cold") and cascade overflow
    # tiers (reachable_tiers) — so a BLASTBOX_POOL_RUNTIME/_TIERS drift can't route a locally-vetted
    # engine onto a public-AWS/remote worker with a different egress posture (no slot spawns on a raise).
    from blastbox.host.dispatch import enforce_allowed_runtimes, reachable_tiers

    enforce_allowed_runtimes(engines, reachable_tiers(pool, tier, warm_only))

    # Capability-based routing: the runtime declares its dispatch_style. A network-endpoint pool
    # (aws / static / cascade) drives workers over http_agent + remote_http via VmJobDispatcher; every
    # other runtime uses the file-handshake Dispatcher below. A cascade mixing styles raises here.
    if pool is not None and getattr(pool.runtime, "dispatch_style", "file") == "network":
        from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher

        # a network-endpoint pool serves ONE worker image/agent (BLASTBOX_ENGINE); a multi-engine
        # dispatcher here would send other engines' jobs to the wrong agent -- require exactly one.
        if len(engines) != 1:
            raise ValueError("network-endpoint tiers (aws/static/cascade) serve a single engine image; "
                             "configure one engine or run separately-scoped remote pools")
        vm = build_remote_vm_dispatcher(
            store, job_root, pool, tier=tier,
            engine=next(iter(engines)),
            engine_spec=next(iter(engines.values())),
            limits=limits,
            worker_timeout_s=float(os.environ.get("BLASTBOX_WORKER_TIMEOUT_S") or "300"),
            warm_claim_timeout_s=float(os.environ.get("BLASTBOX_WARM_CLAIM_TIMEOUT_S") or "60"),
            concurrency=int(os.environ.get("BLASTBOX_DISPATCH_CONCURRENCY") or "1"),
            job_retention_s=int(os.environ.get("BLASTBOX_JOB_RETENTION_SECONDS") or "0"),
        )
        pool.start()   # validation passed -> now spawn/warm slots (nothing to leak on an earlier raise)
        try:
            # One-shot orphan sweep on start (aws-ec2-hibernate only; guarded by hasattr). A fresh run's
            # run_id tags nothing yet, so this can only reclaim a PREDECESSOR/crashed run's leaked stopped
            # slots -- never our own. Opt-in (BLASTBOX_EC2_ORPHAN_MAX_AGE_S); best-effort, never fatal.
            # INSIDE the try so a BaseException here (Ctrl-C, or a blocking describe/terminate) still
            # runs the finally's pool.stop() instead of leaking the just-spawned slots.
            _sweep = getattr(getattr(pool, "runtime", None), "sweep_orphans", None)
            if callable(_sweep):
                try:
                    _sweep()
                except Exception:  # noqa: BLE001 - a sweep hiccup must not block dispatch
                    logging.getLogger("blastbox.host.cli").warning("startup orphan sweep failed", exc_info=True)
            vm.run()
        except BaseException:
            vm.stop()   # release the executor's worker loops so the finally's pool.stop() can reap
            raise
        finally:
            pool.stop()
        return 0

    pre_shrunk = None   # (warm_size, ceiling) captured before pre-shrink, to restore if the
    #                     sizer ends up NOT managing this pool (see below)
    if pool is not None:
        if node_managed:
            # Start UNSPAWNED under the node autosizer: shrink to warm=0/ceiling=1 before
            # start(), so the pool doesn't warm its legacy BLASTBOX_POOL_WARM_SIZE (which,
            # summed across engines at a full/rolling startup, can exceed the node budget)
            # before the sizer's first allocation. The synchronous first tick in
            # _start_node_sizer then sizes it from the node budget before serving begins.
            try:
                pre_shrunk = (pool.warm_size, pool.concurrent_ceiling)  # type: ignore[attr-defined]
                # Provisional (mark_autosized=False): if the sizer never starts, this must not
                # turn on eager reaping — the pool has to behave exactly as a legacy pool would.
                pool.resize(warm_size=0, concurrent_ceiling=1,  # type: ignore[attr-defined]
                            mark_autosized=False)
            except Exception:
                pre_shrunk = None
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: could not pre-shrink pool before start", exc_info=True)
        pool.start()   # file-handshake warm path: start after tier-identity validation
    dispatcher = Dispatcher(
        job_store=store,
        engines=engines,
        limits=limits,
        job_root=job_root,
        # `or "<default>"` (not the get() default) so a SET-BUT-EMPTY var — the
        # common compose idiom `${VAR:-}` meaning "use the default" — falls back
        # instead of raising int("").
        worker_timeout_s=int(os.environ.get("BLASTBOX_WORKER_TIMEOUT_S") or "300"),
        # Retention: 0 (default) keeps artifacts forever; set a TTL (seconds) so run_forever's
        # periodic sweep deletes expired terminal jobs' output (of untrusted documents).
        job_retention_seconds=int(os.environ.get("BLASTBOX_JOB_RETENTION_SECONDS") or "0"),
        # Opt-in ceiling (0 = off) on time a job may sit QUEUED before being FAILed + its input
        # deleted — bounds a target_tier pinned to a tier with no running dispatcher.
        max_queued_age_s=float(os.environ.get("BLASTBOX_MAX_QUEUED_AGE_S") or "0"),
        pool=pool,
        tier=tier,
        # Warm-ONLY sidecar (socket-less gVisor C/R or FC warm dispatcher): on a warm-pool
        # miss, REQUEUE the job for the cold dispatcher instead of cold-falling-back (which
        # would fail closed here — no docker socket). Inert without a pool. (Parsed above for
        # reachable_tiers; reused here so the gate and the dispatcher agree on cold-fallback.)
        warm_only=warm_only,
        # live COLD-admission cap driven by the node autosizer (None when unmanaged) — bounds
        # concurrent cold workers to the budget's cold headroom (ceiling − warm reservation).
        concurrency_gate=concurrency_gate,
    )
    # Opt-in node self-sizer started INSIDE the try below, so pool.stop() in the finally
    # always runs — even if sizer setup raises (bad BLASTBOX_NODE_* / unwritable share_dir)
    # or is Ctrl-C'd mid-mkdir. It must never crash core dispatch or leak the warm pool.
    sizer = None
    try:
        sizer = _start_node_sizer(pool, engines, store, tier, dispatch_concurrency,
                                  concurrency_gate, cold_slot_ram_mib)
        # If we pre-shrank the pool for the autosizer but the sizer did NOT start (incomplete
        # inventory, unwritable share_dir, setup error), nothing will ever size it — restore
        # its configured warm/ceiling so it runs normally (pre-autosizer static behavior)
        # instead of being stuck at warm=0 and unable to serve.
        if sizer is None and pre_shrunk is not None and pool is not None:
            try:
                # Restore AND leave the pool un-managed (mark_autosized=False) so a skipped
                # opt-in keeps legacy lazy-drain behavior, not eager surplus reaping.
                pool.resize(warm_size=pre_shrunk[0], concurrent_ceiling=pre_shrunk[1],
                            mark_autosized=False)
            except Exception:
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: could not restore pool after skipped sizing", exc_info=True)
        dispatcher.run_forever(
            poll_interval_s=args.poll_interval,
            concurrency=dispatch_concurrency,
        )
    finally:
        # Stop the POOL first (reap its slots) while the sizer thread is STILL heartbeating, so
        # our reservation stays fresh in peers' views for the whole (possibly slow) reap — else
        # a pool.stop() longer than the staleness window would let peers reallocate our share
        # while our slots still hold node RAM. Only after the slots are gone do we stop the
        # sizer and remove the snapshot.
        orphans = pool.stop() if pool is not None else 0
        # Cold workers spawn OUTSIDE the pool, so pool.stop() can't see them; the dispatch loop's
        # bounded join may have abandoned a hung cold detonation still holding a gate permit.
        cold_inflight = concurrency_gate.in_flight if concurrency_gate is not None else 0
        if sizer is not None:
            sizer_stop, sizer_thread, sizer_obj = sizer
            sizer_stop.set()
            sizer_thread.join(timeout=5.0)     # sleeps on the event → returns promptly
            # Release the reservation ONLY when EVERYTHING this node was running is gone — every
            # warm slot reaped AND no cold worker still in flight. An orphaned warm VM (destroy
            # failed) or cold container (hung kill past the join deadline) still consumes RAM/vCPU;
            # removing the snapshot would let peers reallocate that still-used capacity (node
            # oversubscription). Leave it to age out after the staleness window instead — by when
            # the orphan's self-terminate TTL should have fired.
            if orphans == 0 and cold_inflight == 0:
                sizer_obj.remove_own_snapshot()
            else:
                # Re-publish a LEASED reservation for exactly what's still running, with an extended
                # lifetime (the sizer thread is stopped, so nothing else refreshes it): peers keep
                # honoring it well past the normal 20s window — a Firecracker orphan has no idle TTL.
                sizer_obj.publish_orphan_lease(orphans + cold_inflight)
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: shutdown left %d unreaped warm slot(s) + %d cold worker(s) "
                    "in flight — leased the node reservation (extended lifetime) so peers don't "
                    "reallocate still-used capacity; a permanent orphan needs an external reaper",
                    orphans, cold_inflight)
    return 0



def _bench_cmd(args: argparse.Namespace) -> int:
    # Import here so `blastbox` startup doesn't pull bench/runtime deps unless used.
    # Importing scenarios also triggers @scenario registration of the built-ins.
    from blastbox.bench.scenarios import BenchConfig, list_scenarios, run_scenario

    if args.list:
        for info in list_scenarios():
            req = ",".join(info.requires) or "-"
            print(f"{info.name:28} requires={req}")
        return 0

    if args.scenario is None:
        print("error: a scenario name is required (or use --list)", file=sys.stderr)
        return 2
    try:
        res = run_scenario(args.scenario, BenchConfig(runs=args.runs, warmup=args.warmup))
    except KeyError:
        print(
            f"error: unknown scenario {args.scenario!r} (try `blastbox bench --list`)",
            file=sys.stderr,
        )
        return 2

    base = res.report.labels()[0] if res.report.labels() else None
    print(res.report.to_table(baseline=base))
    if res.status != "ok":
        # diagnostic → stderr so stdout stays report-only (pipe/JSON-friendly)
        print(f"[{res.status}] {res.note}", file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res.report.to_json(), fh, indent=2)
    return 0


def _version_cmd(_: argparse.Namespace) -> int:
    print(f"blastbox {__version__}")
    return 0


def _pki_cmd(args: argparse.Namespace) -> int:
    from pathlib import Path

    from blastbox.host.pki import ensure_ca

    pki_dir = Path(args.dir)
    ca = ensure_ca(pki_dir)  # generate-or-load the CA
    if args.pki_action == "init":
        crt, key = ca.issue_client("dispatcher", days=args.days).write(pki_dir, "dispatcher")
        print(f"CA ready in {pki_dir}")
        print(f"  ca.crt         (public trust anchor -> bake into worker images) : {pki_dir / 'ca.crt'}")
        print(f"  dispatcher.crt / dispatcher.key  (host mTLS client cert)        : {crt} / {key}")
        return 0
    if args.pki_action == "issue-server":
        name = args.name or (args.san[0] if args.san else "server")
        crt, key = ca.issue_server(args.san, cn=args.cn, days=args.days).write(pki_dir, name)
        print(f"server cert (SAN={args.san}, {args.days}d) -> {crt} / {key}")
        return 0
    if args.pki_action == "issue-client":
        crt, key = ca.issue_client(args.cn, days=args.days).write(pki_dir, args.cn)
        print(f"client cert (cn={args.cn}, {args.days}d) -> {crt} / {key}")
        return 0
    if args.pki_action == "sign-csr":
        cert_pem = ca.sign_csr(Path(args.csr).read_bytes(), days=args.days)
        out = Path(args.out) if args.out else Path(args.csr).with_suffix(".crt")
        out.write_bytes(cert_pem)
        print(f"signed server cert ({args.days}d) -> {out}")
        return 0
    if args.pki_action == "show-ca":
        print((pki_dir / "ca.crt").read_text(), end="")
        return 0
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blastbox")
    sub = p.add_subparsers(dest="command", required=True)

    # serve
    ps = sub.add_parser("serve", help="run the ingress HTTP API")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8000)
    ps.add_argument(
        "--allowed-engines",
        default=os.environ.get("BLASTBOX_ALLOWED_ENGINES", ""),
        help="comma-separated list of allowed engine names",
    )
    ps.set_defaults(func=_serve_cmd)

    # dispatch
    pd = sub.add_parser("dispatch", help="run the job dispatcher loop")
    pd.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="seconds to sleep between empty polls",
    )
    pd.add_argument(
        "--engines",
        default="",
        help="comma-separated NAME=image:tag engine specs",
    )
    pd.set_defaults(func=_dispatch_cmd)

    # bench
    pb = sub.add_parser("bench", help="run a performance benchmark scenario")
    pb.add_argument("scenario", nargs="?", default=None, help="scenario name")
    pb.add_argument("--list", action="store_true", help="list scenarios + requirements")
    pb.add_argument("--runs", type=int, default=12)
    pb.add_argument("--warmup", type=int, default=3)
    pb.add_argument("--json", default=None, help="write the JSON report to this path")
    pb.add_argument("--compare", default=None, help="(reserved) baseline JSON to diff")
    pb.set_defaults(func=_bench_cmd)

    # pki -- worker-mTLS certificate authority
    pk = sub.add_parser("pki", help="worker-mTLS certificate authority (generate + issue certs)")
    pk.add_argument("--dir", default=os.environ.get("BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki"),
                    help="CA/cert state dir (BLASTBOX_PKI_DIR)")
    pks = pk.add_subparsers(dest="pki_action", required=True)
    pk_init = pks.add_parser("init", help="create the CA + a dispatcher client cert")
    pk_init.add_argument("--days", type=int, default=365)
    pk_srv = pks.add_parser("issue-server", help="mint a worker server cert (SAN-pinned)")
    pk_srv.add_argument("--san", action="append", required=True, help="IP or DNS name (repeatable)")
    pk_srv.add_argument("--cn", default=None)
    pk_srv.add_argument("--name", default=None, help="output filename stem (default: first SAN)")
    pk_srv.add_argument("--days", type=int, default=30)
    pk_cli = pks.add_parser("issue-client", help="mint a client cert")
    pk_cli.add_argument("--cn", default="dispatcher")
    pk_cli.add_argument("--days", type=int, default=365)
    pk_csr = pks.add_parser("sign-csr", help="sign a worker-generated CSR -> server cert (key stays on the box)")
    pk_csr.add_argument("--csr", required=True, help="path to the CSR PEM")
    pk_csr.add_argument("--out", default=None, help="output cert path (default: <csr>.crt)")
    pk_csr.add_argument("--days", type=int, default=30)
    pks.add_parser("show-ca", help="print the CA cert (public trust anchor)")
    pk.set_defaults(func=_pki_cmd)

    # version
    pv = sub.add_parser("version", help="print version and exit")
    pv.set_defaults(func=_version_cmd)

    return p


def main(argv: list[str] | None = None) -> int:
    configure_logging(format_="text")
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
