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


def _start_node_sizer(pool, engines, store, tier):
    """Start the opt-in node self-sizer for this dispatcher's warm pool, or return None.

    Fully guarded (`except Exception`): a bad BLASTBOX_NODE_* config, an unwritable
    share_dir, or any setup error logs and disables sizing — it NEVER crashes dispatch.
    (KeyboardInterrupt/SystemExit deliberately propagate so the caller's finally still
    stops the pool.) Returns the stop Event when started, else None."""
    if pool is None:
        return None
    try:
        from blastbox.host.node_config import NodeConfig

        node_cfg = NodeConfig.from_env()   # inside the guard: parse errors mustn't crash dispatch
        if not (node_cfg.resource_management or node_cfg.balancing):
            return None
        import threading as _threading

        from blastbox.host.dispatcher_sizer import DispatcherSizer
        from blastbox.host.node_share import FileNodeShare
        from blastbox.host.node_sizer import local_backlog_fn

        # A dispatcher may serve several engines on one pool; size on ALL of their
        # combined backlog, using the (first) declared engine's footprint for the spec.
        served = list(engines) if engines else [e for e in [os.environ.get("BLASTBOX_ENGINE", "")] if e]
        spec = next((e for e in node_cfg.engines if e.name in served), None)
        if spec is None:
            print(f"node self-sizer: none of this dispatcher's engines {served} are in "
                  f"BLASTBOX_NODE_ENGINES — not sizing (declare one to enable).", file=sys.stderr)
            return None
        sizer_stop = _threading.Event()
        # `tier` is the pool's runtime NAME (firecracker/gvisor/cold) — WarmPool.runtime is
        # the SlotRuntime object, so gating uses this string.
        DispatcherSizer(spec, pool, FileNodeShare(node_cfg.share_dir), node_cfg,
                        runtime=tier,
                        backlog_fn=local_backlog_fn(store, served)).start_thread(sizer_stop)
        print(f"node self-sizer: managing {spec.name!r} warm pool (backlog over {served}) "
              f"from {node_cfg.share_dir} "
              f"({'balancing' if node_cfg.balancing else 'static shares'})", file=sys.stderr)
        return sizer_stop
    except Exception:
        logging.getLogger("blastbox.node_sizer").warning(
            "node self-sizer setup failed — continuing without it", exc_info=True)
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

    if pool is not None:
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
    )
    # Opt-in node self-sizer started INSIDE the try below, so pool.stop() in the finally
    # always runs — even if sizer setup raises (bad BLASTBOX_NODE_* / unwritable share_dir)
    # or is Ctrl-C'd mid-mkdir. It must never crash core dispatch or leak the warm pool.
    sizer_stop = None
    try:
        sizer_stop = _start_node_sizer(pool, engines, store, tier)
        dispatcher.run_forever(
            poll_interval_s=args.poll_interval,
            concurrency=int(os.environ.get("BLASTBOX_DISPATCH_CONCURRENCY") or "1"),
        )
    finally:
        if sizer_stop is not None:
            sizer_stop.set()
        if pool is not None:
            pool.stop()
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
