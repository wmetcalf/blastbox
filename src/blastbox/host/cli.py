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
            engines[name] = EngineSpec(
                name=name, image=image, worker_argv=[],
                allowed_param_keys=allowed, reserved_param_keys=reserved,
            )
    return engines


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

    pool = build_warm_pool()
    if pool is not None:
        pool.start()

    # Tier identity, derived ALONGSIDE the pool so a misconfig fails fast HERE rather than the
    # dispatcher silently mislabeling/misrouting warm jobs as "cold". A built warm pool MUST
    # have a known warm runtime; no pool ⇒ "cold". (build_warm_pool only builds a pool for a
    # valid runtime, so the raise is a belt-and-suspenders guard against drift.)
    if pool is not None:
        _pool_rt = os.environ.get("BLASTBOX_POOL_RUNTIME", "none").strip().lower()
        if _pool_rt not in ("firecracker", "gvisor"):
            raise ValueError(
                f"a warm pool was built but BLASTBOX_POOL_RUNTIME={_pool_rt!r} is not a known "
                "warm tier (firecracker/gvisor); cannot derive the dispatcher tier identity"
            )
        tier = _pool_rt
    else:
        tier = "cold"

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
        pool=pool,
        tier=tier,
        # Warm-ONLY sidecar (socket-less gVisor C/R or FC warm dispatcher): on a warm-pool
        # miss, REQUEUE the job for the cold dispatcher instead of cold-falling-back (which
        # would fail closed here — no docker socket). Inert without a pool.
        warm_only=(os.environ.get("BLASTBOX_DISPATCH_WARM_ONLY", "").strip().lower()
                   in ("1", "true", "yes", "on")),
    )
    try:
        dispatcher.run_forever(
            poll_interval_s=args.poll_interval,
            concurrency=int(os.environ.get("BLASTBOX_DISPATCH_CONCURRENCY") or "1"),
        )
    finally:
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
