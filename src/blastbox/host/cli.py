"""Command-line interface for the blastbox host orchestrator.

Subcommands:
- ``serve``    — start the FastAPI ingress server via uvicorn.
- ``dispatch`` — run the Dispatcher loop (claim + launch worker containers).
- ``bench``    — run a performance benchmark scenario (or ``--list`` them).
- ``egress``   — set up this node's egress tier (bridges, local/global exit, wg overlay).
- ``version``  — print version and exit.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from dataclasses import replace
from pathlib import Path

from blastbox import __version__
from blastbox.limits import Limits
from blastbox.observability import configure_logging


def _serve_workers(
    flag: int | None, env: "os._Environ[str] | dict[str, str] | None" = None
) -> int:
    """Resolve the uvicorn worker count: an explicit --workers, else the env, else 1.

    Tolerates a SET-BUT-EMPTY variable, because that is what compose produces: the list form
    `- BLASTBOX_SERVE_WORKERS=${BLASTBOX_SERVE_WORKERS:-}` renders as the empty STRING, not as
    an absent variable, so `os.environ.get(KEY, "1")` returns "" and the default never applies.
    A bare int() there raises before uvicorn starts, and with `restart: unless-stopped` that is
    a crash loop -- on the ingress, which is the only way into the system.

    Same fail-soft shape as every sibling knob (_int_env, _upload_concurrency): a value that
    cannot be a worker count is an operator typo, not a request.
    """
    if flag:
        return flag
    e = os.environ if env is None else env
    raw = str(e.get("BLASTBOX_SERVE_WORKERS", "")).strip()
    if not raw:
        return 1
    try:
        n = int(raw)
    except ValueError:
        logging.getLogger("blastbox.host.cli").warning(
            "invalid BLASTBOX_SERVE_WORKERS=%r; using 1", raw
        )
        return 1
    if n < 1:
        logging.getLogger("blastbox.host.cli").warning(
            "BLASTBOX_SERVE_WORKERS=%r is below 1; using 1", raw
        )
        return 1
    return n


#: Re-issue the ingress certificate when this little of its life is left. `issue_server` mints
#: 30 days; a week of warning is enough for a hardened host that must have one copied in.
_TLS_RENEW_BEFORE_S = 7 * 86400.0


def _serve_tls_sans(host: str) -> list[str]:
    """Names the auto-issued certificate must answer to.

    ``--host 0.0.0.0`` (or ``::``) is the common production bind, and the first version put
    THAT in the SAN -- a name no client ever connects to. Nodes verify the hostname they were
    given (`client_ssl_context` keeps hostname checking on), so every one of them refused the
    control plane's certificate. Reviewed. For a wildcard bind the machine's own names and
    non-loopback addresses go in; ``BLASTBOX_TLS_SANS`` (comma-separated) adds the names nodes
    are actually configured with -- a load balancer's DNS name, typically -- and is the right
    answer whenever this host is not reached by its own name.
    """
    import socket

    sans: list[str] = []
    extra = os.environ.get("BLASTBOX_TLS_SANS", "")
    sans += [x.strip() for x in extra.split(",") if x.strip()]
    if host and host not in ("0.0.0.0", "::", ""):
        sans.append(host)
    else:
        try:
            name = socket.gethostname()
            sans.append(name)
            fqdn = socket.getfqdn()
            if fqdn and fqdn != name:
                sans.append(fqdn)
            for info in socket.getaddrinfo(name, None):
                ip = str(info[4][0])
                if ip and not ip.startswith(("127.", "::1")) and ip not in sans:
                    sans.append(ip)
        except OSError:
            pass
    sans += ["localhost", "127.0.0.1"]
    seen: list[str] = []
    for x in sans:
        if x not in seen:
            seen.append(x)
    return seen


def _readable_cert(path) -> bool:
    """Whether `path` loads as a PEM certificate at all -- a separate question from whether it was
    issued by the current CA, and one whose answer calls for a different remedy."""
    from cryptography import x509

    try:
        x509.load_pem_x509_certificate(path.read_bytes())
        return True
    except Exception:                   # noqa: BLE001 - unreadable for any reason
        return False


def _leaf_matches_ca(leaf_path, ca_path) -> bool:
    """Was this leaf signed by the CA currently on disk? Unreadable either side -> False.

    Fails CLOSED (towards re-issuing) on any doubt: re-issuing a certificate is cheap and
    self-healing, whereas serving one the fleet no longer trusts looks exactly like a working
    listener and breaks every node at once.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        leaf = x509.load_pem_x509_certificate(leaf_path.read_bytes())
        ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    except Exception:                   # noqa: BLE001 - unreadable is not a match
        return False
    if leaf.issuer != ca.subject:
        return False
    try:
        # This project's CAs are P-256 (see pki.ensure_ca), so the EC branch is the only one
        # that can arise; anything else falls into the except below and reads as "not ours",
        # which is the safe direction (re-issue).
        public_key = ca.public_key()
        algorithm = leaf.signature_hash_algorithm
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or algorithm is None:
            return False
        public_key.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(algorithm))
    except Exception:                   # noqa: BLE001 - InvalidSignature or anything else
        return False
    return True


def _serve_tls(args: argparse.Namespace) -> dict:
    """uvicorn TLS parameters, or {} for plaintext.

    WHY THIS EXISTS. The node-claim protocol (#178) authenticates the NODE cryptographically
    but assumes the CHANNEL is server-authenticated TLS: without it, the session token and
    every job record cross the network in clear, and nothing stops an interposer answering
    as the control plane. `serve` had no way to enable TLS at all, so an operator following
    the deployment guide necessarily ran it plaintext -- a design assumption with no means
    of being satisfied.

    Auto-issued from the local CA when a PKI is present and no explicit cert is given, so
    the secure path needs no extra operator step. An explicit --tls-cert always wins, for a
    deployment terminating TLS with its own certificate.
    """
    _log = logging.getLogger("blastbox.host.cli")
    cert = getattr(args, "tls_cert", None) or os.environ.get("BLASTBOX_TLS_CERT", "")
    key = getattr(args, "tls_key", None) or os.environ.get("BLASTBOX_TLS_KEY", "")
    if bool(cert) != bool(key):
        raise SystemExit("serve: --tls-cert and --tls-key must be given together")
    if cert:
        return {"ssl_certfile": cert, "ssl_keyfile": key}
    if getattr(args, "no_tls", False):
        _log.warning(
            "serve: --no-tls -- the ingress listener is PLAINTEXT. Node session tokens and "
            "job records cross the network in clear and an interposer can answer as the "
            "control plane. Acceptable only behind a TLS-terminating proxy or on a trusted "
            "local socket.")
        return {}
    from blastbox.host.ingress.node_claim import resolve_pki_dir

    pki_dir = resolve_pki_dir()
    if pki_dir is None:
        # No PKI means the node-claim routes are not mounted either, so there is no new
        # secret on this listener and plaintext is exactly the status quo. Say so once
        # rather than refusing to start a deployment that never opted in.
        _log.info("serve: no PKI, serving plaintext as before")
        return {}
    # A CERTIFICATE ALREADY ISSUED ELSEWHERE WINS BEFORE WE ASK FOR THE CA KEY. The HARDENED
    # ingress holds ca.crt and NOT ca.key -- which is exactly what DEPLOYMENT.md tells operators
    # to copy -- so demanding the signing key here made `serve` refuse to start on the very host
    # that is most careful, and the error message offered `--no-tls` as the way out. That turned
    # the hardened deployment into the plaintext one, where a session header is a sniffable
    # ten-minute bearer credential. So: issue on the CA host, drop the pair in beside the anchor,
    # and this picks it up with no CA key present and no flags.
    existing_crt, existing_key = pki_dir / "ingress-server.crt", pki_dir / "ingress-server.key"
    if existing_crt.exists() and existing_key.exists():
        # CHECK THE CLOCK BEFORE REUSING IT. `issue_server` mints 30 days and nothing renewed
        # it: a month after the first `serve`, every node in the fleet fails verification at
        # once, restarting does not help, and recovery means knowing to delete two undocumented
        # files. Reviewed. Inside the renewal window we re-issue if we can, and if we cannot
        # (no CA key here) we serve it and say exactly how long is left.
        import datetime

        from cryptography import x509

        try:
            leaf = x509.load_pem_x509_certificate(existing_crt.read_bytes())
            left = (leaf.not_valid_after_utc
                    - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        except Exception:               # noqa: BLE001 - unreadable: fall through and re-issue
            left = -1.0
        # ...AND CHECK IT STILL CHAINS TO THE CURRENT ANCHOR. The clock is not the only way a
        # leaf goes stale: rotate the fleet CA while this certificate is unexpired and every
        # newly-enrolled node -- which trusts the replacement anchor -- rejects it at the
        # handshake, while this host reports TLS on and never reaches the re-issuance path
        # below, so even a host holding the new CA key cannot heal itself.
        # NOT GATED ON `left`. The first version checked only leaves with more than the
        # renewal window remaining, so a rotated-out leaf with < 7 days left (a quarter of a
        # 30-day leaf's life) kept `_ca_mismatch` False and took the EXPIRY fallback below --
        # serving a certificate every node rejects, with a log line about expiry. Whether a
        # leaf chains to the current anchor has nothing to do with its clock.
        _ca_mismatch = False
        _leaf_unreadable = left == -1.0 and not _readable_cert(existing_crt)
        if _leaf_unreadable:
            _log.warning("serve: the ingress certificate in %s cannot be read; it will be "
                         "re-issued if this host can", pki_dir)
        elif not _leaf_matches_ca(existing_crt, pki_dir / "ca.crt"):
            _log.warning("serve: the ingress certificate in %s was not issued by the CA "
                         "currently in ca.crt (the anchor was rotated); re-issuing rather than "
                         "serving a leaf every node will reject", pki_dir)
            left = -1.0
            _ca_mismatch = True
        if left > _TLS_RENEW_BEFORE_S:
            _log.info("serve: TLS on, using the server certificate already in %s (%.0f days "
                      "left)", pki_dir, left / 86400)
            return {"ssl_certfile": str(existing_crt), "ssl_keyfile": str(existing_key)}
        _log.warning("serve: the ingress certificate in %s expires in %.1f days; re-issuing",
                     pki_dir, max(0.0, left) / 86400)
        _reissue_wanted = True
    else:
        _reissue_wanted = False
        _ca_mismatch = False
        _leaf_unreadable = False

    from blastbox.host.pki import load_ca

    try:
        ca = load_ca(pki_dir)
    except Exception as exc:            # noqa: BLE001 - verify-only host, no CA key here
        if _reissue_wanted and _leaf_unreadable:
            # Its own message, not the rotation one: for a truncated file or a permissions
            # problem, "re-issue on the CA host" is the wrong remedy and the rotation claim is
            # simply false. Refusing is still right -- uvicorn could not load it either.
            raise SystemExit(
                f"serve: {existing_crt} cannot be read as a certificate, and this host has no CA "
                f"key to re-issue it ({exc}). Check the file and its permissions; if it is "
                f"genuinely lost, issue a new pair on the CA host and copy it to {existing_crt} / "
                f"{existing_key}.") from None
        if _reissue_wanted and _ca_mismatch:
            # NOT THE EXPIRY FALLBACK BELOW. That one serves the existing leaf because it still
            # WORKS until its deadline. A leaf from a rotated-out CA does not work at all: every
            # node that trusts the replacement anchor rejects it at the handshake. Serving it
            # would start a control plane that no federated node can reach, with a log line that
            # talks about expiry -- the one thing that is not wrong. On the hardened layout
            # (ca.crt present, ca.key deliberately absent) this host cannot fix it itself, so
            # it says exactly what to do instead of pretending.
            raise SystemExit(
                f"serve: {existing_crt} was issued by a CA that is no longer the one in "
                f"{pki_dir / 'ca.crt'} (the anchor was rotated), and this host has no CA key to "
                f"re-issue it ({exc}). Every node that trusts the new anchor would reject this "
                f"certificate, so ingress will not start with it. On the CA host run "
                f"`blastbox pki issue-server` for this host's names and copy the pair to "
                f"{existing_crt} / {existing_key}.") from None
        if _reissue_wanted:
            # A hardened ingress holds no CA key, so it cannot renew its own certificate. Do
            # not refuse to start over it -- serve the one we have and make the deadline loud.
            _log.error("serve: the ingress certificate is expiring and this host has no CA key "
                       "to re-issue it (%s). Issue a new pair on the CA host and copy it to "
                       "%s / %s BEFORE it lapses, or every node will fail verification at "
                       "once.", exc, existing_crt, existing_key)
            return {"ssl_certfile": str(existing_crt), "ssl_keyfile": str(existing_key)}
        raise SystemExit(
            f"serve: {pki_dir} has a trust anchor but no usable CA key ({exc}), so a server "
            f"certificate cannot be issued here. Either issue one on the CA host and copy it to "
            f"{existing_crt} and {existing_key} (this is the hardened arrangement -- the signing "
            f"key never reaches an internet-facing host), or pass --tls-cert/--tls-key, or "
            "--no-tls if this listener sits behind a TLS-terminating proxy.") from None
    issued = ca.issue_server(_serve_tls_sans(args.host), cn="blastbox-ingress")
    crt, key_path = issued.write(pki_dir, "ingress-server")
    _log.info("serve: TLS on, certificate auto-issued from the local CA (%s)", crt)
    return {"ssl_certfile": str(crt), "ssl_keyfile": str(key_path)}


def _serve_cmd(args: argparse.Namespace) -> int:
    import uvicorn

    workers = _serve_workers(getattr(args, "workers", None))
    tls = _serve_tls(args)

    if workers and workers > 1:
        # uvicorn forks `workers` processes; each must build its own app, so we pass an
        # import-string factory (app_from_env) instead of a prebuilt object. Propagate the
        # CLI --allowed-engines into env so the forked workers reconstruct it identically.
        if args.allowed_engines:
            os.environ["BLASTBOX_ALLOWED_ENGINES"] = args.allowed_engines
        uvicorn.run(
            "blastbox.host.ingress.app:app_from_env",
            factory=True,
            host=args.host,
            port=args.port,
            workers=workers,
            **tls,
        )
        return 0

    from blastbox.host.ingress.app import build_app
    from blastbox.host.ingress.extension import load_ingress_extension

    allowed: set[str] = set()
    if args.allowed_engines:
        allowed = {e.strip() for e in args.allowed_engines.split(",") if e.strip()}

    extension = load_ingress_extension(os.environ.get("BLASTBOX_INGRESS_EXTENSION"))
    app = build_app(allowed_engines=allowed or None, extension=extension)
    uvicorn.run(app, host=args.host, port=args.port, workers=1, **tls)
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
                None
                if keys_raw is None
                else frozenset(
                    k.strip().upper() for k in keys_raw.split(",") if k.strip()
                )
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
                (os.environ.get(f"BLASTBOX_ENGINE_{env_name}_NETPOLICY") or "none")
                .strip()
                .lower()
            )
            # Optional per-engine dispatcher-TIER allowlist (BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES):
            #   BLASTBOX_ENGINE_<NAME>_ALLOWED_RUNTIMES='cold,firecracker,gvisor'
            # Unset OR set-but-empty ⇒ None (any tier) — an empty value is the common `${VAR:-}` compose
            # idiom for "use the default", and unlike the param allowlist an empty set here would be a
            # footgun (an engine permitted on NO tier can never run). Set ⇒ only those tiers; enforced
            # fail-closed at startup (enforce_allowed_runtimes) so a BLASTBOX_POOL_RUNTIME drift can't
            # route the engine onto a tier it wasn't cleared for. An unknown tier name is a config typo —
            # raise, don't silently drop it (a dropped entry could leave the set permitting an unintended tier).
            from blastbox.host.jobs.base import VALID_TIERS

            runtimes_raw = os.environ.get(
                f"BLASTBOX_ENGINE_{env_name}_ALLOWED_RUNTIMES"
            )
            allowed_runtimes: frozenset[str] | None = None
            if runtimes_raw and runtimes_raw.strip():
                parsed = frozenset(
                    t.strip().lower() for t in runtimes_raw.split(",") if t.strip()
                )
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
                name=name,
                image=image,
                worker_argv=[],
                allowed_param_keys=allowed,
                reserved_param_keys=reserved,
                default_params=default_params,
                net_policy=net_policy,
                allowed_runtimes=allowed_runtimes,
            )
    return engines


def _node_manages_tier(tier: str, pool: object = None) -> bool:
    """True if the node autosizer is enabled AND it manages this dispatcher's runtime tier
    (firecracker/gvisor). Fully guarded — a bad BLASTBOX_NODE_* config never crashes dispatch,
    it just reports 'not managed'. Used to make the node budget a HARD cap at startup:
    force warm_only (no uncounted cold spill) and start the pool unspawned until the sizer's
    first allocation (no legacy over-spawn).

    An ALL-LOCAL cascade pool (``tier == "cascade"`` with every member on fc/gvisor) is managed
    too — its whole ceiling is this node's RAM, so it belongs in the water-fill; a cascade with
    any off-node member (aws/static/remote) is left unmanaged (see ``cascade_all_local``)."""
    try:
        from blastbox.host.node_config import NodeConfig
        from blastbox.host.node_sizer import cascade_all_local, manages

        # firecracker/gvisor = warm-pool managed; "cold" = pool-less cold-only dispatcher (a
        # separate cold process in the warm-sidecar deployment) — its docker workers spawn outside
        # any warm pool, so it also needs a budgeted gate + a published cold reservation. An
        # all-local cascade (fc/gvisor members only) is managed via member inspection of its pool.
        return NodeConfig.from_env().active and (
            manages(tier)
            or tier == "cold"
            or cascade_all_local(getattr(pool, "runtime", None))
        )
    except Exception:
        return False


def _parse_mem_mib(raw: str) -> float:
    """Parse a docker --memory-style size to MiB. Suffixes b/k/m/g; a BARE number is BYTES —
    matching what `docker run --memory` enforces and host_limits.parse_memory_gb (so sizing lines
    up with the real container limit). Returns 0.0 on anything unparseable (caller falls back to
    the warm-slot footprint)."""
    s = (raw or "").strip().lower()
    if not s:
        return 0.0
    mult = {"b": 1.0 / (1024 * 1024), "k": 1.0 / 1024, "m": 1.0, "g": 1024.0}
    unit = s[-1]
    try:
        if unit in mult:
            return max(0.0, float(s[:-1]) * mult[unit])
        return max(
            0.0, float(s) / (1024 * 1024)
        )  # BARE number → bytes (docker's unit) → MiB
    except ValueError:
        return 0.0


def _start_node_sizer(
    pool,
    engines,
    store,
    tier,
    concurrency=1,
    concurrency_gate=None,
    cold_slot_ram_mib=0.0,
):
    """Start the opt-in node self-sizer for this dispatcher's warm pool, or return None.

    Fully guarded (`except Exception`): a bad BLASTBOX_NODE_* config, an unwritable
    share_dir, or any setup error logs and disables sizing — it NEVER crashes dispatch.
    (KeyboardInterrupt/SystemExit deliberately propagate so the caller's finally still
    stops the pool.) Returns the stop Event when started, else None.

    A cold-ONLY dispatcher (tier="cold") has NO warm pool (pool is None): it is still managed
    pool-lessly — the sizer publishes a cold-footprint reservation into the node view and drives
    the concurrency gate to a budgeted cold ceiling, so warm fc/gvisor peers account for this
    process's docker workers instead of over-allocating the whole budget to warm slots."""
    cold_only = pool is None and tier == "cold"
    if pool is None and not cold_only:
        return None  # a non-cold dispatcher with no pool has nothing to manage
    sizer = None
    try:
        from blastbox.host.node_config import NodeConfig

        node_cfg = (
            NodeConfig.from_env()
        )  # inside the guard: parse errors mustn't crash dispatch
        if not (node_cfg.resource_management or node_cfg.balancing):
            return None
        import threading as _threading

        from blastbox.host.dispatcher_sizer import DispatcherSizer
        from blastbox.host.node_share import (
            _MAX_CEILING_SANE,
            _MAX_WEIGHT,
            FileNodeShare,
        )
        from blastbox.host.node_sizer import local_backlog_fn

        # A dispatcher may serve several engines on ONE pool; size on ALL of their combined
        # backlog. The pool has a single per-slot footprint, so use the CONSERVATIVE (max)
        # footprint across the served engines — a slot must fit the biggest of them; using
        # the first/smallest would under-count RAM/vCPU and let the ceiling oversubscribe.
        served = (
            list(engines)
            if engines
            else [e for e in [os.environ.get("BLASTBOX_ENGINE", "")] if e]
        )
        declared = {e.name for e in node_cfg.engines}
        mine = [e for e in node_cfg.engines if e.name in served]
        if not mine:
            print(
                f"node self-sizer: none of this dispatcher's engines {served} are in "
                f"BLASTBOX_NODE_ENGINES — not sizing (declare one to enable).",
                file=sys.stderr,
            )
            return None
        missing = [s for s in served if s not in declared]
        if missing:
            # The pool serves ALL of `served`, but the footprint/ceiling are derived only from
            # the DECLARED subset. Sizing on a partial inventory would under-count RAM/vCPU (an
            # omitted engine's slots are invisible) and oversubscribe. Fail closed: require the
            # whole pool declared, or don't size (the pool keeps its static config, no worse
            # than pre-autosizer).
            print(
                f"node self-sizer: served engines {sorted(missing)} are missing from "
                f"BLASTBOX_NODE_ENGINES — not sizing (declare EVERY served engine so the "
                f"pool footprint is complete).",
                file=sys.stderr,
            )
            return None
        base = mine[0]
        # The shared pool serves ALL of `mine`, so its usable ceiling is the SUM of the engines'
        # caps (not the min, which lets a low-cap engine throttle the pool; nor the max, which
        # undercounts SIMULTANEOUS multi-engine work — two engines capped at 8 with concurrency 16
        # and budget for 16 should be able to run 8+8). Bounded by the dispatcher's worker
        # concurrency (run_forever runs at most `concurrency` jobs at once, so a higher ceiling is
        # wasted RAM) and, downstream, by the node budget's water-fill — so it never oversubscribes.
        # (A shared pool can't enforce each engine's individual sub-cap without per-engine tracking;
        # the node budget bounds the aggregate, which is what matters for oversubscription.)
        # Clamp to _MAX_CEILING_SANE too: the reader's _valid() rejects a snapshot whose
        # max_ceiling exceeds it, so an unclamped sum (many high-cap engines + huge concurrency)
        # would silently self-evict this pool from every node view (tick returns no size, pool
        # stuck at warm-0/ceiling-1) — the same guard already applied to the summed weight.
        combined_ceiling = max(
            1, min(sum(e.max_ceiling for e in mine), concurrency, _MAX_CEILING_SANE)
        )
        # A cold-only pool's "slot" IS a docker cold worker, so its footprint is the cold worker
        # RAM (BLASTBOX_WORKER_MEMORY), not the declared warm-slot RAM, and it has NO warm floor.
        cold_footprint = (
            cold_slot_ram_mib if (cold_only and cold_slot_ram_mib > 0) else None
        )
        # NB for an all-local CASCADE (fc+gvisor members): the whole ceiling is priced at this ONE
        # per-ENGINE footprint, but the cascade fills its tiers in order so the marginal slot's real
        # RAM depends on which member tier it lands on. If the fc and gvisor slots of an engine cost
        # materially different RAM, declare BLASTBOX_NODE_ENGINE_<E>_RAM_MIB at the CONSERVATIVE (max)
        # tier footprint — else the reservation understates residency and a sibling could grow into
        # the heavier tier's RAM. (Per-engine, not per-runtime, pricing predates cascades; enrolling
        # the cascade is still strictly better than the prior state where it reserved nothing.)
        spec = replace(  # type: ignore[call-arg]
            base,
            slot_ram_mib=cold_footprint
            if cold_footprint
            else max(e.slot_ram_mib for e in mine),
            slot_vcpus=max(e.slot_vcpus for e in mine),
            # The shared pool serves ALL of `mine`, so its warm floor is the SUM of the engines'
            # floors — each engine wants its own min_warm hot. Taking the max discards the other
            # engines' floors (two engines @ MIN_WARM=2 would keep only 2 hot, not 4). Cap by the
            # combined ceiling: you can't warm more than the pool's hard ceiling anyway.
            min_warm=0
            if cold_only
            else min(sum(e.min_warm for e in mine), combined_ceiling),
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
            spec,
            pool,
            FileNodeShare(node_cfg.share_dir),
            node_cfg,
            runtime=tier,
            # scope backlog to jobs THIS tier can claim (target_tier routing) so
            # the pool isn't sized for work pinned to a tier it can never drain.
            backlog_fn=local_backlog_fn(store, served, claimant_tier=tier),
            # the UNTARGETED portion (target_tier IS NULL) — shared by every tier of the engine —
            # so the planner counts it ONCE across the engine's tier-pools, not once per tier.
            # ATTRIBUTION: like backlog_fn above, this aggregates over ALL of `served` and the
            # snapshot is keyed to mine[0] (base). If two tiers serve DIFFERENT-but-overlapping
            # engine sets that collide on mine[0]'s name (fc serves {aa,bb}, gvisor serves {aa}),
            # bb's untargeted is deduped against gvisor even though gvisor can't drain it — the
            # SAME aggregate-attribution approximation the targeted path already makes (see the
            # per-engine sub-cap note at combined_ceiling). It only ever LOWERS a pool's demand
            # (dedup-under, replacing the pre-dedup per-tier double-count-OVER), so it can under-
            # serve a pool but never oversubscribe — the node budget water-fill remains the hard
            # bound. Precise per-engine untargeted would need per-engine snapshot counts (schema
            # expansion); deferred as a bounded, safe-direction approximation.
            untargeted_backlog_fn=local_backlog_fn(store, served, untargeted_only=True),
            concurrency_gate=concurrency_gate,  # sizer drives its live limit on each resize
            cold_slot_ram_mib=cold_slot_ram_mib,  # price cold permits by the cold worker footprint
        )
        # Print the status FIRST, then start the thread LAST — otherwise if this print raises
        # (broken pipe / closed stderr) the except below returns None while the thread is
        # already running, leaking a daemon the caller can never stop or join.
        print(
            f"node self-sizer: managing {spec.name!r} "
            f"{'cold-only gate' if cold_only else 'warm pool'} (backlog over {served}) "
            f"from {node_cfg.share_dir} "
            f"({'balancing' if node_cfg.balancing else 'static shares'})",
            file=sys.stderr,
        )
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
            "node self-sizer setup failed — continuing without it", exc_info=True
        )
        # The synchronous first tick may have already PUBLISHED a snapshot (the heartbeat succeeds
        # before a later step — the update publish, a read, or start_thread — raises). If we return
        # None now, the caller restores the pool to its legacy size but the phantom snapshot lingers
        # advertising ~0 demand, then ages out permanently → peers reclaim this node's share while
        # the pool runs unmanaged at full size = persistent oversubscription. Remove it on the way out.
        if sizer is not None:
            sizer.remove_own_snapshot()
        return None


def _canary_settings() -> "tuple[bool, float]":
    """(enabled, interval) for the startup/periodic store self-test.

    DISABLED ON EXPLICIT FALSE ONLY. An affirmative allowlist ("1"/"true"/...) turns a typo -- or
    the set-but-empty shape compose produces for an unset variable -- into a silent OFF, which
    fails OPEN on a check whose entire value is failing closed: an operator who fat-fingers `treu`
    would silently get the unfetchable-result failure mode back, with no warning.
    """
    log = logging.getLogger("blastbox.host.cli")
    raw = os.environ.get("BLASTBOX_CANARY")
    val = (raw or "").strip().lower()
    if val in ("0", "false", "no", "off"):
        enabled = False
    else:
        enabled = True
        if raw is not None and val not in ("1", "true", "yes", "on", ""):
            log.warning(
                "BLASTBOX_CANARY=%r is not a recognised boolean; leaving the startup "
                "canary ENABLED (set 0/false/no/off to disable)",
                raw,
            )
    raw_interval = os.environ.get("BLASTBOX_CANARY_INTERVAL_S", "900")
    try:
        interval = float(raw_interval)
    except ValueError:
        log.warning(
            "BLASTBOX_CANARY_INTERVAL_S=%r is not a number; using 900", raw_interval
        )
        interval = 900.0
    # float() happily accepts "nan" and "inf". Neither raises, and both silently switch the
    # periodic pass OFF: every `elapsed >= nan` is False, and `elapsed >= inf` never becomes
    # True. A malformed setting must not disable a check by accident -- that is the same
    # fail-open shape as the boolean parsing above.
    # Negative is the same trap one step along: -1 is finite, passes, and then every dispatcher
    # tests `interval > 0` before scheduling -- so it disables the periodic pass while the
    # documented disable value is 0. A malformed setting must never turn a check off by accident.
    if not math.isfinite(interval) or interval < 0:
        log.warning(
            "BLASTBOX_CANARY_INTERVAL_S=%r is not a usable interval (needs a finite "
            "value >= 0, where 0 means startup-only); using 900",
            raw_interval,
        )
        interval = 900.0
    return enabled, interval


def _require_shared_blob_store() -> bool:
    """Has the operator declared this a fleet whose results MUST be shared?

    The canary cannot infer it: both attempts to deduce "can the other processes read this store"
    from the deployment refused documented single-node and NFS configurations. This is the
    topology evidence, stated by the person who knows it.
    """
    raw = os.environ.get("BLASTBOX_REQUIRE_SHARED_BLOB_STORE")
    val = (raw or "").strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    # An affirmative allowlist here repeats, in the variable added to FIX that bug, the exact
    # fail-open shape already fixed for BLASTBOX_CANARY: a typo returns the default silently.
    # This one is a deliberate topology declaration -- someone set it on purpose -- so a value
    # that parses as neither must be said out loud rather than quietly ignored.
    if raw is not None and val not in ("0", "false", "no", "off", ""):
        logging.getLogger("blastbox.host.cli").warning(
            "BLASTBOX_REQUIRE_SHARED_BLOB_STORE=%r is not a recognised boolean; treating it as "
            "NOT set (the shared-store check stays advisory). Use 1/true/yes/on to enforce.",
            raw,
        )
    return False


def _dispatch_cmd(args: argparse.Namespace) -> int:
    from blastbox.host.dispatch import Dispatcher
    from blastbox.host.jobs.factory import build_job_store_from_env

    # Build engine specs from env or CLI.
    # Format expected: ENGINE_NAME=image:tag[,ENGINE_NAME2=image2:tag2]
    engines_raw = args.engines or os.environ.get("BLASTBOX_ENGINES", "")
    engines = _parse_engine_specs(engines_raw)

    if not engines:
        print(
            "error: no engines configured (set --engines or BLASTBOX_ENGINES)",
            file=sys.stderr,
        )
        return 1

    limits = Limits.from_env()
    job_root = Path(os.environ.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs"))
    store = build_job_store_from_env()

    # Opt-in warm pool (BLASTBOX_POOL_RUNTIME; default "none" → cold path only).
    from blastbox.host.pool_config import build_warm_pool

    pool = (
        build_warm_pool()
    )  # built, NOT started -- start only after all validation below, so a
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

    warm_only = os.environ.get("BLASTBOX_DISPATCH_WARM_ONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    node_managed = _node_manages_tier(tier, pool)
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

    concurrency_gate = (
        DynamicConcurrencyGate(dispatch_concurrency) if node_managed else None
    )
    # Cold worker footprint (BLASTBOX_WORKER_MEMORY, docker --memory default "4g"), so the sizer
    # prices cold permits by REAL cold RAM rather than assuming a cold worker == one warm slot.
    cold_slot_ram_mib = _parse_mem_mib(
        os.environ.get("BLASTBOX_WORKER_MEMORY", "") or "4g"
    )

    # Fail-closed BEFORE pool.start(): refuse to run an engine on ANY tier this dispatcher can execute
    # it on — the advertised tier PLUS the cold-fallback/egress-bypass ("cold") and cascade overflow
    # tiers (reachable_tiers) — so a BLASTBOX_POOL_RUNTIME/_TIERS drift can't route a locally-vetted
    # engine onto a public-AWS/remote worker with a different egress posture (no slot spawns on a raise).
    from blastbox.host.dispatch import enforce_allowed_runtimes, reachable_tiers

    enforce_allowed_runtimes(engines, reachable_tiers(pool, tier, warm_only))

    # Capability-based routing: the runtime declares its dispatch_style. A network-endpoint pool
    # (aws / static / cascade) drives workers over http_agent + remote_http via VmJobDispatcher; every
    # other runtime uses the file-handshake Dispatcher below. A cascade mixing styles raises here.
    if (
        pool is not None
        and getattr(pool.runtime, "dispatch_style", "file") == "network"
    ):
        from blastbox.host.runtime.vm_dispatch import build_remote_vm_dispatcher

        # a network-endpoint pool serves ONE worker image/agent (BLASTBOX_ENGINE); a multi-engine
        # dispatcher here would send other engines' jobs to the wrong agent -- require exactly one.
        if len(engines) != 1:
            raise ValueError(
                "network-endpoint tiers (aws/static/cascade) serve a single engine image; "
                "configure one engine or run separately-scoped remote pools"
            )
        vm = build_remote_vm_dispatcher(
            store,
            job_root,
            pool,
            tier=tier,
            engine=next(iter(engines)),
            engine_spec=next(iter(engines.values())),
            limits=limits,
            worker_timeout_s=float(
                os.environ.get("BLASTBOX_WORKER_TIMEOUT_S") or "300"
            ),
            warm_claim_timeout_s=float(
                os.environ.get("BLASTBOX_WARM_CLAIM_TIMEOUT_S") or "60"
            ),
            concurrency=int(os.environ.get("BLASTBOX_DISPATCH_CONCURRENCY") or "1"),
            job_retention_s=int(
                os.environ.get("BLASTBOX_JOB_RETENTION_SECONDS") or "0"
            ),
        )
        # The network branch returns below without ever reaching Dispatcher.run_forever, so the
        # startup gate has to be applied HERE as well. These are the aws/static/cascade tiers --
        # the distributed ones, whose results necessarily travel through a shared blob store, and
        # therefore the ones where an unwritable or unreadable store is most likely and most
        # expensive. Before pool.start(), so a misconfigured deployment does not spawn microVMs
        # it is only going to fail jobs on.
        _vm_canary, _canary_interval = _canary_settings()
        from blastbox.host.canary import (
            blob_roundtrip,
            check_blob_target_agreement,
            check_store_coherence,
            describe_blob_store,
        )

        _vmlog = logging.getLogger("blastbox.host.cli")
        _vmblobs = getattr(vm, "_blobs", None)
        if _vmblobs is None:
            if _vm_canary:
                _vmlog.warning(
                    "canary: this dispatcher exposes no blob store; skipping"
                )
        else:
            # OUTSIDE THE TOGGLE, exactly as Dispatcher.run_forever does for the container path.
            # That comment states the invariant -- "TOPOLOGY ENFORCEMENT IS NOT THE PROBE, and must
            # not share its off switch" -- and this sibling was left behind when it was written. So
            # on aws/static/cascade, BLASTBOX_CANARY=0 silently dropped the hard
            # BLASTBOX_REQUIRE_SHARED_BLOB_STORE requirement AND the target-agreement check, neither
            # of which that variable documents any control over. Those are the distributed tiers,
            # whose results necessarily travel through a shared store -- the ones with the most to
            # lose. The identity log line moves out too, or the side-by-side grep the guide tells
            # operators to use disappears in precisely the deployments that opted out.
            _vmlog.info("canary.blob_store %s", describe_blob_store(_vmblobs))
            check_store_coherence(
                store, _vmblobs, job_root, require_shared=_require_shared_blob_store()
            )
            # (registration deferred until after the probe -- see below)
        # ...and the ROUND-TRIP stays gated: that is the probe, and the probe is what the toggle is
        # documented to control.
        # Computed unconditionally: it is a string, not a probe, and binding it only inside the
        # canary branch left the periodic-callback default below reading an UNBOUND local whenever
        # BLASTBOX_CANARY=0 -- so the documented opt-out crashed the dispatcher with
        # UnboundLocalError before pool.start() instead of skipping the probe.
        _vmkey = f"{tier or ''}|{next(iter(engines), '')}|{job_root}"
        if _vm_canary and _vmblobs is not None:
            _vmlog.info(
                "canary.ok %s",
                blob_roundtrip(_vmblobs, key_hint=_vmkey, scratch_dir=job_root),
            )
        # AFTER the round-trip, same as Dispatcher.run_forever. A network dispatcher pointed at an
        # unreachable or unauthorized bucket used to claim that target and only then fail its probe,
        # so correcting the config did not let it restart -- it mismatched its own stale
        # registration and needed a `blob-target reset` nobody would think to run. Fifth sibling
        # call site on this branch to need the same fix after the first one got it.
        if _vmblobs is not None:
            check_blob_target_agreement(store, _vmblobs, role="dispatcher")

            # ...and only INSTALL the periodic probe when the probe is enabled. Registering a
            # callback that re-runs the round-trip under CANARY=0 would reintroduce the very thing
            # the operator opted out of, on a timer.
            def _vm_periodic_canary(
                _b=_vmblobs, _l=_vmlog, _k=_vmkey, _jr=job_root
            ) -> None:
                _l.info(
                    "canary.ok %s", blob_roundtrip(_b, key_hint=_k, scratch_dir=_jr)
                )

            # Advisory once serving: a store that goes away mid-run is a brownout, not a
            # config error, and tearing down a warm fleet over it is what #79 exists to stop.
            if _vm_canary:
                vm._canary_cb = _vm_periodic_canary
                vm._canary_interval_s = _canary_interval
        pool.start()  # validation passed -> now spawn/warm slots (nothing to leak on an earlier raise)
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
                    logging.getLogger("blastbox.host.cli").warning(
                        "startup orphan sweep failed", exc_info=True
                    )
            vm.run()
        except BaseException:
            vm.stop()  # release the executor's worker loops so the finally's pool.stop() can reap
            raise
        finally:
            pool.stop()
        return 0

    pre_shrunk = (
        None  # (warm_size, ceiling) captured before pre-shrink, to restore if the
    )
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
                pool.resize(
                    warm_size=0,
                    concurrent_ceiling=1,  # type: ignore[attr-defined]
                    mark_autosized=False,
                )
            except Exception:
                pre_shrunk = None
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: could not pre-shrink pool before start",
                    exc_info=True,
                )
        pool.start()  # file-handshake warm path: start after tier-identity validation
    dispatcher = Dispatcher(
        require_shared_blob_store=_require_shared_blob_store(),
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
        job_retention_seconds=int(
            os.environ.get("BLASTBOX_JOB_RETENTION_SECONDS") or "0"
        ),
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
        # Gate on node_managed so ONLY a tier the autosizer actually manages is sized: fc/gvisor,
        # the cold-only dispatcher, and an ALL-LOCAL cascade (fc/gvisor members). Without this gate
        # _start_node_sizer would size ANY file-dispatch pool whenever NodeConfig is active — e.g. a
        # cascade carrying an off-node member — folding non-local capacity into the local water-fill.
        # (Network pools already returned above via the VmJobDispatcher branch and never reach here.)
        if node_managed:
            sizer = _start_node_sizer(
                pool,
                engines,
                store,
                tier,
                dispatch_concurrency,
                concurrency_gate,
                cold_slot_ram_mib,
            )
        # If we pre-shrank the pool for the autosizer but the sizer did NOT start (incomplete
        # inventory, unwritable share_dir, setup error), nothing will ever size it — restore
        # its configured warm/ceiling so it runs normally (pre-autosizer static behavior)
        # instead of being stuck at warm=0 and unable to serve.
        if sizer is None and pre_shrunk is not None and pool is not None:
            try:
                # Restore AND leave the pool un-managed (mark_autosized=False) so a skipped
                # opt-in keeps legacy lazy-drain behavior, not eager surplus reaping.
                pool.resize(
                    warm_size=pre_shrunk[0],
                    concurrent_ceiling=pre_shrunk[1],
                    mark_autosized=False,
                )
                # The synchronous first tick may have already lowered the gate to the autosizer's
                # cold limit (~1) before setup rolled back; restore it to the operator's dispatch
                # concurrency so an aborted opt-in doesn't leave the dispatcher throttled to 1 cold
                # job until restart.
                if concurrency_gate is not None:
                    concurrency_gate.set_limit(dispatch_concurrency)
            except Exception:
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: could not restore pool after skipped sizing",
                    exc_info=True,
                )
        # BLASTBOX_CANARY=0 disables the startup self-test. It defaults ON and fails closed: a
        # dispatcher that cannot round-trip a result through its own blob store cannot serve a job,
        # and every deployment bug this catches previously surfaced only as DONE jobs whose
        # artifacts 404'd. Provided as an escape hatch for a store that is deliberately unavailable
        # at boot, not as something a normal deployment should set.
        canary, canary_interval_s = _canary_settings()
        dispatcher.run_forever(
            poll_interval_s=args.poll_interval,
            concurrency=dispatch_concurrency,
            canary=canary,
            canary_interval_s=canary_interval_s,
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
        cold_inflight = (
            concurrency_gate.in_flight if concurrency_gate is not None else 0
        )
        if sizer is not None:
            sizer_stop, sizer_thread, sizer_obj = sizer
            sizer_stop.set()
            sizer_thread.join(timeout=5.0)  # sleeps on the event → returns promptly
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
                sizer_obj.publish_orphan_lease(orphans, cold_inflight)
                logging.getLogger("blastbox.host.cli").warning(
                    "node self-sizer: shutdown left %d unreaped warm slot(s) + %d cold worker(s) "
                    "in flight — leased the node reservation (extended lifetime) so peers don't "
                    "reallocate still-used capacity; a permanent orphan needs an external reaper",
                    orphans,
                    cold_inflight,
                )
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
        res = run_scenario(
            args.scenario, BenchConfig(runs=args.runs, warmup=args.warmup)
        )
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


def _blob_target_cmd(args: argparse.Namespace) -> int:
    """Show or clear the blob target registered on the job queue.

    The escape hatch for the agreement check. A fleet deliberately moving buckets would otherwise
    be refused by its own recorded fingerprint forever, so clearing has to be POSSIBLE -- and
    explicit, which is why it is a command rather than an environment variable. An env var set once
    to get past a migration tends to stay set, and would disarm the check permanently on a fleet
    that believes it is protected.
    """
    from blastbox.host.jobs.base import BlobTargetRegistry
    from blastbox.host.jobs.factory import build_job_store_from_env

    store = build_job_store_from_env()
    if not isinstance(store, BlobTargetRegistry):
        print(
            f"{type(store).__name__} cannot record a blob target; nothing to show or reset."
        )
        return 1
    if args.blob_target_cmd == "reset":
        current = store.get_blob_target()
        # STOP THE FLEET FIRST, and say so before doing anything. Agreement is checked at STARTUP
        # only -- in Dispatcher.run_forever, the network CLI path and build_app -- so a process that
        # is already running never revalidates. Clearing under a live fleet therefore lets a
        # restarted process adopt a NEW target while the old ones keep using the previous one, and
        # a rolling restart writes results to one store while still serving from the other. That is
        # the unreadable-results failure this command exists to help you out of, reintroduced by
        # the command itself.
        #
        # Enforcing quiescence is not something this process can do -- it cannot see the fleet --
        # so the honest move is to make the requirement impossible to miss and require the operator
        # to affirm it, rather than printing advice after the registry is already gone.
        if not getattr(args, "yes", False):
            print(
                "REFUSING: `blob-target reset` is only safe on a STOPPED fleet.\n"
                f"  currently registered: {current or '(nothing)'}\n"
                "\n"
                "Agreement is checked at STARTUP only, so processes that are already running\n"
                "will not notice the reset. If you clear this while they are up, a restarted\n"
                "process can adopt a new target while the others keep the old one -- results get\n"
                "written to one store and served from the other, which is the failure this\n"
                "command is meant to help you escape.\n"
                "\n"
                "Stop every dispatcher and ingress on this queue, then re-run with --yes.\n"
                "Afterwards start ONE process first and confirm its logged canary.blob_store\n"
                "line before starting the rest, or you will simply record the wrong target."
            )
            return 2
        store.clear_blob_target()
        print(
            f"blob target cleared (was: {current or 'nothing'}). Start ONE process first and "
            f"confirm its target before starting the rest."
        )
        return 0
    # READ-ONLY. Reaching for claim_blob_target here would let `show` register its own argument on
    # an empty queue, after which every real process mismatches it -- a diagnostic that bricks the
    # thing it is diagnosing. Hence the separate accessor.
    current = store.get_blob_target()
    print(current or "(no blob target recorded yet)")
    return 0


def _claim_key_cmd(args: argparse.Namespace) -> int:
    """Show whether a node signing key is recorded on the job queue, or rotate it.

    NEVER PRINTS THE KEY. `show` reports presence and a short fingerprint so two ingress hosts
    can confirm they resolved the same one; the value itself is a credential and this project
    does not put those on terminals. Same stopped-fleet discipline as `blob-target reset`, for
    the same reason: every ingress caches the key it resolved at boot, so clearing under a live
    fleet is the multi-host divergence reintroduced by the tool meant to manage it.
    """
    import hashlib
    import os as _os

    from blastbox.host.jobs.base import ClaimKeyRegistry
    from blastbox.host.jobs.factory import build_job_store_from_env
    from blastbox.host.node_auth import SECRET_FILE_ENV

    # THE OVERRIDE WINS AT RUNTIME, SO IT WINS HERE. `resolve_claim_secret` returns the file
    # before it ever touches the store, so reporting the store's row on such a host answers a
    # different question than the operator asked -- and the command exists precisely so two
    # hosts can confirm they agree.
    override = (_os.environ.get(SECRET_FILE_ENV) or "").strip()
    if override:
        print(f"{SECRET_FILE_ENV}={override} is set, so this host signs with that FILE and not "
              f"with the job queue. Compare the file across hosts; the queue's row is unused "
              f"here.")
        return 1
    # WITHOUT A DSN THE FACTORY HANDS BACK AN IN-MEMORY STORE, which satisfies the registry --
    # so `reset --yes` printed success and mutated a throwaway object. An operator rotating a
    # suspected-compromised key would restart the fleet onto the same key, told it had changed.
    if not (_os.environ.get("BLASTBOX_DATABASE_URL") or "").strip():
        print("BLASTBOX_DATABASE_URL is not set in this shell, so there is no fleet queue to "
              "read. Set it to the same DSN the ingress processes use and re-run -- otherwise "
              "this would report on a throwaway in-memory store.")
        return 2

    store = build_job_store_from_env()
    if not isinstance(store, ClaimKeyRegistry):
        print(f"{type(store).__name__} cannot record a node signing key; ingress hosts on this "
              f"store use a per-host file (see BLASTBOX_CLAIM_SECRET_FILE).")
        return 1
    current = store.get_signing_key()
    if args.claim_key_cmd == "reset":
        if not getattr(args, "yes", False):
            print(
                "REFUSING: `claim-key reset` is only safe on a STOPPED fleet.\n"
                f"  currently recorded: {'yes' if current else 'no'}\n"
                "\n"
                "Every ingress process resolves the key ONCE at startup and keeps it. Clearing\n"
                "while any are running means the next one to start claims a NEW key while the\n"
                "rest keep the old one -- node sessions minted on one host are then rejected by\n"
                "another, which is the failure this key exists to prevent.\n"
                "\n"
                "Stop every ingress on this queue, then re-run with --yes and restart them all.\n"
                "In-flight node sessions (10 min) and challenges (60 s) are invalidated; nodes\n"
                "re-handshake on their own."
            )
            return 2
        store.clear_signing_key()
        print("node signing key cleared. Restart EVERY ingress; the first one up records the "
              "new key and the rest adopt it.")
        return 0
    if not current:
        print("(no node signing key recorded yet -- the first ingress to start with a PKI "
              "records one)")
        return 0
    # FINGERPRINT THE EFFECTIVE KEY, not the stored half. BLASTBOX_API_KEY is the pepper
    # (see node_auth.resolve_claim_secret), so the stored value is identical on every host by
    # construction -- the command whose whole purpose is "confirm two hosts agree" could never
    # report a difference, and would actively confirm a false agreement between a keyed and a
    # keyless ingress, which is exactly the split that breaks node sessions.
    import hmac as _hmac

    api_key = (_os.environ.get("BLASTBOX_API_KEY") or "").strip()
    if api_key:
        effective = _hmac.new(api_key.encode(), bytes.fromhex(current),
                              hashlib.sha256).digest()
        digest = hashlib.sha256(effective).hexdigest()[:12]
        print(f"recorded, peppered with BLASTBOX_API_KEY (effective fingerprint {digest}). "
              f"Compare this across ingress hosts -- it differs if their API keys differ, "
              f"which is what splits node sessions. The key itself is never printed.")
    else:
        digest = hashlib.sha256(current.encode()).hexdigest()[:12]
        print(f"recorded, NOT peppered -- BLASTBOX_API_KEY is unset here (fingerprint "
              f"{digest}). A host that HAS an API key resolves a different effective key, so "
              f"compare this only against other unkeyed hosts. The key itself is never printed.")
    return 0


def _version_cmd(_: argparse.Namespace) -> int:
    print(f"blastbox {__version__}")
    return 0


def _pki_cmd(args: argparse.Namespace) -> int:
    from pathlib import Path

    from blastbox.host.pki import ensure_ca, import_ca

    pki_dir = Path(args.dir)
    if args.pki_action == "import-ca":
        # install a pre-generated CA (BEFORE ensure_ca, which would otherwise mint a fresh one) so
        # several hosts / a shared worker pool trust one root -- the multi-dispatcher failover case.
        import_ca(
            pki_dir, Path(args.ca_cert).read_bytes(), Path(args.ca_key).read_bytes()
        )
        print(f"imported CA into {pki_dir}")
        print(
            f"  ca.crt  (public trust anchor -> bake into worker images)      : {pki_dir / 'ca.crt'}"
        )
        print(
            f"  ca.key  (issuing key -- keep on issuing hosts only, 0600)      : {pki_dir / 'ca.key'}"
        )
        return 0
    ca = ensure_ca(pki_dir)  # generate-or-load the CA
    if args.pki_action == "init":
        crt, key = ca.issue_client("dispatcher", days=args.days).write(
            pki_dir, "dispatcher"
        )
        print(f"CA ready in {pki_dir}")
        print(
            f"  ca.crt         (public trust anchor -> bake into worker images) : {pki_dir / 'ca.crt'}"
        )
        print(
            f"  dispatcher.crt / dispatcher.key  (host mTLS client cert)        : {crt} / {key}"
        )
        return 0
    if args.pki_action == "issue-server":
        name = args.name or (args.san[0] if args.san else "server")
        crt, key = ca.issue_server(args.san, cn=args.cn, days=args.days).write(
            pki_dir, name
        )
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
    if args.pki_action == "issue-node":
        from blastbox.host.pki import NodeGrants
        grants = NodeGrants(engines=tuple(args.engine), tiers=tuple(args.tier),
                            credentials=bool(args.credentials))
        issued = ca.issue_node(args.node_id, wg_pubkey=args.wg_pubkey,
                               grants=grants, days=args.days)
        if args.out:
            # `write` appends the suffixes, so an --out the operator spelled with one
            # produced toolz3.crt.crt and toolz3.crt.key — findable only by looking.
            stem = Path(args.out)
            if stem.suffix in (".crt", ".key", ".pem"):
                stem = stem.with_suffix("")
            crt, key = issued.write(stem.parent or pki_dir, stem.name)
        else:
            crt, key = issued.write(pki_dir, f"node-{args.node_id}")
        print(f"node cert for {args.node_id} ({args.days}d) -> {crt} / {key}")
        print(f"  {key} is a PRIVATE KEY (0600). Renewal is this same command with the "
              f"same --node-id and --wg-pubkey, then `egress peer-add --cert {crt}`; at "
              f"{args.days}d it is a recurring step, not a one-off enrolment.")
        if not grants.engines and not grants.tiers:
            # Fail-closed defaults are correct but silently useless; say so once here
            # rather than let an operator debug an idle node.
            print("  NOTE: no --engine/--tier granted, so this node is authorised for "
                  "nothing. Reissue with grants when you want it to take work.")
        print(f"  grants: engines={list(grants.engines)} tiers={list(grants.tiers)} "
              f"credentials={grants.credentials}")
        return 0
    if args.pki_action == "show-node":
        from blastbox.host.pki import node_identity
        try:
            ident = node_identity(ca, Path(args.cert).read_bytes(), allow_expired=True)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({
            "node_id": ident.node_id, "wg_pubkey": ident.wg_pubkey,
            "engines": list(ident.grants.engines), "tiers": list(ident.grants.tiers),
            "credentials": ident.grants.credentials,
            "not_after": ident.not_after.isoformat(), "expired": ident.expired,
        }, indent=2))
        return 1 if ident.expired else 0
    if args.pki_action == "node-status":
        # THE QUESTION AN OPERATOR ACTUALLY HAS, which nothing could answer. `show-node
        # --cert <path>` needs them to already know the path, so it cannot reveal what
        # the environment RESOLVES to; it verifies with allow_expired=True, so it prints
        # a healthy identity for a certificate the dispatcher refuses; and it says
        # nothing about whether the gate is armed. A node quietly not draining its queue
        # had no diagnostic at all.
        from blastbox.host.placement import NO_GATE, SelfGrants

        gate = SelfGrants()
        cert_at = gate.cert_path()
        value = gate.grants()
        armed = value is not NO_GATE
        status: dict[str, object] = {
            "gate_armed": armed,
            # EVERY ARM STATES ONLY WHAT WAS ACTUALLY CHECKED. Two were wrong:
            #  * the forced-off arm asserted "DESPITE having a certificate at X" for a
            #    path `cert_path()` deliberately never touches, and then said "unset it
            #    to arm the gate" — which, for a path that does not exist, turns a node
            #    reporting "runs unrestricted" into one that refuses every job. The
            #    command telling the operator to make that edit is the worst place for it.
            #  * with the gate forced ON and no certificate, `grants()` returns None, so
            #    `armed` was True and it reported "certificate configured but DOES NOT
            #    VERIFY" while `cert_path` in the same object was null — contradicting
            #    its own log line a few milliseconds earlier.
            "why": (
                f"{SelfGrants.GATE_ENV} is off, so this node runs unrestricted. A "
                f"certificate path IS configured ({cert_at}) — whether it is usable was "
                f"not checked, because the gate is disabled. Unset {SelfGrants.GATE_ENV} "
                "to arm it, and verify with this command afterwards."
                if not armed and gate.gate_forced() == "off" and cert_at is not None
                else f"{SelfGrants.GATE_ENV} is off, so this node runs unrestricted (no "
                f"certificate is configured either)."
                if not armed and gate.gate_forced() == "off"
                else "no certificate configured — this node runs unrestricted "
                f"(set {SelfGrants.CERT_ENV} to arm it)" if not armed
                else f"{SelfGrants.GATE_ENV} is on but no certificate is configured, so "
                f"this node refuses ALL work. Set {SelfGrants.CERT_ENV}."
                if value is None and cert_at is None
                else "certificate verified" if value is not None
                else "certificate configured but DOES NOT VERIFY — this node refuses "
                     "all work until it is renewed"),
            "cert_path": str(cert_at) if cert_at else None,
            "forced": gate.gate_forced() or None,
            "egress_mode": gate.egress_mode() or None,
        }
        if armed and value is not None:
            status["node_id"] = gate.node_id
            status["engines"] = list(value.engines)
            status["tiers"] = list(value.tiers)
            status["credentials"] = value.credentials
            # What this node would do with the COMMONEST job, which is the thing the
            # grant list does not make obvious: a sealed job needs no tier at all.
            # THROUGH THE GATE'S OWN PREDICATE, not a hand-rolled call that drops
            # `require_credentials`. This printed would_run["socks"] = "yes" for a
            # certificate with credentials=False while the dispatcher refused it — the
            # diagnostic added for "a node quietly not draining its queue" actively
            # contradicting the gate it exists to explain, on four of the eight tiers it
            # lists.
            status["would_run"] = {
                name: (gate.refuse(engine=args.engine,
                                   personality=type("_P", (), {"exit_driver": name})())
                       or "yes")
                for name in ("none", "direct", "tor", "socks", "httpproxy",
                             "openvpn", "wireguard", "inetsim")
            }
            status["checked_engine"] = args.engine
        print(json.dumps(status, indent=2))
        return 0 if (not armed or value is not None) else 1
    if args.pki_action == "show-ca":
        print((pki_dir / "ca.crt").read_text(), end="")
        return 0
    return 2


def _migrate_results_cmd(args) -> int:
    """Upload pre-blob-store results so the scratch reclaim can finally free their disk.

    The reclaim refuses to delete a DONE job whose result is not in the blob store -- those are
    legacy jobs whose only copy is the local tree, and deleting them would destroy results the API
    still serves. Correct, but permanent: nothing else ever uploads them, so on an upgraded node
    they accumulate as trees the sweep can only ever retain (~82k of them on the fleet this was
    written for). This is the operator action that ends that state.
    """
    import logging as _logging
    import os as _os
    from pathlib import Path as _Path

    from blastbox.host.blobs.factory import build_blob_store_from_env
    from blastbox.host.jobs.factory import build_job_store_from_env
    from blastbox.host.jobs.retention import migrate_legacy_results

    job_root = _Path(
        args.job_root or _os.environ.get("BLASTBOX_JOB_ROOT", "/var/lib/blastbox/jobs")
    )
    blobs = build_blob_store_from_env(
        {**_os.environ, "BLASTBOX_JOB_ROOT": str(job_root)}
    )
    store = build_job_store_from_env()
    log = _logging.getLogger("blastbox.migrate")
    migrated, skipped, failed = migrate_legacy_results(
        job_root,
        blobs,
        store,
        log,
        limit=args.limit,
        dry_run=args.dry_run,
    )
    print(
        f"migrated={migrated} already-durable={skipped} failed={failed}"
        + (" (dry run — nothing was uploaded)" if args.dry_run else "")
    )
    return 1 if failed else 0


def _egress_cmd(args: argparse.Namespace) -> int:
    try:
        return _egress_cmd_inner(args)
    except RuntimeError as exc:
        # The host layer raises RuntimeError for "your node is not in a state where this
        # can work" (missing image, unreachable sidecar, nothing free to relocate to).
        # Those are all actionable messages; a traceback hides them.
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _egress_cmd_inner(args: argparse.Namespace) -> int:
    """Node egress setup: bridges, exit mode, overlay transport.

    Deliberately a thin shell over blastbox.host.egress{,_apply} — the decisions live
    there as pure functions so they are testable without root.
    """
    from blastbox.host import egress_apply as ea
    from blastbox.host.egress import EgressConfig

    def cfg_from(args: argparse.Namespace) -> EgressConfig:
        # The node's PERSISTED config is the base, not bare os.environ. `check`/`health`
        # on a managed node must describe that node — reading the environment alone
        # reported a global-mode node as local and probed the default gateway address,
        # which on a relocated node is an address nothing holds. Explicit flags and
        # environment still override, so an operator can inspect a hypothetical.
        base = ea.persisted_config()
        over: dict[str, object] = {}
        for attr, fieldname in (("mode", "mode"), ("upstream_gw", "upstream_gw"),
                                ("gateway_ip", "vpn_gateway_ip"), ("wg_iface", "wg_iface")):
            v = getattr(args, attr, None)
            if v:
                over[fieldname] = v
        return replace(base, **over) if over else base  # type: ignore[arg-type]

    # A misconfiguration is an operator error, not a crash. EgressConfig validates hard
    # (an off-subnet gateway, a global node with no upstream) precisely so these are
    # caught before anything touches the host — but a traceback buries the message.
    try:
        _ = cfg_from(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    action = args.egress_action
    if action == "check":
        cfg = cfg_from(args)
        for row in ea.check_node(cfg):
            print(f"  {row}")
        return 0 if ea.node_health(cfg).healthy else 1

    if action == "health":
        # Machine-readable, for a monitoring probe or the dispatcher's own gate.
        cfg = cfg_from(args)
        h = ea.node_health(cfg)
        print(json.dumps({"healthy": h.healthy, "reason": h.reason, "mode": cfg.mode}))
        return 0 if h.healthy else 1

    if action == "apply":
        cfg = cfg_from(args)
        cfg, notes = ea.apply_node(cfg, dry_run=args.dry_run, auto_subnets=not args.no_auto_subnets)
        for n in notes:
            print(f"  {n}")
        if not args.dry_run:
            h = ea.await_health(cfg)
            print(f"  health: {'OK' if h.healthy else 'DEGRADED'} — {h.reason}")
            # APPLY REPORTS HEALTH; IT DOES NOT FAIL ON IT. A local-mode node that only
            # runs direct/inetsim/socks/tor personalities has no sidecar at the VPN
            # gateway address and never will — so the documented bridge-setup command
            # waited ~45s and exited 1 after configuring everything correctly, and the
            # boot unit then repeated that failure forever under Restart=on-failure.
            # `check` and `health` are the commands whose exit code means "is this node
            # currently able to egress"; `apply` means "did the configuration apply".
            if not h.healthy:
                print("  (the configuration applied; `blastbox egress check` is the "
                      "command whose exit status reflects health)")
        return 0

    if action == "teardown":
        cfg = cfg_from(args)
        for n in ea.teardown_node(cfg, remove_bridges=args.remove_bridges):
            print(f"  {n}")
        return 0

    if action == "gateway":
        cfg = cfg_from(args)
        pub = ea.setup_gateway(cfg)
        print(f"  exit host up on {cfg.overlay_gateway_ip}, udp/{cfg.wg_port}")
        print(f"  public key: {pub}")
        return 0

    if action == "gateway-exit":
        for n in ea.apply_exit_host(cfg_from(args), persist=True):
            print(f"  {n}")
        return 0

    if action == "peer-add":
        cfg = cfg_from(args)
        if args.cert:
            # THE PUBLIC HALF IS ENOUGH, and insisting on more was a real privilege
            # problem: `load_ca` reads ca.key and raises without it, so this — an
            # operation whose whole job is checking a signature — required the key that
            # mints every node identity to sit on the exit host, the machine that
            # carries every peer's traffic. CertAuthority's own docstring says to hold
            # that key only on the dispatcher.
            from blastbox.host.pki import load_trust_anchor, node_identity
            try:
                ident = node_identity(load_trust_anchor(Path(args.pki_dir)),
                                      Path(args.cert).read_bytes())
            except (ValueError, FileNotFoundError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            # IDENTITY IS NOT AUTHORISATION. Verifying the signature says WHICH node
            # this is; it says nothing about whether that node is supposed to be on the
            # overlay. A cert granting no overlay tier belongs to a node that was never
            # meant to peer — a local-mode node, or one enrolled for engine work only —
            # and adding it anyway would let an identity check stand in for a policy
            # decision, which is the habit this whole change exists to break.
            overlay_tiers = tuple(t for t in ("openvpn", "wireguard")
                                  if ident.grants.allows_tier(t))
            if not overlay_tiers and not args.force:
                print(f"error: {ident.node_id} is not granted an overlay tier "
                      f"(has: {list(ident.grants.tiers) or 'none'}). Reissue with "
                      f"--tier openvpn/--tier wireguard, or pass --force to register it "
                      f"anyway.", file=sys.stderr)
                return 1
            name, pubkey = ident.node_id, ident.wg_pubkey
            expires = ident.not_after.isoformat()
            provenance = (f"identity and key verified against the CA "
                          f"(expires {ident.not_after.date()}); "
                          f"overlay tiers granted: {list(overlay_tiers) or 'NONE (--force)'}")
            if args.name and args.name != name:
                print(f"error: --name {args.name!r} contradicts the cert's identity "
                      f"{name!r}", file=sys.stderr)
                return 1
        elif args.public_key and args.name:
            name, pubkey = args.name, args.public_key
            # No cert, so no expiry to enforce — the peer lives until removed by hand.
            # That is the honest consequence of the legacy path, and the output says so.
            expires = None
            provenance = ("UNAUTHENTICATED raw key — nothing ties it to a node identity, "
                          "and it will never be pruned automatically")
        else:
            print("error: give --cert (preferred), or both --name and --public-key",
                  file=sys.stderr)
            return 2
        added = ea.add_peer(cfg, name, args.peer_ip, pubkey, expires=expires)
        print(f"  peer {name} {'added' if added else 'already present'} at {args.peer_ip}/32")
        print(f"  {provenance}")
        print("  no private key changed hands")
        return 0

    if action == "attest":
        cfg = cfg_from(args)
        # Map wg key -> node id from the CERTIFICATES on disk, never from anything a
        # node published: the whole point is an answer the peer cannot influence.
        # The public half only: attestation VERIFIES, and this runs on the exit host,
        # which is the last machine that should hold the key that mints node identities.
        from blastbox.host.pki import load_trust_anchor, node_identity
        key_to_node: dict[str, str] = {}
        pki_dir = Path(args.pki_dir)
        try:
            ca = load_trust_anchor(pki_dir)
        except Exception as exc:
            print(f"error: cannot load the CA from {pki_dir}: {exc}", file=sys.stderr)
            return 1
        # Every cert in the directory, not just `node-*.crt`. `pki issue-node --out`
        # lets an operator name the file anything; globbing a prefix silently ignored
        # those, and their node then read as an UNAUTHORISED peer — a false accusation
        # produced by a filename convention. node_identity() is the filter: a transport
        # cert simply fails it.
        for crt in sorted(pki_dir.glob("*.crt")):
            try:
                ident = node_identity(ca, crt.read_bytes())
            except ValueError:
                continue          # expired or invalid: it authorises nothing
            key_to_node[ident.wg_pubkey] = ident.node_id
        working = {n: True for n in args.working}
        if not working:
            # FAIL-OPEN, and say so. With no working set, nothing can be contradicted:
            # the leak check is inert and a silent "all ok" would be the most misleading
            # output this command could produce. The real fix is sourcing this from the
            # job store; until then the operator must see that it was not supplied.
            print("  WARNING: no --working nodes given, so the leak check is INERT — "
                  "only connectivity and registration hygiene are being verified. "
                  "Pass the nodes the control plane dispatched egress work to.",
                  file=sys.stderr)
        verdicts = ea.attest_peers(cfg, key_to_node=key_to_node, working=working)
        missing = __import__("blastbox.host.exit_attest", fromlist=["missing_peers"]) \
            .missing_peers(ea.observe_peers(cfg), key_to_node=key_to_node)
        if args.json:
            print(json.dumps({
                "verdicts": [{"node_id": v.node_id, "contained": v.contained,
                              "contradicted": v.contradicted, "reason": v.reason}
                             for v in verdicts],
                "enrolled_but_absent": list(missing),
            }, indent=2))
        else:
            for v in verdicts:
                mark = "CONTRADICTED" if v.contradicted else ("ok" if v.contained else "??")
                print(f"  [{mark}] {v.node_id}: {v.reason}")
            for n in missing:
                print(f"  [absent] {n}: enrolled, but no peer on {cfg.wg_iface} — every "
                      "job placed there fails closed")
            if not verdicts and not missing:
                print("  no peers registered on this exit")
        # AN ABSENT PEER IS A FINDING, and this used to exit 0 for it — so a cron or CI
        # invocation reported success for an exit host on which an enrolled node has no
        # tunnel at all and every job placed there fails closed. Distinct codes because
        # the two demand different responses: 1 is a suspected LEAK (investigate the
        # node), 2 is a registration or connectivity fault (fix the enrolment).
        if any(v.contradicted for v in verdicts):
            return 1
        return 2 if missing else 0

    if action == "peer-prune":
        cfg = cfg_from(args)
        gone = ea.prune_expired_peers(cfg)
        print(f"  pruned {len(gone)} expired peer(s)" + (f": {', '.join(gone)}" if gone else ""))
        return 0

    if action == "peer":
        cfg = cfg_from(args)
        pub = ea.setup_peer(cfg, args.peer_ip, args.gateway_addr, args.gateway_pubkey)
        print(f"  peer up at {args.peer_ip} -> {args.gateway_addr}:{cfg.wg_port}")
        print(f"  register this public key on the exit host: {pub}")
        print("  then, in order: `blastbox egress apply --mode global --upstream-gw <overlay gw>`")
        return 0

    raise SystemExit(f"unknown egress action {action!r}")



def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blastbox")
    sub = p.add_subparsers(dest="command", required=True)

    # serve
    ps = sub.add_parser("serve", help="run the ingress HTTP API")
    ps.add_argument("--host", default="127.0.0.1")
    ps.add_argument("--port", type=int, default=8000)
    ps.add_argument("--tls-cert", default=None,
                    help="server certificate (PEM). With a PKI present one is auto-issued "
                         "from the local CA, so this is only needed to use your own.")
    ps.add_argument("--tls-key", default=None, help="private key for --tls-cert")
    ps.add_argument("--no-tls", action="store_true",
                    help="serve plaintext even with a PKI present. Only behind a "
                         "TLS-terminating proxy: node session tokens and job records "
                         "otherwise cross the network in clear.")
    ps.add_argument(
        "--workers",
        type=int,
        default=None,
        help="uvicorn worker processes (default 1, or BLASTBOX_SERVE_WORKERS). "
        ">1 forks; the ingress is otherwise a single event loop whose blob I/O "
        "serializes, so raise this to scale submit/collect throughput.",
    )
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
    pk = sub.add_parser(
        "pki", help="worker-mTLS certificate authority (generate + issue certs)"
    )
    pk.add_argument(
        "--dir",
        default=os.environ.get("BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki"),
        help="CA/cert state dir (BLASTBOX_PKI_DIR)",
    )
    pks = pk.add_subparsers(dest="pki_action", required=True)
    pk_init = pks.add_parser("init", help="create the CA + a dispatcher client cert")
    pk_init.add_argument("--days", type=int, default=365)
    pk_srv = pks.add_parser(
        "issue-server", help="mint a worker server cert (SAN-pinned)"
    )
    pk_srv.add_argument(
        "--san", action="append", required=True, help="IP or DNS name (repeatable)"
    )
    pk_srv.add_argument("--cn", default=None)
    pk_srv.add_argument(
        "--name", default=None, help="output filename stem (default: first SAN)"
    )
    pk_srv.add_argument("--days", type=int, default=30)
    pk_cli = pks.add_parser("issue-client", help="mint a client cert")
    pk_cli.add_argument("--cn", default="dispatcher")
    pk_cli.add_argument("--days", type=int, default=365)
    pk_csr = pks.add_parser(
        "sign-csr",
        help="sign a worker-generated CSR -> server cert (key stays on the box)",
    )
    pk_csr.add_argument("--csr", required=True, help="path to the CSR PEM")
    pk_csr.add_argument(
        "--out", default=None, help="output cert path (default: <csr>.crt)"
    )
    pk_csr.add_argument("--days", type=int, default=30)
    pk_node = pks.add_parser(
        "issue-node",
        help="mint a NODE cert: identity + its WireGuard key + its grants")
    pk_node.add_argument("--node-id", required=True,
                         help="the machine's identity (lowercase, 1-63 chars)")
    pk_node.add_argument("--wg-pubkey", required=True,
                         help="the node's WireGuard PUBLIC key (printed by `egress peer`)")
    pk_node.add_argument("--engine", action="append", default=[],
                         help="engine this node may be assigned (repeatable; default none)")
    pk_node.add_argument("--tier", action="append", default=[],
                         help="netpolicy tier this node may be assigned (repeatable)")
    pk_node.add_argument("--credentials", action="store_true",
                         help="this node may hold provider credentials (a local VPN/proxy "
                              "sidecar). Leave OFF for a global-mode worker node.")
    pk_node.add_argument("--days", type=int, default=7,
                         help="short by design: revocation is 'stop renewing'")
    pk_node.add_argument(
        "--out", default=None,
        help="basename to write, as <out>.crt and <out>.key. A trailing .crt is "
             "stripped, so --out /tmp/toolz3.crt writes /tmp/toolz3.crt and .key rather "
             "than toolz3.crt.crt. Default: <pki-dir>/node-<node-id>.{crt,key} — this "
             "command ALWAYS writes a private key to disk, it never prints to stdout")
    pk_ns = pks.add_parser(
        "node-status",
        help="what THIS node's environment resolves to: is the grants gate armed, does "
             "its certificate verify, and what would it accept? Exit 1 if armed and the "
             "certificate does not verify")
    pk_ns.add_argument("--engine", default="boxjs",
                       help="which engine to report the per-tier verdict for (default: boxjs)")
    pk_show = pks.add_parser("show-node", help="verify a node cert and print its identity")
    pk_show.add_argument("--cert", required=True)
    pks.add_parser("show-ca", help="print the CA cert (public trust anchor)")
    pk_imp = pks.add_parser(
        "import-ca",
        help="install a pre-generated CA (share one root across hosts / a worker pool)",
    )
    pk_imp.add_argument(
        "--ca-cert", required=True, help="path to the pre-generated CA cert PEM"
    )
    pk_imp.add_argument(
        "--ca-key", required=True, help="path to the pre-generated CA private key PEM"
    )
    pk.set_defaults(func=_pki_cmd)

    # version
    pm = sub.add_parser(
        "migrate-results",
        help="upload pre-blob-store results so the scratch reclaim can free their disk",
    )
    pm.add_argument("--job-root", default=None, help="default: BLASTBOX_JOB_ROOT")
    pm.add_argument(
        "--limit",
        type=int,
        default=0,
        help="stop after N uploads (0 = all); run it in batches on a busy node",
    )
    pm.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be uploaded without touching the blob store",
    )
    pm.set_defaults(func=_migrate_results_cmd)

    pk = sub.add_parser(
        "claim-key",
        help="show whether the node signing key is recorded on the job queue, or rotate it",
    )
    pks = pk.add_subparsers(dest="claim_key_cmd", required=True)
    pks.add_parser("show", help="report presence and a fingerprint; the key is never printed")
    pk_reset = pks.add_parser(
        "reset", help="rotate it; requires a STOPPED fleet and a restart of every ingress",
    )
    pk_reset.add_argument("--yes", action="store_true",
                          help="confirm every ingress on this queue is stopped")
    pk.set_defaults(func=_claim_key_cmd)

    pt = sub.add_parser(
        "blob-target",
        help="show or reset the blob target recorded on the job queue (see `show`/`reset`)",
    )
    pts = pt.add_subparsers(dest="blob_target_cmd", required=True)
    pts.add_parser(
        "show", help="print the blob target every process on this queue must agree on"
    )
    pt_reset = pts.add_parser(
        "reset",
        help="forget it, for a DELIBERATE migration; requires a STOPPED fleet (see --yes)",
    )
    pt_reset.add_argument(
        "--yes",
        action="store_true",
        help="confirm every dispatcher and ingress on this queue is stopped",
    )
    pt.set_defaults(func=_blob_target_cmd)

    pp = sub.add_parser(
        "pins",
        help="report every install-path blastbox pin in a consumer repo (exit 1 on drift)",
    )
    pp.add_argument("repo", help="path to the consumer repo (redtusk, clippyshot, ...)")
    pp.add_argument(
        "--set",
        dest="set_version",
        metavar="VERSION",
        help="point every pin at VERSION (one input for every install path), "
        "refreshing hash-pinned locks from PyPI",
    )
    pp.add_argument(
        "--allow-unreleased",
        action="store_true",
        help="with --set, accept a version that is not on PyPI yet",
    )
    pp.set_defaults(func=_pins_cmd)

    bip = sub.add_parser(
        "build-images",
        help="build an engine's declared image chain, stamped and verified, then "
        "export the rootfs artifacts it declares (--dry-run to inspect)",
    )
    bip.add_argument(
        "repo", help="path to the consumer repo (it declares blastbox-images.toml)"
    )
    bip.add_argument("--tag", required=True, help="tag to build the whole chain under")
    bip.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be built and exported, and touch nothing",
    )
    bip.add_argument(
        "--blastbox-version",
        help="the blastbox version the images will INSTALL, recorded in every "
        "stamp. Read from the repo's pyproject when omitted; that is only "
        "correct when the repo pins what it is about to install",
    )
    bip.set_defaults(func=_build_images_cmd)

    pdoc = sub.add_parser(
        "doctor",
        help="report the blastbox version every running container is actually on",
    )
    pdoc.add_argument(
        "--expect",
        metavar="VERSION",
        help="fail unless every container reports exactly this version. A PEP 440 "
        "local suffix (0.1.26+g<sha>) is a DIFFERENT build and does not match "
        "the bare release; pass the full string to require it",
    )
    pdoc.add_argument(
        "--allow-mixed",
        action="store_true",
        help="accept several blastbox versions across the fleet (separate products "
        "on one host); without it a mixed fleet is reported and exits 1",
    )
    pdoc.add_argument(
        "--rootfs",
        action="append",
        default=[],
        metavar="[PROJECT=]PATH",
        help="also read the stamp on a warm rootfs artifact (ext4 file or "
        "exported directory). Repeatable. PROJECT=PATH checks it against that "
        "compose project's containers rather than the host as a whole. A rootfs "
        "is not a process, so it is invisible to the container survey -- which "
        "is where three engines drifted for two months",
    )
    pdoc.add_argument(
        "--json",
        action="store_true",
        help="emit the whole fleet as one JSON object for monitoring: versions, "
        "per-container and per-artifact detail, drift buckets, and any artifact "
        "this host cannot boot. Exit code still reflects health",
    )
    pdoc.set_defaults(func=_doctor_cmd)

    pst = sub.add_parser(
        "stamp",
        help="emit docker build flags recording provenance, or read an image's stamp",
    )
    pst.add_argument(
        "--read",
        metavar="IMAGE",
        help="print the stamp IMAGE carries (exit 1 if unstamped)",
    )
    pst.add_argument(
        "--repo", default=".", help="source repo whose revision to record (default: .)"
    )
    pst.add_argument("--base", help="base image to record by DIGEST, not tag")
    pst.add_argument(
        "-f",
        "--dockerfile",
        help="Dockerfile the flags will be passed to. When given, refuses to emit "
        "a pinned base the Dockerfile does not declare an ARG for -- docker "
        "would ignore it and the stamp would claim a digest the build never used",
    )
    pst.add_argument(
        "--base-arg",
        default="BASE_IMAGE",
        help="Dockerfile ARG that receives the digest-pinned base (default: BASE_IMAGE)",
    )
    pst.add_argument(
        "--blastbox-version",
        help="blastbox version being installed INTO the image. Defaults to the "
        "version running this CLI, which is only correct when they match — "
        "pass it explicitly when stamping a build that pins a different one",
    )
    pst.set_defaults(func=_stamp_cmd)

    # egress -- node-level egress tier (bridges, exit mode, overlay transport)
    pe = sub.add_parser(
        "egress",
        help="set up this node's egress tier (bridges, local or global exit, wg overlay)")
    # Common options live on a PARENT parser that every action inherits, not on the
    # `egress` parser itself. argparse hands everything after the action verb to the
    # sub-parser, so an option declared only on the parent is reachable solely in the
    # pre-verb position — which made every documented `egress apply --mode global ...`
    # die with "unrecognized arguments". Inheriting them puts them in both positions.
    # default=argparse.SUPPRESS is load-bearing. argparse parses a sub-command into a
    # FRESH namespace and copies every key back over the parent's, so an option declared
    # in both places has its pre-verb value overwritten by the sub-parser's default —
    # `egress --mode global apply` silently became mode=None, which is worse than the
    # "unrecognized arguments" it replaced because it fails OPEN into local mode.
    # SUPPRESS omits the key entirely when the option is absent, so neither position
    # clobbers the other.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--mode", choices=("local", "global"), default=argparse.SUPPRESS,
                        help="local: this node runs its own credentialed exit sidecars. "
                             "global: this node holds no credentials and forwards over the "
                             "wg overlay to the central exit host. The gateway ADDRESS is "
                             "identical either way.")
    common.add_argument("--gateway-ip", default=argparse.SUPPRESS,
                        help="override the gateway address")
    common.add_argument("--wg-iface", default=argparse.SUPPRESS)
    common.add_argument("--upstream-gw", default=argparse.SUPPRESS,
                        help="mode=global: overlay IP of the central exit host")
    pe.add_argument("--mode", choices=("local", "global"), default=argparse.SUPPRESS,
                    help=argparse.SUPPRESS)
    pe.add_argument("--gateway-ip", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    pe.add_argument("--wg-iface", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    pe.add_argument("--upstream-gw", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    pes = pe.add_subparsers(dest="egress_action", required=True)

    pe_ap = pes.add_parser("apply", parents=[common],
                           help="bring this node to the configured state (idempotent)")
    pe_ap.add_argument("--dry-run", action="store_true")
    pe_ap.add_argument("--no-auto-subnets", action="store_true",
                       help="fail on a subnet conflict instead of relocating the bridge")
    pes.add_parser("check", parents=[common],
                   help="report state; exit non-zero if egress is degraded")
    pes.add_parser("health", parents=[common],
                   help="one-line JSON health verdict (for probes / the dispatcher)")
    pe_td = pes.add_parser("teardown", parents=[common], help="remove only what we created")
    pe_td.add_argument("--remove-bridges", action="store_true")
    pes.add_parser("gateway", parents=[common],
                   help="exit host: stand up the overlay endpoint, print its public key")
    pes.add_parser("gateway-exit", parents=[common],
                   help="exit host: route peer traffic into the local sidecar")
    pe_pa = pes.add_parser("peer-add", parents=[common],
                           help="exit host: register a peer from its NODE CERT (preferred) "
                                "or a raw public key")
    pe_pa.add_argument("--cert", default=None,
                       help="the peer's node cert. Its identity and WireGuard key are "
                            "taken from the CA-signed payload, so registration is a "
                            "signature check rather than trust in a pasted string.")
    pe_pa.add_argument("--name", default=None,
                       help="peer name (taken from the cert when --cert is used)")
    pe_pa.add_argument("--peer-ip", required=True)
    pe_pa.add_argument("--public-key", default=None,
                       help="LEGACY: a raw WireGuard public key, unauthenticated. Prefer "
                            "--cert; this is kept for nodes not yet enrolled.")
    pe_pa.add_argument("--pki-dir", default=os.environ.get(
        "BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki"))
    pe_pa.add_argument("--force", action="store_true",
                       help="register a verified node whose cert grants no overlay tier")
    pe_at = pes.add_parser(
        "attest", parents=[common],
        help="exit host: verify peers' containment from HERE, where they cannot edit "
             "the answer. Exit 0 = clean, 1 = a peer CONTRADICTS its containment "
             "claim, 2 = an enrolled peer has no tunnel at all")
    pe_at.add_argument("--working", action="append", default=[],
                       help="node id the control plane dispatched egress work to "
                            "(repeatable). Supply this from the job store — never from "
                            "the node's own heartbeat, or the adversary supplies both "
                            "sides of the comparison.")
    pe_at.add_argument("--pki-dir", default=os.environ.get(
        "BLASTBOX_PKI_DIR", "/var/lib/blastbox/pki"))
    pe_at.add_argument("--json", action="store_true")
    pes.add_parser("peer-prune", parents=[common],
                   help="exit host: drop peers whose certificate has expired (run "
                        "automatically on every apply)")
    pe_pr = pes.add_parser("peer", parents=[common],
                           help="worker node: join the overlay (generates its own key)")
    pe_pr.add_argument("--peer-ip", required=True)
    pe_pr.add_argument("--gateway-addr", required=True)
    pe_pr.add_argument("--gateway-pubkey", required=True)
    pe.set_defaults(func=_egress_cmd)

    pv = sub.add_parser("version", help="print version and exit")
    pv.set_defaults(func=_version_cmd)

    return p


def _build_images_cmd(args: argparse.Namespace) -> int:
    """Build a declared image chain, stamped, and verify every result.

    The declaration lives with the Dockerfiles it names, so a new engine writes
    a spec rather than the fourth copy of a shell script -- every one of which
    had drifted from the others in a way that silently produced a wrong image.
    """
    from blastbox.host.images import (  # noqa: PLC0415
        PlanError,
        arg_problems,
        check_tag,
        describe,
        load_plan,
        missing_dockerfiles,
        unresolved_destinations,
    )

    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2
    try:
        check_tag(args.tag)
        plan = load_plan(root)
    except PlanError as exc:
        print(f"cannot read the image plan: {exc}")
        return 2

    missing = missing_dockerfiles(plan)
    if missing:
        # Reported BEFORE anything is built: otherwise this surfaces deep inside
        # a docker build, as an error about something else.
        print(f"{len(missing)} declared Dockerfile(s) do not exist:")
        for m in missing:
            print(f"  {m}")
        return 2

    # The check this module exists for: docker silently ignores a --build-arg the
    # Dockerfile does not declare, so a wrong base_arg means the build resolves
    # its own default while the stamp claims the pinned base.
    problems = arg_problems(plan)
    if problems:
        print(
            f"{len(problems)} image(s) declare a base_arg that does not select their base:"
        )
        for p_ in problems:
            print(f"  {p_}")
        return 2

    # A size that does not resolve is refused HERE, in both paths. Rendering it
    # as `[UNRESOLVED SIZE: ...]` and still exiting 0 would report a checked
    # plan for something that cannot run.
    bad_sizes: list[str] = []
    for rf in plan.rootfs:
        try:
            rf.resolved_size_mib()
        except PlanError as exc:
            bad_sizes.append(str(exc))
    if bad_sizes:
        print(f"{len(bad_sizes)} rootfs size(s) do not resolve:")
        for b in bad_sizes:
            print(f"  {b}")
        return 2

    unresolved = unresolved_destinations(plan)
    if unresolved:
        print(f"{len(unresolved)} export destination(s) contain an unset variable:")
        for u in unresolved:
            print(f"  {u}")
        print("Set them, or give the declaration a ${VAR:-default}.")
        return 2

    # Resolved BEFORE the description is printed. A dry run that renders
    # `--build-arg BLASTBOX_VERSION=$BLASTBOX_VERSION` has not told the operator
    # what it would do, which is the one question a dry run exists to answer.
    version = args.blastbox_version or _declared_blastbox_version(root)
    env = {**os.environ, **({"BLASTBOX_VERSION": version} if version else {})}

    print(describe(plan, args.tag, env))
    if args.dry_run:
        if not version:
            print()
            print("NOTE: the blastbox version these images install could not be")
            print(f"read from {root}/pyproject.toml, so it shows unresolved above.")
            print("Pass --blastbox-version <version> to see the real plan.")
        print()
        print("checked: every Dockerfile exists, every declared ARG is honoured by")
        print("it, and every destination resolves. Nothing was built.")
        return 0

    # Recording the wrong version is worse than recording nothing, so a version
    # that could not be read is a refusal rather than a guess.
    if not version:
        print("could not read the blastbox version these images will install from")
        print(f"  {root}/pyproject.toml")
        print("Pass it explicitly:  --blastbox-version <version>")
        return 2

    from blastbox.host.imagerun import BuildError, run_plan  # noqa: PLC0415

    print()
    try:
        run_plan(plan, args.tag, blastbox_version=version)
    except BuildError as exc:
        print(f"\n{exc}")
        return 1
    print()
    print(f"all images stamped and every artifact exported at :{args.tag}.")
    return 0


def _declared_blastbox_version(root: Path) -> str:
    """The blastbox version ``root``'s pyproject pins, or "".

    Matched on the version DIGITS, not by splitting on `=`: `blastbox>=0.1.27`
    has two fields, `blastbox==0.1.28` three, and a range drags its upper bound
    into whichever field it lands in. Comment lines are dropped first — a
    version mentioned in prose is not a pin, and letting one win here would
    stamp a version nothing installs.
    """
    import re  # noqa: PLC0415

    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
    except OSError:
        return ""
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    # `==`, `~=` and `>=` only -- NOT every two-character operator. `!=0.1.27`
    # names the one version that will not be installed, and reading it as the
    # version this installs writes a false number into every image stamp: the
    # exact lie this tooling exists to catch.
    #
    # `>=` is included on purpose, and it is not "whatever pip resolves". This
    # value is passed to the build, and the Dockerfiles install
    # `blastbox==${BLASTBOX_VERSION}` with it -- the floor becomes an exact
    # install, so recording it is true by construction. `verify_built` then
    # compares the label against what the image actually contains, so a repo
    # whose Dockerfile stops honouring the arg is caught rather than trusted.
    # The COMPLETE PEP 440 version, not just its dotted numeric prefix. A pin
    # of `blastbox==0.2.0rc1` was captured as `0.2.0`, and that truncated value
    # is then passed as the exact build arg -- so the image installs, and
    # truthfully verifies, a different release than the repo declared.
    #
    # PEP 440's own grammar, not a hand-written approximation of it. Every
    # attempt to spell this by hand missed separators that are legal and
    # meaningful: `0.2.0-rc1`, `0.2.0_rev_3` and `0.2.0+linux-x86` each stopped
    # early and yielded a DIFFERENT release than the one declared -- `0.2.0`,
    # a final release, for a pin that names its release candidate.
    version = r"""
        (?:[0-9]+!)?                                  # epoch
        [0-9]+(?:\.[0-9]+)*                           # release
        (?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?   # pre
        (?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?  # post
        (?:[-_.]?dev[-_.]?[0-9]*)?                     # dev
        (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?           # local version
    """
    # Anchored at a BOUNDARY. Without it a pattern that fails to consume the
    # whole version still "matches", and the partial value is passed on as an
    # exact pin -- silently naming a release nobody declared. Refusing to guess
    # leaves the version empty, which the caller already handles.
    m = re.search(
        r"blastbox(?:\[[A-Za-z0-9,._-]+\])?\s*(==|~=|>=)\s*(" + version + r")"
        r"\s*(?=[\"',;)\]]|$)",
        body,
        re.VERBOSE | re.IGNORECASE | re.MULTILINE,
    )
    if not m:
        return ""
    # CANONICAL, not the source spelling. This value is passed to the build as
    # an exact pin AND written to the stamp, while the installed distribution
    # metadata records the normalised form -- so returning `0.2.0-rc1` here
    # produced an image that installed correctly and then failed its own
    # verification against `0.2.0rc1`.
    from blastbox.host.stamp import canonical_version  # noqa: PLC0415

    return canonical_version(m.group(2))


def _release_digests(version: str) -> list[str] | None:
    """sha256 of every artifact PyPI has for ``version``; None when it has none.

    None is "this release does not exist there", which is a refusal reason, not
    an empty list to carry on with. Bumping a consumer to a version PyPI has not
    published yet produces a repo that cannot install -- measured: a floor moved
    to 0.1.29 minutes before the index carried it, and CI failed with
    "No matching distribution found" on a version that had genuinely been
    released.
    """
    import json  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    url = f"https://pypi.org/pypi/blastbox/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as fh:
            data = json.load(fh)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return [f["digests"]["sha256"] for f in data.get("urls", [])]


def _release_requires(version: str) -> list[str]:
    """``version``'s runtime requirements, as PyPI records them.

    ALL of them, extras included. Which apply is decided per lock, from the
    extras that lock's own blastbox entry asks for -- dropping them here meant
    a new dependency of `blastbox[host]` was never checked at all, and the bump
    reported success while the next `--require-hashes` install failed.
    """
    import json  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    url = f"https://pypi.org/pypi/blastbox/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as fh:
        data = json.load(fh)
    return list(data.get("info", {}).get("requires_dist") or [])


def _requirements_of(name: str, version: str) -> list[str] | None:
    """A dependency's own requirements, so its EXTRAS can be checked too.

    `uvicorn` becoming `uvicorn[standard]` enables packages pip must resolve
    and hash as well, and a version match alone says nothing about those. None
    means "could not ask", which the caller reports rather than treating as
    verified.
    """
    import json  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as fh:
            data = json.load(fh)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return list(data.get("info", {}).get("requires_dist") or [])


def _pins_set(root: Path, version: str, *, allow_unreleased: bool) -> int:
    """Point every pin at one version, and prove it by re-scanning."""
    from blastbox.host.pins import (  # noqa: PLC0415
        PinScanError,
        missing_from_locks,
        set_version,
    )

    digests: list[str] | None = []
    try:
        digests = _release_digests(version)
    except Exception as exc:  # noqa: BLE001 -- network shape varies; the message is what matters
        if not allow_unreleased:
            print(f"cannot reach PyPI to check {version}: {exc}")
            print("  Pass --allow-unreleased to set it anyway (a hash-pinned lock")
            print("  cannot be refreshed without the digests, and will refuse).")
            return 2
        digests = []
    if digests is None:
        if not allow_unreleased:
            print(f"blastbox {version} is not on PyPI.")
            print("  Pinning a consumer to it produces a repo that cannot install.")
            print("  Publish the release first, or pass --allow-unreleased.")
            return 2
        digests = []

    # BEFORE writing anything. `pip install --require-hashes` refuses the whole
    # file when a dependency it must resolve is not pinned there, so a release
    # that gains one turns every hash-pinned consumer lock into a lock that
    # cannot install -- and rewriting only the blastbox line makes the bump look
    # successful right up until the image build fails.
    if digests:
        try:
            requires = _release_requires(version)
        except Exception as exc:  # noqa: BLE001 -- network shape varies
            print(f"cannot read {version}'s dependencies from PyPI: {exc}")
            return 2
        try:
            gaps = missing_from_locks(root, requires, requirements_of=_requirements_of)
        except PinScanError as exc:
            # Recognised locks RAISE when they cannot be read, deliberately --
            # reading one as empty reports its whole closure present. That has
            # to arrive as the CLI's own diagnostic and exit 2, not as a
            # traceback from inside a check the operator did not ask for.
            print(f"cannot check the dependency closure: {exc}")
            return 2
        if gaps:
            print(f"refusing to pin {root.name} to blastbox {version}:")
            for path, names in sorted(gaps.items()):
                rel = Path(path).relative_to(root)
                print(f"  {rel} is hash-pinned and does not carry: {', '.join(names)}")
            print(
                "  blastbox {v} needs them, and `pip install --require-hashes`".format(
                    v=version
                )
            )
            print("  rejects the whole file over a dependency it cannot resolve.")
            print("  Regenerate the lock's closure (not just the blastbox line)")
            print("  and re-run this.")
            return 2

    try:
        changed = set_version(root, version, digests=digests)
    except PinScanError as exc:
        print(f"cannot set: {exc}")
        return 2
    for path in changed:
        print(f"  updated {Path(path).relative_to(root)}")
    print(f"OK: every pin in {root.name} now resolves to {version}")
    return 0


def _pins_cmd(args: argparse.Namespace) -> int:
    """Report every install-path blastbox pin in a consumer repo.

    Exit 1 when they disagree: that state is the bug (a fleet ran host 0.1.26,
    cold-worker 0.1.25 and guest 0.1.17 simultaneously), and it is invisible
    unless something compares the files.
    """
    from blastbox.host.pins import PinScanError, disagreements, scan  # noqa: PLC0415

    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2

    if getattr(args, "set_version", None):
        return _pins_set(root, args.set_version, allow_unreleased=args.allow_unreleased)

    try:
        pins = scan(root)
    except PinScanError as exc:
        # Exit 2 == "could not perform the check", matching doctor and stamp.
        # Sharing DRIFT's exit 1 would make a crashed scan look like a finding.
        print(f"cannot scan: {exc}")
        return 2
    if not pins:
        # Verifying nothing is not a pass. The scanner only recognises
        # pyproject/Dockerfile/requirements-style files, so a repo installing
        # blastbox another way yields zero pins -- which must not read as OK.
        print(f"NO PINS FOUND under {root}: nothing was verified.")
        print("  If this repo installs blastbox, it does so by a path this")
        print("  scanner does not recognise; that is a gap, not a clean result.")
        return 1

    groups = disagreements(pins)
    for pin in pins:
        rel = Path(pin.path).relative_to(root)
        print(f"  {pin.floor or '?':<10} {pin.kind:<16} {rel}:{pin.line}")
    print()
    if not groups:
        # Pins exist but none guarantees a version (upper bounds only).
        print(f"NO FLOOR: {len(pins)} pin(s), none of which guarantees a version.")
        print("  An upper bound alone constrains nothing; any release below it")
        print("  satisfies these pins, so the repo declares no version at all.")
        return 1
    floorless = [p for p in pins if p.floor is None]
    if len(groups) == 1 and not floorless:
        only = next(iter(groups))
        print(f"OK: {len(pins)} pin(s), all resolve to {only}")
        return 0
    if len(groups) == 1 and floorless:
        # A direct reference or a bare upper bound cannot be compared to a
        # version. Reporting OK because the COMPARABLE pins agree would hide
        # exactly the pin that is hardest to reason about.
        only = next(iter(groups))
        print(
            f"UNCOMPARABLE: {len(groups and [only])} version group ({only}), but "
            f"{len(floorless)} pin(s) carry no comparable version:"
        )
        for pin in floorless:
            rel = Path(pin.path).relative_to(root)
            print(f"  {rel}:{pin.line}  {pin.specifier}")
        print("  These cannot be checked against the rest; verify them by hand.")
        return 1
    print(f"DRIFT: {len(pins)} pin(s) resolve to {len(groups)} different versions:")
    for version in sorted(groups):
        where = ", ".join(
            f"{Path(p.path).relative_to(root)}:{p.line}" for p in groups[version]
        )
        print(f"  {version}: {where}")
    print()
    print("A consumer installs blastbox by more than one path (pyproject for the")
    print("host tier, a Dockerfile ARG for the worker, a hashed lock for the")
    print("dispatcher image). They drift independently unless something checks.")
    return 1


def _doctor_cmd(args: argparse.Namespace) -> int:
    """Report the blastbox version every running container is actually on."""
    from blastbox.host.doctor import (  # noqa: PLC0415 -- CLI-only
        DockerUnavailable,
        artifact_problems,
        fleet_report,
        survey,
        survey_rootfs,
        verdict,
    )

    artifacts = survey_rootfs(getattr(args, "rootfs", []) or [])
    docker_error = ""
    try:
        containers = survey()
    except DockerUnavailable as exc:
        # Docker being unreachable does not make the ARTIFACTS unreadable: they are files,
        # so report what could be read -- but as a problem, never as a healthy fleet.
        containers, docker_error = [], str(exc) or "docker unavailable"
    as_json = bool(getattr(args, "json", False))
    if docker_error and not artifacts and not as_json:
        print(f"cannot inspect anything: {docker_error}")
        return 2

    # ONE verdict, whatever the output format: the policy flags define success, so the JSON
    # report and the text report must never disagree about the exit code.
    problems = verdict(
        containers,
        artifacts,
        expect=args.expect,
        allow_mixed=bool(getattr(args, "allow_mixed", False)),
        docker_error=docker_error,
    )

    if as_json:
        report = fleet_report(containers, artifacts)
        report["policy"] = {"expect": args.expect,
                            "allow_mixed": bool(getattr(args, "allow_mixed", False))}
        report["problems"] = problems
        report["ok"] = not problems
        print(json.dumps(report, indent=2, sort_keys=True))
        if docker_error and not artifacts:
            return 2       # nothing could be inspected at all, as in text mode
        return 0 if not problems else 1

    if not containers and not artifacts:
        print("no running blastbox containers found")
        for p in problems:
            print(f"PROBLEM: {p}")
        return 1 if problems else 0

    if artifacts:
        awidth = max(len(a.path) for a in artifacts)
        for a in artifacts:
            where = f"{a.runtime or '?'}/{a.arch or '?'}"
            note = f"  <- {a.detail}" if a.detail else ""
            print(f"  {'rootfs':<18} {a.path:<{awidth}}  {where:<26} {a.version}{note}")
        for art, why in artifact_problems(artifacts):
            print(f"  UNBOOTABLE HERE: {art.path}: {why}")
        if containers:
            print()
    if containers:
        width = max(len(c.name) for c in containers)
        for c in sorted(containers, key=lambda c: (c.project, c.name)):
            note = f"  <- {c.detail}" if c.detail else ""
            print(f"  {c.project:<18} {c.name:<{width}}  {c.image:<26} {c.version}{note}")
    print()
    if problems:
        for p in problems:
            print(f"PROBLEM: {p}")
        if not getattr(args, "allow_mixed", False) and any(
            "versions:" in p for p in problems
        ):
            print("\n  (pass --allow-mixed if separate products on one host are expected)")
        return 1
    versions = sorted({c.version for c in containers if c.known}
                      | {a.version for a in artifacts if a.known})
    tail = f", {len(artifacts)} artifact(s)" if artifacts else ""
    if len({c.version for c in containers if c.known}) > 1:
        # Never "OK" beside several versions: allowed is not the same as uniform.
        print(f"MIXED (allowed by --allow-mixed): {len(containers)} container(s){tail}, "
              f"blastbox {', '.join(versions)}")
        return 0
    print(f"OK: {len(containers)} container(s){tail}, blastbox {', '.join(versions)}")
    return 0


def _stamp_cmd(args: argparse.Namespace) -> int:
    """Emit build flags that record provenance, or read what an image recorded."""
    from blastbox.host import stamp as st  # noqa: PLC0415 -- CLI-only

    if not args.read:
        try:
            version = args.blastbox_version or _installed_version()
            print(
                " ".join(
                    st.build_args(
                        blastbox_version=version,
                        repo=Path(args.repo),
                        base=args.base,
                        base_arg=args.base_arg,
                        dockerfile=args.dockerfile,
                    )
                )
            )
        except st.StampError as exc:
            print(f"stamp failed: {exc}")
            return 2
        return 0

    try:
        got = st.read(args.read)
        agrees, detail = st.verify_contents(args.read)
        resolvable = got.resolvable() if got.reproducible else False
        moved = got.base_moved() if resolvable else ""
    except st.StampError as exc:
        # "could not perform the check" -- distinct from a real finding, and the
        # same exit code doctor and pins use for it.
        print(f"stamp failed: {exc}")
        return 2
    print(f"  blastbox    {got.blastbox}")
    print(f"  revision    {got.revision}")
    print(f"  base name     {got.base_name}")
    print(f"  base digest   {got.base_digest}")
    print(f"  base image id {got.base_image_id}")
    # Provenance nobody can read is not provenance. A multi-stage image COPIES
    # files out of its builders, so which builder it used belongs beside the
    # base -- otherwise reading it means knowing the label name and running
    # `docker inspect` by hand.
    if got.builders:
        for pair in got.builders.split(","):
            arg, _, ref = pair.partition("=")
            print(f"  builder       {arg} = {ref}")
    else:
        print("  builder       (none declared)")
    if agrees is None:
        print(f"  contents     {detail} (nothing to join)")
    elif not agrees:
        print(
            f"\nSTAMP DISAGREES WITH THE IMAGE: {detail}\n"
            "  The blastbox label is a self-report written at build time. It\n"
            "  says one thing; the image contains another, so rebuilding from\n"
            "  the recorded facts would not reproduce what is here."
        )
        return 1
    if got.reproducible:
        if resolvable and moved:
            print(
                f"\nTHE BASE HAS MOVED: {got.base_name} resolved to\n"
                f"  {got.base_image_id} when this was stamped, and to\n"
                f"  {moved} now.\n"
                "  A local reference is not an immutable pin, so this image may\n"
                "  have been built from a different image than its label names.\n"
                "  Push the base to a registry to pin by digest instead."
            )
            return 1
        if resolvable:
            print("\nOK: records what it was built from, and that base is still here")
            return 0
        print(
            "\nSTAMPED BUT UNBUILDABLE: the recorded base is no longer on this\n"
            "  host. The stamp is intact; the thing it names is gone. Pull or\n"
            "  rebuild the base before trying to reproduce this image."
        )
        return 1
    print(
        "\nUNSTAMPED: this image does not record what it was built from.\n"
        "  A tag can be re-pointed or deleted; without the base DIGEST the\n"
        "  image cannot be deliberately rebuilt. Measured cost of this gap:\n"
        "  the base that built redtusk-cold-worker:rows no longer exists."
    )
    return 1


def _installed_version() -> str:
    from blastbox import __version__  # noqa: PLC0415 -- CLI-only

    return __version__


def main(argv: list[str] | None = None) -> int:
    configure_logging(format_="text")
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
