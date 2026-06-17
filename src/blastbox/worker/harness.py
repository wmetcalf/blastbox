"""Worker harness: run one detonation, seal the result, write metadata.json.

This module is the keystone of Layer 2.  It is the code that runs *inside*
the disposable worker container.  It:

1. Computes ``input_sha256`` from the actual input file (chunked read).
2. Calls ``engine.detonate(input_path, output_dir, limits)``.
3. Seals the result via ``contract.seal_envelope`` (same function the host
   uses when re-validating), writing hashes/sizes from disk.
4. Falls back to a clean ``engine_error`` envelope if the engine raises or
   if ``seal_envelope`` itself raises (e.g. missing / traversal artifact).
5. Writes ``output_dir/metadata.json`` and returns exit code 0.

A non-zero exit is reserved for harness-internal failures (e.g. unable to
write metadata.json at all) — the envelope ``status`` field carries the
semantic outcome.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING

from blastbox.contract import (
    Detection,
    Warning,
    seal_envelope,
)
from blastbox.contract.nodes import Record
from blastbox.errors import sanitize_public_error
from blastbox.limits import Limits

if TYPE_CHECKING:
    from blastbox.worker.engine import Engine

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024  # 64 KiB read chunks

# Egress-readiness barrier env knobs. On a netd-wired tier (inspect/vpn) the worker's only route
# out is installed by netd AFTER the container starts (it reacts to the docker start event), so a
# one-shot worker that reaches the network immediately races the wiring and fails closed
# ("Temporary failure in name resolution"). When BLASTBOX_NET_WAIT_GATEWAY is set the harness
# blocks until the default route points at that gateway (netd's wiring signal) before detonating.
_NET_WAIT_GATEWAY_ENV = "BLASTBOX_NET_WAIT_GATEWAY"
_NET_WAIT_S_ENV = "BLASTBOX_NET_WAIT_S"
_DEFAULT_NET_WAIT_S = 20.0


def _gateway_route_hex(ip: str) -> str:
    """The /proc/net/route Gateway field for ``ip``: the 4 address bytes in LITTLE-endian hex
    (e.g. 172.32.0.10 → '0A0020AC'). Raises OSError on a malformed address."""
    return "".join(f"{b:02X}" for b in reversed(socket.inet_aton(ip)))


def _default_route_via(gateway_ip: str) -> bool:
    """True iff the kernel routing table has a default route (Destination 00000000) whose gateway
    is ``gateway_ip`` — i.e. netd has wired this worker's egress. Reads /proc/net/route (no `ip`
    binary needed)."""
    try:
        want = _gateway_route_hex(gateway_ip)
    except OSError:
        return False
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            next(fh, None)  # header row
            for line in fh:
                cols = line.split()
                if len(cols) >= 3 and cols[1] == "00000000" and cols[2].upper() == want:
                    return True
    except OSError:
        return False
    return False


def _wait_for_egress_gateway(
    gateway_ip: str, timeout_s: float, *, sleep_fn=time.sleep, clock=time.monotonic
) -> bool:
    """Block until the default route is via ``gateway_ip`` (netd wired us) or ``timeout_s`` elapses.
    Returns True if wired, False on timeout (caller proceeds anyway — fail-open to the engine, which
    fails closed on its own if egress never came up)."""
    deadline = clock() + timeout_s
    while True:
        if _default_route_via(gateway_ip):
            return True
        if clock() >= deadline:
            return False
        sleep_fn(0.1)


def _sha256_file(path: Path) -> str:
    """Compute the hex SHA-256 of a file via chunked streaming reads."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _synthetic_detection() -> Detection:
    """Fallback Detection used when the engine fails before detecting."""
    return Detection(
        label="unknown",
        mime="application/octet-stream",
        confidence=0.0,
        source="harness",
    )


def _engine_error_envelope(
    *,
    engine: Engine,
    output_dir: Path,
    input_sha256: str,
    error: str,
    detected: Detection | None = None,
):
    """Build and return a minimal, valid engine_error Envelope.

    ``error`` must already be scrubbed by the caller.
    """
    scrubbed = sanitize_public_error(error)
    det = detected if detected is not None else _synthetic_detection()
    return seal_envelope(
        engine=engine.name,
        outdir=output_dir,
        input_sha256=input_sha256,
        detected=det,
        declared=[],
        warnings=[Warning(code="engine_error", message=scrubbed)],
        payload=Record(fields={"error": scrubbed}),
        status="engine_error",
    )


def run_detonation(
    engine: "Engine",
    *,
    input_path: Path,
    output_dir: Path,
    limits: Limits,
) -> int:
    """Run one detonation; write ``output_dir/metadata.json``; return exit code.

    Always returns 0 — the ``status`` field in the envelope encodes the
    semantic outcome (``"ok"``, ``"rejected"``, ``"engine_error"``).
    A non-zero exit would mean the harness itself failed to write metadata.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: hash the input
    input_sha256 = _sha256_file(input_path)

    # Step 2: optional pre-detection
    detected: Detection | None = None
    if hasattr(engine, "detect"):
        try:
            detected = engine.detect(input_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("engine.detect() failed: %s", sanitize_public_error(str(exc)))
            detected = None

    # Step 3: run the engine
    env = None
    try:
        result = engine.detonate(input_path, output_dir, limits)
        # Use the engine's detected result (or fall back to pre-detection)
        final_detected = result.detected if detected is None else detected

        # Step 3a: seal (may raise if artifacts are missing or traversal)
        try:
            env = seal_envelope(
                engine=engine.name,
                outdir=output_dir,
                input_sha256=input_sha256,
                detected=final_detected,
                declared=result.artifacts,
                warnings=result.warnings,
                payload=result.payload,
                status=result.status,
            )
        except Exception as seal_exc:  # noqa: BLE001
            raw_msg = f"seal_envelope failed: {seal_exc}"
            logger.error("seal_envelope raised: %s", sanitize_public_error(raw_msg))
            env = _engine_error_envelope(
                engine=engine,
                output_dir=output_dir,
                input_sha256=input_sha256,
                error=raw_msg,
                detected=final_detected,
            )

    except Exception as engine_exc:  # noqa: BLE001
        raw_msg = str(engine_exc)
        logger.error("engine.detonate() raised: %s", sanitize_public_error(raw_msg))
        env = _engine_error_envelope(
            engine=engine,
            output_dir=output_dir,
            input_sha256=input_sha256,
            error=raw_msg,
            detected=detected,
        )

    # Step 4: write metadata.json
    meta_path = output_dir / "metadata.json"
    try:
        meta_path.write_text(env.model_dump_json(by_alias=True), encoding="utf-8")
    except OSError as write_exc:
        logger.critical("failed to write metadata.json: %s", write_exc)
        return 1

    return 0


def main(engine: "Engine", argv: list[str] | None = None) -> int:
    """Worker entrypoint: resolve input/output dirs + limits; call run_detonation.

    Usage inside an engine image::

        if __name__ == "__main__":
            import sys
            from blastbox.worker.harness import main
            from my_engine import MyEngine
            sys.exit(main(MyEngine()))

    Args:
        engine: The engine implementation.
        argv: Argument list for testing (``None`` uses ``sys.argv[1:]``).

    Returns:
        Exit code (0 = success or engine_error sealed; non-zero = harness failure).
    """
    parser = argparse.ArgumentParser(
        description="Blastbox worker: run one detonation job.",
        add_help=True,
    )
    parser.add_argument(
        "--input-dir",
        default=None,
        help=(
            "Directory containing the single input file "
            "(env: BLASTBOX_INPUT_DIR, default: /in)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help=(
            "Directory to write output artifacts + metadata.json "
            "(env: BLASTBOX_OUTPUT_DIR, default: /out)"
        ),
    )

    args = parser.parse_args(argv)

    # Resolve input-dir from arg → env → default
    input_dir_str = (
        args.input_dir
        or os.environ.get("BLASTBOX_INPUT_DIR")
        or "/in"
    )
    output_dir_str = (
        args.output_dir
        or os.environ.get("BLASTBOX_OUTPUT_DIR")
        or "/out"
    )

    input_dir = Path(input_dir_str)
    output_dir = Path(output_dir_str)

    # Find the single regular file in input_dir
    try:
        regular_files = [
            p for p in input_dir.iterdir()
            if p.is_file() and not p.is_symlink()
        ]
    except OSError as exc:
        logger.critical("cannot read input dir %s: %s", input_dir, exc)
        return 2

    if len(regular_files) == 0:
        logger.critical("no regular files found in input dir: %s", input_dir)
        return 2

    if len(regular_files) > 1:
        names = [p.name for p in regular_files]
        logger.critical("expected exactly 1 file in input dir, found %d: %s", len(names), names)
        return 2

    input_path = regular_files[0]
    limits = Limits.from_env()

    # Egress-readiness barrier (netd-wired tiers only): wait for our route out before detonating,
    # so a fast one-shot engine doesn't reach the network before netd finishes wiring it.
    wait_gateway = os.environ.get(_NET_WAIT_GATEWAY_ENV, "").strip()
    if wait_gateway:
        timeout_s = float(os.environ.get(_NET_WAIT_S_ENV) or _DEFAULT_NET_WAIT_S)
        if _wait_for_egress_gateway(wait_gateway, timeout_s):
            logger.info("egress ready: default route via %s", wait_gateway)
        else:
            logger.warning(
                "egress gateway %s not wired after %.0fs; proceeding (engine may fail closed)",
                wait_gateway, timeout_s,
            )

    return run_detonation(engine, input_path=input_path, output_dir=output_dir, limits=limits)
