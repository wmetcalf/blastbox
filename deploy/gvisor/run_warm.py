"""gVisor warm worker entrypoint — the file-trigger analog of the FC run_guest.py.

Runs ``serve_warm`` with a ``FileWarmControl`` over the per-slot bind-mounted ``/ctrl``
dir (host writes ``go.json`` + reads ``done``; the worker polls). The untrusted input
arrives at ``/in`` (read-only bind mount) and output goes to ``/out`` (rw bind mount) —
both paths are delivered by the host in ``go.json`` (already rewritten to the in-sandbox
mount points by ``GvisorHostWarmControl``). The engine is chosen by ``BLASTBOX_GVISOR_ENGINE``
(default ``probe``). After ``serve_warm`` returns (job done or idle), the worker blocks until
the host reaps the slot — one untrusted document per disposable restore.

This is the gVisor-tier counterpart to ``deploy/firecracker/run_guest.py`` (which uses a
vsock control instead of the file trigger). Set the warm entrypoint to
``["python3", "/opt/blastbox/run_warm.py"]`` via ``BLASTBOX_GVISOR_WARM_ARGV`` and bake the
engine name into ``/opt/blastbox/engine`` (Docker ENV is dropped by ``docker export``).
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from blastbox.limits import Limits
from blastbox.worker.warm import FileWarmControl, serve_warm
# NOTE: `engines` (/opt/blastbox/engines.py, on sys.path[0]) is imported LAZILY inside main()
# so an import/engine-resolution failure is caught + logged + breadcrumbed rather than killing
# the process at module load (before logging is configured), and so this module stays importable
# for unit tests on hosts without engines.py present.

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)
_log = logging.getLogger("blastbox.gvisor.run_warm")

CTRL_DIR = os.environ.get("BLASTBOX_GVISOR_CTRL_DIR", "/ctrl")
ENGINE_FILE = "/opt/blastbox/engine"  # baked by Dockerfile.shim; module-level for testability


def _engine_name() -> str:
    # Baked into the rootfs filesystem at build time (Docker ENV is dropped by
    # `docker export`); env/default is the running-the-image-directly fallback.
    try:
        baked = Path(ENGINE_FILE).read_text().strip()
        if baked:
            return baked
    except OSError:
        pass
    return os.environ.get("BLASTBOX_GVISOR_ENGINE", "probe")


def _idle_timeout_s(raw: str | None) -> float:
    # A snapshot-restored worker must NOT self-retire while it sits warm in the pool — the
    # HOST reaps idle slots. Default high; guarded parse (a garbage value falls back rather
    # than killing the worker before serve_warm starts).
    raw = (raw or "").strip()
    try:
        return float(raw) if raw else 86400.0
    except ValueError:
        _log.warning("invalid BLASTBOX_WARM_IDLE_TIMEOUT_S=%r; using 86400.0", raw)
        return 86400.0


def _write_setup_breadcrumb(message: str) -> None:
    # If engine setup fails BEFORE serve_warm can signal_ready, the host only sees a bare
    # ready-timeout. Drop a breadcrumb into the bind-mounted ctrl dir (it exists at restore
    # time) so the failure is diagnosable. Best-effort — never raises.
    try:
        ctrl = Path(CTRL_DIR)
        ctrl.mkdir(parents=True, exist_ok=True)
        (ctrl / "setup_error").write_text(message, encoding="utf-8")
    except OSError:
        pass


def main() -> None:
    try:
        from engines import get_engine  # /opt/blastbox/engines.py (sys.path[0] for this script)

        engine = get_engine(_engine_name())
    except Exception as exc:
        # Bad engine name / missing engines.py would otherwise be a silent death → host
        # ready-timeout with no cause. Log loudly + breadcrumb, then exit non-zero.
        _log.exception("run_warm: engine setup failed (engine=%r) — worker cannot serve", _engine_name())
        _write_setup_breadcrumb(f"engine setup failed: {exc!r}")
        raise
    _log.info(
        "run_warm start engine=%s uid=%d gid=%d",
        getattr(engine, "name", _engine_name()),
        os.getuid(),
        os.getgid(),
    )
    control = FileWarmControl(Path(CTRL_DIR))
    rc = serve_warm(
        engine,
        control=control,
        limits=Limits.from_env(),
        idle_timeout_s=_idle_timeout_s(os.environ.get("BLASTBOX_WARM_IDLE_TIMEOUT_S")),
    )
    _log.info("serve_warm returned rc=%s; idle until reap", rc)
    # One job per disposable restore — block until the host SIGKILLs the slot.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
