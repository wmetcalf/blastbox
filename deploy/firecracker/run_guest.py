"""Guest agent — runs inside the blastbox FC microVM as PID 1's child.

Drives the full warm lifecycle over vsock via ``serve_warm``:

    warmup() -> READY (vsock) -> wait one job (vsock GO + input) -> detonate ->
    write artifacts + metadata.json to the output disk -> DONE (vsock).

The engine is chosen by ``BLASTBOX_FC_ENGINE`` (baked into the rootfs at build
time): ``probe`` (hash → text) or ``pdf``/``pdfrasterize`` (poppler PDF → PNGs).
After DONE the agent blocks so the VM stays alive until the host reaps it (one
untrusted document per disposable VM).
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from blastbox.limits import Limits
from blastbox.worker.fc_warm import VsockWarmControl
from blastbox.worker.warm import serve_warm
from engines import get_engine  # /opt/blastbox/engines.py (sys.path[0] in the VM)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)
_log = logging.getLogger("blastbox.fc.run_guest")

OUTPUT_DIR = "/mnt/outdisk"   # ext4 output disk (vdb); host reads via rdump
INPUT_DIR = "/tmp/in"          # tmpfs (init mounts tmpfs at /tmp); off the output disk


def _engine_name() -> str:
    # Baked into the rootfs FILESYSTEM at build time — Docker ENV is dropped by
    # `docker export`, so the engine choice is read from a file (env/default as a
    # fallback for running the image directly).
    try:
        baked = Path("/opt/blastbox/engine").read_text().strip()
        if baked:
            return baked
    except OSError:
        pass
    return os.environ.get("BLASTBOX_FC_ENGINE", "probe")


def main() -> None:
    engine_name = _engine_name()
    engine = get_engine(engine_name)
    _log.info(
        "run_guest start engine=%s uid=%d gid=%d",
        getattr(engine, "name", engine_name),
        os.getuid(),
        os.getgid(),
    )

    control = VsockWarmControl(input_dir=INPUT_DIR, output_dir=OUTPUT_DIR)
    # The warm/snapshot tier sets BLASTBOX_WARM_IDLE_TIMEOUT_S high (the HOST reaps
    # idle slots): a snapshot-restored guest must NOT self-retire while it sits warm
    # in the pool. The cold tier keeps the modest default. (The guest clock can also
    # skew across snapshot/restore, which makes a short self-timeout fire early.)
    # Guarded parse: a garbage env value falls back to the default rather than killing
    # the guest agent before serve_warm even starts.
    _raw_idle = os.environ.get("BLASTBOX_WARM_IDLE_TIMEOUT_S", "").strip()
    try:
        idle_timeout_s = float(_raw_idle) if _raw_idle else 120.0
    except ValueError:
        _log.warning("invalid BLASTBOX_WARM_IDLE_TIMEOUT_S=%r; using 120.0", _raw_idle)
        idle_timeout_s = 120.0
    rc = serve_warm(
        engine,
        control=control,
        limits=Limits.from_env(),
        idle_timeout_s=idle_timeout_s,
    )
    # NOTE: after serve_warm returns (job done OR its own idle_timeout), the guest does
    # NOT exit — it blocks until the host SIGKILLs the slot. So slot lifetime is entirely
    # host-reaper-controlled (pool warm_size/ceiling + release/health/stop); the idle
    # env above does not bound a warm slot's life. A warm IDLE slot holds its firecracker
    # process + a COW share of the (single) /dev/shm base mem until the host reaps it —
    # bounded by warm_size, but there is no idle-TTL reaper. Budget RAM via warm_size.
    _log.info("serve_warm returned rc=%s; idle until reap", rc)
    # One job per disposable VM — block until the host reaps the slot.
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
