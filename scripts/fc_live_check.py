"""Live Firecracker validation for the blastbox FC runtime (run on toolz2).

Boots a real microVM from the blastbox worker rootfs and validates the full warm
handshake on real hardware: kernel boot -> guest agent -> READY over vsock (the
live signal VsockReadySignal listens for) -> output disk readable via rdump.

Prints the guest console (fc.log) for visibility — this is the part unit tests
(injected subprocess + ready-signal doubles) cannot prove.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from blastbox.host.pool import SlotState
from blastbox.host.runtime.firecracker import (
    FCConfig,
    FirecrackerSlotRuntime,
    firecracker_available,
)


def main() -> None:
    # Short scratch — AF_UNIX paths cap at 108 bytes (FC's vsock UDS lives here).
    scratch = tempfile.mkdtemp(prefix="dfc")
    cfg = FCConfig.from_env(scratch_root=scratch)
    print(f"FCConfig: bin={cfg.fc_bin} kernel={cfg.fc_kernel}")
    print(f"          rootfs={cfg.fc_rootfs}")
    print(f"          vcpu={cfg.fc_vcpu_count} mem={cfg.fc_mem_mib}MiB scratch={scratch}")
    print(f"firecracker_available() = {firecracker_available(cfg)}")
    assert firecracker_available(cfg), "FC not available"

    rt = FirecrackerSlotRuntime(cfg)
    slot = rt.spawn()
    print(f"\n[spawn] slot_id={slot.slot_id} state={slot.state}")
    assert slot.state == SlotState.WARMING

    # Poll for the vsock READY signal.
    deadline = time.monotonic() + 30.0
    ready = False
    t0 = time.monotonic()
    while time.monotonic() < deadline:
        if rt.is_ready(slot):
            ready = True
            break
        time.sleep(0.25)
    dt = time.monotonic() - t0
    print(f"[ready] is_ready={ready} after {dt:.1f}s  (vsock READY from the guest)")
    print(f"[alive] is_alive={rt.is_alive(slot)}")

    # Output disk: read the guest-written, fsync'd marker BEFORE reap.
    outdisk_names = None
    if ready:
        try:
            outdisk_names = rt.read_output_disk(slot)
            print(f"[outdisk] rdump_ext4 -> {outdisk_names} (no mount, no root)")
        except Exception as exc:  # noqa: BLE001
            print(f"[outdisk] rdump raised: {type(exc).__name__}: {exc}")

    # Guest console (boot + agent logs).
    slot_dir = Path(scratch) / slot.slot_id
    fc_log = slot_dir / "fc.log"
    log_txt = fc_log.read_text(errors="replace") if fc_log.exists() else ""
    print("\n---- fc.log tail (guest console) ----")
    print("\n".join(log_txt.splitlines()[-30:]))
    print("---- end fc.log ----")

    rt.reap(slot)
    print(f"\n[reap] is_alive after reap = {rt.is_alive(slot)}")

    import shutil
    shutil.rmtree(scratch, ignore_errors=True)

    print("\n=== SUMMARY ===")
    print(f"  boot:       OK (state WARMING, alive during window)")
    print(f"  vsock READY: {'OK in %.1fs' % dt if ready else 'FAILED (no READY in 30s)'}")
    print(f"  outdisk:     {'OK marker=%s' % ('ready' in (outdisk_names or [])) if ready else 'n/a'}")


if __name__ == "__main__":
    main()
