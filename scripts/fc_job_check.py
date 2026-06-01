"""Live end-to-end FC warm JOB round-trip (run on toolz2).

Does exactly what the dispatcher warm path does for an FC slot, against a real
microVM, and validates the result through the REAL trust gate:

  spawn -> wait READY (vsock) -> signal_go(input over vsock) -> wait_for_done
        -> read_output_disk (rdump) -> validate_worker_output

Asserts the envelope is ok, the input-sha round-trips, and the artifact's hash
was recomputed from disk by the trust gate (never trusted from the guest).
"""
from __future__ import annotations

import hashlib
import shutil
import tempfile
import time
from pathlib import Path

from blastbox.host.runtime.firecracker import (
    FCConfig,
    FirecrackerSlotRuntime,
    firecracker_available,
)
from blastbox.host.trust import validate_worker_output
from blastbox.limits import Limits
from blastbox.worker.warm import WarmJobSpec


def main() -> None:
    scratch = tempfile.mkdtemp(prefix="dfc")
    cfg = FCConfig.from_env(scratch_root=scratch)
    assert firecracker_available(cfg), "FC not available"
    rt = FirecrackerSlotRuntime(cfg)

    # A real "untrusted document".
    payload = b"BLASTBOX FC JOB ROUND-TRIP " + b"A" * 4096
    sha = hashlib.sha256(payload).hexdigest()
    src = Path(scratch) / "input.bin"
    src.write_bytes(payload)
    print(f"input: {len(payload)} bytes sha256={sha[:16]}...")

    slot = rt.spawn()
    print(f"[spawn] {slot.slot_id}")

    # Wait for the guest to warm + signal READY over vsock.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and not rt.is_ready(slot):
        time.sleep(0.25)
    assert rt.is_ready(slot), "guest never signalled READY"
    print("[ready] vsock READY received")

    try:
        # Deliver the job over vsock + read the status — the dispatcher's seam.
        control = rt.host_warm_control(slot)
        control.signal_go(WarmJobSpec(input_path=src, output_dir=slot.output_dir, params={}))
        print("[go] input sent over vsock")
        status = control.wait_for_done(timeout_s=30.0)
        print(f"[done] guest status={status!r}")

        # Materialize output off the ext4 disk (no mount, no root).
        names = rt.read_output_disk(slot)
        print(f"[outdisk] rdump -> {sorted(names)}")

        # Validate through the REAL trust gate (re-seals + re-hashes from disk).
        envelope = validate_worker_output(
            output_dir=slot.output_dir,
            input_sha256=sha,
            engine="probe",
            limits=Limits.from_env(),
        )
        print("\n=== TRUST-VALIDATED ENVELOPE ===")
        print(f"  status:        {envelope.status}")
        print(f"  input_sha256:  {envelope.input_sha256[:16]}...  (round-trips: "
              f"{envelope.input_sha256 == sha})")
        print(f"  artifacts:     {[(a.id, a.sha256[:12]) for a in envelope.artifacts]}")
        print(f"  warnings:      {len(envelope.warnings)}")

        # Independently confirm the trust gate recomputed the artifact hash from disk.
        for art in envelope.artifacts:
            disk = (slot.output_dir / art.path).read_bytes()
            recomputed = hashlib.sha256(disk).hexdigest()
            ok = recomputed == art.sha256
            print(f"  verify {art.path}: disk-sha matches envelope = {ok}")
            assert ok, "artifact hash mismatch — trust gate did not re-hash from disk!"

        assert envelope.status == "ok"
        assert envelope.input_sha256 == sha
        print("\nRESULT: FULL JOB ROUND-TRIP OK (input over vsock -> detonate -> "
              "output via rdump -> trust-validated)")
    finally:
        rt.reap(slot)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
