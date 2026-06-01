"""Live end-to-end ClippyShot (LibreOffice) detonation in a Firecracker microVM.

Uses the clippyshot rootfs (FROM clippyshot:dev + blastbox agent): sends a real
.docx over vsock, the guest runs ClippyShot's actual Converter (soffice → PDF →
pdftoppm → PNGs + scanners) as the non-root `clippy` user, the host rdumps the
output disk + trust-validates. Dumps the guest console on failure (soffice in a
microVM is the part most likely to surprise).
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

DOCX = Path("/home/coz/fixture.docx")


def main() -> None:
    scratch = tempfile.mkdtemp(prefix="dfc")
    cfg = FCConfig.from_env(scratch_root=scratch)
    assert firecracker_available(cfg), "FC not available"
    rt = FirecrackerSlotRuntime(cfg)

    data = DOCX.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    src = Path(scratch) / "input.docx"
    src.write_bytes(data)
    print(f"input .docx: {len(data)} bytes sha256={sha[:16]}...")

    slot = rt.spawn()
    fc_log = Path(scratch) / slot.slot_id / "fc.log"

    def dump_log(n: int = 50) -> None:
        try:
            print("---- fc.log tail ----")
            print("\n".join(fc_log.read_text(errors="replace").splitlines()[-n:]))
            print("---- end ----")
        except OSError:
            pass

    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline and not rt.is_ready(slot):
        time.sleep(0.5)
    if not rt.is_ready(slot):
        dump_log()
        rt.reap(slot)
        shutil.rmtree(scratch, ignore_errors=True)
        raise SystemExit("guest never signalled READY")
    print("[ready] vsock READY")

    try:
        control = rt.host_warm_control(slot)
        control.signal_go(WarmJobSpec(input_path=src, output_dir=slot.output_dir, params={}))
        print("[go] .docx sent over vsock; running ClippyShot Converter...")
        status = control.wait_for_done(timeout_s=120.0)
        print(f"[done] guest status={status!r}")

        uid_line = next(
            (ln for ln in fc_log.read_text(errors="replace").splitlines()
             if "run_guest start" in ln), "",
        )
        print(f"[guest] {uid_line.split('run_guest start', 1)[-1].strip() or '(no uid line)'}")

        names = rt.read_output_disk(slot)
        print(f"[outdisk] rdump -> {sorted(names)}")

        env = validate_worker_output(
            output_dir=slot.output_dir, input_sha256=sha, engine="clippyshot",
            limits=Limits.from_env(),
        )
        print("\n=== TRUST-VALIDATED ENVELOPE ===")
        print(f"  status:       {env.status}")
        print(f"  input_sha256: round-trips={env.input_sha256 == sha}")
        print(f"  artifacts ({len(env.artifacts)}):")
        for art in env.artifacts:
            disk = (slot.output_dir / art.path).read_bytes()
            ok = hashlib.sha256(disk).hexdigest() == art.sha256
            print(f"    {art.path}: {len(disk)} bytes  disk-sha-matches={ok}")
            assert ok
        print(f"  warnings: {len(env.warnings)}")

        assert env.status == "ok", f"status={env.status}"
        assert env.input_sha256 == sha
        assert len(env.artifacts) >= 1
        print("\nRESULT: REAL CLIPPYSHOT (LibreOffice) RASTERIZATION IN A WARM FC "
              "MICROVM (.docx over vsock -> soffice -> pdftoppm -> trust-validated)")
    except Exception:
        dump_log(70)
        raise
    finally:
        rt.reap(slot)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
