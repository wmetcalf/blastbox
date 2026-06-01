"""Live end-to-end PDF rasterization in a Firecracker microVM (run on toolz2).

Uses the PDF rootfs (BLASTBOX_FC_ROOTFS=...-pdf.ext4, ENGINE=pdf baked in): sends
a real multi-page PDF over vsock, the guest rasterizes it with poppler's pdftoppm
to per-page PNGs, the host rdumps + trust-validates. Proves a REAL detonation
engine (not the toy ProbeEngine) runs in the warm disposable microVM.
"""
from __future__ import annotations

import hashlib
import importlib.util
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

# Load build_sample_pdf from the rootfs engines module (loaded by path).
_spec = importlib.util.spec_from_file_location(
    "fc_engines", str(Path(__file__).resolve().parents[1] / "deploy" / "firecracker" / "engines.py")
)
_eng = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_eng)  # type: ignore[union-attr]


def main() -> None:
    scratch = tempfile.mkdtemp(prefix="dfc")
    cfg = FCConfig.from_env(scratch_root=scratch)
    assert firecracker_available(cfg), "FC not available (set BLASTBOX_FC_* incl. the -pdf rootfs)"
    rt = FirecrackerSlotRuntime(cfg)

    pdf = _eng.build_sample_pdf("BLASTBOX LIVE", pages=3)
    sha = hashlib.sha256(pdf).hexdigest()
    src = Path(scratch) / "doc.pdf"
    src.write_bytes(pdf)
    print(f"input PDF: {len(pdf)} bytes, 3 pages, sha256={sha[:16]}...")

    slot = rt.spawn()
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and not rt.is_ready(slot):
        time.sleep(0.25)
    assert rt.is_ready(slot), "guest never signalled READY"
    print("[ready] vsock READY")

    try:
        control = rt.host_warm_control(slot)
        control.signal_go(WarmJobSpec(input_path=src, output_dir=slot.output_dir, params={}))
        status = control.wait_for_done(timeout_s=60.0)
        print(f"[done] guest status={status!r}")

        # Hardening evidence: the guest dropped to non-root before detonating.
        fc_log = Path(scratch) / slot.slot_id / "fc.log"
        uid_line = next(
            (ln for ln in fc_log.read_text(errors="replace").splitlines()
             if "run_guest start" in ln),
            "",
        )
        print(f"[guest] {uid_line.split('run_guest start', 1)[-1].strip() or '(uid line not found)'}")

        names = rt.read_output_disk(slot)
        print(f"[outdisk] rdump -> {sorted(names)}")

        env = validate_worker_output(
            output_dir=slot.output_dir, input_sha256=sha, engine="pdfrasterize",
            limits=Limits.from_env(),
        )
        print("\n=== TRUST-VALIDATED ENVELOPE ===")
        print(f"  status:       {env.status}")
        print(f"  input_sha256: round-trips={env.input_sha256 == sha}")
        print(f"  page artifacts ({len(env.artifacts)}):")
        for art in env.artifacts:
            disk = (slot.output_dir / art.path).read_bytes()
            ok = hashlib.sha256(disk).hexdigest() == art.sha256
            w, h = _eng.png_dims(slot.output_dir / art.path)
            print(f"    {art.path}: {w}x{h}px  disk-sha-matches-envelope={ok}")
            assert ok

        assert env.status == "ok"
        assert env.input_sha256 == sha
        assert len(env.artifacts) == 3
        print("\nRESULT: REAL PDF RASTERIZATION IN A WARM FC MICROVM "
              "(PDF over vsock -> pdftoppm -> 3 PNGs via rdump -> trust-validated)")
    finally:
        rt.reap(slot)
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    main()
