"""Real workloads for the conversion/sandbox benchmark scenarios.

Imported lazily by the scenarios so the bench package imports with no soffice."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from blastbox.bench.scenarios import BenchConfig

_SOFFICE = "/usr/bin/soffice"


def soffice_argv(input_path: str, outdir: str) -> list[str]:
    return [
        _SOFFICE,
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        outdir,
        input_path,
    ]


def available_sandbox_backends() -> tuple[str, ...]:
    """``none`` (baseline) + whichever sandbox binaries are installed."""
    backends = ["none"]
    for name, present in (
        ("bwrap", shutil.which("bwrap")),
        ("nsjail", shutil.which("nsjail")),
        ("nono", shutil.which("nono")),
    ):
        if present:
            backends.append(name)
    return tuple(backends)


def cfg_timeout(cfg: BenchConfig) -> int:
    raw = cfg.params.get("timeout_s", "120")
    return int(raw)


def soffice_runner(cfg: BenchConfig) -> Callable[[str], None]:
    """Return ``run_one(backend)`` that converts a fixture under that backend.

    Uses the blastbox sandbox protocol for real backends; ``none`` runs soffice
    directly. Each call uses a fresh per-run output dir."""
    tmp = Path(tempfile.mkdtemp(prefix="blastbox-bench-"))
    inp = tmp / "in.txt"
    inp.write_text("blastbox bench fixture\nsecond line\n")

    def run_one(backend: str) -> None:
        out = Path(tempfile.mkdtemp(prefix="bench-out-", dir=tmp))
        argv = soffice_argv(str(inp), str(out))
        if backend == "none":
            subprocess.run(argv, capture_output=True, timeout=cfg_timeout(cfg))
            return
        from blastbox.worker.sandbox.base import Mount, SandboxRequest
        from blastbox.worker.sandbox.detect import select_sandbox

        sb = select_sandbox(backend=backend)
        sb.run(
            SandboxRequest(
                argv=argv,
                ro_mounts=[Mount(source=inp, target=inp)],
                rw_mounts=[Mount(source=out, target=out, read_only=False)],
            )
        )

    return run_one
