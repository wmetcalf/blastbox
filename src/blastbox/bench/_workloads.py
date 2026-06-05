"""Real workloads for the conversion/sandbox benchmark scenarios.

Imported lazily by the scenarios so the bench package imports with no soffice."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from blastbox.bench.scenarios import BenchConfig

# Resolve via PATH so the workload uses the SAME soffice the requirement check
# (shutil.which) found, not a possibly-different hardcoded location.
_SOFFICE = shutil.which("soffice") or "/usr/bin/soffice"


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


@contextmanager
def soffice_runner(cfg: BenchConfig) -> Iterator[Callable[[str], None]]:
    """Context manager yielding ``run_one(backend)``; cleans up its scratch on exit.

    ``run_one`` converts a fixture under the named backend (the blastbox sandbox
    protocol for real backends; ``none`` runs soffice directly). It reuses a single
    output dir, recreated each call, so repeated runs don't accumulate temp dirs; the
    whole scratch tree is removed when the ``with`` block exits."""
    tmp = Path(tempfile.mkdtemp(prefix="blastbox-bench-"))
    try:
        inp = tmp / "in.txt"
        inp.write_text("blastbox bench fixture\nsecond line\n")
        out = tmp / "out"

        def run_one(backend: str) -> None:
            # A failed/timed-out conversion MUST raise so measure() drops the sample
            # rather than recording a meaningless timing (which would hide regressions).
            if out.exists():
                shutil.rmtree(out)
            out.mkdir()
            argv = soffice_argv(str(inp), str(out))
            if backend == "none":
                subprocess.run(
                    argv, capture_output=True, timeout=cfg_timeout(cfg), check=True
                )
                return
            from blastbox.limits import Limits
            from blastbox.worker.sandbox.base import Mount, SandboxRequest
            from blastbox.worker.sandbox.detect import select_sandbox

            sb = select_sandbox(backend=backend)
            res = sb.run(
                SandboxRequest(
                    argv=argv,
                    ro_mounts=[Mount(source=inp, target=inp)],
                    rw_mounts=[Mount(source=out, target=out, read_only=False)],
                    limits=Limits(timeout_s=cfg_timeout(cfg)),
                )
            )
            if res.killed or res.exit_code != 0:
                raise RuntimeError(
                    f"sandbox conversion failed: exit={res.exit_code} killed={res.killed}"
                )

        yield run_one
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
