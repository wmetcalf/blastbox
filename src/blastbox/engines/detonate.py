"""Generic detonation engine: run an allow-listed CLI tool on the input.

The framework's building block for content-gated detection-as-code and arbitrary
one-shot detonations. The host **cold-dispatches** this engine with a tool spec
(argv via ``BLASTBOX_DETONATE_ARGV``); the dispatcher runs it in a **disposable,
hardened worker** (the docker/gVisor/Firecracker runtime, optionally an in-worker
bwrap/nsjail jail) — *that worker is the sandbox*. This engine just runs the tool
as a subprocess under the worker's ``Limits`` (no shell) and hands its stdout back
inside the typed, host-validated ``Envelope`` (sealed provenance), so the expensive
tool runs only on the gated fraction.

It does not re-sandbox: a dedicated one-shot detonation worker is itself the jail,
and isolation/backend selection are the dispatcher's job (see ``host/dispatch.py``,
``host/runtime/``). For an *untrusted* tool sharing a long-lived worker, jail the
subprocess with ``select_sandbox()`` instead — a separate, opt-in concern.

argv substitution: any element equal to ``"{input}"`` → the input file path; any
element equal to ``"{outdir}"`` → the output directory. With no ``"{input}"`` token
the input bytes are fed on stdin. stdout is written as the ``stdout`` artifact
(``stdout.bin``), capped at ``limits.max_artifact_bytes``.

    BLASTBOX_DETONATE_ARGV='["base64","-d","{input}"]' \\
    python -m blastbox.engines.detonate --input-dir /in --output-dir /out
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from blastbox.contract import DeclaredArtifact, Detection, Record, Warning
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult

ARGV_ENV = "BLASTBOX_DETONATE_ARGV"


def _detected() -> Detection:
    return Detection(
        label="detonate",
        mime="application/octet-stream",
        confidence=1.0,
        source="detonate",
    )


class DetonateEngine:
    """Run an allow-listed CLI tool (argv from ``BLASTBOX_DETONATE_ARGV``) on the input."""

    name = "detonate"
    formats = frozenset({"*"})

    def __init__(self, argv: list[str] | None = None, name: str | None = None) -> None:
        # argv may be injected directly (tests / a host that builds the spec) or read
        # from the environment at detonate time (the dispatched-worker path).
        self._argv = argv
        # The engine's reported name (sealed into the Envelope). When this engine is
        # cold-dispatched, the host trust gate requires it to equal the dispatcher's
        # EngineSpec name — so per-tool images set it via BLASTBOX_DETONATE_NAME
        # (operator-fixed, never job-derived). Defaults to the class name.
        if name is not None or "BLASTBOX_DETONATE_NAME" in os.environ:
            self.name = name or os.environ["BLASTBOX_DETONATE_NAME"]

    def _resolve_argv(self) -> list[str]:
        if self._argv is not None:
            argv = self._argv
        else:
            raw = os.environ.get(ARGV_ENV)
            if not raw:
                raise ValueError(f"{ARGV_ENV} is unset; nothing to detonate")
            argv = json.loads(raw)
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(a, str) for a in argv)
        ):
            raise ValueError(f"{ARGV_ENV} must be a non-empty JSON array of strings")
        return argv

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        argv_tmpl = self._resolve_argv()
        tool = argv_tmpl[0]
        uses_input_path = any(a == "{input}" for a in argv_tmpl)
        argv = [
            str(input) if a == "{input}" else str(outdir) if a == "{outdir}" else a
            for a in argv_tmpl
        ]
        stdin = None if uses_input_path else input.read_bytes()
        cap = limits.max_artifact_bytes

        warnings: list[Warning] = []
        killed = False
        try:
            # NEVER shell=True; argv is a fixed list. Isolation is the worker's job.
            proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
                argv,
                input=stdin,
                capture_output=True,
                timeout=limits.timeout_s,
                check=False,
            )
            stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
        except FileNotFoundError:
            return DetonationResult(
                payload=Record(fields={"tool": tool, "error": "tool_not_found"}),
                artifacts=[],
                detected=_detected(),
                warnings=[Warning(code="tool_not_found", message=f"no such tool: {tool}")],
                status="engine_error",
            )
        except subprocess.TimeoutExpired as exc:
            killed = True
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            code = -9
            warnings.append(
                Warning(code="timeout", message=f"tool exceeded {limits.timeout_s}s")
            )

        truncated = len(stdout) > cap
        if truncated:
            stdout = stdout[:cap]
            warnings.append(
                Warning(code="output_truncated", message=f"stdout capped at {cap} bytes")
            )

        (outdir / "stdout.bin").write_bytes(stdout)

        return DetonationResult(
            payload=Record(
                fields={
                    "tool": tool,
                    "exit_code": code,
                    "killed": killed,
                    "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                    "stdout_len": len(stdout),
                    "stderr_len": len(stderr),
                    "truncated": truncated,
                },
            ),
            artifacts=[DeclaredArtifact(id="stdout", path="stdout.bin", kind="raw")],
            detected=_detected(),
            warnings=warnings,
            status="ok",
        )


if __name__ == "__main__":
    import sys

    from blastbox.worker.harness import main

    # detect/warmup are optional (the harness hasattr-checks them); the Engine
    # Protocol over-declares them, so this is correct at runtime.
    sys.exit(main(DetonateEngine()))  # type: ignore[arg-type]
