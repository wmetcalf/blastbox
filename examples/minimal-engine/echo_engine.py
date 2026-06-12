"""The smallest complete blastbox engine — copy/paste starting point.

An engine implements ONE method, `detonate(input, outdir, limits)`, writes its output
files into `outdir`, and returns a `DetonationResult` referencing them. The framework gives
you everything else (ingress, a hardened disposable worker per job, output-trust re-sealing,
artifact serving, the CLI) for free — see the repo README.

Run it directly through the worker harness — it reads the single file in `--input-dir`, runs
detonate, seals the output, and writes metadata.json into `--output-dir`:

    mkdir -p /tmp/in /tmp/out && cp anyfile /tmp/in/
    python examples/minimal-engine/echo_engine.py --input-dir /tmp/in --output-dir /tmp/out
    cat /tmp/out/metadata.json

The harness recomputes every artifact's sha256/size from disk and writes metadata.json — your
engine never has to handle hashes or path confinement defensively.
"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from blastbox.contract import DeclaredArtifact, Detection, Record
from blastbox.limits import Limits
from blastbox.worker.engine import DetonationResult


class EchoEngine:
    name = "echo"
    formats = frozenset({"*"})  # accept anything

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        data = input.read_bytes()
        sha = hashlib.sha256(data).hexdigest()

        # Write an output artifact into outdir (a copy of the input).
        copy = outdir / "copy.bin"
        shutil.copyfile(input, copy)

        return DetonationResult(
            # Record is the generic node "floor" — `type` is the fixed discriminator
            # ("record"); put your data in `fields`. Engines that need richer/recursive
            # output use Page / EmbeddedResource / a registered subtype instead.
            payload=Record(
                type="record",
                fields={"kind": "echo", "filename": input.name, "size": len(data), "sha256": sha},
            ),
            artifacts=[DeclaredArtifact(id="copy", path="copy.bin", kind="file")],
            detected=Detection(
                label="echo", mime="application/octet-stream", confidence=1.0, source="echo"
            ),
        )


if __name__ == "__main__":
    import sys

    from blastbox.worker.harness import main

    sys.exit(main(EchoEngine()))
