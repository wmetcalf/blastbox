# minimal-engine — the smallest complete blastbox engine

`echo_engine.py` is a ~40-line, runnable engine: it copies the input to an artifact and
returns a `Record` with the filename / size / sha256. It exists to show the whole engine
contract in one screen — **you implement one method, the framework does the rest**.

## Run it

```sh
mkdir -p /tmp/in /tmp/out && cp anyfile /tmp/in/
python examples/minimal-engine/echo_engine.py --input-dir /tmp/in --output-dir /tmp/out
cat /tmp/out/metadata.json
```

The worker **harness** reads the single file in `--input-dir`, calls your `detonate()`, then
**seals** the result — recomputing every artifact's sha256/size from disk, confining paths,
and writing `metadata.json`. Your engine never touches hashes or path confinement.

## What you implement

```python
class EchoEngine:
    name = "echo"
    formats = frozenset({"*"})
    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        ...  # write artifact files into outdir; return DetonationResult(payload, artifacts, detected)
```

- **`payload`** — a node: `Record` (the generic floor, `type="record"` + a `fields` dict),
  `Page`, or a registered subtype. Recursive engines (e.g. Tika) build `EmbeddedResource` trees.
- **`artifacts`** — `DeclaredArtifact(id, path, kind)` for each file you wrote into `outdir`.
- **`detected`** — a `Detection(label, mime, confidence, source)`.

## Run it as a real service

The same engine plugs into the host orchestrator — point `serve` + `dispatch` at a shared
job store and register the engine (see the repo README's *Run (host)* section). The host
then gives it ingress, a hardened disposable worker per job, output-trust validation, artifact
serving, optional warm pooling, metrics, and a CLI — without changing a line of the engine.
