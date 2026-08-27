# Magika engine

Neural content-type identification as a blastbox engine. Predicts what a file **is** from
its bytes, independently of extension or magic table.

## Why it earns a slot next to magic-byte identification

The two agree on ordinary files, so the value is entirely in the disagreements: a script
with a misleading extension, a payload wearing a document header, a polyglot. A second
opinion is only useful if it can be *compared*, which is why the envelope carries enough
to compare with — the label, the mime type, the score, and the model's own pre-overwrite
prediction.

## The two things this engine is careful about

**The score travels with the label.** Magika predicts; `elf` at 1.000 and `bmp` at 0.61
are not the same claim, and `detected.confidence` is the model's actual certainty rather
than 1.0. Anything that ranks or thresholds on confidence sees the truth.

**Magika sometimes overrules itself, and both answers are sealed.** Below a confidence
floor it replaces its prediction with a generic label: random bytes come back `unknown`,
while the model underneath guessed `psd` at 0.344. The envelope carries the delivered
`label`, the raw `model_label`, and the `overwrite_reason` that separates them, plus a
`low_confidence_overwrite` warning. Sealing only one of the two would either hide that a
guess existed or report a guess the tool declined to stand behind.

A model that fails to load seals `engine_error` and emits **no `label` key at all** —
because `unknown` is a real Magika answer, and a failure must not be able to manufacture
one.

## Build

```bash
docker build -t magika-cold-worker:dev -f deploy/docker/Dockerfile.magika-cold-worker .
docker build --build-arg BASE=magika-cold-worker:dev \
  -f deploy/gvisor/Dockerfile.magika -t magika-warm:gvisor .
```

The build loads the model once as a smoke test, so an image that cannot identify a file
fails to build rather than failing on its first sample.

## Register it

```bash
BLASTBOX_ENGINES='magika=magika-cold-worker:dev'
BLASTBOX_ENGINE_MAGIKA_PARAM_KEYS=''          # reads nothing from a job
BLASTBOX_ENGINE_MAGIKA_NETPOLICY='none'       # the model ships in the image; nothing to fetch
BLASTBOX_ENGINE_MAGIKA_ALLOWED_RUNTIMES='cold,gvisor'
```

Warm additionally:

```bash
BLASTBOX_GVISOR_WARM_ARGV='["python3","/opt/blastbox/run_warm.py"]'
```

`BLASTBOX_MAGIKA_MAX_BYTES` (default 64 MiB) caps the read. Magika inspects a prefix,
suffix and middle window rather than the whole file, so the cap costs nothing for
ordinary inputs; a truncated read is disclosed as a `truncated_input` warning.

## Warm is optional here

Model load is ~77 ms against ~13 ms per scan — a 6x startup tax, not ClamAV's gigabyte.
Warm helps throughput, but unlike ClamAV a **cold Magika worker is perfectly usable**.
Don't carry the "obviously needs warm" reasoning across from that engine.
