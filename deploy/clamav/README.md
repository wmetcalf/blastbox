# ClamAV engine

Signature scanning as a blastbox engine. The daemon runs **inside the worker guest** on a
unix socket; nothing outside the guest can reach it, and Loadout never speaks the clamd
protocol.

## Why it is shaped this way

The first version was a long-lived clamd **service** that callers scanned against over
TCP. That is the obvious design and it is wrong here: the sample reached the scanner
without a signed job bundle and the verdict came back without a sealed envelope, so the
ADR-002 boundary every other engine crosses was simply skipped for this one. It also put
every tenant's samples through one shared daemon's address space.

Moving clamd into the worker makes it an ordinary engine — same intake, same limits, same
sealing — and costs nothing, because the thing that made a service tempting (not paying
the database load per scan) is what the **warm tier** already solves.

## Build

```bash
docker build -t clamav-cold-worker:dev -f deploy/docker/Dockerfile.clamav-cold-worker .
docker build --build-arg BASE=clamav-cold-worker:dev \
  -f deploy/gvisor/Dockerfile.clamav -t clamav-warm:gvisor .
```

The cold image bakes the signature database at build time, so the database version is a
property **of the image** — which is what the engine seals with every verdict. A stale
image is visible in the evidence instead of invisible.

## Register it

Engines are operator config, never job-derived:

```bash
BLASTBOX_ENGINES='clamav=clamav-cold-worker:dev'
# Client params open the worker's env namespace, and this engine reads nothing from a
# job. An explicitly EMPTY allowlist blocks all of them (it does not fall back to the
# legacy denylist).
BLASTBOX_ENGINE_CLAMAV_PARAM_KEYS=''
# Signature scanning needs no egress. `freshclam` runs at BUILD time, not at scan time.
BLASTBOX_ENGINE_CLAMAV_NETPOLICY='none'
# Pin it to the local hardened tiers rather than letting a BLASTBOX_POOL_RUNTIME drift
# route it onto a public-AWS worker with a different egress posture.
BLASTBOX_ENGINE_CLAMAV_ALLOWED_RUNTIMES='cold,gvisor'
```

Warm (gVisor C/R) additionally needs:

```bash
BLASTBOX_GVISOR_WARM_ARGV='["/usr/local/bin/clamav-entrypoint","python3","/opt/blastbox/run_warm.py"]'
```

**The entrypoint must stay in that argv.** It blocks until clamd is answering, which is
what makes the checkpoint capture a *ready* daemon. Checkpointing mid-load would freeze a
daemon with no database — one that answers `OK` to everything — and every restore from
that image would report every sample clean. That failure is permanent, baked into an
artifact, and looks exactly like a working deployment.

## Refreshing signatures

Rebuild the image. There is deliberately no in-place `freshclam --daemon` in the worker:
a warm slot that updates its own database makes the version sealed in an envelope a claim
about *when the scan ran* rather than about the image, and two slots from one checkpoint
would disagree. Rebuild, re-checkpoint, roll.
