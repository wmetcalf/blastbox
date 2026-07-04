# blastbox

**A reusable framework for running untrusted/malicious documents through disposable, hardened
workers** — and turning their output into a typed, host-validated result you can trust.

Extracted from the common substrate of two production services (a LibreOffice document→image
rasterizer and a Tika recursive-extraction service) that had each grown a parallel, drifting copy of
the same machinery. blastbox is the single, audited-once core; each service becomes a thin *engine*.

- **Write one function.** An engine implements `detonate(input, outdir, limits) -> DetonationResult`.
  The framework gives it ingress, a JobStore, a disposable hardened worker per job, output-trust
  validation, artifact serving, optional warm pooling, metrics, and a CLI — for free.
- **Output is never trusted.** A worker processes a malicious document; the host **re-seals its
  output from disk** (recomputing hashes/sizes, confining paths) before believing a byte of it.
- **One untrusted doc per disposable slot** — always. Warm pooling pre-pays startup in the
  background; it never reuses a worker across documents.
- **Typed, engine-shaped output.** A shared node library (`Page`, `EmbeddedResource`, `ExtractedText`,
  a generic `Record` floor, recursive) lets engines be as specific or generic as they need, while the
  framework validates a fixed security envelope identically for everyone.

Proven end-to-end against two real, language-diverse engines: a **Python + LibreOffice** rasterizer
and a **JVM + Tika** recursive extractor.

## Architecture

```
blastbox/
├── contract/   typed node tree + security envelope + seal/validate (registry-aware at any depth)
├── host/       LAYER 1 — host orchestrator (engine-agnostic) — needs blastbox[host]
│   ├── ingress     FastAPI API + CLI: upload, status, artifact serving, /metrics
│   ├── jobs/       JobStore protocol + memory / sql / redis backends + retention
│   ├── dispatch    claim → launch disposable worker → validate output → serve   (+ warm path)
│   ├── runtime/    backend select (fail-closed): hardened `docker run` (runc/runsc)
│   │               OR a Firecracker microVM per slot (AF_VSOCK warm protocol; the
│   │               engine defines warmup — a JVM engine via CRaC, with guest-console
│   │               CPU-feature-mismatch detect + a probe; a non-JVM engine without)
│   ├── pool        warm slot pool (one-doc-per-slot, never-reuse; burst + health loops)
│   ├── trust       output-trust validator — re-seals worker output from disk
│   ├── netpolicy   opt-in egress OVERLAY: personality → exit driver, fail-closed to `none`
│   ├── netd        privileged rooter: per-worker pcap + netns wiring + non-TCP leak guard (v4+v6)
│   └── observability
├── worker/     LAYER 2 — worker SDK (runs inside the disposable worker) — lean core
│   ├── engine      the seam: detect / warmup / detonate
│   ├── harness     read input → detonate → seal → write metadata.json (+ egress-readiness barrier)
│   ├── sandbox/    auto-selected in-process hardening: nsjail / bwrap / nono / container
│   │               (BLASTBOX_SANDBOX override; container inside OCI; nono = Landlock, no userns)
│   ├── warm        service lifecycle: boot → warmup → one job → exit
│   └── fc_warm / fc_guest   Firecracker guest: AF_VSOCK control plane + warm protocol
└── engines/    reference EXAMPLES only (detonate, urlgrab) — domain engines live in their own repos
```

The host never imports an engine; it depends only on the **contract**. An engine never handles
hashes/paths defensively; the worker SDK and host do that in audited code. blastbox ships **no domain
engines** — `engines/` holds runnable *examples* (`detonate`, `urlgrab`); real engines (ClippyShot,
RedTusk, …) live in their own repos and plug in via `BLASTBOX_ENGINE=module:Class`.

## Writing an engine

```python
from pathlib import Path
from blastbox import Engine, DetonationResult, run_detonation
from blastbox.contract import Page, DeclaredArtifact, Detection, ArtifactRef, Dimensions
from blastbox.limits import Limits

class MyEngine:
    name = "myengine"
    formats = frozenset({"pdf"})

    def detonate(self, input: Path, outdir: Path, limits: Limits) -> DetonationResult:
        # ... render/extract; write artifact files into outdir ...
        (outdir / "page-001.png").write_bytes(png_bytes)
        return DetonationResult(
            payload=Page(index=0, dims=Dimensions(width=210, height=297, unit="mm"),
                         image=ArtifactRef(id="p0")),
            artifacts=[DeclaredArtifact(id="p0", path="page-001.png", kind="image")],
            detected=Detection(label="pdf", mime="application/pdf", confidence=1.0, source="myengine"),
        )

# worker entrypoint:
if __name__ == "__main__":
    import sys
    from blastbox.worker.harness import main
    sys.exit(main(MyEngine()))
```

The harness seals your declared artifacts (recomputing sha256/size from disk, confining paths,
resolving references) and writes `metadata.json`. The host's `validate_worker_output` re-validates it.
Complex engines build recursive `EmbeddedResource` trees (e.g. Tika's recursive metadata); simple
ones use `Page`/`Record`. Engine-specific node subtypes register via `contract.register_node_type`.

## Install

```sh
pip install blastbox           # lean core — everything an ENGINE needs (pydantic only)
pip install blastbox[host]     # + the host orchestrator (FastAPI, jobstores, observability)
```

## Run (host)

```sh
# serve + dispatch are SEPARATE processes — point both at a SHARED job store:
export BLASTBOX_DATABASE_URL=sqlite:////var/lib/blastbox/jobs.db   # or postgresql://… / redis://…
blastbox serve     --host 127.0.0.1 --port 8000     # the ingress API
blastbox dispatch                                    # the worker dispatcher loop
```

> **`BLASTBOX_DATABASE_URL` is required for the two-process flow above.** Unset, each command
> uses its own in-memory store, so jobs submitted to `serve` are invisible to `dispatch` (a
> warning is logged). `sqlite:///…`, `postgresql://…`, and `redis://…` are supported.

`POST /v1/jobs` (multipart `file` + `engine`) enqueues a job; the dispatcher launches a hardened
disposable worker for it; `GET /v1/jobs/{id}/artifacts/{artifact_id}` serves validated output.

The defaults run a secure single-host deployment — you set almost nothing. For the warm-pool /
runtime / sandbox tiers, **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** is the tier-decision guide
(incl. the per-tier capability matrix) and **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** is the
full `BLASTBOX_*` reference.

## Testing

```sh
python3 -m venv .venv && .venv/bin/pip install -e .[dev]
.venv/bin/pytest tests          # unit (mocked) — runs anywhere
.venv/bin/ruff check src tests && .venv/bin/mypy src
```

The gated `integration` suite (gVisor C/R + Firecracker warm round-trips, real sandboxes) needs
real runtimes + (on Ubuntu 24.04+) **root**, because the hardened kernel restricts the
unprivileged user namespaces `runsc`/`bwrap`/`nsjail` need. See **[docs/TESTING.md](docs/TESTING.md)**
for the full setup (incl. building a `probe`-engine rootfs and the userns workaround).

## Security model

- Disposable worker per job: `--network=none --cap-drop=ALL --no-new-privileges --read-only`; the
  input is deleted after conversion. **No network is the default** — egress is an explicit opt-in
  (see *Network overlay* below) and is fail-closed at every layer.
- **runsc (gVisor) is required by default — fail-closed.** If no secure runtime is available the
  dispatcher refuses the job *early* with an actionable `InsecureRuntimeRefused` (rather than letting
  the worker start and fail its own sandbox self-check opaquely). To run **without** gVisor, the
  operator must explicitly opt in with **`BLASTBOX_ALLOW_RUNC=1`** — that runs the worker under plain
  `runc` in deliberate degraded mode (no gVisor isolation; the per-job warning is recorded, and the
  worker is told to run its self-check leniently). `BLASTBOX_REQUIRE_SECURE_RUNTIME=1` is a hard
  lockdown that refuses `runc` even when `BLASTBOX_ALLOW_RUNC` is set. (`BLASTBOX_WORKER_RUNTIME=runc`
  forces the runtime but still needs the `ALLOW_RUNC` consent flag.)
- The host re-seals worker output from disk — worker-reported hashes/sizes are never trusted; artifact
  paths are confined; the input-SHA round-trip is checked; `metadata.json` must be a regular file.
- Ingress rejects oversized bodies before spooling, sanitizes filenames, serves artifacts by id under
  a confined path, and (optionally) sits behind a bearer token / auth proxy.
- The contract bounds payload size/depth and validates every node; engine subtypes are validated
  against their registered schema.

## Network overlay (opt-in egress)

Most detonation is done sealed (`--network=none`). But some analysis *needs* the network — a URL
fetch, a sample that only behaves when it can call home. blastbox exposes a **safe, opt-in egress
overlay** that any engine can choose to use, **the same way across every sandbox type** (runc /
gVisor / Firecracker microVM). The overlay is a capability the framework provides; the engine just
declares it wants an exit.

**Fail-closed by default, at every layer.** A worker cannot grant itself the network:

- The effective egress is a named **personality** (`BLASTBOX_NETPOLICY_<NAME>='exit=…,k=v'`).
  Resolution order is per-job override (only when `BLASTBOX_ALLOW_NETPOLICY_OVERRIDE=1` *and* the
  name is declared) → per-engine default → **`none`**. An unknown name at any step collapses to
  `none`; `none` is reserved and cannot be redefined to grant egress.
- The disposable worker attaches **`--network=none`** unless a personality with a real exit resolved;
  the in-process sandbox keeps its netns **unshared** unless egress was explicitly granted.
- To get *any* egress, all of these must line up: an operator declares a personality **and** stands
  up the exit infra **and** an engine opts in (or a job overrides, with the gate on).

**`netd`** — a small privileged host rooter (the analogue of CAPE's `rooter`, now containerized and
`cap-drop=ALL` + minimal caps, reaching Docker through a read-only socket-proxy) — watches container
events and, per opted-in worker: captures its traffic to a per-job pcap, wires its network namespace
to the chosen exit, and installs a **non-TCP leak guard** (an in-netns `iptables`/`ip6tables` OUTPUT
firewall) so a sample can't punch UDP/ICMP/raw or IPv6 out past a TCP-only tier.

**Per-personality egress hardening** — two composable knobs, declared in the
`BLASTBOX_NETPOLICY_<NAME>` entry, for the **netd-gated tiers `tor` / `openvpn` / `wireguard`**:

- `egress_ports=53 80 443` — a **web-only L4 allowlist** (DNS/HTTP/HTTPS): drop every other TCP port
  *and* all non-TCP (UDP:53 only when 53 is itself listed), fail-closed via a catch-all DROP.
- `block_internal=1` — drop all **RFC1918 + link-local/metadata** destinations: no SSRF into the host
  LAN, no `169.254.169.254`, no lateral movement to sibling workers (non-internal UDP/ICMP preserved).

`netd` folds both into the in-netns leak guard — a **precondition** for wiring, so they are
fail-closed (no guard ⇒ no egress). The restriction to those tiers is deliberate: there the worker's
own OUTPUT carries the real destination IP:port (so the filter is meaningful) *and* egress only exists
once netd has wired it. A SOCKS/httpproxy *proxy hop* would have its own tunnel dropped, and a plain
bridge (`direct`/`inetsim`) would fail **open** under the gVisor default runtime — both are refused
with a clear diagnostic. Proven live (toolz3): web-only via VPN, internal blocked.

**Egress methodologies** (all exposed to any engine, all fail-closed):

| Exit | What it does | Credentials |
|------|--------------|-------------|
| `inetsim` (**fakenet**) | sinkhole — a FakeNet-NG sidecar answers everything | **none — example** |
| `tor` | transparent CAPE recipe (TransPort/DNSPort) or a country-pinned SocksPort fleet | **none — example** |
| `socks` | transparent tunnel through any SOCKS5 exit (tun2socks) | bring-your-own provider |
| `httpproxy` | HTTP(S)_PROXY through any chaining proxy sidecar | bring-your-own provider |
| `openvpn` / `wireguard` | all-IP path via a VPN+NAT gateway sidecar | bring-your-own provider |
| `inspect` | route through a TLS-MITM gateway; export keys → decrypt the capture | (layered on an exit) |

**tor and fakenet need no accounts and no credentials**, so they are the worked examples; the others
are provider-agnostic *mechanism* (bring your own SOCKS/HTTP-proxy/VPN — blastbox ships no provider
secrets). The reference engine **`blastbox.engines.urlgrab`** (fetch one URL, seal the response — it
does *not* render or execute) is the example consumer used to demonstrate the overlay end-to-end:
`net_policy=fakenet` proves the whole pipe safely, `net_policy=tor` fetches attribution-protected.

## Status

Core framework complete and adversarially tested: contract + full host orchestrator + worker SDK
(harness, sandbox self-check, warm protocol) + warm pool (burst + health loops) + warm dispatch.

**A family of runtime backends** behind one `SlotRuntime` seam, all fail-closed and config-selected
(`BLASTBOX_POOL_RUNTIME`, no code changes to switch): **local** — hardened `docker run` (runc/runsc), a
**Firecracker microVM per slot** (AF_VSOCK warm protocol — *the engine* defines what "warmup" means, so
the tier is engine-agnostic), and **gVisor checkpoint/restore**; and **network-endpoint** — a fixed fleet
of boxes you own (`static`) or disposable cloud workers (`aws-ec2` / `aws-lambda-microvm`), where any
engine runs off-box via `python -m blastbox.worker.http_agent` over a generic HTTP+tar transport (same
sealed-envelope contract). A **`cascade`** composes them into one pool — e.g. *X warm locally, overflow to
other hardware then AWS* (`BLASTBOX_POOL_TIERS=gvisor:4,static:8,aws-ec2:16`). **Four in-process sandbox backends**, auto-selected (`nsjail` → `bwrap` → `nono` →
`container`; `container` inside an OCI host) with a `BLASTBOX_SANDBOX` override. `nono` is a **Landlock**
capability sandbox — filesystem + network containment **without user namespaces**, for hosts where
`bwrap`/`nsjail` can't run (restricted-userns / no `CAP_SYS_ADMIN`); it's `secure=False` (no
seccomp/namespaces) and so an explicit opt-in, at ~1–4 % per-job overhead.

Warmup is per-engine: the **JVM/Tika** engine warms via **CRaC** (checkpoint/restore), and for that path
the Firecracker runtime adds guest-console **CPU-feature-mismatch detection** + a one-shot compatibility
**probe**. The **LibreOffice**
engine has **no CRaC** (it isn't a JVM): instead its ~750 ms `soffice` boot is hidden by the **warm-UNO
FC snapshot/restore** tier (below), or it falls back to cold-starting `soffice --convert-to` per job.

Proven end-to-end — live on a Firecracker host — with two real, language-diverse engines, both in the
**FC warm-pool tier**: a **JVM + Tika** recursive extractor (CRaC warm-restore) and a **Python +
LibreOffice** rasterizer (warm-UNO snapshot/restore, or cold-boot; `deploy/firecracker/Dockerfile.clippyshot`).
The LibreOffice engine also runs standalone on the **docker + sandbox** tier (runc/runsc).

**Warm-UNO via FC snapshot/restore — shipped.** A microVM with a running, idle in-guest `unoserver`
(soffice `--accept` on a local UDS) is captured in a Firecracker memory snapshot built *first-boot on the
host*, then restored→converted→destroyed per job — the "FC but not CRaC" warm route that hides the
~750 ms soffice boot. Validated end-to-end on a Firecracker host: snapshot a live `unoserver` → restore
from `/dev/shm` → convert → output is **pixel-identical to cold** `--convert-to` across calc/csv **and
impress/draw** (pptx / odp / ppt / odg). Measured: a warm restore (~0.5 s; the FC `load-snapshot`
primitive itself is ~4 ms) replaces a ~7.8 s cold boot+warmup — **~13.5× to a ready slot** — with the
copy-on-write mem base optionally **pinned in RAM** (`BLASTBOX_SNAPSHOT_MEM_TMPFS`, a per-host toggle).
Everything UNO stays in-guest; only the existing vsock + output-disk channels cross the boundary. Gated
opt-in: `BLASTBOX_POOL_RUNTIME=firecracker` + `BLASTBOX_POOL_WARM_SNAPSHOT=1`; bare-metal
`bwrap`/`nsjail`/`nono` stays cold. Implemented in `host/runtime/fc_snapshot*.py`
(`SnapshotManager` + `SnapshotSlotRuntime`); design:
`docs/specs/2026-06-03-warm-uno-fc-snapshot-design.md`.

**Benchmarking — `blastbox bench`.** A runtime-agnostic perf harness (stats + percentiles + A/B
comparisons) with a scenario registry that skips cleanly when prerequisites are absent, plus a
`perf`-marked CI ratio gate. `blastbox bench --list`; scenarios include `sandbox.overhead` (nono vs
bwrap vs none), `snapshot.restore-latency`, and `convert.latency`. Design:
`docs/specs/2026-06-04-blastbox-bench-design.md`.

## License

MIT.
