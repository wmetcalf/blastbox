# LambdaMicroVMRuntime — design + fit analysis

> **Status:** exploratory design (local-untracked draft). Not committed. Captures the 2026-07-01
> research on AWS Lambda MicroVMs and how a managed-microVM runtime backend would slot into blastbox.

## Goal

Support **both** deployment models behind blastbox's existing pluggable-runtime seam:

- **host-local** (unchanged): `docker` (runc/runsc), `firecracker`-per-slot, `libvirt-vm` — self-hosted, full control, on-prem/air-gap capable.
- **managed microVM** (new): a `LambdaMicroVMRuntime` backend so a sealed-Linux engine can "fire up" on AWS Lambda MicroVMs with no infra to run.

The engine + worker SDK are **unchanged** — that is the whole point of the engine/host split. The same
backend interface generalizes to other managed-Firecracker peers (Fly Machines, E2B, Modal), so
"any other tool" is one abstraction, not N.

`BLASTBOX_RUNTIME={docker,firecracker,gvisor,libvirt,lambda-microvm,...}`, **capability-gated per
engine** (a sealed-Linux engine may target any; win-validator refuses `lambda-microvm`).

---

## What AWS Lambda MicroVMs actually are (research, 2026-07-01)

GA **2026-06-22** (~1wk old at time of writing). ARM64 only; 5 regions. A distinct primitive from
classic Lambda FaaS: a Firecracker microVM you `run/suspend/resume/terminate`, with **memory+disk
state persisted up to 8h**, a per-VM public HTTPS URL + JWE auth, per-tenant isolated kernel.

| Question | Finding |
|---|---|
| What you run | **[CONFIRMED]** Dockerfile on Amazon Linux 2023 base (ARM64), boots your app, `/ready` hook → AWS snapshots mem+disk. General-purpose Linux userland you control (packages, mounts, shell, background procs). LibreOffice-headless + JVM run fine. **No custom kernel.** |
| Root / caps | **[CONFIRMED]** `additionalOsCapabilities:["ALL"]` → CAP_NET_ADMIN, netns, veth, iptables/nftables, eBPF, raw sockets, mounts. |
| TUN | **[CONFIRMED — the gotcha]** guest kernel compiled **without `CONFIG_TUN`** (no `wireguard.ko`). tun2socks / WireGuard / OpenVPN-TUN / FakeNet-NG-TUN **fail even with `["ALL"]`**. Caps ≠ missing kernel module. |
| Networking | **[CONFIRMED]** inbound = unique public HTTPS URL, **JWE token required** (`create-microvm-auth-token`, scoped to VM+ports+expiry); `NO_INGRESS` to disable. Egress = public internet by default, OR a **customer VPC egress connector** (ENIs in your VPC, your SGs/NACLs). Outbound UDP blocked by default **[LIKELY]**. |
| Nested virt / Windows | **[LIKELY, high-conf]** Firecracker exposes no `/dev/kvm`/nested-virt/GPU; Linux guests only. **No VM-in-VM, no Windows.** |
| Suspend/resume | **[CONFIRMED]** FC snapshot of mem+disk; idle policy or explicit; hooks `/ready /run /suspend /resume /terminate`; `autoResume` holds the request. AWS says **re-establish network/creds on `/resume`** (don't assume sockets survive). **Resume latency: UNKNOWN (no number).** **CPU-feature portability across hosts: UNKNOWN** — real risk for a warm JVM. |
| Limits | **[CONFIRMED]** max lifetime 8h; sizes 0.5GB/0.25vCPU → 8GB/4vCPU baseline → **32GB/16vCPU peak (4× burst)**; disk 8–32GB; no GPU. Account total-memory quota across running+suspended. |
| Pricing | **[LIKELY]** Fargate-shaped per-second (vCPU-s + GB-s baseline+burst) + snapshot storage + data transfer. ~$3/day per 1vCPU+2GB (~9× Fargate Spot). Expensive for sustained, good for burst. |
| AUP (detonation) | **[CONFIRMED]** malware detonation = **restricted, requires AWS prior approval** (pen-test/simulated-event form); default public egress from AWS IPs is a problem; must sinkhole / no-outbound VPC. |

**Bottom line:** bake your own Linux userland + arbitrary processes = **yes** (ARM64, no custom kernel);
privileged networking = **partial** (netns/veth/iptables/eBPF/raw yes, **TUN no**); Linux-only = **yes**
(no Windows, no nested virt).

---

## Runtime backend contract → AWS API mapping

blastbox's runtime seam is `spawn / is_ready / reap` (+ a `SnapshotBackend` for warm tiers, already
generalized for FC + gVisor). Map:

- **golden warm snapshot ← the image `/ready` snapshot.** Ship the engine worker image (ARM64
  Dockerfile on AL2023) that runs `engine.warmup()` then signals `/ready`; AWS snapshots mem+disk.
  That primed image-snapshot IS the golden.
- **`spawn` (one disposable slot) ← `run-microvm` from the image-snapshot** — fast resume of the primed
  state; honors one-doc-per-slot / never-reuse.
- **`is_ready` ← microVM up + worker `/healthz`** via the dedicated HTTPS URL + a minted JWE token.
- **per-job detonate ← `/run` hook / POST job to the VM URL** (JWE in `X-aws-proxy-auth`, port via
  `X-aws-proxy-port`; worker agent on 8080). Output re-sealed by the host from the persisted disk (or
  returned + S3). Same worker-agent contract as the raw `IP:8765` path — only the transport (URL+JWE)
  differs, handled in the backend adapter.
- **`reap` ← `terminate-microvm`** after each job. (Per-VM `suspend/resume` — keeping a VM warm
  *between* requests — is the thing blastbox deliberately does NOT do; use image-snapshot-per-job.)
- **sealing / netpolicy ← `NO_INGRESS` + no egress connector** (the `--network=none` analog); a VPC
  egress connector with a no-outbound SG for controlled egress. **No TUN** ⇒ egress *steering* is
  SOCKS/veth-NAT/VPC-firewall only, not transparent TUN interception.

---

## Per-engine fit

| Engine | Fit | Notes |
|---|---|---|
| **ClippyShot** (LibreOffice→PNG, sealed) | **clean — ideal first target** | warm-UNO ← `/ready` snapshot of a primed `unoserver`; retires `SnapshotManager`/FC-snapshot plumbing for this tier. Sealed ⇒ TUN gap + AUP irrelevant. Caveat: **ARM64 image + pixel/pHash parity gate** (cross-arch render differences → run the mode-parity sweep with `lambda-arm64` as a mode). |
| **RedTusk** (Tika/JVM, sealed) | **clean — retires CRaC** | warm JVM ← `/ready` mem-snapshot IS the checkpoint; no CRIU / accept-retry shim. Same warm-delta ceiling as CRaC (saves boot+warmup, not per-doc parse tax). Caveat: **CPU-feature snapshot portability** (JIT) is the undocumented risk — validate. |
| **network-detonation engines** | **partial** | SOCKS/veth-NAT/VPC-egress-firewall yes; **transparent TUN interception (tun2socks/VPN/FakeNet-TUN) NO** (`CONFIG_TUN` absent); + AWS malware-detonation approval + egress-from-AWS-IP attribution. Keep host-local for full capability. |
| **win-validator** (Windows) | **impossible** | no nested virt / `/dev/kvm` / Windows guest. Host-local libvirt only. |

---

## Caveats (net)

1. **ARM64-only** → new build target for engine images; ClippyShot cross-arch pixel parity is a real gate.
2. **CPU-feature snapshot portability UNKNOWN** → warm-JVM (RedTusk) risk; validate, don't assume.
3. **Cost Fargate-shaped (~9× spot)** → burst/on-demand/no-infra win; sustained-corpus loses to owned hardware. (Which is exactly why "let people choose" is the design.)
4. **Transport is HTTPS+JWE via AWS URL**, not raw `IP:port` → small backend adapter (token minting), same worker-agent contract.
5. **Detonation needs AWS approval + sealed egress** → only sealed engines are frictionless.

---

## Spike plan (small, decisive)

Do it against **ClippyShot** (sealed, warm-native, validates the whole backend):
1. Build an ARM64 ClippyShot worker image (AL2023 Dockerfile) with `engine.warmup()` → `/ready`.
2. `run-microvm` → POST a doc via the VM URL+JWE → confirm PNGs+metadata, host re-seals from disk.
3. **Pixel/pHash parity vs the host-local tier** (the go/no-go gate).
4. Measure resume latency + cost per job; confirm the warm image-snapshot resume works per-slot.
5. If green, wrap as `LambdaMicroVMRuntime` behind the runtime seam + a per-engine capability gate.

Then RedTusk (retires CRaC) as the second target, watching the CPU-feature-portability risk on the
warm JVM.
