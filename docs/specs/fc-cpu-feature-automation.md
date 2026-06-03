# FC CRaC CPU-Feature Mismatch — Detection & Auto-Handling

Status: **Phase 1 shipped** · Phase 2 designed/pending · Owner: Will · 2026-06-02

**Phase 1 (runtime auto-detect) is implemented + unit-tested:**
- blastbox canonical: `src/blastbox/host/runtime/cpu_features.py`
  (`parse_cpu_mismatch` + `CpuFeatureMismatch`), `errors.FcCpuFeatureMismatch`,
  tests in `tests/host/runtime/test_cpu_features.py` (8).
- RedTusk consumer: vendored `src/redtusk/fc_cpu_features.py`,
  `errors.FcCpuFeatureMismatchError`, metric `redtusk_fc_cpu_feature_mismatch_total`,
  wired into `FirecrackerWorkerRuntime.poll_fifo` →
  `_raise_if_cpu_feature_mismatch`, tests in `tests/unit/test_fc_cpu_features.py` (9).

Phase 2 (build-time auto-bake / probe microVM) below is **not yet built** — it
needs FC-host integration + a rootfs rebuild to validate, deliberately deferred.

## Problem

CRaC "warp" checkpoints are created in the **build container** (which sees the
full host CPU feature set) but restored inside a **Firecracker microVM** (which
exposes a *reduced* feature set — a CPU template and/or what the guest kernel
surfaces). If the checkpoint's recorded features are not a subset of the guest's,
the warp engine aborts the restore:

```
[crac] Restore failed due to incompatible or missing CPU features,
       try using -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint.
[crac] Failed to restore from /app/checkpoint
Error: Could not create the Java Virtual Machine.
```

The JVM dies → init panics → the warm pool never fills. The **only** symptom the
operator sees is the generic, opaque:

```
slot <id>: fifo not found within warmup timeout
```

### Real incident (2026-06-02)

A host microcode/kernel drift since the last good rootfs made a fresh checkpoint
capture features the FC guest lacks. The opaque timeout cost **hours** to diagnose
(ruling out "transient", ext4 format, and memory before capturing the guest serial
console, which finally showed the real CRaC error). Manual fix: pin
`-XX:CPUFeatures=0x102100055bbd7,0x1c8` (the value the warp error itself reports)
on the AOT-create **and** checkpoint commands, then rebuild. Committed in RedTusk
`8838962`.

**The error literally tells us the value to use** — so detection is parsing, not
guessing. That is what makes this automatable.

### Scope note

blastbox's own FC warm tier (`worker/fc_warm.py`) uses a **vsock READY/GO**
warm-start, **not CRaC** — it has no checkpoint and is immune. This mismatch is
specific to **CRaC-based** FC warm-start, which today is **RedTusk's** FC runtime
(`src/redtusk/worker_runtime.py` + `deploy/docker/Dockerfile.crac` +
`build-vsock-checkpoint.sh`). The primitive below lives in blastbox so RedTusk (and
any future blastbox CRaC tier) can share it.

## Goals

1. **Detect** — turn the opaque warmup-timeout into a clear, actionable signal that
   names the exact `-XX:CPUFeatures` value required.
2. **Prevent (auto-bake)** — derive the guest-compatible value automatically at
   build time, bake it into the checkpoint, delete the hardcoded magic constant, and
   self-heal across future host-CPU drift.

## Non-goals

- No change to the non-CRaC blastbox FC tier.
- No runtime auto-rebuild of the rootfs (a rebuild is ~10–15 min; runtime only
  **detects + reports**, it does not self-rebuild).
- Not portable across CPU families — the value is per build-host/guest pair (the
  probe re-derives it per target).

## Design

### Reusable primitive: `blastbox.host.runtime.cpu_features`

Small, dependency-light, mostly pure. Lives next to `host/runtime/firecracker.py`.

```python
# src/blastbox/host/runtime/cpu_features.py
import re
from dataclasses import dataclass

# The warp/CRaC restore error names the compatible value, e.g.
#   "... incompatible or missing CPU features, try using
#    -XX:CPUFeatures=0x102100055bbd7,0x1c8 on checkpoint."
_MISMATCH_RE = re.compile(
    r"incompatible or missing CPU features.*?-XX:CPUFeatures=([0-9a-fx,]+)",
    re.IGNORECASE | re.DOTALL,
)

@dataclass(frozen=True)
class CpuFeatureMismatch:
    needed: str        # value to pin on the checkpoint, e.g. "0x102100055bbd7,0x1c8"
    raw_line: str      # full matched line, for logs

def parse_cpu_mismatch(console_text: str) -> CpuFeatureMismatch | None:
    """Scan a guest serial console for the warp CRaC CPU-feature-mismatch
    signature. Returns the suggested -XX:CPUFeatures value, or None if the
    console shows no such mismatch (so callers fall back to the generic path)."""
    m = _MISMATCH_RE.search(console_text)
    if not m:
        return None
    return CpuFeatureMismatch(needed=m.group(1), raw_line=m.group(0).strip())
```

`parse_cpu_mismatch` is the single source of truth for the error format; the regex
is the one place to update if warp changes the wording. Trivially unit-testable.

### Part 1 — Runtime auto-detect (safety net) — **ship first**

**Value:** turns "hours of opaque debugging" into a one-line actionable error. Pure
upside on the error path — no behavior change on success.

**Integration (RedTusk), all already in place:**
- Guest console is **already captured** to `<slot_dir>/fc.log`
  (`worker_runtime.py:545` — firecracker `stdout`→fc.log, `stderr`=STDOUT).
- The warmup timeout is raised at `pool.py:229`
  (`WorkerError("slot <id>: fifo not found within warmup timeout")`), after
  `poll_fifo(... worker_warmup_timeout_s)`.

**Flow:**
1. On warmup timeout, before raising the generic `WorkerError`, read the slot's
   `fc.log` and call `parse_cpu_mismatch(text)`.
2. If a mismatch is found, raise a **specific** `FcCpuFeatureMismatch(needed=...)`
   instead of the generic timeout, and:
   - `log.error("fc.cpu_feature_mismatch", needed=..., remediation="rebuild the FC rootfs with -XX:CPUFeatures=<needed>")`
   - bump a `redtusk_fc_cpu_feature_mismatch_total` counter (so it's visible on the
     dashboard, not just buried in a warning).
3. Otherwise raise the existing generic error unchanged (no regression).

**Touch points:** new `cpu_features.py` in blastbox; ~10 lines in RedTusk `pool.py`
(or the `FirecrackerWorkerRuntime.poll_fifo` caller) to read fc.log + branch.

### Part 2 — Build-time auto-bake (prevention)

**Goal:** derive the guest-compatible `-XX:CPUFeatures` automatically and bake it in;
remove the hardcoded `0x102100055bbd7,0x1c8`.

**Why a probe is required:** the build host cannot observe the guest's feature set
(that *is* the bug). We must ask the actual guest. Boot a one-shot **probe microVM**
on the **target kernel** and read the compatible value off its serial console.

Two probe strategies (pick one during implementation):
- **(a) Deliberate-mismatch probe** — boot a checkpoint built with the build host's
  (over-broad) features; the restore fails and the warp error reports the guest's
  value; parse it with `parse_cpu_mismatch`. Reuses Part 1's parser; needs a
  throwaway "wrong" checkpoint.
- **(b) Generate probe** — run `java -XX:CPUFeatures=generate` (or the Azul warp
  equivalent) **inside** the guest; it emits the value directly. Cleaner if the flag
  exists. *Open: confirm the in-guest dump flag is supported by this Azul build.*

**API:**
```python
def probe_guest_cpu_features(
    *, fc_bin: str, kernel: str, probe_rootfs: str, console_timeout_s: float = 20.0,
) -> str:
    """Boot a one-shot probe microVM on the target kernel and return the guest's
    compatible -XX:CPUFeatures value. Raises ProbeError on boot/parse failure —
    never silently returns the host's features (that reproduces the bug)."""
```

**Build wiring (RedTusk):**
- `Dockerfile.crac` (AOT-create) and `build-vsock-checkpoint.sh` (checkpoint) already
  carry `-XX:CPUFeatures=...`; change the literal to a build-arg/env
  (`ARG FC_CPU_FEATURES` → `ENV REDTUSK_FC_CPU_FEATURES`).
- `setup_firecracker_host.sh` calls `probe_guest_cpu_features()` **once** before the
  build and passes `--build-arg FC_CPU_FEATURES=<probed>`.
- Result: every rebuild bakes the right value for the actual guest; the magic
  constant is gone; host CPU drift is handled with zero manual steps.

## Edge cases / failure modes

- **Probe can't boot** (no `/dev/kvm`, missing kernel): fail the build **loudly** —
  never fall back to the host's features (that silently reproduces the bug).
- **Console not captured / no signature on timeout**: runtime detector returns
  `None` → existing generic error → no regression.
- **warp error string drifts**: single regex, covered by a unit test on a captured
  sample.
- **Multiple FC environments / CPU templates**: the value is per target; the probe
  is re-run per build host. Document that copying a prebuilt rootfs across CPU
  families is unsupported.

## Testing

- **Unit** (pure, fast): `parse_cpu_mismatch` on captured console samples — a real
  mismatch line (returns the value) and a clean boot (returns `None`).
- **Integration** (gated `fc` marker, needs an FC host): `probe_guest_cpu_features`
  returns a plausible value; a full build using the probed value restores **3/3**
  standalone and the pool warms 8/8 (the exact checks used to validate `8838962`).
- **Regression**: `FcCpuFeatureMismatch` is raised on a captured mismatch console and
  the generic error otherwise.

## Rollout

- **Phase 1** ✅ **shipped** — `cpu_features.parse_cpu_mismatch` + the RedTusk
  runtime detector. Low-risk, high-value, independently shippable. (Would have
  reduced the 2026-06-02 incident to ~5 minutes.) Deploys with the next RedTusk
  api/dispatcher image rebuild — no FC rebuild required (error-path only).
- **Phase 2** — `probe_guest_cpu_features` + the `setup_firecracker_host.sh`
  build-arg wiring; delete the hardcoded value. Not yet built.

## Open questions

1. ~~Does RedTusk's FC capture the guest console?~~ **Yes** — `<slot.scratch_dir>/fc.log`
   (`worker_runtime.py`, firecracker `stdout`→fc.log, `stderr`=STDOUT). Resolved.
2. Probe strategy (a) deliberate-mismatch vs (b) in-guest `-XX:CPUFeatures=generate`
   — does this Azul warp build support an in-guest dump flag? *(Phase 2; leaning
   (a) — it reuses the Phase-1 parser and doesn't depend on an unconfirmed flag.)*
3. ~~Import blastbox vs vendor the parser?~~ **Vendored** in RedTusk
   (`redtusk/fc_cpu_features.py`), canonical + tests in blastbox. RedTusk pins
   `blastbox>=0.1.2,<0.2` from PyPI (non-editable install), so importing the new
   module would couple this error-path fix to a blastbox PyPI release. The
   ~20-line pure parser is vendored with a "keep in sync" note instead. Resolved.
4. Probe rootfs: a minimal JVM-only image (fast boot) vs reuse the worker rootfs
   (simpler, slower)? *(Phase 2.)*
