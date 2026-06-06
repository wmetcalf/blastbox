# Code-review brief — gVisor (runsc) C/R warm-snapshot tier

> **For the reviewing model:** You are reviewing a self-contained feature branch on **blastbox**,
> a framework that runs **untrusted / actively malicious office documents** through disposable,
> hardened sandboxed workers. This is security-sensitive code: a bug that weakens isolation or
> lets a slot be reused across jobs is a real vulnerability, not a style nit. Be adversarial.
>
> **Inputs you have:** this brief + the companion unified diff
> `docs/review/2026-06-05-gvisor-cr-code.diff` (2878 lines, `src/` + `tests/` + `deploy/`, base
> `origin/main` 3c1ef13 → head 9a1b079). Deeper design context, if you want it, is in
> `docs/specs/2026-06-05-gvisor-cr-snapshot-design.md` and `docs/plans/2026-06-05-gvisor-cr-snapshot.md`.
> Please return findings as: **severity (blocker / high / medium / low / nit) · file:line · claim ·
> suggested fix**, and explicitly flag anything you could only *suspect* without running it.

---

## 1. What this change does

Adds a **second** warm-snapshot backend to blastbox's worker pool: **gVisor `runsc` native
checkpoint/restore** (Sentry-level C/R, *not* CRIU), alongside the existing Firecracker microVM
tier. The warm tier's value: pay the slow sandbox+LibreOffice boot **once**, snapshot the idle
warm process, then `restore` a fresh disposable copy per job in ~tens of ms.

To add the second backend without forking the lifecycle, the existing FC `SnapshotManager` is
refactored behind a **`SnapshotBackend` seam**: one runtime-agnostic manager (build-once,
restore-per-slot) driving an **opaque artifact**, with `FcSnapshotBackend` and
`GvisorSnapshotBackend` implementing the seam.

**The hard part** (worth your closest attention) was that **LibreOffice hangs after a gVisor
restore**. That was root-caused and fixed with an `LD_PRELOAD` shim — see §4.

## 2. Threat model (so you weight findings correctly)

- The document is **hostile**. The worker process parsing it is assumed potentially compromised.
- **Isolation invariants** that MUST hold:
  - The worker runs **non-root, no capabilities, no-new-privs, read-only rootfs, network=none**.
  - A slot processes **exactly one** document, then is destroyed. No state may leak between jobs.
  - Host-side dirs shared with the container must not be reachable by **other unprivileged local
    users** (the `0o777` bind-mount leaves are the sharp edge — see §5).
- **Fail-closed**, not fail-open: if the warm tier can't be set up correctly, it must refuse to
  run, not silently fall back to something weaker.
- Conversely, **scanner/▸runtime hiccups must fail the *job*, not corrupt isolation** — and the
  warm path must fall back to a cold boot rather than wedging the pool.

## 3. Architecture — file-by-file (what to hold in your head)

| File | Responsibility | Review weight |
|---|---|---|
| `src/blastbox/host/runtime/snapshot_backend.py` | The `SnapshotBackend` / `BootHandle` / `RestoreHandle` `@runtime_checkable` Protocols. The opaque-artifact contract. | medium |
| `src/blastbox/host/runtime/fc_snapshot.py` | Refactored runtime-agnostic `SnapshotManager` (build/restore lifecycle, slot-id validation, leak cleanup). Was FC-specific; now backend-driven. | **high** (refactor — FC tier must stay byte-identical) |
| `src/blastbox/host/runtime/fc_snapshot_backend.py` | Extracted FC mechanics (create/restore API calls, RAM-preload mem-dir toggle, `FcSnapshotArtifact`). | medium |
| `src/blastbox/host/runtime/gvisor_snapshot.py` | **New** `GvisorSnapshotBackend`: drives `runsc run/checkpoint/restore`, emits the OCI spec, per-slot bind-mount dirs, liveness. | **high** (new + security-critical) |
| `src/blastbox/host/runtime/gvisor_snapshot_runtime.py` | **New** `GvisorSnapshotSlotRuntime` (spawn/ready/alive/reap) + `GvisorHostWarmControl` (path translation) + env-config selector. | **high** |
| `src/blastbox/host/pool_config.py` | `BLASTBOX_POOL_RUNTIME=gvisor` routing (+7 lines). | low |
| `deploy/gvisor/accept_retry.c` | The `LD_PRELOAD` accept-retry shim (see §4). | **high** (C, in the hot path, in the sandbox) |
| `deploy/gvisor/run_warm.py` | The in-container warm entrypoint (file-trigger `serve_warm`). | medium |
| `deploy/gvisor/{Dockerfile.shim,README.md}` | Build/deploy of the shim. | low |
| `tests/host/runtime/test_*` , `tests/integration/test_gvisor_snapshot_roundtrip.py` | Unit (mock subprocess/runsc) + gated end-to-end. | medium |

**Data/control flow per job:** `spawn()` → (first call only) `SnapshotManager.build()` boots the
warm base container, waits for its `ctrl/ready` marker, `runsc checkpoint`s it, kills the base →
then `restore()` restores the checkpoint into a fresh per-slot bundle. The host stages the input
into the slot's `in/` bind mount and writes `ctrl/go.json`; the restored worker (blocked in
`serve_warm`'s `wait_for_go`) picks it up, runs the engine, writes output to `out/` + `ctrl/done`.
Host reads `done` + the output directly from the bind mount. No vsock, no ext4 image.

## 4. The LibreOffice-restore hang — root cause + fix (review this hardest)

**Symptom:** a warm soffice worker, restored from a gVisor checkpoint, hangs forever on the first
conversion. (The JVM/Tika engine does *not* hang — no shim needed there.)

**Root cause:** gVisor's `restore` delivers **EINTR** to syscalls that were blocked at checkpoint
time, *regardless of `SA_RESTART` or the signal mask*. LibreOffice's `osl_acceptPipe`
(`sal/osl/unx/pipe.cxx`) issues a **single, non-retrying** `accept(fd, nullptr, nullptr)` — its
self-pipe wakeup loop is `#ifdef`'d FreeBSD-only — so on the restore-time EINTR it bails, the
queued UNO-pipe connection is lost, and the converter waits forever.

**Fix:** `deploy/gvisor/accept_retry.c`, an `LD_PRELOAD` shim that transparently retries
`accept`/`accept4` on `EINTR` (restoring the behavior `osl` omits). It is **inert** everywhere
else — the retry only ever fires on a restore-time EINTR — and is loaded **only** in the soffice
warm container.

**What to scrutinize here:**
- Is wrapping `accept`/`accept4` and looping on `EINTR` *correct and complete*? Any blocked syscall
  the shim should also cover for this engine (it deliberately covers only the two that osl mishandles)?
- The constructor resolves `dlsym(RTLD_NEXT, ...)` once; calls guard against NULL (`errno=ENOSYS`).
  Any TOCTOU / ordering hazard vs. a very early `accept` before the constructor runs? (Constructors
  run before `main`/library init that would call `accept`; argue it through.)
- Does retrying `EINTR` *mask* a legitimate shutdown signal the worker should honor? (Worker is
  single-purpose and reaped by the host via SIGKILL — argue whether that's safe.)

## 5. Security model — invariants to verify in the diff

- `gvisor_snapshot.py::_oci_config` — confirm the spec is **non-root (uid/gid 65532), all five
  capability sets empty, `noNewPrivileges: true`, `root.readonly: true`, no loopback** (network ns
  with `network=none`), `/tmp` tmpfs `mode=1777`, `/dev` tmpfs. Is there any field whose absence
  would default *open*?
- `_prepare_slot_dirs` — the worker runs non-root but the **gofer runs uid0 without
  CAP_DAC_OVERRIDE**, so the `out/`+`ctrl/` bind dirs are `0o777` and the slot `workdir` is clamped
  to `0o700`. **Verify the threat claim**: with `workdir` `0o700`, are the `0o777` leaves actually
  unreachable by other unprivileged local users? Does the deploy parent assumption
  (`/var/lib/blastbox/...` root-owned `0o700`) hold up, and is the in-code `0o700` clamp a correct
  belt-and-suspenders or a false sense of security?
- `SnapshotManager.restore` — `slot_id` is stringified and rejected if it contains `/`, NUL, or is
  `.`/`..` before becoming a path component under `slots/`. **Try to defeat this** (the only caller
  passes a uuid4, but the signature is `object`). Is rejecting those four cases sufficient to keep
  the slot inside `slots/`?
- `GvisorHostWarmControl.signal_go` — rewrites host paths to the fixed in-sandbox mount points
  (`/in/<basename>`, `/out`) before writing `go.json`. **Confirm** the worker can't be steered to
  read/write outside its binds via a crafted `input_path` (note `Path(spec.input_path).name`).
- Reuse/leak: after `reap`, is the slot workdir fully removed? Can any artifact survive into the
  next restore of the same checkpoint?

## 6. Review focus areas (most-likely-to-harbor-bugs, ranked)

1. **The FC refactor** (`fc_snapshot.py` + `fc_snapshot_backend.py` + `fc_snapshot_launcher.py`):
   the FC tier is *shipped and load-bearing*. The refactor must be behavior-preserving. Diff the
   old vs new control flow for the RAM-preload (mem-dir) path and the artifact round-trip. The FC
   unit suite must stay green (it does, locally) — but verify the *logic*, not just that tests pass.
2. **`is_ready()` liveness** (`gvisor_snapshot_runtime.py`): `control_dir` exists on the host
   *before* `runsc restore`, so existence alone is insufficient — it now also gates on
   `handle.alive()`. Confirm a dead/exited restore can't be promoted to IDLE. (Bug was caught in
   review; verify the fix is actually sufficient and the settle-window interaction is right.)
3. **Failure/leak paths**: `restore`/`boot_base` now `rmtree` the just-created host dir on failure
   (no handle is returned to reap it). Check for any *other* early-return/raise that leaks a dir or
   a `runsc` container (e.g. checkpoint fails after base boot; restore fails mid-way).
4. **Bounded subprocess**: `_default_run_text` (used by `alive()` from the pool's hot path) has a
   10s timeout. Are there other unbounded `runsc` invocations that could wedge pool claim/promote?
5. **Env-config robustness** (`_gvisor_config_from_env`): malformed `BLASTBOX_GVISOR_WARM_ARGV`
   JSON now warns + falls back. Any other env field whose bad value crashes host startup?
6. **The shim** (§4).

## 7. One review comment I (the author) *declined* — please second-guess me

A reviewer asked that `GvisorSnapshotBackend.available()` verify the binary *supports* C/R, not
just that `runsc` exists on PATH. **I declined**, reasoning: runsc's `checkpoint`/`restore` are
**unconditional built-in subcommands** (not compile-gated like some KVM features), so a present
binary always carries them; a *genuine capability* probe (vs. subcommand presence) would require
performing an actual checkpoint cycle, too expensive for a selection-time `available()`; and
fail-closed is still honored (`require_available=True` raises `GvisorUnavailable` when absent, and
the integration gate runs `runsc help`). **If you think this is wrong** — e.g. a runsc build/config
where C/R is present-but-disabled and `available()` would wrongly select it — say so concretely.

## 8. Validation already performed (don't re-flag these as untested)

- `ruff check src tests` clean; `mypy src` clean (59 files).
- Full unit/cli/http suite green; `accept_retry.c` compiles clean under `-Wall -Wextra -Werror`.
- **Gated end-to-end integration test passes on a real `runsc` host**: build snapshot → checkpoint
  → restore → stage input → file-trigger `go` → `done=ok` → output present → reap, with the worker
  running as **non-root uid 65532**. (Uses a `ProbeEngine` = hash→text, so it proves the C/R +
  control-plane + bind-mount + security plumbing without needing soffice in the test image.)
- The soffice-with-shim pixel-parity vs. cold conversion was validated separately during the spike
  (see the design doc); the *automated* gate uses ProbeEngine.

## 9. How to run it

```sh
# unit (no runsc needed)
.venv/bin/pytest tests/host tests/host/runtime -q
.venv/bin/ruff check src tests && .venv/bin/mypy src
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -o /dev/null deploy/gvisor/accept_retry.c -ldl

# gated end-to-end (needs a runsc host with C/R + root; build a warm rootfs first — see deploy/gvisor/README.md)
sudo env BLASTBOX_GVISOR_ROOTFS=<exported-rootfs> BLASTBOX_GVISOR_RUNSC=runsc \
  BLASTBOX_GVISOR_WARM_ARGV='["python3","/opt/blastbox/run_warm.py"]' BLASTBOX_GVISOR_ENGINE=probe \
  .venv/bin/pytest tests/integration/test_gvisor_snapshot_roundtrip.py -v -o addopts=''
```
