# Warm-UNO via Firecracker snapshot/restore — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve ClippyShot's LibreOffice conversions from a warm `unoserver` captured in a Firecracker memory snapshot and restored per job, hiding the ~750 ms soffice boot.

**Architecture:** A first-boot, host-local FC memory snapshot captures a running-but-idle in-guest `unoserver`. The warm pool's spawn op becomes restore-from-snapshot (unique vsock UDS + fresh output disk per restore); the guest agent runs `unoconvert` against the in-guest UNO socket; results return over the existing output-disk channel; the VM is destroyed after one job. Bare-metal bwrap/nsjail stays cold.

**Tech Stack:** Python 3.12, Firecracker v1.12.1 (HTTP API over a Unix socket for snapshot/restore), `unoserver` v3.6 + python-uno, AF_VSOCK, virtio-blk + debugfs rdump, pytest. Validation host: toolz2 (172.18.101.15), `/opt/kata/bin/firecracker`.

**Spec:** `docs/specs/2026-06-03-warm-uno-fc-snapshot-design.md`

---

## Ground rules

- **Gated + opt-in throughout.** A new env `BLASTBOX_FC_SNAPSHOT=1` selects the snapshot spawn path; default off keeps the proven cold-boot FC tier byte-for-byte unchanged. Every task must keep cold-boot green.
- **Two repos.** blastbox = `/home/coz/Downloads/blastbox/` (branch `feat/warm-uno-snapshot`). ClippyShot = `/home/coz/Downloads/ClippyShot/`.
- **FC-host work runs on toolz2** (pre-authorized). Host-dependent steps are validated there, not in unit CI. Unit tests use an **injected fake FC API client** (subprocess/HTTP boundary) so the Python logic is testable off-host — follow the existing `firecracker.py` pattern of an injectable runner.
- **Corpus is the regression gate** (the standing FC rule): 342-doc on toolz2, warm output hashes vs cold baseline, before declaring done.

## File structure

| file | responsibility | create/modify |
|---|---|---|
| `src/blastbox/host/runtime/fc_snapshot.py` | snapshot/restore primitives + `SnapshotManager`; pure logic over an injectable FC-API client | **create** |
| `src/blastbox/host/runtime/fc_api.py` | thin Firecracker HTTP-over-UDS client (`put`, `get`) + the snapshot/vm action payloads | **create** |
| `src/blastbox/host/runtime/firecracker.py` | wire snapshot path into `FirecrackerSlotRuntime` (spawn=restore when enabled); keep cold path default | modify |
| `src/blastbox/host/pool_config.py` | `BLASTBOX_FC_SNAPSHOT` → build a snapshot-backed pool runtime | modify |
| `deploy/firecracker/init` | warm `unoserver` + READY when the UNO socket listens (snapshot-build boot) | modify |
| `deploy/firecracker/run_guest.py` | guest agent: on a job, run `unoconvert` against the in-guest UNO socket; cold `--convert-to` fallback | modify |
| `deploy/firecracker/Dockerfile.clippyshot` | bundle `unoserver` v3.6 + python-uno | modify |
| `tests/host/runtime/test_fc_snapshot.py` | unit tests for snapshot/restore logic + SnapshotManager (fake API client) | **create** |
| `scripts/fc_snapshot_spike.py` | Phase 0 throwaway de-risk driver (toolz2) | **create** |
| `scripts/fc_warm_uno_check.py` | end-to-end warm-UNO restore→convert→destroy driver (toolz2) | **create** |
| ClippyShot `src/clippyshot/engine.py` | `detonate()` guest-side `unoconvert` path when running under snapshot runtime | modify |

---

## Phase 0 — De-risk: FC vsock across snapshot/restore (DO THIS FIRST)

**Why first:** if a vsock device snapshotted while idle can't accept a fresh host connection after restore, the whole architecture changes. Prove it with a throwaway before building anything. This runs on toolz2 against a *probe* rootfs (no unoserver yet) — we only need to prove the snapshot/restore + vsock mechanics.

### Task 0.1: Spike script — snapshot an idle warm VM, restore it, reconnect vsock

**Files:**
- Create: `scripts/fc_snapshot_spike.py`

- [ ] **Step 1: Write the spike driver.** It must, against `/opt/kata/bin/firecracker` on toolz2 using the **API socket** (not `--no-api`):
  1. Launch `firecracker --api-sock /tmp/fc-spike.sock` (no `--config-file`).
  2. `PUT /boot-source`, `PUT /drives` (rootfs), `PUT /vsock` (guest_cid=3, uds_path=/tmp/fc-spike.vsock), `PUT /machine-config` (vcpu=1).
  3. `PUT /actions {action_type:"InstanceStart"}`.
  4. Wait for the guest's existing READY over vsock (the probe rootfs already signals READY — reuse `VsockReadySignal`).
  5. `PATCH /vm {state:"Paused"}` → `PUT /snapshot/create {snapshot_type:"Full", snapshot_path, mem_file_path}` → kill the FC process.
  6. **Restore:** new `firecracker --api-sock /tmp/fc-restore.sock`; `PUT /snapshot/load {snapshot_path, mem_file_path, enable_diff_snapshots:false, resume_vm:false}` with a **NEW** `vsock` UDS remap if the API allows, then `PATCH /vm {state:"Resumed"}`.
  7. From the host, open a fresh AF_VSOCK→UDS connection to the restored guest and confirm a round-trip (the probe guest echoes).

```python
# scripts/fc_snapshot_spike.py  — stdlib only; HTTP-over-UDS via http.client
import http.client, json, socket, subprocess, sys, time, os
# (full driver: see steps; keep it self-contained + delete its workdir in a finally)
```

- [ ] **Step 2: Run it on toolz2.**

Run: `scp scripts/fc_snapshot_spike.py coz@172.18.101.15:/home/coz/redtusk-bench/ && ssh coz@172.18.101.15 'cd /home/coz/redtusk-bench && python3 fc_snapshot_spike.py /home/coz/redtusk-bench/detonator-rootfs.ext4 /home/coz/redtusk-bench/fc/vmlinux'`
Expected: prints `SNAPSHOT created`, `RESTORE resumed`, `VSOCK round-trip OK`.

- [ ] **Step 3: Record the outcome in the spec.** If vsock round-trips after restore → proceed. If the host UDS must be re-declared at load time (it does — `PUT /snapshot/load` takes a `vsock` remap in FC ≥1.5), capture the exact field names used; they feed Task 1.3. If vsock can't restore at all, STOP and escalate — the design needs revisiting (e.g. defer vsock connect until post-resume via a fresh device).

- [ ] **Step 4: Commit the spike + findings.**

```bash
git add scripts/fc_snapshot_spike.py docs/specs/2026-06-03-warm-uno-fc-snapshot-design.md
git commit -m "spike(fc): prove vsock survives snapshot/restore on toolz2"
```

**Gate:** do not start Phase 1 until Task 0.1 Step 3 confirms the vsock-restore mechanic + the exact `PUT /snapshot/load` remap fields.

---

## Phase 1 — FC snapshot primitives (off-host testable)

### Task 1.1: `fc_api.py` — Firecracker HTTP-over-UDS client

**Files:**
- Create: `src/blastbox/host/runtime/fc_api.py`
- Test: `tests/host/runtime/test_fc_api.py`

- [ ] **Step 1: Failing test** — a `FcApiClient(sock_path).put(path, body)` issues an HTTP PUT over the UDS and returns status; use a temp `socketserver` UnixStreamServer fake that records requests.

```python
def test_put_serializes_json_over_uds(tmp_path):
    sock = tmp_path / "fc.sock"
    rec = start_fake_uds_http(sock)            # helper in the test
    client = FcApiClient(str(sock))
    client.put("/vm", {"state": "Paused"})
    assert rec.last == ("PUT", "/vm", {"state": "Paused"})
```

- [ ] **Step 2:** Run → FAIL (`FcApiClient` undefined).
- [ ] **Step 3:** Implement `FcApiClient` with `http.client.HTTPConnection` over a `socket.AF_UNIX` (subclass that overrides `connect()` to dial the UDS). Methods `put(path, body)->status`, `patch(...)`, `get(path)->(status, json)`. Raise `FcApiError(status, body)` on >=400.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(fc): HTTP-over-UDS client for the Firecracker API`.

### Task 1.2: `fc_snapshot.py` — `create_snapshot()` orchestration

**Files:**
- Create: `src/blastbox/host/runtime/fc_snapshot.py`
- Test: `tests/host/runtime/test_fc_snapshot.py`

- [ ] **Step 1: Failing test** — `create_snapshot(api, snapshot_path, mem_path)` issues, in order: `PATCH /vm {state:Paused}` then `PUT /snapshot/create {snapshot_type:"Full", snapshot_path, mem_file_path}`. Use a fake `api` recording calls.

```python
def test_create_snapshot_pauses_then_snapshots():
    api = FakeApi()
    create_snapshot(api, "/s/state", "/s/mem")
    assert api.calls == [
        ("PATCH", "/vm", {"state": "Paused"}),
        ("PUT", "/snapshot/create",
         {"snapshot_type": "Full", "snapshot_path": "/s/state", "mem_file_path": "/s/mem"}),
    ]
```

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `create_snapshot`. Order matters (must Pause before Create). On any `FcApiError`, raise `SnapshotError` with context.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(fc): create_snapshot (pause→snapshot) orchestration`.

### Task 1.3: `restore_from_snapshot()` with per-restore vsock + outdisk remap

**Files:**
- Modify: `src/blastbox/host/runtime/fc_snapshot.py`
- Test: `tests/host/runtime/test_fc_snapshot.py`

- [ ] **Step 1: Failing test** — `restore_from_snapshot(api, snapshot_path, mem_path, *, vsock_uds, resume=True)` issues `PUT /snapshot/load` with the snapshot/mem paths **and the per-restore `vsock.uds_path` remap field confirmed in Task 0.1**, then `PATCH /vm {state:Resumed}`.

```python
def test_restore_loads_with_unique_vsock_then_resumes():
    api = FakeApi()
    restore_from_snapshot(api, "/s/state", "/s/mem", vsock_uds="/run/slot7.vsock")
    load = api.calls[0]
    assert load[0:2] == ("PUT", "/snapshot/load")
    assert load[2]["snapshot_path"] == "/s/state"
    assert load[2]["mem_backend"]["backend_path"] == "/s/mem"
    assert load[2]["vsock"]["uds_path"] == "/run/slot7.vsock"   # per-restore uniqueness
    assert api.calls[1] == ("PATCH", "/vm", {"state": "Resumed"})
```

> NOTE: the exact `mem_backend`/`vsock` field shape comes from Task 0.1's findings against FC 1.12.1 — adjust the literal to match what the spike proved before implementing.

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `restore_from_snapshot`. The output disk is **excluded from the snapshot and attached fresh per restore** (decided here per the spec's open question — confirm in 0.1 that `PUT /snapshot/load` permits a fresh drive remap; if not, fall back to snapshotting with a placeholder drive and `PATCH /drives` the fresh outdisk before Resume).
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(fc): restore_from_snapshot with per-restore vsock + outdisk`.

### Task 1.4: `SnapshotManager` — build once, serve restores

**Files:**
- Modify: `src/blastbox/host/runtime/fc_snapshot.py`
- Test: `tests/host/runtime/test_fc_snapshot.py`

- [ ] **Step 1: Failing test** — `SnapshotManager(cfg, launcher).build()` boots a base VM via the injected `launcher`, waits READY (injected ready signal), calls `create_snapshot`, kills the base VM, and records `{snapshot_path, mem_path}`. A second `build()` is idempotent (no rebuild). `restore(slot_id)` returns a launched FC handle with a unique vsock UDS derived from `slot_id`.

```python
def test_build_is_idempotent_and_records_artifact(tmp_path):
    mgr = SnapshotManager(cfg(tmp_path), launcher=FakeLauncher(ready=True))
    a = mgr.build(); b = mgr.build()
    assert a == b and mgr.artifact.snapshot_path.exists_called  # built once
def test_restore_derives_unique_vsock_per_slot(tmp_path):
    mgr = SnapshotManager(cfg(tmp_path), launcher=FakeLauncher(ready=True)); mgr.build()
    h7 = mgr.restore("slot-7"); h8 = mgr.restore("slot-8")
    assert h7.vsock_uds != h8.vsock_uds
```

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `SnapshotManager`: `build()` (guarded by a built-flag), `restore(slot_id)` (fresh FC proc + API client + `restore_from_snapshot` + fresh outdisk path under the slot scratch). Build failure → raise `SnapshotBuildError` (callers fall back to cold-boot). Restore failure → raise `SnapshotRestoreError` (caller reaps slot + cold-boots that job).
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(fc): SnapshotManager — first-boot build + per-slot restore`.

---

## Phase 2 — Wire snapshot into the runtime + pool (gated)

### Task 2.1: `FirecrackerSlotRuntime` snapshot spawn path

**Files:**
- Modify: `src/blastbox/host/runtime/firecracker.py`
- Test: `tests/host/runtime/test_firecracker.py`

- [ ] **Step 1: Failing test** — with `cfg.use_snapshot=True`, `FirecrackerSlotRuntime.spawn(slot)` calls `SnapshotManager.restore(slot.id)` (injected) instead of the cold `--no-api --config-file` launch; with `use_snapshot=False` (default) the cold path is unchanged (assert the cold argv `_fc_base_argv`-equivalent still used).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Add a `use_snapshot` flag + an injected `SnapshotManager` to `FirecrackerSlotRuntime`; branch `spawn`. Cold path untouched. On `build()` failure at startup → log + auto-disable snapshot (fall back to cold).
- [ ] **Step 4:** Run → PASS (both branches).
- [ ] **Step 5:** Commit: `feat(fc): snapshot-backed spawn path in FirecrackerSlotRuntime (gated)`.

### Task 2.2: `pool_config` — `BLASTBOX_FC_SNAPSHOT` env

**Files:**
- Modify: `src/blastbox/host/pool_config.py`
- Test: `tests/host/test_pool_config.py`

- [ ] **Step 1: Failing test** — `PoolConfig.from_env()` with `BLASTBOX_FC_SNAPSHOT=1` builds a runtime with `use_snapshot=True`; unset → `use_snapshot=False` (cold, unchanged).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Read the env (default off), thread `use_snapshot` into the FC runtime factory.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit: `feat(fc): BLASTBOX_FC_SNAPSHOT opt-in env`.

---

## Phase 3 — Warm-UNO in the rootfs

### Task 3.1: init warms `unoserver` + READY on UNO-socket-listening

**Files:**
- Modify: `deploy/firecracker/init`
- Test: `tests/deploy/test_fc_init.py` (parse/lint the init logic where feasible; full behavior validated on toolz2 in Phase 5)

- [ ] **Step 1:** In init (snapshot-build boot path, selected by a kernel arg / guest.env flag `BLASTBOX_WARM_UNO=1`): start `unoserver --daemon --interface 127.0.0.1 --port 2003` (loopback, in-guest only — never a host-reachable bind), then poll until the UNO port is listening, THEN signal READY (reuse the existing READY signal). Keep PATH exported (the known PID-1 setpriv/execvp PATH gotcha).
- [ ] **Step 2:** Lint: `bash -n deploy/firecracker/init`. Expected: clean.
- [ ] **Step 3:** Commit: `feat(fc-rootfs): warm unoserver + READY when UNO socket listens`.

### Task 3.2: guest agent runs `unoconvert`; cold fallback

**Files:**
- Modify: `deploy/firecracker/run_guest.py`

- [ ] **Step 1:** On a job, the agent converts via `unoconvert --convert-to pdf --filter calc_pdf_Export --filter-options SinglePageSheets=true <in> <out>` (writer/calc filters mirrored from `uno_spike.sh`), choosing the filter by detected family. On non-zero exit / UNO error → fall back to `soffice --headless --convert-to ...` for that doc (so a UNO hiccup never fails the job). Output PDF → the existing output-disk path; the rest of the ClippyShot pipeline (PDFium raster, scanners) is unchanged.
- [ ] **Step 2:** `python3 -m py_compile deploy/firecracker/run_guest.py`. Expected: clean.
- [ ] **Step 3:** Commit: `feat(fc-rootfs): guest agent converts via unoconvert + cold fallback`.

### Task 3.3: bundle `unoserver` in the rootfs image

**Files:**
- Modify: `deploy/firecracker/Dockerfile.clippyshot`

- [ ] **Step 1:** `pip install` `unoserver==3.6.*` into the clippyshot venv (it needs the LO python-uno bridge already present in `clippyshot:dev`/LO 25.8). Pin the version. Verify the binary lands at a known path used by Task 3.1/3.2.
- [ ] **Step 2:** Build the rootfs on toolz2 (existing `build-rootfs.sh DOCKERFILE=Dockerfile.clippyshot`); confirm `unoserver`/`unoconvert` exist in the image.
- [ ] **Step 3:** Commit: `feat(fc-rootfs): bundle unoserver v3.6`.

---

## Phase 4 — ClippyShot engine wiring

### Task 4.1: `detonate()` uses guest-side unoconvert under the snapshot runtime

**Files:**
- Modify: ClippyShot `src/clippyshot/engine.py`
- Test: ClippyShot `tests/unit/test_engine_warm.py`

- [ ] **Step 1: Failing test** — when the engine runs in the guest with the warm UNO socket available (env/flag), the converter uses the unoconvert path; otherwise it uses cold `--convert-to`. Assert the selection logic (mock the runner) — no real soffice in unit tests.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Add the selection in the ClippyShot LibreOffice runner / converter so the soffice→PDF step is unoconvert-when-warm, cold otherwise. The mapping to blastbox contract types (Phase output) is unchanged.
- [ ] **Step 4:** Run → PASS; ClippyShot's existing unit suite stays green (`.venv/bin/pytest tests/unit -q`).
- [ ] **Step 5:** Commit (ClippyShot repo): `feat(engine): warm unoconvert conversion path`.

---

## Phase 5 — Validation gates (toolz2; blocking)

### Task 5.1: Output-parity gate — impress/draw on LO 25.8

**Files:**
- Modify: `scripts/fc_warm_uno_check.py` (extend `uno_spike.sh` coverage)

- [ ] **Step 1:** On the `clippyshot:audit` (LO 25.8) image, convert pptx/odp/odg via warm `unoconvert` vs cold `--convert-to`; render both to PNG @ same DPI; compare pixel (MSE/diff_px) + PDF bytes (minus CreationDate/ID). The spike proved writer/calc; this proves impress/draw.
- [ ] **Step 2:** Run on toolz2. Expected: `diff_px=0` (or document any rasterized-away deltas). **If impress/draw diverge → STOP and decide:** restrict warm-UNO to writer/calc families (cold fallback for impress/draw) or fix the filter — update the spec accordingly.
- [ ] **Step 3:** Commit findings.

### Task 5.2: Snapshot/restore correctness

- [ ] **Step 1:** On toolz2: build the warm snapshot, restore 4 VMs, confirm each has a live UNO server + unique vsock + fresh outdisk + no cross-restore state bleed (convert a different doc in each; outputs independent).
- [ ] **Step 2:** Driver: `scripts/fc_warm_uno_check.py`. Expected: 4/4 independent conversions, all trust-validated.

### Task 5.3: 342-doc corpus regression (the standing FC gate)

- [ ] **Step 1:** Run the 342-doc corpus on toolz2 through the warm-UNO snapshot path (`BLASTBOX_FC_SNAPSHOT=1`), comparing output hashes vs the cold baseline.
- [ ] **Step 2:** Expected: no regression vs the cold 342/342; latency shows the soffice-stage win (boot hidden). Record wall-time + per-ext.
- [ ] **Step 3:** Only after this passes: flip docs/spec status to "validated", and decide on enabling `BLASTBOX_FC_SNAPSHOT` by default.

---

## Self-review notes (coverage vs spec)

- Spec "API-socket restore path" → Task 1.1. "create_snapshot/restore_from_snapshot" → 1.2/1.3. "SnapshotManager first-boot" → 1.4. "per-restore unique vsock + fresh outdisk" → 1.3/1.4. "pool spawn = restore, gated" → 2.1/2.2. "rootfs warms unoserver + READY" → 3.1. "guest unoconvert + cold fallback" → 3.2. "bundle unoserver" → 3.3. "ClippyShot detonate unoconvert" → 4.1. "parity gate impress/draw" → 5.1. "snapshot correctness" → 5.2. "342 corpus" → 5.3. "highest-risk vsock-across-restore first" → Phase 0 gate.
- Non-goals (bare-metal warm, build-time snapshot, CRaC migration) → not planned, by design.
- Open risk (output-disk remap) → resolved explicitly in Task 1.3 Step 3 with a named fallback.
