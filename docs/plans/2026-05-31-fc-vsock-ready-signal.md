# FC warm-readiness over vsock — implementation plan

> Surfaced by the toolz2 live run (2026-05-31): `test_live_is_ready_after_warmup`
> FAILS because `FileReadySignal` checks the host `output_dir`, which a *live* FC
> microVM can never populate (host can't read the in-guest disk without mounting;
> reap then deletes it). Consequence: a WARMING FC slot never becomes IDLE, so the
> FC + warm-pool combination is non-functional for readiness. Only unit tests pass
> because they inject a `ReadySignal` double.

**Goal:** A real, live readiness signal for the FC tier — host detects the guest
worker's READY over AF_VSOCK — and a blastbox-worker rootfs that emits it, so
`test_live_is_ready_after_warmup` passes on toolz2 for the right reason.

**Architecture:** Firecracker's AF_VSOCK Unix-socket backend: when the guest opens
an AF_VSOCK connection to CID 2 (host) on port P, firecracker connects to a host
Unix socket at `<uds_path>_<P>`. So the host pre-binds `<slot>/vsock.sock_<READY_PORT>`
before launch; the guest connects to (CID 2, READY_PORT) after `warmup()` and sends
a READY frame. Output stays on the ext4 disk (read post-exit via rdump) — vsock
carries only small control frames (the hard-won "no large vsock transfers" lesson).

**Tech stack:** Python stdlib `socket` (AF_UNIX host side, AF_VSOCK guest side),
threads; the existing `ReadySignal` seam; Docker→ext4 rootfs build on toolz2.

---

## Phase 1 — Host `VsockReadySignal` (firecracker.py + unit tests)

- `VsockReadySignal` implements `ReadySignal` plus lifecycle `prepare(slot)` /
  `cleanup(slot)`:
  - `prepare(slot)`: bind a non-blocking AF_UNIX listener at
    `slot.output_dir.parent / f"vsock.sock_{READY_PORT}"`, start a daemon accept
    thread. On a connection, read ≤64 bytes; if it contains `READY`, set a per-slot
    `threading.Event`. Idempotent; one state dict keyed by `slot_id` under a lock.
  - `is_ready(slot)`: non-blocking — return the slot's event `.is_set()`.
  - `cleanup(slot)`: stop the thread, close the socket, unlink the UDS.
- Wire `FirecrackerSlotRuntime`:
  - Default `ready_signal` becomes `VsockReadySignal()` (was `FileReadySignal()`).
  - `spawn()`: build the `Slot` *before* launching FC, call
    `ready_signal.prepare(slot)` if it exposes `prepare`, then launch — so the
    listener exists when FC forwards the guest's connect.
  - `reap()`: call `ready_signal.cleanup(slot)` if present, before rmtree.
- `FileReadySignal` retained (explicit opt-in / existing post-exit-marker tests).
- Unit tests (no VM): a test client connects to `<uds>_<READY_PORT>` and sends
  `READY` — exactly what firecracker does on the guest's behalf — asserting
  `is_ready` flips False→True; plus: not-ready before connect, wrong token stays
  False, byte cap, cleanup closes/unlinks, double-prepare idempotent, reap calls
  cleanup. Existing tests that relied on the `FileReadySignal` default inject it
  explicitly.

## Phase 2 — Guest agent + warm control (worker/ + unit tests)

- `worker/fc_guest.py`: `signal_ready_vsock(cid=2, port=READY_PORT, retries, backoff)`
  — open AF_VSOCK, connect, send `READY\n`, retry until connected or deadline
  (covers the host-binds-slightly-late race). Pure framing is unit-tested over a
  loopback AF_UNIX stand-in (AF_VSOCK needs a VM); the AF_VSOCK call path is thin.
- `run_fc_guest(engine)`: mount nothing (init does it) — call `engine.warmup()`,
  then `signal_ready_vsock()`. (Job round-trip GO/DONE is a documented follow-on;
  this slice targets the readiness signal the failing test asserts.)
- A minimal `ProbeEngine` (detect=always, warmup=noop, detonate=write one page
  artifact) lives in the rootfs build inputs, not the library.

## Phase 3 — blastbox-worker rootfs (deploy/firecracker/, built on toolz2)

- `deploy/firecracker/Dockerfile.worker`: debian/python-slim + `pip install` the
  blastbox core wheel (pydantic only) + the probe engine + the guest agent.
- `deploy/firecracker/init`: PID 1 — mount /proc /sys /dev, `mount /dev/vdb /mnt/outdisk`,
  exec the guest agent; on exit, `reboot`/`poweroff` (panic=1 reboots).
- `deploy/firecracker/build-rootfs.sh`: `docker build` → `docker export` →
  `mkfs.ext4` + populate via `debugfs` (no mount/root needed — mirror the
  host-side rdump discipline) → `rootfs.ext4`.

## Phase 4 — Live validation (toolz2)

- `BLASTBOX_FC_ROOTFS=<new rootfs>` + the FC env, run
  `test_live_is_ready_after_warmup` → PASS (guest signals READY <30s).
- Re-run the full `TestFirecrackerLiveBoot` class + the standalone
  `scripts/fc_live_check.py` (extend it to assert `is_ready` True).

## Out of scope (documented follow-on)

- Full job round-trip over vsock (GO carries input, DONE, output on disk) wired
  into the dispatcher's warm path (`VsockWarmControl` host+guest). This slice
  establishes the vsock control channel; the job plane reuses it.
