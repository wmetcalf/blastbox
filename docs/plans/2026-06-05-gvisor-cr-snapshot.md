# gVisor (runsc) C/R Warm-Snapshot Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a second warm-snapshot backend — gVisor (`runsc`) checkpoint/restore — behind a generic `SnapshotManager`/`SnapshotBackend` seam, so the docker/runsc deployment tier gets a warm path on any cloud VM (no nested virt), for both the JVM/Tika and (with an accept-retry shim) the soffice engines.

**Architecture:** Refactor the existing Firecracker `SnapshotManager` to talk to a runtime-agnostic `SnapshotBackend` seam with an **opaque artifact** (extracting the FC mechanics into `FcSnapshotBackend`, keeping all FC tests green). Add `GvisorSnapshotBackend` (a `runsc run/checkpoint/create/restore` subprocess driver with per-slot bind mounts) and `GvisorSnapshotSlotRuntime` (file-trigger control via the existing `HostWarmControl`/`FileWarmControl`; output read directly from a bind mount — no vsock, no ext4). Wire it into `pool_config` behind `BLASTBOX_POOL_RUNTIME=gvisor`. Ship the ~10-line accept-retry `LD_PRELOAD` shim in the soffice warm image.

**Tech Stack:** Python 3.12, `subprocess` (runsc), `typing.Protocol`, pytest (unit tests mock subprocess; integration is gated behind a `runsc` host like the FC tier). The fix + every mechanic here is already proven end-to-end on toolz2 (spec: `docs/specs/2026-06-05-gvisor-cr-snapshot-design.md`).

**Ground rules:** TDD, frequent commits, `ruff` + `mypy` clean. The branch is `feat/gvisor-cr-snapshot` (spec already committed). After each task: `.venv/bin/pytest tests/host tests/worker -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`. **The FC snapshot tests (`tests/host/runtime/test_fc_snapshot*.py`) MUST stay green through the refactor — they are the regression guard for the shipped FC tier.**

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `src/blastbox/host/runtime/snapshot_backend.py` | The runtime-agnostic seam: `SnapshotBackend` / `BootHandle` / `RestoreHandle` Protocols + the opaque-artifact contract | **Create** |
| `src/blastbox/host/runtime/fc_snapshot.py` | Generic `SnapshotManager` (talks only to the seam); FC-specific mechanics move out | **Refactor** |
| `src/blastbox/host/runtime/fc_snapshot_backend.py` | `FcSnapshotBackend` — the FC implementation of the seam (artifact = `{snapshot, mem}`, the RAM-preload toggle, Pause+Create / load+resume) | **Create** (extracted) |
| `src/blastbox/host/runtime/fc_snapshot_launcher.py` | FC process spawner; `_Handle` gains a `checkpoint()` method | **Modify** |
| `src/blastbox/host/runtime/fc_snapshot_runtime.py` | FC `SnapshotSlotRuntime` — adjusted to the refactored manager | **Modify** |
| `src/blastbox/host/runtime/gvisor_snapshot.py` | `GvisorSnapshotBackend` + `GvisorBootHandle`/`GvisorRestoreHandle` — the `runsc` subprocess driver | **Create** |
| `src/blastbox/host/runtime/gvisor_snapshot_runtime.py` | `GvisorSnapshotSlotRuntime` + `select_gvisor_snapshot_runtime()` | **Create** |
| `src/blastbox/host/pool_config.py` | `RUNTIME_GVISOR` + the backend switch | **Modify** |
| `deploy/docker/accept_retry.c` | The accept-retry `LD_PRELOAD` shim (soffice-only) | **Create** |
| `deploy/docker/Dockerfile.clippyshot-warm` (or the existing warm image build) | Build the shim + set `LD_PRELOAD` in the warm soffice entrypoint | **Modify/Create** |
| `tests/host/runtime/test_snapshot_backend.py` | Seam contract tests | **Create** |
| `tests/host/runtime/test_gvisor_snapshot.py` | `GvisorSnapshotBackend` unit tests (mock subprocess) | **Create** |
| `tests/host/runtime/test_gvisor_snapshot_runtime.py` | `GvisorSnapshotSlotRuntime` unit tests (fake backend) | **Create** |
| `tests/integration/test_gvisor_snapshot_roundtrip.py` | Gated integration (needs a `runsc` host) | **Create** |

---

## Task 1: The `SnapshotBackend` seam

**Files:**
- Create: `src/blastbox/host/runtime/snapshot_backend.py`
- Test: `tests/host/runtime/test_snapshot_backend.py`

The seam the generic manager talks to. Artifacts are **opaque** to the manager — each backend defines its own and the manager only round-trips it back to `restore_in`.

- [ ] **Step 1: Write the failing test** (`tests/host/runtime/test_snapshot_backend.py`)

```python
from pathlib import Path
from blastbox.host.runtime.snapshot_backend import SnapshotBackend, BootHandle, RestoreHandle

def test_protocols_are_runtime_checkable():
    # A minimal fake satisfies the Protocols structurally.
    class FakeBoot:
        def wait_ready(self, timeout_s: float) -> None: ...
        def checkpoint(self, dest_dir: Path) -> object: return {"art": str(dest_dir)}
        def kill(self) -> None: ...
    class FakeRestore:
        def kill(self) -> None: ...
    class FakeBackend:
        def available(self) -> bool: return True
        def boot_base(self) -> BootHandle: return FakeBoot()
        def restore_in(self, slot_workdir: Path, artifact: object) -> RestoreHandle: return FakeRestore()
    b = FakeBackend()
    assert isinstance(b, SnapshotBackend)
    assert isinstance(b.boot_base(), BootHandle)
    assert isinstance(b.restore_in(Path("/x"), {"art": "y"}), RestoreHandle)
```

- [ ] **Step 2: Run it to verify it fails** — `Run: .venv/bin/pytest tests/host/runtime/test_snapshot_backend.py -v` → FAIL (`ModuleNotFoundError: snapshot_backend`).

- [ ] **Step 3: Write the seam**

```python
"""Runtime-agnostic warm-snapshot seam.

One generic SnapshotManager (fc_snapshot.py) drives any SnapshotBackend. The
artifact a backend produces at checkpoint time is OPAQUE to the manager — the
manager stores it and hands it back to restore_in(), never inspecting it. FC's
artifact is a {snapshot, mem} file pair; gVisor's is a runsc image-path dir.
"""
from __future__ import annotations
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class BootHandle(Protocol):
    """A launched base sandbox used to build the snapshot."""
    def wait_ready(self, timeout_s: float) -> None:
        """Block until the base sandbox's engine signals READY (warm-idle)."""
        ...
    def checkpoint(self, dest_dir: Path) -> object:
        """Capture the warm snapshot, writing artifacts under/near dest_dir.
        Returns an OPAQUE artifact the manager round-trips to restore_in()."""
        ...
    def kill(self) -> None:
        """Tear down the base sandbox."""
        ...


@runtime_checkable
class RestoreHandle(Protocol):
    """A restored per-slot sandbox. Backend-specific I/O accessors are added by
    the concrete handle; the seam only requires kill()."""
    def kill(self) -> None: ...


@runtime_checkable
class SnapshotBackend(Protocol):
    """Spawns/checkpoints/restores the real sandboxes for one runtime (FC, gVisor)."""
    def available(self) -> bool:
        """True iff this backend's prerequisites are present (fail-closed selection)."""
        ...
    def boot_base(self) -> BootHandle: ...
    def restore_in(self, slot_workdir: Path, artifact: object) -> RestoreHandle: ...
```

- [ ] **Step 4: Run to verify it passes** — `Run: .venv/bin/pytest tests/host/runtime/test_snapshot_backend.py -v` → PASS.

- [ ] **Step 5: Commit** — `git add src/blastbox/host/runtime/snapshot_backend.py tests/host/runtime/test_snapshot_backend.py && git commit -m "feat(snapshot): runtime-agnostic SnapshotBackend seam"`

---

## Task 2: Generalize `SnapshotManager` to the seam

Make the manager runtime-agnostic: it talks to a `SnapshotBackend`, holds an opaque artifact, and owns only the lifecycle (build-once idempotency, safe-`slot_id` guard, restore-per-slot, fail-closed wrapping). FC mechanics move to Task 3.

**Files:**
- Modify: `src/blastbox/host/runtime/fc_snapshot.py` (the `SnapshotManager` class)
- Test: `tests/host/runtime/test_fc_snapshot.py` (update to the new ctor/seam)

- [ ] **Step 1: Update the manager's tests** to construct it with a fake **backend** (not a launcher) and assert the new flow. Add to `tests/host/runtime/test_fc_snapshot.py`:

```python
from pathlib import Path
from blastbox.host.runtime.fc_snapshot import SnapshotManager, SnapshotRestoreError

class _FakeBoot:
    def __init__(self, log): self._log = log
    def wait_ready(self, timeout_s): self._log.append(("wait_ready", timeout_s))
    def checkpoint(self, dest_dir): self._log.append(("checkpoint", str(dest_dir))); return {"artifact": "warm"}
    def kill(self): self._log.append(("kill",))

class _FakeRestore:
    def kill(self): ...

class _FakeBackend:
    def __init__(self): self.log=[]; self.restored=[]
    def available(self): return True
    def boot_base(self): return _FakeBoot(self.log)
    def restore_in(self, slot_workdir, artifact): self.restored.append((str(slot_workdir), artifact)); return _FakeRestore()

def test_build_is_idempotent_and_opaque(tmp_path):
    be=_FakeBackend()
    m=SnapshotManager(tmp_path, be)
    a1=m.build(); a2=m.build()
    assert a1 == a2 == {"artifact": "warm"}
    assert [e[0] for e in be.log] == ["wait_ready","checkpoint","kill"]  # built once

def test_restore_passes_opaque_artifact_and_guards_slot_id(tmp_path):
    be=_FakeBackend(); m=SnapshotManager(tmp_path, be); m.build()
    m.restore("slot-A")
    assert be.restored == [(str(tmp_path/"slots"/"slot-A"), {"artifact":"warm"})]
    for bad in ("", "../escape", "a/b", "."):
        try: m.restore(bad); assert False, bad
        except SnapshotRestoreError: pass

def test_restore_before_build_raises(tmp_path):
    try: SnapshotManager(tmp_path, _FakeBackend()).restore("x"); assert False
    except SnapshotRestoreError: pass
```

- [ ] **Step 2: Run to verify failure** — `Run: .venv/bin/pytest tests/host/runtime/test_fc_snapshot.py -k "opaque or guards or before_build" -v` → FAIL (manager still takes a launcher / calls FC APIs).

- [ ] **Step 3: Refactor `SnapshotManager`** in `fc_snapshot.py`. New shape (replace the launcher-driven `build`/`restore`; keep `SnapshotError`/`SnapshotBuildError`/`SnapshotRestoreError`):

```python
class SnapshotManager:
    """Builds the warm snapshot once, then serves restores. Runtime-agnostic:
    talks only to a SnapshotBackend; the artifact is opaque."""
    def __init__(self, base_dir: Path, backend: "SnapshotBackend", *, ready_timeout_s: float = 120.0) -> None:
        self._base_dir = Path(base_dir)
        self._backend = backend
        self._ready_timeout_s = ready_timeout_s
        self._artifact: object | None = None

    @property
    def artifact(self) -> object | None:
        return self._artifact

    def build(self) -> object:
        if self._artifact is not None:
            return self._artifact
        self._base_dir.mkdir(parents=True, exist_ok=True)
        try:
            boot = self._backend.boot_base()
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(f"warm snapshot base boot failed: {exc}") from exc
        try:
            boot.wait_ready(self._ready_timeout_s)
            artifact = boot.checkpoint(self._base_dir)
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(f"warm snapshot build failed: {exc}") from exc
        finally:
            boot.kill()
        self._artifact = artifact
        return artifact

    def restore(self, slot_id: object) -> "RestoreHandle":
        if self._artifact is None:
            raise SnapshotRestoreError("snapshot not built; call build() first")
        sid = str(slot_id)
        if not sid or "/" in sid or "\x00" in sid or sid in (".", ".."):
            raise SnapshotRestoreError(f"unsafe slot_id: {sid!r}")
        slot_workdir = self._base_dir / "slots" / sid
        slot_workdir.mkdir(parents=True, exist_ok=True)
        try:
            return self._backend.restore_in(slot_workdir, self._artifact)
        except SnapshotError:
            raise
        except Exception as exc:
            raise SnapshotRestoreError(f"restore failed: {exc}") from exc
```

Remove from `fc_snapshot.py` (they move to Task 3's `FcSnapshotBackend`): `resolve_mem_dir`, the `_ENV_MEM_*` constants, `create_snapshot`, `restore_from_snapshot`, `SnapshotArtifact`, `FcApi`, `BootHandle`/`RestoreHandle`/`SnapshotLauncher` Protocols (the seam ones now live in `snapshot_backend.py`), and the `from_env`/`mem_dir` ctor params. Import `SnapshotBackend`, `RestoreHandle` from `snapshot_backend`. Keep `SnapshotError`, `SnapshotBuildError`, `SnapshotRestoreError`.

- [ ] **Step 4: Run to verify** — `Run: .venv/bin/pytest tests/host/runtime/test_fc_snapshot.py -v` → the new tests PASS; FC-mechanics tests that referenced the old API will FAIL — they move to Task 3. Mark/move them: cut the `create_snapshot`/`restore_from_snapshot`/`resolve_mem_dir`/`from_env` tests out of this file (they re-home into `test_fc_snapshot_backend.py` in Task 3). Re-run → PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "refactor(snapshot): SnapshotManager is runtime-agnostic (opaque artifact + backend seam)"`

---

## Task 3: Extract `FcSnapshotBackend` (keep FC green)

Move every FC-ism (the `{snapshot, mem}` artifact, the RAM-preload toggle, Pause+CreateSnapshot, load+resume) into a backend that implements the seam over the existing `FcSnapshotLauncher`. **Behavior must be identical** — the FC launcher/runtime integration is unchanged; only the wiring moves.

**Files:**
- Create: `src/blastbox/host/runtime/fc_snapshot_backend.py`
- Modify: `src/blastbox/host/runtime/fc_snapshot_launcher.py` (`_Handle.checkpoint`)
- Modify: `src/blastbox/host/runtime/fc_snapshot_runtime.py` (construct the manager with `FcSnapshotBackend`)
- Test: `tests/host/runtime/test_fc_snapshot_backend.py` (re-homed FC-mechanics tests)

- [ ] **Step 1: Write the failing test** (`tests/host/runtime/test_fc_snapshot_backend.py`) covering: `from_env` honors `BLASTBOX_SNAPSHOT_MEM_TMPFS`/`BLASTBOX_SNAPSHOT_MEM_DIR` (re-home `resolve_mem_dir` cases); `boot_base().checkpoint(dest)` issues Pause then CreateSnapshot with the mem file under the resolved mem_dir and returns a `FcSnapshotArtifact(snapshot, mem)`; `restore_in(workdir, artifact)` spawns + issues `/snapshot/load` (`mem_backend` File) + resume and returns a handle exposing `vsock_uds`. Use the existing FC test doubles (fake `FcApi` recording PUTs/PATCHes, fake launcher) — copy them from the old `test_fc_snapshot.py`.

```python
def test_checkpoint_pauses_then_creates_and_returns_artifact(tmp_path, monkeypatch):
    # fake launcher.boot_base() -> handle with a recording api; checkpoint() must
    # PATCH /vm {state: Paused} then PUT /snapshot/create {snapshot_type: Full, ...}
    ...
def test_restore_in_loads_mem_backend_file_and_resumes(tmp_path):
    # restore_in -> launcher.restore_in(workdir) then PUT /snapshot/load with
    # mem_backend={"backend_type":"File","backend_path": <mem>} + resume_vm true
    ...
def test_from_env_mem_tmpfs(monkeypatch, tmp_path):
    monkeypatch.setenv("BLASTBOX_SNAPSHOT_MEM_TMPFS","1")
    be = FcSnapshotBackend.from_env(tmp_path, launcher=_fake_launcher())
    assert be.mem_dir == Path("/dev/shm")
```

- [ ] **Step 2: Run to verify failure** — `Run: .venv/bin/pytest tests/host/runtime/test_fc_snapshot_backend.py -v` → FAIL (`fc_snapshot_backend` missing).

- [ ] **Step 3: Implement `FcSnapshotBackend`** (`fc_snapshot_backend.py`). It owns: the `_ENV_MEM_*` constants + `resolve_mem_dir` (moved verbatim from old `fc_snapshot.py`), `FcSnapshotArtifact(snapshot_path, mem_path)`, and:

```python
class FcSnapshotBackend:
    def __init__(self, base_dir, launcher, *, mem_dir=None): self._base_dir=Path(base_dir); self._launcher=launcher; self._mem_dir=Path(mem_dir) if mem_dir else self._base_dir
    @classmethod
    def from_env(cls, base_dir, launcher, *, mem_dir=None):
        return cls(base_dir, launcher, mem_dir=mem_dir if mem_dir is not None else resolve_mem_dir() or base_dir)
    @property
    def mem_dir(self): return self._mem_dir
    def available(self): return True  # caller already gated on firecracker_available
    def boot_base(self): return self._launcher.boot_base()   # _Handle now has .checkpoint
    def restore_in(self, slot_workdir, artifact):
        handle = self._launcher.restore_in(slot_workdir)
        try:
            _restore_from_snapshot(handle.api, str(artifact.snapshot_path), str(artifact.mem_path))
        except Exception:
            handle.kill(); raise
        return handle
```

Move `create_snapshot` → into `_Handle.checkpoint(dest_dir)` in `fc_snapshot_launcher.py`:

```python
# fc_snapshot_launcher.py, _Handle:
def checkpoint(self, dest_dir):
    from blastbox.host.runtime.fc_snapshot_backend import FcSnapshotArtifact, _create_snapshot
    snap = Path(dest_dir) / "warm.snapshot"
    mem = self._mem_dir / "warm.mem"   # _Handle gains _mem_dir, passed by FcSnapshotLauncher.boot_base
    _create_snapshot(self.api, str(snap), str(mem))
    return FcSnapshotArtifact(snap, mem)
```

`FcSnapshotLauncher.__init__` takes `mem_dir` and passes it into the `_Handle` it returns from `boot_base`. `_create_snapshot`/`_restore_from_snapshot` are the old `create_snapshot`/`restore_from_snapshot` bodies (Pause+Create / load+resume), moved into `fc_snapshot_backend.py`.

- [ ] **Step 4: Re-wire `fc_snapshot_runtime.py`** — `select_snapshot_runtime` builds `FcSnapshotBackend.from_env(base_dir, launcher)` and `SnapshotManager(base_dir, backend)` (drop the old `SnapshotManager.from_env`). The `SnapshotSlotRuntime` already reads `handle.vsock_uds` and the per-slot ext4 — unchanged.

- [ ] **Step 5: Run the FULL FC suite** — `Run: .venv/bin/pytest tests/host/runtime/test_fc_snapshot.py tests/host/runtime/test_fc_snapshot_backend.py tests/host/runtime/test_fc_snapshot_runtime.py tests/host/runtime/test_fc_snapshot_launcher.py -v` → all PASS (FC behavior identical). Then `.venv/bin/ruff check src tests && .venv/bin/mypy src`.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "refactor(snapshot): extract FcSnapshotBackend; FC mechanics behind the seam (FC tests green)"`

---

## Task 4: `GvisorSnapshotBackend` — the runsc driver

**Files:**
- Create: `src/blastbox/host/runtime/gvisor_snapshot.py`
- Test: `tests/host/runtime/test_gvisor_snapshot.py`

The new backend. All `runsc` invocations go through an injected `run` callable so it's unit-tested with no real runsc. Mechanics are exactly the spike's: `runsc run -detach` a warm container → wait READY (the worker writes `ready` into the bind-mounted control dir) → `runsc checkpoint -image-path`; restore = `runsc restore -image-path -detach` into a fresh container with per-slot bind mounts (`in/` ro, `out/` rw, `ctrl/` rw).

- [ ] **Step 1: Write failing tests** (`tests/host/runtime/test_gvisor_snapshot.py`):

```python
from pathlib import Path
from blastbox.host.runtime.gvisor_snapshot import GvisorSnapshotBackend, GvisorConfig

class _Rec:
    def __init__(self): self.calls=[]
    def __call__(self, argv, **kw): self.calls.append(argv); return 0

def _cfg(tmp_path): return GvisorConfig(runsc_bin="runsc", root=tmp_path/"root", image_rootfs=tmp_path/"rootfs", network="none", warm_argv=["/warm-entrypoint"])

def test_boot_base_runs_then_checkpoint(tmp_path):
    rec=_Rec(); be=GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d,t: None)
    boot=be.boot_base(); boot.wait_ready(5.0)
    art=boot.checkpoint(tmp_path/"ckpt")
    joined=[" ".join(c) for c in rec.calls]
    assert any("run" in c and "-detach" in c for c in joined)
    assert any("checkpoint" in c and "-image-path" in c for c in joined)
    assert Path(str(art)).name == "checkpoint"   # artifact is the image-path dir

def test_restore_in_creates_then_restores_with_swapped_mounts(tmp_path):
    rec=_Rec(); be=GvisorSnapshotBackend(_cfg(tmp_path), run=rec, ready_wait=lambda d,t: None)
    wd=tmp_path/"slots"/"s1"; wd.mkdir(parents=True)
    be.restore_in(wd, str(tmp_path/"ckpt"/"checkpoint"))
    joined=[" ".join(c) for c in rec.calls]
    assert any("restore" in c and "-image-path" in c for c in joined)
    # per-slot bind dirs created
    for sub in ("in","out","ctrl"): assert (wd/sub).is_dir()

def test_available_checks_runsc_and_checkpoint_support(tmp_path):
    be=GvisorSnapshotBackend(_cfg(tmp_path), run=lambda a,**k: 0, ready_wait=lambda d,t: None,
                             probe=lambda: True)
    assert be.available() is True
```

- [ ] **Step 2: Run to verify failure** — `Run: .venv/bin/pytest tests/host/runtime/test_gvisor_snapshot.py -v` → FAIL.

- [ ] **Step 3: Implement** `gvisor_snapshot.py`:

```python
"""GvisorSnapshotBackend — runsc checkpoint/restore as a SnapshotBackend.

Drives `runsc` directly (containerd/CRI checkpoint is unimplemented upstream;
the dispatcher already drives the runtime directly). The warm container runs the
worker entrypoint (serve_warm + FileWarmControl); it writes `ready` into the
bind-mounted control dir, which we poll before checkpointing. I/O is bind mounts
(in/ ro, out/ rw, ctrl/ rw) — no vsock, no ext4.
"""
from __future__ import annotations
import json, shutil, subprocess, time, uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from blastbox.host.runtime.snapshot_backend import RestoreHandle

@dataclass(frozen=True)
class GvisorConfig:
    runsc_bin: str
    root: Path                 # runsc --root state dir
    image_rootfs: Path         # exported OCI rootfs for the warm container
    network: str               # "none" | "sandbox"
    warm_argv: list[str]       # the warm worker entrypoint argv (inside the container)
    ignore_cgroups: bool = True
    platform: str | None = None
    cpu_features_annotation: str | None = None  # dev.gvisor.internal.cpufeatures (pinning)

def _runsc(cfg: GvisorConfig) -> list[str]:
    a=[cfg.runsc_bin, "-root", str(cfg.root), f"-network={cfg.network}"]
    if cfg.ignore_cgroups: a.append("-ignore-cgroups")
    if cfg.platform: a.append(f"-platform={cfg.platform}")
    return a

def _default_run(argv, **kw) -> int:
    return subprocess.run(argv, check=True, **kw).returncode

def _default_ready_wait(ctrl_dir: Path, timeout_s: float) -> None:
    deadline=time.monotonic()+timeout_s
    while time.monotonic()<deadline:
        if (ctrl_dir/"ready").exists(): return
        time.sleep(0.2)
    raise TimeoutError(f"warm base not READY within {timeout_s}s ({ctrl_dir})")

class GvisorBootHandle:
    def __init__(self, cfg, run, cid, base_dir, ctrl_dir, ready_wait):
        self._cfg=cfg; self._run=run; self._cid=cid; self._base=base_dir; self._ctrl=ctrl_dir; self._ready=ready_wait
    def wait_ready(self, timeout_s: float) -> None:
        self._ready(self._ctrl, timeout_s)
    def checkpoint(self, dest_dir: Path) -> object:
        img = Path(dest_dir)/"checkpoint"; img.mkdir(parents=True, exist_ok=True)
        self._run([*_runsc(self._cfg), "checkpoint", "-image-path", str(img), self._cid])
        return str(img)
    def kill(self) -> None:
        try: self._run([*_runsc(self._cfg), "delete", "-force", self._cid])
        except Exception: pass

class GvisorRestoreHandle:
    def __init__(self, cfg, run, cid, slot_workdir):
        self._cfg=cfg; self._run=run; self._cid=cid
        self.slot_workdir=Path(slot_workdir)          # SlotRuntime reads out/ + ctrl/ here
        self.control_dir=self.slot_workdir/"ctrl"
        self.output_dir=self.slot_workdir/"out"
        self.input_dir=self.slot_workdir/"in"
    def kill(self) -> None:
        for argv in (["kill", self._cid, "KILL"], ["delete","-force", self._cid]):
            try: self._run([*_runsc(self._cfg), *argv])
            except Exception: pass

class GvisorSnapshotBackend:
    def __init__(self, cfg, *, run=_default_run, ready_wait=_default_ready_wait, probe=None):
        self._cfg=cfg; self._run=run; self._ready=ready_wait; self._probe=probe
    def available(self) -> bool:
        if self._probe is not None: return self._probe()
        return shutil.which(self._cfg.runsc_bin) is not None
    def _bundle(self, workdir: Path, *, in_ro: bool) -> Path:
        # write a minimal OCI config.json with the warm argv + per-slot bind mounts.
        # (Generate via `runsc spec` then patch, or emit directly. Helper _write_oci_config.)
        ...
    def boot_base(self):
        base=self._cfg.root.parent/"gvisor-base"; ctrl=base/"ctrl"
        for d in (base/"in", base/"out", ctrl): d.mkdir(parents=True, exist_ok=True)
        cid="warm-base"
        self._write_oci_config(base, in_ro=True)
        self._run([*_runsc(self._cfg), "run", "-detach", "-bundle", str(base), cid],
                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return GvisorBootHandle(self._cfg, self._run, cid, base, ctrl, self._ready)
    def restore_in(self, slot_workdir, artifact):
        wd=Path(slot_workdir)
        for sub in ("in","out","ctrl"): (wd/sub).mkdir(parents=True, exist_ok=True)
        cid=f"slot-{uuid.uuid4().hex[:12]}"
        self._write_oci_config(wd, in_ro=True)
        self._run([*_runsc(self._cfg), "restore", "-image-path", str(artifact),
                   "-detach", "-bundle", str(wd), cid],
                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return GvisorRestoreHandle(self._cfg, self._run, cid, wd)
```

Implement `_write_oci_config(workdir, in_ro)` to emit `workdir/config.json`: `process.args = cfg.warm_argv`, `process.terminal=False`, `root.path=str(cfg.image_rootfs)` (or copy/symlink), `root.readonly=False`, env including `LD_PRELOAD=/opt/clippyshot/accept-retry.so` (soffice) — set via cfg, mounts for `/in`(ro)`/out`(rw)`/ctrl`(rw) → `workdir/{in,out,ctrl}` + a `/tmp` tmpfs, and `process.capabilities` (+`CAP_SYS_PTRACE` only if debugging). Reuse the exact JSON shape proven in the spike. Unit-test `_write_oci_config` separately (asserts mounts + args + LD_PRELOAD).

- [ ] **Step 4: Run to verify** — `Run: .venv/bin/pytest tests/host/runtime/test_gvisor_snapshot.py -v` → PASS.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(gvisor): GvisorSnapshotBackend — runsc checkpoint/restore driver"`

---

## Task 5: `GvisorSnapshotSlotRuntime` + selector

**Files:**
- Create: `src/blastbox/host/runtime/gvisor_snapshot_runtime.py`
- Test: `tests/host/runtime/test_gvisor_snapshot_runtime.py`

The SlotRuntime: `spawn` builds the snapshot once then restores per slot; the warm-path seam uses the **existing** `HostWarmControl` (host writes `go.json`, reads `done`) and reads output **directly** from the per-slot `out/` bind mount (no ext4/rdump).

- [ ] **Step 1: Write failing tests** (`tests/host/runtime/test_gvisor_snapshot_runtime.py`) with a fake `SnapshotManager` (its `restore` returns a fake `GvisorRestoreHandle` with `slot_workdir`/`control_dir`/`output_dir`):

```python
def test_spawn_builds_once_then_restores(tmp_path):
    mgr=_FakeMgr(tmp_path)
    rt=GvisorSnapshotSlotRuntime(mgr, settle_s=0.0)
    s1=rt.spawn(); s2=rt.spawn()
    assert mgr.built==1 and mgr.restores==2
    assert s1.state.name=="WARMING" and s1.control_dir.name=="ctrl"

def test_host_warm_control_is_file_based(tmp_path):
    from blastbox.worker.warm import HostWarmControl
    rt=GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    slot=rt.spawn()
    assert isinstance(rt.host_warm_control(slot), HostWarmControl)

def test_materialize_output_is_noop_output_already_present(tmp_path):
    rt=GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    slot=rt.spawn(); (slot.output_dir).mkdir(parents=True, exist_ok=True)
    (slot.output_dir/"x.pdf").write_bytes(b"%PDF")
    rt.materialize_warm_output(slot)            # must not raise; output stays
    assert (slot.output_dir/"x.pdf").exists()

def test_reap_kills_and_cleans(tmp_path):
    rt=GvisorSnapshotSlotRuntime(_FakeMgr(tmp_path), settle_s=0.0)
    slot=rt.spawn(); rt.reap(slot)
    assert not slot.output_dir.parent.exists()
```

- [ ] **Step 2: Run to verify failure** — `Run: .venv/bin/pytest tests/host/runtime/test_gvisor_snapshot_runtime.py -v` → FAIL.

- [ ] **Step 3: Implement** `gvisor_snapshot_runtime.py` — mirror the structure of `fc_snapshot_runtime.py`'s `SnapshotSlotRuntime` but with the file-trigger seam:

```python
class GvisorSnapshotSlotRuntime:
    def __init__(self, manager, *, settle_s=1.0, clock=time.monotonic):
        self._mgr=manager; self._settle_s=settle_s; self._clock=clock
        self._handles={}; self._restored_at={}; self._lock=threading.Lock()
    def spawn(self):
        self._mgr.build()
        slot_id=str(uuid.uuid4()); handle=self._mgr.restore(slot_id)
        wd=Path(handle.slot_workdir)
        with self._lock: self._handles[slot_id]=handle; self._restored_at[slot_id]=self._clock()
        return Slot(slot_id=slot_id, control_dir=wd/"ctrl", input_dir=wd/"in",
                    output_dir=wd/"out", state=SlotState.WARMING, spawned_at=0.0)
    def is_ready(self, slot):
        with self._lock:
            h=self._handles.get(slot.slot_id); t=self._restored_at.get(slot.slot_id)
        if h is None: return False
        if t is not None and self._clock()-t < self._settle_s: return False
        return Path(slot.control_dir).exists()
    def is_alive(self, slot):  # the job protocol's go/done surfaces a dead guest; alive=handle present
        with self._lock: return slot.slot_id in self._handles
    def reap(self, slot):
        with self._lock: h=self._handles.pop(slot.slot_id, None); self._restored_at.pop(slot.slot_id, None)
        if h is not None:
            try: h.kill()
            except Exception as e: _log.warning("gvisor.reap_kill_error %s: %s", slot.slot_id, e)
        wd=Path(slot.output_dir).parent
        if wd.exists(): shutil.rmtree(wd, ignore_errors=True)
    # --- warm-path seam (file-trigger; output already on disk) ---
    def host_warm_control(self, slot):
        from blastbox.worker.warm import HostWarmControl
        return HostWarmControl(slot.control_dir)
    def stage_warm_input(self, slot, staged_input_path):
        dst=Path(slot.input_dir)/Path(staged_input_path).name
        shutil.copyfile(staged_input_path, dst); return dst
    def materialize_warm_output(self, slot):
        return None   # output is written directly into the bind-mounted out/ dir
```

Add `select_gvisor_snapshot_runtime(*, cfg=None, require_available=False, manager=None)` mirroring `select_snapshot_runtime`: build `GvisorConfig` from env (`BLASTBOX_GVISOR_RUNSC`, `BLASTBOX_GVISOR_ROOTFS`, `BLASTBOX_GVISOR_NETWORK`, warm argv from the engine deploy), `GvisorSnapshotBackend(cfg)`, `SnapshotManager(base_dir, backend)`, `GvisorSnapshotSlotRuntime(manager, settle_s=BLASTBOX_SNAPSHOT_SETTLE_S)`. When `require_available` and `not backend.available()` → raise a `GvisorUnavailable` error.

- [ ] **Step 4: Run to verify** — `Run: .venv/bin/pytest tests/host/runtime/test_gvisor_snapshot_runtime.py -v` → PASS; then full `tests/host tests/worker` green.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(gvisor): GvisorSnapshotSlotRuntime (file-trigger control, bind-mount output) + selector"`

---

## Task 6: Pool wiring — `BLASTBOX_POOL_RUNTIME=gvisor`

**Files:**
- Modify: `src/blastbox/host/pool_config.py`
- Test: `tests/host/test_pool_config.py` (add cases)

- [ ] **Step 1: Write failing tests**:

```python
def test_gvisor_runtime_routes_to_gvisor_snapshot(monkeypatch):
    monkeypatch.setenv("BLASTBOX_POOL_RUNTIME","gvisor")
    monkeypatch.setenv("BLASTBOX_POOL_WARM_SNAPSHOT","1")
    seen={}
    import blastbox.host.runtime.gvisor_snapshot_runtime as g
    monkeypatch.setattr(g, "select_gvisor_snapshot_runtime", lambda **k: seen.setdefault("called", object()))
    from blastbox.host.pool_config import build_warm_pool, PoolConfig
    build_warm_pool(PoolConfig.from_env())
    assert "called" in seen
```

- [ ] **Step 2: Run to verify failure** → FAIL (`unknown pool runtime: 'gvisor'`).

- [ ] **Step 3: Implement** — in `pool_config.py` add `RUNTIME_GVISOR = "gvisor"` and a branch in `build_warm_pool`:

```python
elif cfg.runtime == RUNTIME_GVISOR:
    from blastbox.host.runtime.gvisor_snapshot_runtime import select_gvisor_snapshot_runtime
    runtime = select_gvisor_snapshot_runtime(require_available=True)
```

(gVisor is inherently a warm-snapshot tier, so it routes regardless of `warm_snapshot`; keep the `firecracker`+`warm_snapshot` branch as-is.)

- [ ] **Step 4: Run to verify** → PASS; full suite + `ruff` + `mypy`.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(pool): BLASTBOX_POOL_RUNTIME=gvisor routes to the gVisor C/R warm tier"`

---

## Task 7: The accept-retry shim (deploy artifact)

**Files:**
- Create: `deploy/docker/accept_retry.c`
- Modify: the soffice warm image build (`deploy/docker/Dockerfile.clippyshot-warm` or the existing warm rootfs build) + the warm entrypoint env

The proven fix: a tiny `LD_PRELOAD` that retries `accept`/`accept4` on EINTR (osl's lone non-retrying accept is the one consumer that breaks under gVisor's restore-EINTR). soffice-only; inert for FC/cold/JVM.

- [ ] **Step 1: Create `deploy/docker/accept_retry.c`** (verbatim from the proven shim):

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
static int (*real_accept)(int,struct sockaddr*,socklen_t*)=0;
static int (*real_accept4)(int,struct sockaddr*,socklen_t*,int)=0;
int accept(int fd, struct sockaddr*a, socklen_t*l){
  if(!real_accept) real_accept=dlsym(RTLD_NEXT,"accept");
  for(;;){ int r=real_accept(fd,a,l); if(r<0 && errno==EINTR) continue; return r; }
}
int accept4(int fd, struct sockaddr*a, socklen_t*l, int fl){
  if(!real_accept4) real_accept4=dlsym(RTLD_NEXT,"accept4");
  for(;;){ int r=real_accept4(fd,a,l,fl); if(r<0 && errno==EINTR) continue; return r; }
}
```

- [ ] **Step 2: Build it into the soffice warm image** — add to the warm Dockerfile:

```dockerfile
COPY deploy/docker/accept_retry.c /tmp/accept_retry.c
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && gcc -shared -fPIC -O2 -o /opt/clippyshot/accept-retry.so /tmp/accept_retry.c -ldl \
 && apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* /tmp/accept_retry.c
```

(Or compile on the host and `COPY` the `.so` if a slimmer image is preferred — the build artifact is the `.so` at `/opt/clippyshot/accept-retry.so`.)

- [ ] **Step 3: Set `LD_PRELOAD` for the warm soffice path** — the `GvisorConfig.warm_argv`/env for the soffice engine sets `LD_PRELOAD=/opt/clippyshot/accept-retry.so` (only the soffice warm container; the Tika/JVM warm container does not). Document in `deploy/docker/README.md`: "the shim is required only for the gVisor-C/R soffice warm tier; it is inert otherwise (the retry only fires on a restore-time EINTR)."

- [ ] **Step 4: Smoke-build the image** — `Run: docker build -f deploy/docker/Dockerfile.clippyshot-warm -t clippyshot-warm:gvisor .` → succeeds; `docker run --rm --entrypoint sh clippyshot-warm:gvisor -c 'ls -l /opt/clippyshot/accept-retry.so'` → present.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "deploy(gvisor): accept-retry LD_PRELOAD shim for the soffice warm tier"`

---

## Task 8: Gated integration round-trip (needs a runsc host)

**Files:**
- Create: `tests/integration/test_gvisor_snapshot_roundtrip.py`

Mirror the FC integration gating: marked `integration`, skipped unless a `runsc` host with checkpoint support is present. This documents the end-to-end gate (already proven manually on toolz2) as a runnable test.

- [ ] **Step 1: Write the gated test**:

```python
import shutil, pytest
pytestmark = pytest.mark.integration

def _runsc_cr_available() -> bool:
    if not shutil.which("runsc"): return False
    import subprocess
    out = subprocess.run(["runsc","help"], capture_output=True, text=True).stdout
    return "checkpoint" in out and "restore" in out

@pytest.mark.skipif(not _runsc_cr_available(), reason="needs runsc with checkpoint/restore")
def test_warm_restore_convert_roundtrip(tmp_path):
    # build GvisorConfig from a real clippyshot-warm rootfs + the shim; build the
    # snapshot, restore a slot, signal_go a docx via HostWarmControl, assert a PDF
    # appears in the slot out/ dir and (optionally) rasterize-compare to cold.
    ...
```

- [ ] **Step 2: Run (host without runsc)** — `Run: .venv/bin/pytest tests/integration/test_gvisor_snapshot_roundtrip.py -v` → SKIPPED (documents the gate; CI without runsc stays green).

- [ ] **Step 3: Commit** — `git add -A && git commit -m "test(gvisor): gated integration round-trip (runsc host)"`

---

## Final verification

- [ ] Full suite: `.venv/bin/pytest tests/host tests/worker tests/contract -q` → green (FC tests included — the regression guard).
- [ ] `.venv/bin/ruff check src tests && .venv/bin/mypy src` → clean.
- [ ] Update `README.md`: add the gVisor-C/R warm tier to the runtime/snapshot section (one paragraph: portable warm tier on any cloud VM, both engines, the soffice shim).
- [ ] Dispatch a final code-reviewer over the whole branch, then `superpowers:finishing-a-development-branch`.

## Notes for the implementer

- **Keep FC green at every step.** Tasks 2–3 refactor shipped, tested code. Run the FC snapshot suite after each step in those tasks, not just at the end.
- **The artifact is opaque.** The manager never inspects it. FC's is `FcSnapshotArtifact`; gVisor's is the image-path `str`. Don't add `isinstance` checks in the manager.
- **No vsock/ext4 in the gVisor path.** Output is read directly from the per-slot `out/` bind mount; `materialize_warm_output` is a no-op. Control is the existing `HostWarmControl`/`FileWarmControl` (file-trigger), not a new transport.
- **The shim is soffice-only and inert elsewhere** — the retry only fires on a restore-time EINTR, which only the osl pipe acceptor hits. Don't preload it for the JVM/Tika warm container.
- Everything here is proven on toolz2; if an integration result diverges from the spec's measured numbers, trust the spec and re-check the wiring.
