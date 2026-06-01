# Worker SDK — Sandbox Abstraction Slice (container backend)

**Goal:** `blastbox.worker.sandbox` — the isolation the engine uses to run untrusted subprocesses
(soffice, pdftoppm, java, …). A `Sandbox` protocol + the `ContainerSandbox` backend (in-process
hardening self-checks + a subprocess runner) + `select_sandbox()`. This is the primary
container/compose deployment mode.

**Scope:** container backend only. **Host-native `bwrap`/`nsjail` are a deferred follow-up** (bare-metal
modes; a large host-specific port of AppArmor-path-matching + seccomp-BPF building). Design the
`Sandbox` protocol so they slot in later without changing callers. Service-lifecycle (warm) mode is a
separate later slice too.

**Architecture:** In the container deployment the worker already runs inside a hardened container the
dispatcher launched (`--cap-drop=ALL --no-new-privileges --read-only --network=none` + seccomp). So
`ContainerSandbox` does NOT nest another sandbox — it (1) **self-checks** that the outer container's
hardening is actually effective before any engine code runs, then (2) runs subprocesses directly with
per-call rlimits + timeout. The engine receives a `Sandbox` and calls `sandbox.run(SandboxRequest)`.

**Tech Stack:** Python 3.12+, stdlib `subprocess`/`resource`, `blastbox.limits`/`errors`, pytest.

**Reference (port + generalize the just-hardened code):**
- `/home/coz/Downloads/ClippyShot/src/clippyshot/sandbox/base.py` — `Sandbox`/`SandboxRequest`/`SandboxResult`/`Mount`.
- `/home/coz/Downloads/ClippyShot/src/clippyshot/sandbox/container.py` — `ContainerSandbox`: the in-proc
  `_runtime_hardening_reasons()` checks (NoNewPrivs/Seccomp/CapEff from `/proc/self/status`), the
  `runc`-vs-`runsc` "insecure" determination, the `WARN_ON_INSECURE` gate, `_apply_rlimits`.
- `/home/coz/Downloads/ClippyShot/src/clippyshot/sandbox/detect.py` — `select_sandbox()` smoketest + selection.

## File structure
- `src/blastbox/worker/sandbox/__init__.py` — exports
- `src/blastbox/worker/sandbox/base.py` — `Sandbox` protocol, `SandboxRequest`, `SandboxResult`, `Mount`
- `src/blastbox/worker/sandbox/container.py` — `ContainerSandbox`
- `src/blastbox/worker/sandbox/detect.py` — `select_sandbox()`
- `tests/worker/sandbox/test_container.py`, `test_detect.py`

## Public API
```python
@dataclass(frozen=True)
class Mount:
    source: Path
    target: Path
    read_only: bool = True

@dataclass
class SandboxRequest:
    argv: list[str]
    ro_mounts: list[Mount] = field(default_factory=list)
    rw_mounts: list[Mount] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    env: dict[str, str] = field(default_factory=dict)

@dataclass
class SandboxResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    killed: bool          # True if killed by timeout

class Sandbox(Protocol):
    name: str
    secure: bool
    def run(self, request: SandboxRequest) -> SandboxResult: ...

class ContainerSandbox:
    name = "container"
    def __init__(self, *, warn_on_insecure: bool | None = None,
                 status_path: Path = Path("/proc/self/status")): ...
    @property
    def secure(self) -> bool: ...           # False if any insecurity_reasons
    @property
    def insecurity_reasons(self) -> list[str]: ...

def select_sandbox(*, backend: str | None = None) -> Sandbox: ...  # BLASTBOX_SANDBOX override
```

## ContainerSandbox behavior
- **Construction self-check** `_runtime_hardening_reasons(status_path)`: read `/proc/self/status` and
  collect reasons it's NOT provably hardened: `NoNewPrivs` != 1 → `"no_new_privs_off"`; `Seccomp` == 0
  → `"seccomp_off"`; `CapEff` != 0 → `"cap_not_dropped"`. Under gVisor (`runsc`) `/proc/self/status`
  is virtualized so these may not reflect host-applied flags — when `warn_on_insecure` is true (set by
  the dispatcher under runsc via `BLASTBOX_WARN_ON_INSECURE=1`) the checks are advisory (reasons
  recorded but the sandbox is still usable); when false (runc, strict) a non-empty reason set means
  `secure == False`. Always append a structural `"network_egress_not_verified"` reason so
  `secure` is conservative (the container backend can't itself prove `--network=none`).
- **`run(request)`**: `subprocess.run(request.argv, capture_output=True, env={**minimal, **request.env},
  timeout=request.limits.timeout_s, check=False, preexec_fn=apply rlimits)`. `_apply_rlimits` sets
  `RLIMIT_AS`=memory_bytes, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CPU` (best-effort). On
  `TimeoutExpired` → `SandboxResult(exit_code=-9, killed=True, stdout/stderr=partial)`. Mounts are
  advisory/no-op for the container backend (files already accessible) — record them but don't act.
  argv is a list (no shell). The minimal env strips the ambient environment (clean `PATH`, `HOME=/tmp`,
  `request.env` overlaid).

## select_sandbox
- `BLASTBOX_SANDBOX=container` forces it; else default to `container` (the only backend this slice
  ships). Run a `/bin/true` smoketest via the chosen backend; if it can't run, raise
  `SandboxUnavailable`. (When bwrap/nsjail land, this picks the best available.)

## Security requirements (review WILL check)
- `run` never uses `shell=True`; argv is a list; the ambient env is stripped (no host env leaks to the
  subprocess) except an explicit minimal set + `request.env`.
- rlimits actually applied (probe: a child that allocates > `RLIMIT_AS` is killed; a child exceeding
  `timeout_s` is killed with `killed=True`).
- `secure` is conservative: any insecurity reason (or the structural egress one) → `secure == False`.
- The self-check parses `/proc/self/status` robustly (missing fields, gVisor-virtualized values).

## Tests (TDD; ContainerSandbox runs real subprocesses — works on the host)
- `run(["/bin/echo","hi"])` → exit 0, stdout `b"hi\n"`, not killed.
- `run(["/bin/sleep","5"], limits=Limits(timeout_s=1))` → `killed=True`. (use a short timeout)
- env stripped: `run(["/usr/bin/env"])` with a sentinel in `os.environ` → the sentinel is NOT in
  stdout; `request.env={"X":"1"}` → `X=1` IS present.
- rlimit: a python `-c` child that tries to allocate well over a tiny `memory_bytes` exits non-zero
  (MemoryError) — or assert RLIMIT_AS is set in the child via reading its own `resource.getrlimit`.
- hardening self-check: feed a fake `status_path` with `NoNewPrivs:\t0`, `Seccomp:\t0`,
  `CapEff:\t0000003fffffffff` → `insecurity_reasons` contains the three + egress; a "good" status
  (`NoNewPrivs:1`, `Seccomp:2`, `CapEff:0000000000000000`) + `warn_on_insecure=False` → only the
  structural egress reason; `secure` False in both (egress) — assert the per-flag reasons appear/clear.
- `select_sandbox(backend="container")` returns a `ContainerSandbox`; `/bin/true` smoketest passes.

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. host + worker harness + contract), mypy + ruff clean. Don't push.
