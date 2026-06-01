# Host Orchestrator — Runtime Selection + Worker Launch Slice

**Goal:** `blastbox.host.runtime` — choose the best available container runtime (gVisor `runsc` →
`runc`, fail-closed when a secure runtime is required) and assemble the narrow, fully-hardened
`docker run` argv that launches one disposable worker per job. Engine-agnostic: takes an image +
mounts + the worker command; knows nothing about what the engine does inside.

**Scope:** Docker runtime only (runc/runsc). **Firecracker and the warm/cold pool are explicitly
out of scope** — later slices (the pool is gated on the warm-UNO container-init-overlap measurement).
Define the seam so FC can be added later without reshaping callers.

**Tech Stack:** Python 3.12+, stdlib `subprocess`/`json`, `blastbox.limits`/`errors`, pytest.

**Reference (port + generalize the just-hardened code):**
- `/home/coz/Downloads/ClippyShot/src/clippyshot/runtime/docker_runtime.py` — this was hardened THIS
  session: `InsecureRuntimeRefused`, `_require_secure_runtime`, `_finalize_runtime`,
  `select_worker_runtime`, `build_worker_docker_run_argv`, runtime detection, the seccomp/apparmor
  attachment, `setpgid/setsid` are deploy-side. Preserve every security property.
- `/home/coz/Downloads/ClippyShot/src/clippyshot/runtime/host_limits.py` — host CPU/mem → default
  worker caps (generalize for the auto-sizing helper).

## File structure
- `src/blastbox/host/runtime/__init__.py` — exports
- `src/blastbox/host/runtime/docker.py` — selection + argv + detection
- `src/blastbox/host/runtime/host_limits.py` — host-resource → default caps helper
- `tests/host/runtime/test_docker.py`, `tests/host/runtime/test_host_limits.py`

## Public API (docker.py)
```python
@dataclass(frozen=True)
class RuntimeSelection:
    runtime: str            # "runsc" | "runc"
    secure: bool
    warnings: list[str]

class InsecureRuntimeRefused(SandboxError): ...   # from blastbox.errors

def select_worker_runtime(*, available_runtimes: Iterable[str] | None = None) -> RuntimeSelection:
    """Detect (or accept injected) runtimes; prefer runsc; honor BLASTBOX_WORKER_RUNTIME override;
    fail closed (raise InsecureRuntimeRefused) when BLASTBOX_REQUIRE_SECURE_RUNTIME is set and the
    chosen runtime is not secure."""

def build_worker_docker_run_argv(
    *, image: str, input_path: Path, input_mount_path: str, output_dir: Path, output_mount_path: str,
    worker_argv: Sequence[str], runtime: RuntimeSelection, container_name: str | None = None,
    worker_uid: int = 10001, worker_gid: int = 10001, workdir: str = "/tmp",
    labels: Mapping[str, str] | None = None, extra_env: Mapping[str, str] | None = None,
) -> list[str]:
    """Build a narrow, hardened `docker run` argv (a LIST — no shell)."""
```

## Security requirements (review WILL check these)
1. **argv is always a Python list** (no `shell=True`, no string-built commands). No job-derived value
   (image, paths, container_name, labels, extra_env) can introduce a *new* flag: `extra_env` becomes
   single `-e KEY=VALUE` tokens; mounts are `-v src:dst:ro|rw` single tokens; everything attacker-
   adjacent lands in a value position, never a flag position.
2. **Every hardening flag present**, unconditionally: `--rm`, `--runtime=<sel>`, `--user UID:GID`,
   `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--read-only`,
   `--memory` + `--memory-swap` (swap disabled = equal), `--pids-limit`, `--cpus`, `--ulimit nofile`,
   input bind **`:ro`**, output bind `:rw`, `--tmpfs /tmp:...,nosuid,noexec`. Resource caps come from
   `BLASTBOX_WORKER_{MEMORY,PIDS_LIMIT,CPUS,NOFILE}` env (defaults from host_limits).
3. **Fail-closed**: `BLASTBOX_REQUIRE_SECURE_RUNTIME` truthy + chosen runtime not secure → raise
   `InsecureRuntimeRefused` (don't silently downgrade). `runsc` preferred; missing runsc → runc with a
   recorded warning (and the fail-closed gate if required). `BLASTBOX_WORKER_RUNTIME=runc|runsc` forces.
4. **gVisor opt-in**: under `runsc`, set `-e BLASTBOX_WARN_ON_INSECURE=1` (gVisor virtualizes
   /proc so the in-worker hardening self-checks can't observe host-applied flags — same rationale as
   ClippyShot). Under runc, leave it unset (strict).
5. **Optional MAC layers attached only if the operator wired host paths** (`BLASTBOX_SECCOMP_JSON_HOST`
   → `--security-opt seccomp=<path>`; apparmor profile if loaded) — else record a warning, don't fail.
6. Runtime detection via `docker info --format '{{json .Runtimes}}'`; on any error return empty set
   (caller's fail-closed logic decides). Never trust a job field to pick the runtime/image.

## host_limits.py
Generalize: read host CPU count + total memory, derive sane default worker `--memory`/`--cpus`/
`--pids-limit`/nofile (e.g. a fraction of host, floored/capped), overridable by the `BLASTBOX_WORKER_*`
env. Pure computation, unit-testable with injected cpu/mem values.

## Tests (TDD)
- `select_worker_runtime`: `["runsc","runc"]`→runsc/secure; `["runc"]`→runc/insecure+warning;
  `BLASTBOX_REQUIRE_SECURE_RUNTIME=1` + `["runc"]`→raises `InsecureRuntimeRefused`;
  `BLASTBOX_WORKER_RUNTIME=runc` forces runc even when runsc present; empty set + require-secure → raises.
- `build_worker_docker_run_argv`: assert each required flag (#2) is present; argv is a `list[str]`;
  input bind ends `:ro`, output `:rw`; `extra_env={"K":"V; --privileged"}` yields exactly one token
  `-e K=V; --privileged` and `--privileged` is NOT a standalone argv element (no flag injection);
  a `container_name`/`image` containing shell metachars stays a single value token; runsc sets the
  warn-on-insecure env, runc doesn't; missing seccomp host path records a warning not a failure.
- `host_limits`: injected (cpus, mem_bytes) → expected default caps; env override wins; floors/ceilings.

## Finish
`.venv/bin/pytest tests/ -q` all pass (incl. contract/jobs/trust), mypy + ruff clean. Don't push.
