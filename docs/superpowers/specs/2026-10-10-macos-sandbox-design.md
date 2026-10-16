# macOS sandbox backends: `seatbelt` and `appsandbox`

**Status:** implemented on `feat/macos-sandbox` · **Date:** 2026-10-10
**Motivating engine:** William Tells QR Killer (Apple Vision barcode decoding on the Neural Engine)

## Problem

Some engines are only worth running on a Mac because they use Apple's own parsers and ML.
William Tells decodes QR codes exactly the way an iPhone does by calling Vision. Those frameworks
(ImageIO, CoreGraphics, Vision) are high-value exploit targets: FORCEDENTRY went through
CoreGraphics' JBIG2 decoder, and BLASTPASS through ImageIO's WebP decoder. blastbox had no macOS
story:

- `detect.py` only knew the Linux backends, and on a Mac `container` would be an unconfined host
  subprocess.
- The `nono` backend grants `/proc`, `/sys` and `/lib64` and describes Landlock guarantees. It was
  never written for Darwin, even though the `nono` binary itself runs there.
- The per-job VM answer doesn't fit. macOS VMs get no Neural Engine (which breaks "decodes like an
  iPhone"), Apple licensing caps a host at two macOS VMs, and they're slow.

## Decision

Two new worker sandbox backends. Both enforce through Sandbox.kext (Seatbelt), the same kernel
mechanism behind App Sandbox, Safari's helpers and Chrome's renderers:

| | `seatbelt` (auto default) | `appsandbox` (explicit opt-in) |
|---|---|---|
| Attach | `sandbox-exec -p <profile> -D k=v…` | ad-hoc-signed launcher with `com.apple.security.app-sandbox`, which `execv`s the target |
| Profile | per run, `(deny default)` + `system.sb`, built from the request | Apple's application profile + per-slot path exceptions |
| Accelerators | default-deny; `gpu` / `ane` add exactly the needed clients/services | allowed by Apple's profile |
| Mounts | identity (real paths) | staged into the slot's `io/` (APFS clone), args rewritten, rw copied back |
| Setup | none | `blastbox macos prepare --slots N --ro <dirs>` |
| Cost | free | free: ad-hoc signing, no Developer account, no provisioning profile |

Host side: **no new runtime.** A Mac runs the existing `blastbox.worker.http_agent` and is
reached through `static` / `cascade`. A Mac-only deployment points its own dispatcher at
`127.0.0.1:8765`. `dispatch.py` is unchanged.

## Why seatbelt is the default (and App Sandbox isn't "more secure")

App Sandbox is not a stronger mechanism. It's Seatbelt with Apple's general-purpose *application*
profile, which allows the many system services ordinary apps need. A per-run deny-default profile
is strictly narrower. This is what Vision needs on the Neural Engine, measured with
`VNDetectBarcodesRequest` forced to the ANE compute device (macOS 26.6, M4 Pro):

| Grant | Why |
|---|---|
| `(import "system.sb")` | dyld, libSystem, read-only `/System`, `/usr/lib` |
| `file-read-metadata`, `sysctl-read` | path resolution, CPU feature probes |
| `gpu`: user clients `IOSurfaceRootUserClient`, `AGXDeviceUserClient`; service `com.apple.cvmsServ` | Metal / CoreImage |
| `ane`: service `com.apple.appleneuralengine`; user clients `H11ANEIn*`, `H1xANELoadBalancerDirectPathClient`, … | Neural Engine |
| read on the executable's **directory** (a listing, not the subtree) | CFBundle resolves the main bundle; without it Vision fails with "Null bundleID" |
| `ane` also: `file-issue-extension`, read class only, for the scratch dir only | Vision compiles its ANE plan into the per-run cache, then gives the **out-of-process** `ANECompilerService` a read extension for it. Without this, a cold compile fails ("Cannot load network …"). It lets a system service read files this run wrote, and grants the child nothing. |
| a fresh scratch dir as `HOME` / `CFFIXED_USER_HOME` / `TMPDIR` | Vision's E5RT model cache goes there, not into the shared `~/Library/Caches` |

Still denied while decoding works: LaunchServices, TCC, Contacts, DiskArbitration, the window
server, the shared per-user Metal shader cache (`$DARWIN_USER_CACHE_DIR`), the user's home, all
network.

`appsandbox` exists for operators who want the confinement carried by a code signature (a
mis-built argv can't skip it), on a mechanism Apple documents and supports. `sandbox-exec(1)` is
marked deprecated, though it still ships in macOS 26 and is used widely. If it disappears,
selection falls through to `appsandbox`.

## The failure mode that matters: silent false negatives

A grant that's too narrow usually doesn't crash Vision; it returns **no detections with exit 0**.
This was seen twice while building the profile: the E5RT cache dir denied, then the missing
bundle id. For a scanner, "nothing found" is a plausible verdict, so a sandbox regression would
look like a clean result. Hence:

- `blastbox macos doctor -- <cmd>` runs an engine's **known-positive self-test** under the backend
  with the engine's accelerators. The command must exit non-zero when it finds nothing.
- Engines that use accelerators should run the same self-test in `warmup()` and refuse to serve if
  it fails.
- `ANE_USER_CLIENTS` is per chip generation. A new Apple silicon generation with a new class name
  shows up as a self-test failure, not as quietly wrong results.

## Warm caches without cross-job state: `seed_home` / `capture_home`

Per-run isolation means every run starts with an empty cache, so Vision **recompiles its Neural
Engine plan for every image**. Two optional `SandboxRequest` fields recover that cost without
sharing writable state:

- `capture_home=DIR`: after a successful run, `DIR` gets the run's scratch HOME (minus `tmp/`).
  **Trusted runs only.** The engine uses it for its self-test on a generated QR code, never on
  job input.
- `seed_home=DIR`: before a run, `DIR` is cloned (APFS copy-on-write, no-follow, size-capped)
  into the fresh scratch. The child can change its copy, but nothing flows back. A real-sandbox
  test on each backend has a child overwrite a seeded file and checks that the seed and the next
  run still see the original.
- On `appsandbox` the frameworks put caches in the slot **container**
  (`~/Library/Containers/<id>/Data`), ignoring `HOME`/`CFFIXED_USER_HOME`, so both fields target
  the container there.

Measured per-image latency, `wtqrk-scan scan` of a QR PNG, median of 8 runs (M4 Pro, macOS 26.6):

| | ms / image |
|---|---|
| unsandboxed CLI (persistent user cache) | 87 |
| `seatbelt`, empty cache per run | 1147 |
| `seatbelt`, seeded | 153 |
| `appsandbox`, empty cache per run | 1051 |
| `appsandbox`, seeded | 95 |

## Engine-side lesson: frameworks write to stdout

Apple's E5RT runtime prints diagnostics to **fd 1**, which corrupted the CLI's JSON (`Extra data`)
during development. An engine CLI that reports on stdout should duplicate the real stdout at
startup, point fd 1 at stderr, and write its result only to the duplicate. `wtqrk-scan` does this.

## Mechanics shared by both backends (`macos_common.py`)

- Env built from scratch: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, scratch `HOME`/`TMPDIR`/
  `CFFIXED_USER_HOME`. A request can't override those keys.
- `start_new_session`, stdin closed, `close_fds`, wall-clock timeout, then SIGKILL of the group
  (`kill_sandbox_group`).
- rlimits Darwin actually enforces: `FSIZE`, `NOFILE`, `CPU`, `CORE`. `RLIMIT_AS` isn't enforced by
  XNU, so `Limits.memory_bytes` is a **process-group RSS watchdog** (polling `ps`, SIGKILL over the
  limit). `RLIMIT_NPROC` is per-user on Darwin and is deliberately left unset.
- `Limits.net_egress` is **ignored, so the network stays denied**. On Linux it means "share the
  netd-steered netns"; macOS has no rooter, so honouring it would be direct host egress.
- argv[0] is exec'd **as invoked** (a venv's `bin/python` symlink must stay the invoked path or the
  venv disappears), and both it and its resolved target are granted.

### seatbelt specifics
- Paths never appear in the profile text. Each one is `(param "RO_3")` with
  `-D RO_3=<path>`, so a path containing `")(allow default)(` is inert (tested).
- Identity mounts only (no mount namespace). A remapped mount is refused rather than silently
  ignored.

### appsandbox specifics
- **Generic launcher.** One signed launcher per slot runs *any* unsigned target via `execv`. The
  sandbox survives exec, and nothing is signed per engine. The launcher calls `sandbox_check` and
  exits 70 if it isn't sandboxed, so a stripped signature fails closed (tested).
- **Slots.** Entitlement path exceptions are fixed at signing, so `prepare` builds N slots: N bundle
  ids, N containers, each granted read-write only on its own `io/`. Concurrency is the slot count
  (`flock`). `--ro` paths may not overlap the root, which would let slots read each other's I/O.
- **Staging.** Mounts are APFS-cloned into `io/`. argv/env tokens naming a mount (whole token, a
  `target/…` prefix, or `--flag=PATH`) are rewritten. rw mounts are mirrored back with bind-mount
  semantics, no-follow and size-capped: symlinks are recreated, never followed; FIFOs and devices are
  skipped, so a planted FIFO can't hang the worker.
- **Wipe.** `io/` and `~/Library/Containers/<bundle-id>/Data/*` are emptied before and after every
  run. The container's metadata plist is system-protected; `Data/` is not, and wiping it was verified
  to remove state between runs.
- Measured gotchas: a bare executable with the entitlement crashes (SIGTRAP) unless it's inside a
  bundle with a complete Info.plist (`CFBundleExecutable`, `CFBundlePackageType`). A target that is
  itself signed with an app-sandbox entitlement but without `com.apple.security.inherit` is killed
  with SIGTRAP (the backend appends a hint). `/usr/bin/python3` (the xcrun shim) refuses to run under
  App Sandbox.

## Selection

`detect.py` asks `base.host_platform()`. On macOS auto mode tries `seatbelt`, then `appsandbox`
(skipped unless prepared); it never tries a Linux backend or `container`. Forcing a backend built
for the other OS raises `SandboxUnavailable` (no substitution). `NonoSandbox` refuses on Darwin and
points at `seatbelt`. The existing Linux selection tests run on any host through an autouse fixture
that simulates Linux; macOS tests opt out with `@pytest.mark.host_platform`.

## Not done / follow-ups
- Egress on macOS (an analogue of netd): out of scope; macOS stays fail-closed.
- Stacking both backends (sandbox-exec inside App Sandbox): untested.
- Running under a LaunchDaemon (no GUI session) hasn't been verified for Metal/ANE access.
- EC2 `mac2*` hosts: not yet verified (expected to match: same macOS, bare metal).


## Addendum: native agents, and why not XPC (measured 2026-10-10)

An engine that is native code can skip both backends and the Python agent: serve the worker
protocol itself and spawn its parser App-Sandboxed (William Tells' `wtqrk-worker`). Measured on an
M4 Pro, macOS 26.6:

- **A directly spawned, App-Sandboxed tool works per image.** Sign it ad hoc with
  `com.apple.security.app-sandbox` and an embedded Info.plist; the kernel sandboxes it at exec,
  whoever launches it. Hand it the input as an inherited fd (stdin) and it needs no path
  exception at all. About 105 ms per image with a warm plan cache, on the Neural Engine.
- **The container is keyed by the signing identifier**, not the Info.plist bundle id: re-sign a
  clone with `codesign -i <id>.slotN` to give each concurrent slot its own container.
- **App Sandbox lets a program read its own executable's directory.** Keep slot directories free
  of anything but the binary, and never stage input there. A confinement probe with a canary
  beside the binary caught this.
- **XPC can't do one-process-per-image.** An app-sandboxed XPC service decodes fine (fd passing
  works), but launchd delays relaunching any service that exited (cleanly or by SIGKILL) within
  10 s of starting: every image after the first took 10.1 s. Reusing one service process across
  images would avoid that and give up the per-image process. Only private API
  (`_MultipleInstances` + `xpc_connection_set_instance`) gets around it.
