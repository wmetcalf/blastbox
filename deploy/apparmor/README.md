# AppArmor: scoped user-namespace enablement for bwrap / nsjail

On **Ubuntu 24.04+** (and similar hardened kernels) `kernel.apparmor_restrict_unprivileged_userns=1`
blocks the unprivileged user namespaces that the `bwrap` and `nsjail` inner-sandbox backends need.
Without a fix, those backends can't start and `select_sandbox` falls through to `container`.

There are three ways to enable them; **use the scoped profiles** (option 1):

## 1. Scoped per-binary profiles (recommended)

These two profiles grant **only** the `userns` capability to **one specific binary each** — the
host-wide restriction stays in force for everything else. Reboot-persistent.

```sh
# adjust the binary paths inside each profile first if `which bwrap`/`which nsjail` differ
sudo cp blastbox-bwrap blastbox-nsjail /etc/apparmor.d/
sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-bwrap
sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-nsjail

# ONLY if you run runsc rootless -- see below. Do not copy this file otherwise: everything in
# /etc/apparmor.d/ is loaded at boot and on a full policy reload, so copying it "for later"
# grants the exception now, whatever the parser line beside it says.
sudo cp blastbox-runsc /etc/apparmor.d/ && sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-runsc

sudo grep -E '^blastbox-' /sys/kernel/security/apparmor/profiles   # name AND mode of each
```

`blastbox-runsc` is needed only for **rootless** runsc; run as root (the usual Docker
`--runtime=runsc` path) it is exempt from the restriction and the profile is unnecessary.
Without it, a rootless `runsc run` fails with

```
cannot create gofer process: gofer: fork/exec /proc/self/exe: permission denied
```

which never mentions AppArmor. The kernel does, and is worth checking first
(`sudo dmesg -T | grep -i apparmor`):

```
apparmor="DENIED" operation="exec" profile="unprivileged_userns" name="/proc/self/exe" comm="runsc"
```

Verify it took effect (test the **binary**, not `unshare` — the grant is per-binary, so a
passing check for one binary says nothing about another, and the profiles match on the path you
edited above):

```sh
bwrap --unshare-user --uid 0 --ro-bind / / -- /bin/true && echo "bwrap userns OK"
nsjail -Mo --user 0 --group 0 -R / -- /bin/true         && echo "nsjail userns OK"
runsc --rootless do /bin/true                          && echo "runsc rootless userns OK"
```

`-R /` is not decoration: without it nsjail gives the child an empty mount namespace, so
`/bin/true` does not exist inside and the check fails with `Couldn't launch the child process`
(exit 255) on a host where the grant is perfectly fine. All three lines above were run.

The runsc line is the one to run if you installed `blastbox-runsc`. Without the grant it exits
**128** with

```
Error executing inside namespace: re-executing self: fork/exec /proc/self/exe: permission denied
```

(measured on a host with `apparmor_restrict_unprivileged_userns=1` and no `blastbox-runsc`
loaded), which is the same denial that surfaces from a real run as `cannot create gofer process`.

## 2. Run the tests/worker as root

Root isn't subject to the restriction. Fine for CI/integration runs; not a deployment posture.

## 3. Global sysctl — avoid

```sh
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0   # ← host-wide, do NOT use
```

This disables the restriction for **every** process on the host (a system-wide kernel-attack-surface
control) and only lasts until reboot. The scoped profiles above achieve the same for `bwrap`/`nsjail`
without lowering it for anything else.

---

**Not needed for** `firecracker` (a KVM hypervisor — no user namespaces), `nono` (Landlock needs no
userns), or the `container` backend (trusts the enclosing OCI boundary). It is needed for the
`bwrap`/`nsjail` backends and for `runsc` run rootless — which is why there is a profile for each
of those three, `runsc` included. See **[../../docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)**.

---

## What these two profiles do NOT do

They enable a user namespace for one binary each. **They do not confine the sandboxed child**, and
on a default installation nothing else in this repository does either. Worth stating plainly,
because a directory named `deploy/apparmor` invites the opposite assumption.

Both backends attach a profile named by `BLASTBOX_APPARMOR_PROFILE`, defaulting to
**`blastbox-sandbox`** — a profile this repository does not ship. Unless you have loaded one
yourself under that name (or set the variable), it is absent, and the child inherits the
`unconfined`-flagged profile attached to the sandbox binary above. Measured on a real AppArmor host
by launching each backend through its own argv builder and reading `/proc/self/attr/current` from
inside:

```
nsjail child -> <binary-profile> (unconfined)
bwrap  child -> <binary-profile> (unconfined)
```

Both backends say so: `apparmor_missing` appears in `insecurity_reasons` and the backend is not
`secure`. That is new in [#160](https://github.com/wmetcalf/blastbox/issues/160) — nsjail used to
stay silent, because it evaluated the profile only when the installed nsjail advertised
`--proc_apparmor`, a flag no upstream build has ever had. The probe was always False, so nsjail
never attached a profile *and* never reported the lack: a backend with no MAC confinement
whatsoever reporting `secure = True`, while bwrap in the identical situation reported itself
insecure. nsjail now attaches the profile through `aa-exec` like bwrap does, and reports
`apparmor_missing` when it cannot.

Note the consequence for auto-selection, since nsjail is first in the order: on a host with **no
`blastbox-sandbox` profile loaded**, nsjail is no longer `secure`, so `select_sandbox` skips it
(and bwrap, for the same reason) unless `BLASTBOX_WARN_ON_INSECURE=1` is set. Load a profile —
["Attaching a real child profile"](#attaching-a-real-child-profile) below — or set that variable
knowingly.

| | can a MAC profile be attached to the child? |
|---|---|
| **bwrap** | **Yes.** `aa-exec -p <profile> --` is prefixed to the inner argv; `/proc/self/attr/exec` is writable inside, so the transition reaches the kernel. It needs only a profile that exists. |
| **nsjail** | **Yes, since [#160](https://github.com/wmetcalf/blastbox/issues/160).** `--proc_apparmor` does not exist in any upstream nsjail (checked against 3.6, the installed build, and a code search of the whole tree — `apparmor` appears zero times), so the profile is attached the same way bwrap attaches it: `aa-exec -p <profile> --` on the inner argv. That needs one thing from nsjail — `--proc_rw`. aa-exec transitions by writing `/proc/self/attr/exec`, nsjail mounts `/proc` read-only by default, and the write returns `EROFS`, which fails the **execve** — so the prefix without the flag is not weaker confinement, it is every job dying with `aa-exec: ERROR: Read-only file system`. Both are attached together, and only when the profile is confirmed enforcing. |

`--proc_rw` widens `/proc` for the child by more than `/proc/self/attr` — `/proc/self/mem` among
them. The measurement and the profile rules that take that surface back are in
[Attaching a real child profile](#attaching-a-real-child-profile) below; the flag is attached only
alongside an enforcing profile, never by default.

So without a loaded profile the inner sandboxes rest on **namespaces, plus seccomp where its
prerequisites are met** — kafel for nsjail, a BPF denylist for bwrap. Neither filter is
unconditional: bwrap needs `python3-libseccomp` (without it the child runs with no syscall filter
and the backend records `seccomp_not_implemented`), and nsjail needs its kafel policy file
(`seccomp_policy_missing` otherwise). Both of those make the backend non-`secure`, so auto-selection
skips it — unless `BLASTBOX_WARN_ON_INSECURE=1` is set, which lets a degraded backend be chosen.
Check `insecurity_reasons` on the selected sandbox rather than assuming the filter is there.

## Attaching a real child profile

Write an enforcing profile for the parser workload, load it, and name it:

```sh
sudo apparmor_parser -r -W /etc/apparmor.d/my-parser-profile

# Verify the MODE, not just that the name is loaded. `aa-status | grep <name>` cannot do this:
# it groups names under a heading and prints the bare name, so the mode is exactly what the grep
# throws away. Either of these answers the real question:
sudo aa-status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["profiles"]["my-parser-profile"])'
sudo grep "^my-parser-profile " /sys/kernel/security/apparmor/profiles     # -> my-parser-profile (enforce)

export BLASTBOX_APPARMOR_PROFILE=my-parser-profile
```

**One variable, since [#160](https://github.com/wmetcalf/blastbox/issues/160).** This used to also
require `BLASTBOX_SANDBOX=bwrap`, because `select_sandbox` tries nsjail first and a stock nsjail
could not attach a profile *and* reported no `apparmor_missing` for it — so on a host with a working
nsjail, the profile you carefully loaded was never applied, silently, and nothing said so. Both
backends now attach it and both report when they cannot. Still check the result rather than trusting
the recipe: the selected sandbox's `apparmor_active` is the attach outcome, not a capability probe.

**Your profile must also permit `/usr/bin/true`.** `select_sandbox` smoketests each backend by
running it, through the full argv — profile included, because a probe that skips the confinement is
not testing what will actually run. A profile narrow enough to deny the probe's loader and libraries
fails the smoketest, and the backend is rejected. That is now diagnosed rather than blamed on the
backend: the rejection re-runs the probe with the profile suspended and, if that passes, says so —

```
nsjail smoketest fails with AppArmor profile 'my-parser-profile' but passes without it:
the profile denies the probe /usr/bin/true. Permit it in the profile ... or unload the profile
```

— but the fix is yours: `/usr/bin/true ix,` plus whatever your base abstraction needs.

### Measured on a real AppArmor 3.0.4 host

Everything below was verified on Ubuntu 22.04.5 (AppArmor parser 3.0.4) by loading this profile
and launching a child through `aa-exec -p blastbox-sandbox`, the way both backends do. Kernel
answers, not reasoning:

```
profile (from /proc/self/attr/current):  blastbox-sandbox (enforce)
  EACCES  /proc/self/mem
  EACCES  /proc/self/task/<tid>/mem          <- the alias a single-star glob misses
  EACCES  /proc/self/clear_refs
  EACCES  /proc/self/attr/exec
  EACCES  /proc/self/oom_score_adj
getaddrinfo("localhost"):  OK               <- netlink still permitted
```

Both halves were proved, not just the good one. A variant profile carrying the original
`deny /proc/*/mem` was loaded on the same host, and under it `/proc/self/task/<tid>/mem` came back
**WRITABLE** — so the glob distinction is real and this profile closes it. And the same file
declaring `abi <abi/4.0>` does not compile there at all (`Could not open 'abi/4.0'`), which is why
this one pins 3.0.

**The rules your profile needs, because `--proc_rw` widens /proc.** nsjail is launched with
`--proc_rw` whenever a profile is attached, and it has to be: aa-exec transitions by writing
`/proc/self/attr/exec`, and nsjail's default read-only `/proc` turns that into `EROFS`, killing the
exec rather than weakening it.

Measured inside the real argv at the child's uid (65534, user namespace), with `open(O_WRONLY)` —
not `echo`, which fails with `EINVAL` on files that reject the content and reads as "blocked":

| path | default | with `--proc_rw` |
|---|---|---|
| `/proc/self/attr/*`, `/proc/self/mem`, `/proc/self/clear_refs`, `/proc/self/coredump_filter`, `/proc/self/oom_score_adj`, `/proc/1/oom_score_adj`, `/proc/self/{uid,gid}_map` | `EROFS` | **writable** |
| `/proc/sys/**`, `/proc/sysrq-trigger` | `EACCES` | `EACCES` (ownership + userns, not the mount flag) |

`/proc/self/mem` is the one that matters: a payload can rewrite its own read-only and executable
mappings without `mprotect`. Cross-process `/proc/<pid>/mem` is still gated by `ptrace_scope`, so
this is a wider surface inside the jail, not an escape from it — but it is wider than the child had
before, and the profile is what takes it back. The flag and the profile travel together by design:
no profile, no `--proc_rw`, and the child keeps its read-only `/proc`.

So a child profile is not optional hardening here; it is the mitigation for the flag it enables:

```
deny /proc/*/mem rw,
deny /proc/*/clear_refs w,
deny /proc/*/coredump_filter w,
deny /proc/*/oom_score_adj w,
deny /proc/*/{uid,gid}_map w,
deny /proc/*/attr/{current,exec} w,
audit deny change_profile,
```

(The `change_profile` line is belt and braces: a transition out of a confined profile is permitted
only by a rule in the profile being left, so a profile with no `change_profile` rules already
refuses. Reasoned from AppArmor's semantics, not measured — this repo's CI host has no loadable
profile.)

`BLASTBOX_APPARMOR_PROFILE` is what a deployed worker needs: the sandbox it uses comes from
`select_sandbox`, which constructs the backend with no arguments, so passing `apparmor_profile=` to
a constructor only works if you are building the sandbox yourself in code (where the explicit
argument wins over the variable).

The profile must be loaded in **`enforce`** or **`kill`** mode. `complain` logs and allows,
`unconfined` confines nothing, and prompt mode (which securityfs prints as `user`) refers the
decision to an agent outside this system; none of those count as confinement. Under either backend,
a profile in one of those modes is reported as `apparmor_missing` rather than silently attached. The mode is re-read on every launch, so switching
a profile to complain under a running worker stops the attachment and shows up in
`insecurity_reasons` instead of going unnoticed.

Attaching a profile that is **not** loaded is not a degraded mode — it fails the exec and breaks
every run — which is why the profile is confirmed before it is attached.

**AppArmor 3.x is enough for this one.** `blastbox-sandbox` declares `abi <abi/3.0>`, unlike the per-binary profiles here, which need `abi <abi/4.0>` for their `userns` rule. A 3.x parser (Ubuntu 22.04 LTS) has no `abi/4.0`, and this is the profile a host must load for any inner backend to be `secure` — so it stays loadable there.

**Permit a file reader if you want the assertion checked.** The proof below runs
`/bin/cat /proc/self/attr/current` inside the jail. A workload profile that permits only its
parser and `/usr/bin/true` cannot run it — that is reported as *unverified* (a warning naming
this), not as a disproof, so a correctly configured host is never rejected over a diagnostic.
Reaching that state is itself evidence of enforcement, which is why `--proc_rw` is still
attached there: the attach probe succeeded, so the profile exists and permits `/usr/bin/true`, and
the reader then *failed* — but a complain-mode profile denies nothing, so its reader probe would
have succeeded and reported `(complain)`, which disarms. An attaching profile that refuses the
reader is an enforcing one. The residual gap, stated rather than papered over: the reader could
fail for a reason that is not the profile (the seccomp filter blocking a syscall `cat` needs but
`true` does not), which is why this state warns instead of reporting the profile as proven.

Permit `/usr/bin/cat` to have the assertion actually checked — the `/usr` path, because on a
merged-`/usr` host (`/bin` → `usr/bin`) that is what the kernel resolves the exec to and what
AppArmor matches; a rule written as `/bin/cat` never fires.

**An asserted profile is now proved before anything is traded for it.** Because securityfs is
root-only, a non-root worker's only route to "the profile is enforcing" is the assertion below —
and an assertion cannot tell `enforce` from `complain`, while arming on it buys `--proc_rw`. So
when the evidence is an assertion, the backend runs one probe through the jail and reads
`/proc/self/attr/current` from inside: the kernel naming the profile *and* its mode, which cannot
be asserted away. A child that comes back `(complain)`, `unconfined`, or wearing another profile
disarms the attachment and gets `apparmor_missing` instead. A profile the kernel itself reported is
not re-probed.

The proof is **re-measured on a 30-second TTL**, not once at startup: where securityfs is
unreadable the assertion is a static environment variable, so a profile switched to `complain`
under a running worker would otherwise stay "active" for the life of that worker while nothing
enforced anything. One extra jail launch per half-minute is noise next to a detonation; what
matters is that the staleness window is bounded.

### Better than the escape hatch: what the dispatcher measured

A dispatcher-launched worker does not have to rely on the assertion below at all. The dispatcher
runs on the host, where `/sys/kernel/security/apparmor/profiles` is readable, so it measures the
child profile's mode at launch and passes it down as `BLASTBOX_APPARMOR_OBSERVED=<profile>:<mode>`
(both launchers do this: `host/runtime/docker.py` and the gVisor warm/snapshot tier).

That is strictly better evidence than a name a human typed, because it carries the kernel's own
word: a profile the host sees in `complain` becomes a **disproof** in the worker, which an
assertion could never express. It is still not proof that *this child* received the profile — the
in-jail proof supplies that, and an observed profile goes through it exactly like an asserted one.

Nothing to configure; it appears only when the dispatcher could actually read the kernel.

### The `BLASTBOX_APPARMOR_PROFILES` escape hatch (plural)

On a host where the worker cannot read `/sys/kernel/security/apparmor/profiles`, assert what is
loaded with `BLASTBOX_APPARMOR_PROFILES=name1,name2`. Note the trade you are making: an assertion is
believed without reading the kernel, so **the per-launch re-check does not apply to an asserted
profile**. If you unload it, every run fails at exec; if you switch it to complain mode, the backend
goes on reporting confinement that is not being enforced. Prefer making securityfs readable, and use
the assertion only where that is impossible.
