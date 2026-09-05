# AppArmor: scoped user-namespace enablement for bwrap / nsjail

On **Ubuntu 24.04+** (and similar hardened kernels) `kernel.apparmor_restrict_unprivileged_userns=1`
blocks the unprivileged user namespaces that the `bwrap` and `nsjail` inner-sandbox backends need.
Without a fix, those backends can't start and `select_sandbox` falls through to `container`.

There are three ways to enable them; **use the scoped profiles** (option 1):

## 1. Scoped per-binary profiles (recommended)

These two profiles grant **only** the `userns` capability to **one specific binary each** — the
host-wide restriction stays in force for everything else. Reboot-persistent.

```sh
# adjust the binary paths inside each profile first if `which bwrap`/`which nsjail`/`which runsc` differ
sudo cp blastbox-bwrap blastbox-nsjail blastbox-runsc /etc/apparmor.d/
sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-bwrap
sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-nsjail
sudo apparmor_parser -r -W /etc/apparmor.d/blastbox-runsc      # only if you run runsc ROOTLESS
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

Verify it took effect (test the **binary**, not `unshare` — the grant is per-binary):

```sh
bwrap --unshare-user --uid 0 --ro-bind / / -- /bin/true && echo "bwrap userns OK"
```

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

bwrap says so: `apparmor_missing` appears in `insecurity_reasons` and the backend is not `secure`.
nsjail does not, and the asymmetry is deliberate rather than an oversight — it only evaluates the
profile when the installed nsjail advertises `--proc_apparmor`, which no upstream build does, so on
a stock nsjail a complain, unconfined, or entirely absent profile produces **no reason at all**.
Whether that should change is [#160](https://github.com/wmetcalf/blastbox/issues/160); it is not a
free fix, because nsjail is first in the auto-selection order and making it permanently non-`secure`
would silently move every deployment to another backend.

| | can a MAC profile be attached to the child? |
|---|---|
| **bwrap** | **Yes.** `aa-exec -p <profile> --` is prefixed to the inner argv; `/proc/self/attr/exec` is writable inside, so the transition reaches the kernel. It needs only a profile that exists. |
| **nsjail** | **Not as shipped.** `--proc_apparmor` does not exist in any upstream nsjail (checked against 3.6 and the installed build), and the userspace route fails with `aa-exec: ERROR: Read-only file system` because nsjail mounts `/proc` read-only. Adding `--proc_rw` does make the transition reach the kernel, with `/proc/sys` still read-only — see [#160](https://github.com/wmetcalf/blastbox/issues/160). |

So on a default installation the inner sandboxes rest on **namespaces, plus seccomp where its
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

export BLASTBOX_SANDBOX=bwrap
export BLASTBOX_APPARMOR_PROFILE=my-parser-profile
```

**Both variables are needed, and the first is the one that is easy to miss.** `select_sandbox` tries
nsjail before bwrap, and a stock nsjail cannot attach a profile *and* records no `apparmor_missing`
for it — so on a host with a working nsjail it passes selection, and the profile you carefully
loaded is simply never applied, silently. Setting `BLASTBOX_SANDBOX=bwrap` picks the backend that
can actually carry it. (Check the result rather than trusting the recipe: the selected sandbox's
`apparmor_active` is the attach outcome, not a capability probe.)

`BLASTBOX_APPARMOR_PROFILE` is what a deployed worker needs: the sandbox it uses comes from
`select_sandbox`, which constructs the backend with no arguments, so passing `apparmor_profile=` to
a constructor only works if you are building the sandbox yourself in code (where the explicit
argument wins over the variable).

The profile must be loaded in **`enforce`** or **`kill`** mode. `complain` logs and allows,
`unconfined` confines nothing, and prompt mode (which securityfs prints as `user`) refers the
decision to an agent outside this system; none of those count as confinement. Under bwrap — and
under an nsjail patched to support attachment — a profile in one of those modes is reported as
`apparmor_missing` rather than silently attached. The mode is re-read on every launch, so switching
a profile to complain under a running worker stops the attachment and shows up in
`insecurity_reasons` instead of going unnoticed.

Attaching a profile that is **not** loaded is not a degraded mode — it fails the exec and breaks
every run — which is why the profile is confirmed before it is attached.

### The `BLASTBOX_APPARMOR_PROFILES` escape hatch (plural)

On a host where the worker cannot read `/sys/kernel/security/apparmor/profiles`, assert what is
loaded with `BLASTBOX_APPARMOR_PROFILES=name1,name2`. Note the trade you are making: an assertion is
believed without reading the kernel, so **the per-launch re-check does not apply to an asserted
profile**. If you unload it, every run fails at exec; if you switch it to complain mode, the backend
goes on reporting confinement that is not being enforced. Prefer making securityfs readable, and use
the assertion only where that is impossible.
