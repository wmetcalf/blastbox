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
sudo aa-status | grep blastbox          # verify both are loaded
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
`bwrap`/`nsjail` backends and for `runsc` run rootless. See **[../../docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)**.

---

## What these two profiles do NOT do

They enable a user namespace for one binary each. **They do not confine the sandboxed child**, and
nothing else in this repository does either today. Worth stating plainly, because a directory named
`deploy/apparmor` invites the opposite assumption.

Both backends accept an `apparmor_profile`, defaulting to **`blastbox-sandbox`** — a profile this
repository does not ship and which is therefore absent on every host. Consequences, measured on a
real AppArmor host by launching each backend through its own argv builder and reading
`/proc/self/attr/current` from inside:

```
nsjail child -> <binary-profile> (unconfined)
bwrap  child -> <binary-profile> (unconfined)
```

The child inherits the `unconfined`-flagged profile attached to the sandbox binary above. bwrap says
so — `apparmor_missing` appears in `insecurity_reasons` and the backend is not `secure`. nsjail says
nothing, for a reason worth knowing:

| | can a MAC profile be attached to the child? |
|---|---|
| **bwrap** | **Yes.** `aa-exec -p <profile> --` is prefixed to the inner argv; `/proc/self/attr/exec` is writable inside, so the transition reaches the kernel. It needs only a profile that exists. |
| **nsjail** | **Not as shipped.** `--proc_apparmor` does not exist in any upstream nsjail (checked against 3.6 and the installed build), and the userspace route fails with `aa-exec: ERROR: Read-only file system` because nsjail mounts `/proc` read-only. Adding `--proc_rw` does make the transition reach the kernel, with `/proc/sys` still read-only — see [#160](https://github.com/wmetcalf/blastbox/issues/160), which is where that trade-off is being decided. |

So on the current release the inner sandboxes rest on **namespaces plus seccomp** (kafel for nsjail,
a BPF denylist for bwrap), not on MAC. That is a real boundary, and it is the one you are getting.

To attach a real child profile today, write an enforcing profile for the parser workload, load it,
and point the backend at it by name:

```sh
sudo apparmor_parser -r -W /etc/apparmor.d/my-parser-profile
sudo aa-status | grep my-parser-profile      # must read `(enforce)` -- see below
```

```python
BubblewrapSandbox(apparmor_profile="my-parser-profile")
```

The name must be a profile loaded in **`enforce`** or **`kill`** mode. `complain` logs and allows,
`unconfined` confines nothing, and prompt mode (which securityfs prints as `user`) refers the
decision to an agent outside this system — none of those are treated as confinement, and a profile
in one of them is reported as `apparmor_missing` rather than silently attached. On a host where the
worker cannot read `/sys/kernel/security/apparmor/profiles`, assert what is loaded with
`BLASTBOX_APPARMOR_PROFILES=name1,name2`.

Attaching a profile that is **not** loaded is not a degraded mode — it fails the exec and breaks
every run — which is why both backends confirm the profile before attaching it, and re-confirm it
per launch rather than trusting a snapshot taken at startup.
