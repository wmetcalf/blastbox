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
