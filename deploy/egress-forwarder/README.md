# Egress forwarder

The credential-free stand-in for an exit sidecar, used by `blastbox egress --mode global`.

## Why it is shaped this way

The obvious way to give every worker node a VPN exit is to run a VPN client on every
node. That means copying the provider profile to every node, and a node compromise then
yields the profile. This container exists so exactly one host holds credentials and every
other node reaches it over a WireGuard overlay.

**It occupies the same gateway address a real sidecar would.** In per-host mode
`172.31.0.10` *is* the OpenVPN client; in global mode it is this container. Personalities,
netd flags, worker labels and the in-netns routes are byte-identical either way — a node's
mode is only ever *which container sits at that address*, which is why neither mode needed
a change to `netwire.gateway_route_commands`.

It holds no credentials. A compromised worker node yields a WireGuard transport key, never
a VPN profile or a proxy key.

## What it does not do

**It is plumbing, not enforcement.** It cannot put its own default route on the overlay —
the peer address is not on-link from inside a docker bridge, and the kernel rejects a `via`
whose gateway it cannot reach directly. The real packet path is
`worker → forwarder → the node → wg`, and the node-side `ip rule` + DROP pair installed by
`blastbox egress apply` is what makes that binding enforceable. See
`blastbox.host.egress` for the four ways this arrangement fails open.

Two behaviours are therefore deliberate and should not be "fixed":

- **It refuses to start if it cannot reach the overlay peer.** Only the node's source route
  can make that probe succeed, so reachability is positive proof that node-side enforcement
  is live. Failing to start is correct: it leaves the gateway address empty, the worker's
  default route points at a dead IP, and the tier is closed. A forwarder that came up
  without the node rules would quietly NAT malware onto the node's WAN.
- **It exits when the overlay later dies**, rather than lingering. The node's DROP rule
  already prevents a WAN escape; a forwarder still advertising an address it can no longer
  serve just turns a hard failure into a slow one.

`blastbox egress apply` runs it with `--restart on-failure:3`, never `unless-stopped` — a
crash-looping container looks healthy in `docker ps` forever, and health is asserted from
its gate log line plus a zero restart count.

## Build

```bash
docker build -t blastbox-egress-forwarder:dev deploy/egress-forwarder
```

`blastbox egress apply --mode global` builds it automatically if the tag is absent.

## Verify

```bash
sudo blastbox egress check
sudo scripts/test-egress-leak.sh --mode global --gateway-ip 172.31.0.10
```

The leak test is the only thing that proves the tier: it demands a **failed** fetch with
the overlay down, which is the check that catches a source route falling through to the
node's WAN.
