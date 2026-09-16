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

- **It refuses to start if it cannot reach the overlay peer.** Failing to start is correct: it leaves the gateway address empty, the worker's
  default route points at a dead IP, and the tier is closed. A forwarder that came up
  without the node rules would quietly NAT malware onto the node's WAN.
- **It exits when the overlay stays dead**, rather than lingering. The node's DROP rule
  already prevents a WAN escape; a forwarder still advertising an address it can no longer
  serve just turns a hard failure into a slow one. It takes three consecutive failed
  probes (three packets each, 15s apart) to call the overlay dead — a single dropped ICMP
  packet used to be enough, and with `on-failure:3` that made three unrelated blips over
  a week into a permanent node outage.

`blastbox egress apply` runs it with `--restart on-failure:3`, never `unless-stopped` — a
crash-looping container looks healthy in `docker ps` forever. Health is asserted from the
gate log line **of the container's current start** (`docker logs --since` its `StartedAt`;
reading the whole history lets a line from a previous, since-failed start vouch for a
forwarder that is now crash-looping).

The restart count is **reported, not disqualifying**. This README and the `egress` module
docstring both used to say health required a zero restart count; `forwarder_health` takes
`restart_count` as informational only, and deliberately so — ejecting a node from the
dispatch pool permanently because one overlay blip restarted its forwarder is a worse
failure than the one it prevents. What is recovered from should not be held against a
node forever.

## Build

```bash
docker build -t blastbox-egress-forwarder:dev deploy/egress-forwarder
```

`blastbox egress apply --mode global` requires this image to exist and refuses to
start without it — deliberately, and *before* touching a running forwarder, so a
pruned tag cannot turn a working node into an empty gateway address.

## Verify

```bash
sudo blastbox egress check
sudo scripts/test-egress-leak.sh --mode global --gateway-ip 172.31.0.10
```

The leak test is the only thing that proves the tier: it demands a **failed** fetch with
the overlay down, which is the check that catches a source route falling through to the
node's WAN.
