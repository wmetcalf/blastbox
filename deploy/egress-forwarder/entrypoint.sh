#!/bin/sh
# Forward worker traffic from the local internal bridge into the WireGuard overlay so it
# exits at the ONE host that holds the provider credentials.
#
# WHERE ENFORCEMENT ACTUALLY LIVES — READ THIS BEFORE CHANGING ANYTHING HERE.
# This container cannot put its own default route on the overlay: the peer address
# (10.77.0.1) is not on-link from inside a docker bridge, and the kernel rejects a `via`
# whose gateway it cannot reach directly ("Nexthop has invalid gateway"). So the packet
# path is: worker -> us (172.31.0.10) -> our uplink next hop = the NODE -> the node
# source-routes us into wg. The node-side ip rule/DROP pair installed by
# 'blastbox egress apply --mode global' (blastbox.host.egress.forwarder_source_route_steps)
# is the enforcement; we are the plumbing.
#
# WHICH MEANS WE MUST NOT TRUST OUR OWN UPLINK. Left alone, our default route reaches the
# node's WAN — precisely the leak the tier exists to prevent. Two things stop that:
#   1. FORWARD policy DROP first, before any route is touched.
#   2. A startup gate: we must be able to reach the overlay peer. If it fails we EXIT,
#      leaving nothing at the gateway address — the worker's default route then points
#      at a dead IP and the tier is closed.
#      WHAT THIS GATE DOES **NOT** PROVE: that node-side enforcement is installed. The
#      peer address is inside the overlay prefix, and the node's priority-99
#      "to <overlay> lookup main" rule sorts AHEAD of the source route, the blackhole
#      guard and the BB-WG-FWD chain — so this probe is resolved out of the main table
#      without consulting any of them. It proves the TUNNEL is up, nothing more. The
#      node checks containment itself, from where the rules are visible:
#      blastbox.host.egress_apply.enforcement_present. Do not re-describe this gate as
#      a containment proof; an earlier version of this comment did, and the claim was
#      false in a way that made a degraded node report healthy.
# Failing to start is the correct outcome. A forwarder that comes up without the node
# rules is a forwarder that quietly NATs malware onto the node's WAN.
#
#   BLASTBOX_UPSTREAM_GW   overlay address of the central exit host (e.g. 10.77.0.1) [required]
#   BLASTBOX_WORKER_SUBNET local worker subnet to serve            (default 172.31.0.0/16)
#   BLASTBOX_UPLINK_GW     next hop toward the node       (default: the existing default route)
#   BLASTBOX_GATE_RETRIES  startup gate attempts, 2s apart               (default 15)
set -eu
UP="${BLASTBOX_UPSTREAM_GW:?BLASTBOX_UPSTREAM_GW is required (overlay IP of the exit host)}"
SUBNET="${BLASTBOX_WORKER_SUBNET:-172.31.0.0/16}"
# Consecutive failed probes (each 3 packets, 15s apart) before we call the overlay
# dead. 3 => ~45s of sustained silence, comfortably longer than a wg re-key.
LOSS_THRESHOLD="${BLASTBOX_FORWARDER_LOSS_THRESHOLD:-3}"
RETRIES="${BLASTBOX_GATE_RETRIES:-15}"

UPLINK_GW="${BLASTBOX_UPLINK_GW:-$(ip route show default | awk '/default/{print $3; exit}')}"
UPLINK_IF="$(ip route show default | awk '/default/{print $5; exit}')"
[ -n "$UPLINK_GW" ] && [ -n "$UPLINK_IF" ] || {
  echo "forwarder: no uplink route — cannot reach the overlay; refusing to start" >&2; exit 1; }

# 1. Fail closed BEFORE anything else. Nothing is forwarded until a rule says so.
iptables -P FORWARD DROP

# 2. THE GATE RUNS BEFORE THE PLUMBING, and the order is the point.
#
# The first version installed the MASQUERADE and the forwarding ACCEPT here and probed
# afterwards — so for the whole retry window (15 tries x 2s = ~30s) the container was
# fully forwarding worker traffic to the node while still deciding whether node-side
# enforcement existed. `--restart on-failure:3` repeated that up to four times, about two
# minutes of live forwarding per boot. The file's own claim ("if it fails we EXIT, leaving
# nothing at the gateway address") and the CI assertion both describe the END state and
# neither covered that window.
#
# It is reachable on an ordinary reboot: dockerd restores this container before
# blastbox-egress.service can run (the unit is After=docker.service by design), so the
# node has no source route and no BB-WG-FWD, and docker's own terminal ACCEPT for the
# non-internal bb-net0 bridge would carry those packets out of the node's WAN.
#
# Reaching the overlay peer proves the node IS source-routing us — only its rules can
# make that succeed. So: prove it first, forward second.
n=0
until ping -c1 -W2 "$UP" >/dev/null 2>&1; do
  n=$((n+1))
  [ "$n" -lt "$RETRIES" ] || {
    echo "forwarder: overlay peer $UP unreachable after ${RETRIES} tries." >&2
    echo "forwarder: node-side source routing is missing or wg is down. Exiting so the" >&2
    echo "forwarder: gateway address stays empty and the tier fails CLOSED." >&2
    exit 1; }
  sleep 2
done

# 3. Only now is it safe to carry traffic.
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$UPLINK_IF" -j MASQUERADE
iptables -A FORWARD -s "$SUBNET" -o "$UPLINK_IF" -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "forwarder: overlay peer $UP reachable via ${UPLINK_IF}/${UPLINK_GW}"
echo "forwarder: serving $SUBNET (fail-closed; holds no provider credentials)"

# 3. Stay closed if the overlay later dies. The node's DROP rule already prevents a WAN
#    escape, but a forwarder advertising a gateway address it can no longer serve just
#    turns a hard failure into a slow one. Exit and let the worker hit a dead route.
#
#    A THRESHOLD, NOT A SINGLE PACKET. This was `while ping -c1 -W2 "$UP"; do sleep 15;
#    done` — one probe, one packet, no retry. Any single loss (ICMP rate limiting on the
#    exit host, a handshake re-key taking longer than 2s, ordinary WAN jitter) ended the
#    container. That matters because `--restart on-failure:3` is deliberate and
#    RestartCount is monotonic for the container's life: three such blips, days apart,
#    spend the budget and leave the forwarder Exited for good. The overlay being down is
#    a sustained condition; require evidence of one.
LOST=0
while :; do
  if ping -c3 -W3 -i 0.3 "$UP" >/dev/null 2>&1; then
    if [ "$LOST" -gt 0 ]; then
      echo "forwarder: overlay peer $UP answered again after ${LOST} failed probe(s)" >&2
    fi
    LOST=0
  else
    LOST=$((LOST + 1))
    echo "forwarder: overlay peer $UP did not answer (${LOST}/${LOSS_THRESHOLD})" >&2
    if [ "$LOST" -ge "$LOSS_THRESHOLD" ]; then
      echo "forwarder: lost the overlay peer $UP for ${LOST} consecutive probes — exiting to fail closed" >&2
      exit 1
    fi
  fi
  sleep 15
done
