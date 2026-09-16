# Credential-free egress FORWARDER — the "global mode" stand-in for a real exit sidecar.
#
# THE WHOLE TRICK: the gateway address a worker routes to is identical in both modes. In
# per-host mode 172.31.0.10 IS the OpenVPN client (holding provider credentials). In
# global mode this container occupies that same address and simply forwards over the
# WireGuard overlay to the ONE host that runs the real sidecars. Personalities, netd
# flags, worker labels and routes are byte-identical either way — a node's mode is just
# which container sits at that IP.
#
# It holds NO credentials. A compromised worker node yields a wg tunnel, never a VPN
# profile or a proxy key. That is the reason to centralise exits rather than copy secrets
# to every node.
#
# WHERE THE FAIL-CLOSED PROPERTY ACTUALLY LIVES — this said the opposite for a while,
# which is worse than saying nothing, because it is the first thing a reader consults
# before changing the container. It claimed "the default route inside points at the
# overlay peer, so if WireGuard is down there is nowhere for packets to go". It does
# not. entrypoint.sh cannot install such a route (the peer is not on-link from a docker
# bridge; the kernel rejects a `via` it cannot reach directly), says so explicitly, and
# instead MASQUERADEs the worker subnet out its own uplink — which reaches the node's
# WAN. Nothing inside this container stops a packet once its startup gate has passed.
#
# Fail-closed is enforced ENTIRELY node-side, by blastbox.host.egress
# .forwarder_source_route_steps: an `ip rule` sending our source address to a table whose
# only route is the tunnel, a blackhole rule behind it so an empty table cannot fall
# through to main, and the BB-WG-FWD chain's DROP. This container's contribution is to
# EXIT when the overlay dies, so the gateway address goes empty and the worker's default
# route points at nothing. Do not read anything here as a second, independent guard.
#
#   docker build -t blastbox-egress-forwarder:dev deploy/egress-forwarder
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 iputils
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
LABEL org.opencontainers.image.title="blastbox-egress-forwarder" \
      org.opencontainers.image.description="Credential-free forwarder: worker bridge -> WireGuard overlay -> central exit sidecar"
