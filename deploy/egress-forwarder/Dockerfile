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
# NOT a NAT to the internet: the default route inside points at the overlay peer, so if
# WireGuard is down there is nowhere for packets to go and the tier fails closed —
# the same property the internal bridge gives us locally.
#
#   docker build -t blastbox-egress-forwarder:dev deploy/egress-forwarder
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 iputils
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
LABEL org.opencontainers.image.title="blastbox-egress-forwarder" \
      org.opencontainers.image.description="Credential-free forwarder: worker bridge -> WireGuard overlay -> central exit sidecar"
