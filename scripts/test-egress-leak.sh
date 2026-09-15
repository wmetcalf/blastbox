#!/usr/bin/env bash
# blastbox egress LEAK TEST — the only thing that actually proves the tier.
#
# A setup script that reports "installed" has demonstrated nothing. What matters is two
# facts, in order:
#
#   1. BEFORE wiring, a worker on the internal bridge CANNOT reach the internet.
#   2. AFTER wiring, it reaches the internet AND its source IP is the proxy's, not ours.
#
# Fact 1 is the one people skip, and it is the one that matters: a tier that egresses
# correctly but would ALSO egress when the proxy is down is not fail-closed, it is
# merely configured. This test FAILS if the pre-wiring fetch succeeds.
#
# It also compares the worker's exit IP against the HOST's own exit IP. Equal means the
# traffic went out our WAN — a leak — even if the fetch "worked".
#
# Setup lives in `blastbox egress` (see docs/DEPLOYMENT.md). This script is the PROOF,
# kept separate on purpose: a setup tool reporting its own success proves nothing.
#
#   sudo scripts/test-egress-leak.sh                 # uses the local sidecar
#   sudo scripts/test-egress-leak.sh --proxy socks5://user:pass@host:port
#
# GLOBAL (overlay) MODE adds the checks that only a two-node setup can make: that a
# worker here exits at the CENTRAL host, and — the one that matters — that killing the
# overlay removes its egress instead of dropping it back onto this node's WAN. A silent
# fallback is the whole failure mode the overlay introduces, so it is tested explicitly
# rather than reasoned about.
#
#   sudo scripts/test-egress-leak.sh --mode global --gateway-ip 10.31.0.10
#
# Exit 0 only if fail-closed held AND the exit IP differs from the host's.
set -euo pipefail

BB_SOCKS="${BB_SOCKS:-bb-socks}"
BB_NET0="${BB_NET0:-bb-net0}"
BB_VPN="${BB_VPN:-bb-vpn}"
PROXY=""
TEST_MODE=local; GATEWAY_IP="${VPN_GATEWAY_IP:-172.31.0.10}"
WG_IF="${WG_IF:-bbwg0}"
# An IP-literal endpoint on purpose: an internal bridge has no working DNS until netd
# wires one, and a DNS failure here would look identical to an egress failure.
IP_ECHO="${IP_ECHO:-https://1.1.1.1/cdn-cgi/trace}"
ip_of() { grep -m1 '^ip=' | cut -d= -f2; }
PROBE_IMAGE="${PROBE_IMAGE:-curlimages/curl:latest}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy) PROXY="$2"; shift ;;
    --proxy-file) PROXY="$(tr -d '\r\n' < "$2")"; shift ;;
    --mode) TEST_MODE="$2"; shift ;;
    --gateway-ip) GATEWAY_IP="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ $EUID -eq 0 ]] || { echo "ERROR: needs root" >&2; exit 1; }

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }
info() { printf '  ---- %s\n' "$*"; }

HOST_IP="$(curl -fsS --max-time 15 "$IP_ECHO" 2>/dev/null | ip_of || echo unknown)"
info "host exit IP: ${HOST_IP}"

# Run a probe on the internal worker bridge with its default route pointed at the
# gateway address — exactly what netd does to a real worker's netns, and nothing more.
wired_exit_ip() {
  timeout 60 docker run --rm --network "$BB_VPN" --cap-add NET_ADMIN --user 0 \
    --dns 1.1.1.1 "$PROBE_IMAGE" \
    sh -c "ip route replace default via ${GATEWAY_IP} && curl -fsS --max-time 25 ${IP_ECHO}" \
    2>/dev/null | ip_of || true
}

if [[ "$TEST_MODE" == global ]]; then
  echo "== global (overlay) mode: gateway ${GATEWAY_IP}, overlay ${WG_IF} =="
  docker network inspect "$BB_VPN" >/dev/null 2>&1 || {
    echo "ERROR: $BB_VPN missing — run 'blastbox egress apply --mode global' first" >&2; exit 1; }

  echo "== G1. the forwarder is genuinely healthy, not crash-looping =="
  rc="$(docker inspect -f '{{.RestartCount}}' bb-egress-forwarder 2>/dev/null || echo missing)"
  if docker ps --format '{{.Names}}' | grep -qx bb-egress-forwarder \
     && docker logs bb-egress-forwarder 2>&1 | grep -q 'overlay peer .* reachable'; then
    ok "forwarder up and past its startup gate (restarts=${rc})"
  else
    bad "forwarder is not healthy (restarts=${rc}) — global egress cannot work"
  fi

  echo "== G2. unwired worker on the internal bridge cannot reach the internet =="
  if timeout 40 docker run --rm --network "$BB_VPN" --user 0 --dns 1.1.1.1 \
       "$PROBE_IMAGE" -fsS --max-time 12 "$IP_ECHO" >/dev/null 2>&1; then
    bad "unwired worker REACHED the internet — $BB_VPN is not fail-closed"
  else
    ok "unwired worker has no egress (fail-closed holds)"
  fi

  echo "== G3. a wired worker exits at the CENTRAL host, not ours =="
  WIRED_IP="$(wired_exit_ip)"
  if [[ -z "$WIRED_IP" ]]; then
    bad "wired worker got no egress at all — the overlay path is broken"
  elif [[ "$WIRED_IP" == "$HOST_IP" ]]; then
    bad "wired worker exited as ${WIRED_IP} == this node WAN — traffic never left the box"
  else
    ok "wired worker exited as ${WIRED_IP}, not this node ${HOST_IP}"
  fi

  echo "== G4. overlay DOWN must remove egress, not fall back to our WAN =="
  # THE test. An `ip rule` that matches but finds an empty table falls through to main,
  # so a dead tunnel silently becomes direct WAN egress. That happened here during
  # bring-up and is why a blackhole rule sits behind the lookup. Prove it stays true.
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg-quick down "$WG_IF" >/dev/null 2>&1 || ip link set "$WG_IF" down 2>/dev/null || true
    DOWN_IP="$(wired_exit_ip)"
    if [[ -z "$DOWN_IP" ]]; then
      ok "overlay down => no egress (failed closed)"
    elif [[ "$DOWN_IP" == "$HOST_IP" ]]; then
      bad "LEAK: overlay down and the worker fell back to this node WAN (${DOWN_IP})"
    else
      bad "overlay down but the worker still egressed as ${DOWN_IP}"
    fi
    wg-quick up "$WG_IF" >/dev/null 2>&1 || true
    docker start bb-egress-forwarder >/dev/null 2>&1 || true
    info "overlay restored; re-run --peer-forwarder if the routes did not come back"
  else
    info "SKIPPED: $WG_IF not present"
  fi

  echo
  printf '  %d passed, %d failed\n' "$pass" "$fail"
  [[ $fail -eq 0 ]] || exit 1
  exit 0
fi

docker network inspect "$BB_SOCKS" >/dev/null 2>&1 || {
  echo "ERROR: $BB_SOCKS missing — run 'blastbox egress apply' first" >&2; exit 1; }

echo "== 1. fail-closed: worker on the internal bridge, NOT wired =="
# --network is INTERNAL, so docker installs no default route off the box. A success
# here means the bridge is not actually internal and every downstream claim is void.
if out="$(timeout 40 docker run --rm --network "$BB_SOCKS" "$PROBE_IMAGE" \
            -fsS --max-time 12 "$IP_ECHO" 2>/dev/null | ip_of)"; then
  bad "unwired worker REACHED the internet as ${out} — the bridge is not fail-closed"
else
  ok "unwired worker could not reach the internet (fail-closed holds)"
fi

echo "== 2. the internal bridge really is internal =="
if docker network inspect "$BB_SOCKS" --format '{{.Internal}}' | grep -qx true; then
  ok "$BB_SOCKS is marked internal"
else
  bad "$BB_SOCKS is NOT internal — workers can route off-box without the sidecar"
fi

echo "== 3. wired egress exits via the proxy, not our WAN =="
if [[ -z "$PROXY" ]]; then
  SIDE_IP="$(docker inspect bb-socks-sidecar \
    --format "{{(index .NetworkSettings.Networks \"$BB_SOCKS\").IPAddress}}" 2>/dev/null || true)"
  [[ -n "$SIDE_IP" ]] && PROXY="socks5://${SIDE_IP}:1080"
fi
if [[ -z "$PROXY" ]]; then
  info "SKIPPED: no --proxy and no local sidecar found"
else
  # Prove routing with a cooperative client first (curl --socks5-hostname). This
  # isolates "can the proxy carry our traffic" from "is netd's transparent TUN wired",
  # so a failure here is a proxy/credential problem, not a netd one.
  # Is the proxy LOCAL (on our own bridge) or REMOTE (e.g. BrightData)? A local sidecar
  # egresses via the same WAN we do, so an identical exit IP is EXPECTED and proves
  # nothing. Conflating "traversed the proxy" with "exited elsewhere" would make this
  # test fail on a correct local setup and, worse, pass a remote one that silently fell
  # back to direct. So the two facts are checked separately.
  phost="${PROXY#socks5://}"; phost="${phost#*@}"; phost="${phost%%:*}"
  LOCAL_PROXY=0
  case "$phost" in 172.30.*|172.31.*|172.28.*|172.29.*|127.*|localhost) LOCAL_PROXY=1 ;; esac

  if out="$(timeout 60 docker run --rm --network "$BB_SOCKS" "$PROBE_IMAGE" \
              -fsS --max-time 25 --socks5-hostname "${PROXY#socks5://}" "$IP_ECHO" 2>/dev/null | ip_of)"; then
    ok "worker reached the internet through the proxy (exit IP ${out})"
    if [[ $LOCAL_PROXY -eq 1 ]]; then
      info "local sidecar: exit IP is expected to equal the host's (${HOST_IP}) — it shares our WAN."
      info "this proves the PATH works; it cannot prove anonymisation. Re-run with --proxy"
      info "pointed at the real egress provider to check the exit IP actually differs."
      # Prove the traffic really depended on the proxy rather than leaking around it:
      # with the sidecar stopped, the same fetch MUST fail.
      if docker ps --format '{{.Names}}' | grep -qx bb-socks-sidecar; then
        docker stop bb-socks-sidecar >/dev/null 2>&1 || true
        if timeout 40 docker run --rm --network "$BB_SOCKS" "$PROBE_IMAGE" \
             -fsS --max-time 12 --socks5-hostname "${PROXY#socks5://}" "$IP_ECHO" >/dev/null 2>&1; then
          bad "fetch STILL succeeded with the sidecar stopped — traffic is not going through it"
        else
          ok "fetch fails with the sidecar stopped — the proxy is genuinely in the path"
        fi
        docker start bb-socks-sidecar >/dev/null 2>&1 || true
      fi
    elif [[ "$out" == "$HOST_IP" ]]; then
      bad "remote proxy configured but exit IP == host IP (${out}) — traffic bypassed it"
    else
      ok "remote proxy: exit IP ${out} differs from host ${HOST_IP} — egress is anonymised"
    fi
  else
    bad "worker could not reach the internet through the proxy (proxy down or creds wrong)"
  fi
fi

echo
printf '  %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
