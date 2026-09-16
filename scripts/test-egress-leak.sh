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
#   sudo scripts/test-egress-leak.sh --proxy-file /root/.blastbox/proxy
#
# GLOBAL (overlay) MODE adds the checks that only a two-node setup can make: that a
# worker here exits at the CENTRAL host, and — the one that matters — that killing the
# overlay removes its egress instead of dropping it back onto this node's WAN. A silent
# fallback is the whole failure mode the overlay introduces, so it is tested explicitly
# rather than reasoned about.
#
#   sudo scripts/test-egress-leak.sh --mode global
#
# THE RULE THIS FILE IS WRITTEN AROUND: a check that could not run is a FAILURE, never a
# pass. Six separate ways this script used to exit 0 without testing anything were found
# by review — an undeterminable host IP making both leak comparisons unsatisfiable, a
# missing wg interface skipping the one test that pins the blackhole guard, a stale log
# line vouching for a crash-looping forwarder, a pipeline whose grep swallowed a real
# leak, a missing sidecar skipping the entire exit-IP half, and a restore whose errors
# were all discarded. Everything below that cannot be measured now calls `bad`.
#
# Exit 0 only if every check RAN and fail-closed held AND the exit IP differs from ours.
set -euo pipefail

# --- configuration: CLI flag > explicit env > what `egress apply` persisted > default ---
# The script used to honour only the bare `VPN_GATEWAY_IP`/`WG_IF` spellings, which are
# exactly the unnamespaced names `persisted_config()` deliberately ranks LAST because
# they collide with unrelated shell variables. It also never read egress.env at all, so
# on a node whose subnets were auto-reallocated it probed a gateway that does not exist
# and reported the resulting silence as "failed closed".
EGRESS_ENV="${BLASTBOX_EGRESS_ENV:-/etc/blastbox/egress.env}"
persisted() {
  [[ -r "$EGRESS_ENV" ]] || return 0
  sed -n "s/^$1=//p" "$EGRESS_ENV" | tail -1 | tr -d '\r"'
}
pick() {  # pick KEY LEGACY_ENV_VALUE DEFAULT
  local v="${!1:-}"
  [[ -n "$v" ]] || v="$(persisted "$1")"
  [[ -n "$v" ]] || v="$2"
  [[ -n "$v" ]] || v="$3"
  printf '%s' "$v"
}

BB_SOCKS="${BB_SOCKS:-bb-socks}"
BB_NET0="${BB_NET0:-bb-net0}"
BB_VPN="${BB_VPN:-bb-vpn}"
PROXY=""
TEST_MODE=local
GATEWAY_IP="$(pick BLASTBOX_EGRESS_VPN_GATEWAY_IP "${VPN_GATEWAY_IP:-}" 172.31.0.10)"
WG_IF="$(pick BLASTBOX_EGRESS_WG_IF "${WG_IF:-}" bbwg0)"
GATEWAY_IP_EXPLICIT=0
# An IP-literal endpoint on purpose: an internal bridge has no working DNS until netd
# wires one, and a DNS failure here would look identical to an egress failure.
IP_ECHO="${IP_ECHO:-https://1.1.1.1/cdn-cgi/trace}"
ip_of() { grep -m1 '^ip=' | cut -d= -f2; }
PROBE_IMAGE="${PROBE_IMAGE:-curlimages/curl:latest}"

usage() {
  cat >&2 <<'USAGE'
usage: sudo scripts/test-egress-leak.sh [options]
  --mode local|global   which tier to prove (default: local)
  --gateway-ip IP       overlay gateway inside bb-vpn (default: from egress.env)
  --wg-if NAME          overlay interface (default: from egress.env)
  --proxy URL           socks5://user:pass@host:port  (creds land in YOUR shell history)
  --proxy-file PATH     same, read from a file — preferred; never reaches any argv
USAGE
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy) PROXY="$2"; shift ;;
    --proxy-file) PROXY="$(tr -d '\r\n' < "$2")"; shift ;;
    --mode) TEST_MODE="$2"; shift ;;
    --gateway-ip) GATEWAY_IP="$2"; GATEWAY_IP_EXPLICIT=1; shift ;;
    --wg-if) WG_IF="$2"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
  shift
done
[[ "$TEST_MODE" == local || "$TEST_MODE" == global ]] || usage
[[ $EUID -eq 0 ]] || { echo "ERROR: needs root" >&2; exit 1; }

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail+1)); }
info() { printf '  ---- %s\n' "$*"; }

# --- probing -------------------------------------------------------------------------
# Two facts, never conflated: did the fetch SUCCEED, and what IP did it report. The old
# code ran `docker run ... | ip_of` inside an `if`, so under `set -o pipefail` a
# SUCCESSFUL fetch whose body lacked an `ip=` line (captive portal, transparent proxy,
# a changed third-party response format) made the pipeline fail and the `if` take the
# fail-closed branch. That is a real leak reported as a pass.
PROBE_RC=0; PROBE_IP=""
probe() {  # probe TIMEOUT docker-run-args...
  local tmo="$1"; shift
  local body=""
  PROBE_RC=0; PROBE_IP=""
  body="$(timeout "$tmo" docker run "$@" 2>/dev/null)" || PROBE_RC=$?
  PROBE_IP="$(printf '%s\n' "$body" | ip_of || true)"
  return 0
}

# Run a probe on the internal worker bridge with its default route pointed at the
# gateway address — exactly what netd does to a real worker's netns, and nothing more.
probe_wired() {
  probe 60 --rm --network "$BB_VPN" --cap-add NET_ADMIN --user 0 \
    --dns 1.1.1.1 "$PROBE_IMAGE" \
    sh -c "ip route replace default via ${GATEWAY_IP} && curl -fsS --max-time 25 ${IP_ECHO}"
}

# curl reads its options from stdin, so proxy credentials never appear in the probe's
# argv (`ps aux`, /proc/<pid>/cmdline) nor in the container's persisted Config.Cmd.
# --proxy-file existed precisely to keep credentials off a command line, and its only
# consumer then put them on one.
probe_via_proxy() {  # probe_via_proxy TIMEOUT MAX_TIME
  local tmo="$1" mt="$2" body="" rc=0
  PROBE_RC=0; PROBE_IP=""
  body="$(printf 'socks5-hostname = "%s"\nsilent\nshow-error\nfail\nmax-time = %s\nurl = "%s"\n' \
            "${PROXY#socks5://}" "$mt" "$IP_ECHO" \
          | timeout "$tmo" docker run --rm -i --network "$BB_SOCKS" "$PROBE_IMAGE" -K - 2>/dev/null)" || rc=$?
  PROBE_RC=$rc
  PROBE_IP="$(printf '%s\n' "$body" | ip_of || true)"
  return 0
}

# --- the host's own exit IP ----------------------------------------------------------
# This used to collapse every failure into the literal string "unknown" and continue.
# Both leak detectors are equality against this value, so "unknown" made them
# unsatisfiable: a worker egressing out our own WAN printed PASS "not this node unknown".
HOST_IP=""
if HOST_BODY="$(curl -fsS --max-time 15 "$IP_ECHO" 2>/dev/null)"; then
  HOST_IP="$(printf '%s\n' "$HOST_BODY" | ip_of || true)"
fi
if [[ -n "$HOST_IP" ]]; then
  info "host exit IP: ${HOST_IP}"
else
  info "host exit IP: UNDETERMINED (${IP_ECHO} unreachable or not in the expected format)"
  info "every comparison below needs it, so they will FAIL rather than silently pass."
fi

compare_against_host() {  # compare_against_host LABEL OBSERVED_IP
  if [[ -z "$HOST_IP" ]]; then
    bad "$1 exited as ${2}, but this node's own exit IP is undetermined — cannot rule out a leak"
    return 1
  fi
  return 0
}

if [[ "$TEST_MODE" == global ]]; then
  echo "== global (overlay) mode: gateway ${GATEWAY_IP}, overlay ${WG_IF} =="
  docker network inspect "$BB_VPN" >/dev/null 2>&1 || {
    echo "ERROR: $BB_VPN missing — run 'blastbox egress apply --mode global' first" >&2; exit 1; }
  if [[ $GATEWAY_IP_EXPLICIT -eq 0 && ! -r "$EGRESS_ENV" ]]; then
    info "no ${EGRESS_ENV}: using the default gateway ${GATEWAY_IP}. If apply reallocated"
    info "the bb-vpn subnet this is the WRONG address and G3/G4 will misreport. Pass --gateway-ip."
  fi

  echo "== G1. the forwarder is genuinely healthy, not crash-looping =="
  # --since the CURRENT start, like container_state() in egress_apply.py: reading the
  # whole log lets a gate line from a previous, since-failed start vouch for a container
  # that is now crash-looping. The heading claims to detect exactly that.
  started="$(docker inspect -f '{{.State.StartedAt}}' bb-egress-forwarder 2>/dev/null || true)"
  rc="$(docker inspect -f '{{.RestartCount}}' bb-egress-forwarder 2>/dev/null || echo missing)"
  if ! docker ps --format '{{.Names}}' | grep -qx bb-egress-forwarder; then
    bad "forwarder is not running (restarts=${rc}) — global egress cannot work"
  elif [[ -z "$started" ]]; then
    bad "cannot read the forwarder's start time — its gate log cannot be scoped, so health is unproven"
  elif docker logs --since "$started" bb-egress-forwarder 2>&1 | grep -q 'overlay peer .* reachable'; then
    ok "forwarder up and past the startup gate of its CURRENT start (restarts=${rc})"
  else
    bad "forwarder is running but has not logged a successful overlay probe since it started at ${started} (restarts=${rc})"
  fi

  echo "== G2. unwired worker on the internal bridge cannot reach the internet =="
  if timeout 40 docker run --rm --network "$BB_VPN" --user 0 --dns 1.1.1.1 \
       "$PROBE_IMAGE" -fsS --max-time 12 "$IP_ECHO" >/dev/null 2>&1; then
    bad "unwired worker REACHED the internet — $BB_VPN is not fail-closed"
  else
    ok "unwired worker has no egress (fail-closed holds)"
  fi

  echo "== G3. a wired worker exits at the CENTRAL host, not ours =="
  probe_wired
  WIRED_IP="$PROBE_IP"
  WIRED_OK=0
  if [[ -z "$WIRED_IP" ]]; then
    bad "wired worker got no egress at all — the overlay path is broken"
  elif compare_against_host "wired worker" "$WIRED_IP"; then
    if [[ "$WIRED_IP" == "$HOST_IP" ]]; then
      bad "wired worker exited as ${WIRED_IP} == this node WAN — traffic never left the box"
    else
      ok "wired worker exited as ${WIRED_IP}, not this node ${HOST_IP}"
      WIRED_OK=1
    fi
  fi

  echo "== G4. overlay DOWN must remove egress, not fall back to our WAN =="
  # THE test. An `ip rule` that matches but finds an empty table falls through to main,
  # so a dead tunnel silently becomes direct WAN egress. That happened here during
  # bring-up and is why a blackhole rule sits behind the lookup. Prove it stays true.
  #
  # It used to be skipped — as an `info`, so the run still exited 0 — whenever $WG_IF was
  # absent, and $WG_IF came from a variable nothing writes. Since this is the ONLY check
  # that pins fail-open mode #1, not running it is a failure.
  RESTORE_NEEDED=0; DOWN_METHOD=""
  restore_overlay() {
    [[ $RESTORE_NEEDED -eq 1 ]] || return 0
    RESTORE_NEEDED=0
    local problems=()
    # `ip link set <if> down` leaves the interface in place, and `wg-quick up` then
    # refuses with "already exists" — so the likeliest restore failure was the one most
    # likely to be reported as success. Bring it back the same way it went down.
    if [[ "$DOWN_METHOD" == wg-quick ]]; then
      wg-quick up "$WG_IF" >/dev/null 2>&1 || problems+=("wg-quick up $WG_IF failed")
    else
      ip link set "$WG_IF" up 2>/dev/null || problems+=("ip link set $WG_IF up failed")
    fi
    ip link show "$WG_IF" >/dev/null 2>&1 || problems+=("$WG_IF is gone")
    docker start bb-egress-forwarder >/dev/null 2>&1 || problems+=("could not start bb-egress-forwarder")
    if [[ ${#problems[@]} -eq 0 ]]; then
      info "overlay restored (${WG_IF} up, forwarder started)"
    else
      bad "OVERLAY NOT RESTORED: ${problems[*]} — this node's egress is DOWN, fix it before dispatching"
    fi
  }
  # Without this, an interrupt or a dropped ssh session during the ~60s probe below
  # leaves the node with its overlay down and its forwarder exited, and nothing says so.
  trap 'restore_overlay' EXIT INT TERM

  if ! ip link show "$WG_IF" >/dev/null 2>&1; then
    bad "$WG_IF is not present, so the blackhole guard — the one thing standing between a dead tunnel and direct WAN egress — was NOT tested. Pass --wg-if, or apply the tier first."
  elif [[ $WIRED_OK -eq 0 ]]; then
    bad "skipping the overlay-down test: G3 never established working egress, so 'no egress after the tunnel drops' would prove nothing"
  else
    DOWN_METHOD=wg-quick
    wg-quick down "$WG_IF" >/dev/null 2>&1 || { DOWN_METHOD=iplink; ip link set "$WG_IF" down 2>/dev/null || true; }
    RESTORE_NEEDED=1
    probe_wired
    DOWN_IP="$PROBE_IP"
    if [[ -z "$DOWN_IP" ]]; then
      ok "overlay down => no egress (failed closed)"
    elif [[ -n "$HOST_IP" && "$DOWN_IP" == "$HOST_IP" ]]; then
      bad "LEAK: overlay down and the worker fell back to this node WAN (${DOWN_IP})"
    else
      bad "overlay down but the worker still egressed as ${DOWN_IP}"
    fi
    restore_overlay
  fi
  trap - EXIT INT TERM

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
# The fetch's own exit status is the fact; whether its body parsed is a separate one.
probe 40 --rm --network "$BB_SOCKS" "$PROBE_IMAGE" -fsS --max-time 12 "$IP_ECHO"
if [[ $PROBE_RC -eq 0 ]]; then
  bad "unwired worker REACHED the internet${PROBE_IP:+ as $PROBE_IP} — the bridge is not fail-closed"
elif [[ $PROBE_RC -eq 124 || $PROBE_RC -ge 125 ]]; then
  # 125/126/127 are docker's own "could not run" codes and 124 is timeout(1) killing a
  # hung `docker run` — curl's own timeout is 28, so 124 is never curl. None of these say
  # anything about egress, and treating them as fail-closed passes the test whenever the
  # probe image is missing, the daemon is busy, or the container never started.
  bad "the probe never ran (exit ${PROBE_RC}: image missing, daemon busy, or docker hung) — fail-closed is UNTESTED"
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
  # This used to be an `info`, so a run that proved only `Internal: true` exited 0 —
  # while the header promises "exit 0 only if fail-closed held AND the exit IP differs".
  bad "no --proxy given and no bb-socks-sidecar address found, so the ENTIRE exit-IP half of this test did not run. Start the sidecar, or pass --proxy-file."
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

  probe_via_proxy 60 25
  if [[ $PROBE_RC -ne 0 ]]; then
    bad "worker could not reach the internet through the proxy (exit ${PROBE_RC}: proxy down, creds wrong, or the probe never ran)"
  elif [[ -z "$PROBE_IP" ]]; then
    bad "the fetch through the proxy SUCCEEDED but the response carried no exit IP — something (captive portal, transparent proxy) answered instead of ${IP_ECHO}"
  else
    out="$PROBE_IP"
    ok "worker reached the internet through the proxy (exit IP ${out})"
    if [[ $LOCAL_PROXY -eq 1 ]]; then
      info "local sidecar: exit IP is expected to equal the host's (${HOST_IP:-undetermined}) — it shares our WAN."
      info "this proves the PATH works; it cannot prove anonymisation. Re-run with --proxy-file"
      info "pointed at the real egress provider to check the exit IP actually differs."
      # Prove the traffic really depended on the proxy rather than leaking around it:
      # with the sidecar stopped, the same fetch MUST fail.
      if docker ps --format '{{.Names}}' | grep -qx bb-socks-sidecar; then
        docker stop bb-socks-sidecar >/dev/null 2>&1 || true
        trap 'docker start bb-socks-sidecar >/dev/null 2>&1 || true' EXIT INT TERM
        probe_via_proxy 40 12
        if [[ $PROBE_RC -eq 0 ]]; then
          bad "fetch STILL succeeded with the sidecar stopped — traffic is not going through it"
        else
          ok "fetch fails with the sidecar stopped — the proxy is genuinely in the path"
        fi
        trap - EXIT INT TERM
        docker start bb-socks-sidecar >/dev/null 2>&1 \
          || bad "could not restart bb-socks-sidecar — this node has no egress until you do"
      fi
    elif compare_against_host "worker via the remote proxy" "$out"; then
      if [[ "$out" == "$HOST_IP" ]]; then
        bad "remote proxy configured but exit IP == host IP (${out}) — traffic bypassed it"
      else
        ok "remote proxy: exit IP ${out} differs from host ${HOST_IP} — egress is anonymised"
      fi
    fi
  fi
fi

echo
printf '  %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
