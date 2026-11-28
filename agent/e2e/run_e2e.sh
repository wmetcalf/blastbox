#!/usr/bin/env bash
# End-to-end proof: the Go blastbox-agent against a REAL `blastbox serve` + `blastbox node-finalizer`.
# Everything is local (127.0.0.1) with throwaway keys in a temp dir; it never touches a deployment.
#
#   AGENT_BIN   path of the built blastbox-agent (required)
#   BLASTBOX    the blastbox CLI (default: blastbox on PATH)
#   PYTHON      python used for JSON parsing and free-port discovery (default: python3)
#   NSJAIL      nsjail binary for the linux sandbox (default: command -v nsjail)
#   AA_PROFILE  AppArmor profile the agent attaches to nsjail (default: blastbox-sandbox)
#   BB_PYTHON   python that can import blastbox, to verify the receipt signature
#               (default: the python next to BLASTBOX, else PYTHON)
#   E2E_PORT    ingress port (default: a free one)
#   E2E_RENEW   1 (default) runs the renewal round trip; 0 skips it
#   E2E_RENEW_LIVE_WAIT  seconds to let the RUNNING agent adopt the renewed cert on its own
#               (its cert loop runs every 5 min) before restarting it to adopt it at start (default 0)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
REPO=$(cd "$HERE/../.." && pwd -P)
AGENT_BIN=${AGENT_BIN:?set AGENT_BIN to the blastbox-agent binary}
BLASTBOX=${BLASTBOX:-blastbox}
PYTHON=${PYTHON:-python3}
BB_DIR=$(cd "$(dirname "$(command -v "$BLASTBOX")")" && pwd -P)
BB_PYTHON=${BB_PYTHON:-$( [ -x "$BB_DIR/python" ] && echo "$BB_DIR/python" || echo "$PYTHON")}
NODE=e2e-node
KEY=e2e-throwaway-key-$$
TIMEOUT=${E2E_TIMEOUT:-90}

T=$(mktemp -d "${TMPDIR:-/tmp}/blastbox-e2e.XXXXXX")
T=$(cd "$T" && pwd -P)
PIDS=()
log() { printf '[e2e] %s\n' "$*"; }
fail() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  rc=$?
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  # A sandboxed engine can outlive a SIGKILLed agent; match on the temp dir only.
  pkill -f "$T" 2>/dev/null || true
  sleep 1
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true; done
  if [ "$rc" -ne 0 ]; then
    for f in serve finalizer agent; do
      [ -f "$T/$f.log" ] && { echo "----- $f.log (tail) -----" >&2; tail -n 60 "$T/$f.log" >&2; }
    done
  fi
  rm -rf "$T"
  exit "$rc"
}
trap cleanup EXIT INT TERM

case "$(uname -s)" in
  Linux)  SANDBOX=nsjail ;;
  Darwin) SANDBOX=seatbelt ;;
  *) fail "unsupported OS $(uname -s)" ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
json() { "$PYTHON" -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

PORT=${E2E_PORT:-}
[ -n "$PORT" ] || PORT=$("$PYTHON" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])")
BASE="https://127.0.0.1:$PORT"
CA="$T/pki/ca.crt"
api() { curl -sS --fail-with-body --cacert "$CA" -H "Authorization: Bearer $KEY" "$@"; }

# 1. PKI. `serve` auto-issues an ingress server cert (SAN 127.0.0.1) from this CA.
mkdir -p "$T/jobs" "$T/node"
"$BLASTBOX" pki --dir "$T/pki" init >/dev/null

export BLASTBOX_DATABASE_URL="sqlite:///$T/jobs.db"
export BLASTBOX_JOB_ROOT="$T/jobs"
export BLASTBOX_BLOB_LOCAL_ROOT="$T/blobs"
export BLASTBOX_PKI_DIR="$T/pki"
export BLASTBOX_API_KEY="$KEY"
export BLASTBOX_ALLOWED_ENGINES=e2e
export BLASTBOX_NODE_CLAIM_RECLAIM_AFTER_S=900
export BLASTBOX_NODE_HEARTBEAT_S=5
export BLASTBOX_ATTEST_KEY="$T/attest.key"
export BLASTBOX_HOST_ID=e2e-host
# Pull-agent deployments must keep DONE with the finalizer (no node-written terminal status).
export BLASTBOX_NODE_TERMINAL_WRITES=finalizer-only

# 2. serve, 3. finalizer (same job root, DB and blob settings; it holds the attest key).
"$BLASTBOX" serve --host 127.0.0.1 --port "$PORT" >"$T/serve.log" 2>&1 &
PIDS+=($!)
"$BLASTBOX" node-finalizer --interval 0.5 >"$T/finalizer.log" 2>&1 &
PIDS+=($!)

log "waiting for serve on $BASE"
for _ in $(seq 1 60); do
  curl -sS -o /dev/null --cacert "$CA" "$BASE/v1/healthz" 2>/dev/null && break
  kill -0 "${PIDS[0]}" 2>/dev/null || fail "blastbox serve exited"
  sleep 0.5
done
curl -sS -o /dev/null --cacert "$CA" "$BASE/v1/healthz" || fail "serve did not come up"

# 4. Enrol: the node key never leaves $T/node; the CA host signs the CSR.
"$AGENT_BIN" enrol --node-id "$NODE" --dir "$T/node" >/dev/null
"$BLASTBOX" pki --dir "$T/pki" sign-node-csr --csr "$T/node/node.csr" --node-id "$NODE" \
  --engine e2e --tier none --days 7 --out "$T/pki/node-$NODE.crt" >/dev/null
cp "$T/pki/node-$NODE.crt" "$T/node/node.crt"
cp "$CA" "$T/node/ca.crt"
chmod 600 "$T/node/node.key"

# 5. Agent config.
NSJAIL_TABLE=""
if [ "$SANDBOX" = nsjail ]; then
  NSJAIL=${NSJAIL:-$(command -v nsjail)}
  NSJAIL_TABLE="[nsjail]
path = \"$NSJAIL\"
sha256 = \"$(sha256_of "$NSJAIL")\"
seccomp_policy = \"$REPO/deploy/seccomp/blastbox.seccomp.policy\"
apparmor_profile = \"${AA_PROFILE:-blastbox-sandbox}\""
fi
cat >"$T/agent.toml" <<TOML
ingress = "$BASE"
ca_file = "$T/node/ca.crt"
cert_file = "$T/node/node.crt"
key_file = "$T/node/node.key"
state_dir = "$T/state"
claim = true

[[engine]]
name = "e2e"
argv = ["$HERE/engine.sh", "{input}", "{out}"]
output = "dir"
sandbox = "$SANDBOX"
ro_paths = ["$HERE"]
slots = 1

$NSJAIL_TABLE
TOML
mkdir -p "$T/state"

start_agent() {
  "$AGENT_BIN" run --config "$T/agent.toml" >>"$T/agent.log" 2>&1 &
  AGENT_PID=$!
  PIDS+=("$AGENT_PID")
}
start_agent
sleep 1
kill -0 "$AGENT_PID" 2>/dev/null || fail "agent exited at start"

head -c 4096 /dev/urandom >"$T/sample.bin"
SAMPLE_SHA=$(sha256_of "$T/sample.bin")

submit() { # [E2E_SLEEP seconds]
  local args=(-F "file=@$T/sample.bin" -F engine=e2e -F "params=E2E_INPUT_SHA256=$SAMPLE_SHA")
  [ -n "${1:-}" ] && args+=(-F "params=E2E_SLEEP=$1")
  api -X POST "${args[@]}" "$BASE/v1/jobs" | json "d['job_id']"
}
status_of() { api "$BASE/v1/jobs/$1" | json "d['status']"; }
wait_status() { # job_id status...
  local id=$1; shift
  local deadline=$((SECONDS + TIMEOUT)) st
  while [ $SECONDS -lt $deadline ]; do
    st=$(status_of "$id")
    for want in "$@"; do [ "$st" = "$want" ] && { echo "$st"; return 0; }; done
    case "$st" in done|failed|expired) echo "$st"; return 1 ;; esac
    sleep 1
  done
  echo "timeout"; return 1
}


# 6-7. Happy path.
JOB=$(submit)
log "job $JOB submitted; waiting for DONE (<= ${TIMEOUT}s)"
st=$(wait_status "$JOB" done) || fail "job $JOB ended as $st"
log "job $JOB done"
api "$BASE/v1/jobs/$JOB/attestation" >"$T/receipt.json" || fail "no receipt for $JOB"
api "$BASE/v1/attestation/key" >"$T/attest-pub.json" \
  || fail "no attestation key"
check_receipt() { # receipt.json node.crt
  "$BB_PYTHON" - "$1" "$NODE" "$2" "$SAMPLE_SHA" "$SANDBOX" "$T/attest-pub.json" <<'PY'
import hashlib, json, ssl, sys
from pathlib import Path
from blastbox.host import attest
rcpt, node, crt, sample, runtime, pub = sys.argv[1:]
doc = json.load(open(rcpt))
assert doc.get("signature"), "receipt is unsigned"
d = doc["attestation"]
print("[e2e] receipt:", json.dumps(doc, sort_keys=True))
der = ssl.PEM_cert_to_DER_cert(open(crt).read())
want = hashlib.sha256(der).hexdigest()
assert d.get("node_id") == node, f"node_id {d.get('node_id')!r}"
assert d.get("node_cert_sha256") == want, f"node_cert_sha256 {d.get('node_cert_sha256')!r} != {want}"
assert d.get("worker_tier") == "node-agent", f"worker_tier {d.get('worker_tier')!r}"
assert d.get("input_sha256") == sample, "input_sha256 mismatch"
assert d.get("worker_runtime") == runtime, f"worker_runtime {d.get('worker_runtime')!r} != {runtime}"
assert attest.verify_body(attest.load_verify_key(Path(pub)), doc), "receipt signature does not verify"
print("[e2e] receipt ok (signature valid):",
      {k: d[k] for k in ("node_id", "node_cert_sha256", "worker_tier", "worker_runtime") if k in d})
PY
}
check_receipt "$T/receipt.json" "$T/node/node.crt" || fail "receipt check failed"

# 7b. A run long enough for the memory and disk watchdogs to sample it many times under the
# real sandbox (and, on linux, the enforced AppArmor child profile) must still finish DONE,
# without a failed sample.
LONG=$(submit 6)
log "long job $LONG submitted; waiting for DONE"
st=$(wait_status "$LONG" done) || fail "long job $LONG ended as $st"
if grep -q "watchdog read failed" "$T/agent.log"; then
  grep "watchdog read failed" "$T/agent.log" >&2
  fail "a watchdog could not sample the confined run"
fi
log "long job $LONG done; every watchdog sample read the confined run"

# 9. Liveness while the agent runs: node present, heartbeating, no node_silent alert.
api "$BASE/v1/fleet/liveness" >"$T/live.json"
"$PYTHON" - "$T/live.json" "$NODE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); node = sys.argv[2]
rows = [n for n in d["nodes"] if n["node_id"] == node]
assert rows, f"{node} missing from liveness: {d['nodes']}"
assert rows[0]["last_heartbeat_at"], f"{node} never heartbeated"
assert not d["alerts"], f"liveness alerts while running: {d['alerts']}"
print("[e2e] liveness node:", json.dumps(rows[0], sort_keys=True), "alerts:", d["alerts"])
print("[e2e] liveness ok: heartbeating, no alerts")
PY

# 8. kill -9 mid-run: the restarted agent fails the job, and nothing re-runs it.
SLOW=$(submit 120)
log "slow job $SLOW submitted; waiting for it to run"
st=$(wait_status "$SLOW" running) || fail "slow job $SLOW never ran ($st)"
sleep 2
kill -9 "$AGENT_PID"
wait "$AGENT_PID" 2>/dev/null || true
log "agent killed -9 mid-run; restarting"
start_agent
st=$(wait_status "$SLOW" failed) || fail "slow job $SLOW ended as $st, wanted failed"
err=$(api "$BASE/v1/jobs/$SLOW" | json "d.get('error') or ''")
case "$err" in *"agent restarted mid-run"*) ;; *) fail "slow job error is $err" ;; esac
snap() { api "$BASE/v1/jobs/$1" | json "(d['status'], d.get('started_at'), d.get('finished_at'), d.get('worker_runtime'))"; }
before=$(snap "$SLOW")
sleep 8   # long enough for a (wrong) re-claim to show up
after=$(snap "$SLOW")
[ "$before" = "$after" ] || fail "slow job changed after failing: $before -> $after"
log "slow job failed with: $err (record unchanged after 8s: $after)"

# 10. Renewal round trip with proof of possession: the agent queues a CSR signed by its CURRENT
# key, the CA host signs it (`pki renew-pending`), and the agent adopts the new cert.
if [ "${E2E_RENEW:-1}" = 1 ]; then
  old_sha=$(sha256_of "$T/node/node.crt")
  "$AGENT_BIN" renew --config "$T/agent.toml" >"$T/renew.out" 2>&1 || { cat "$T/renew.out" >&2; fail "renew request refused"; }
  log "renew: $(tr '\n' ' ' <"$T/renew.out")"
  [ -f "$T/node/node.key.next.csr" ] || fail "no persisted renewal CSR"
  "$BLASTBOX" pki --dir "$T/pki" renew-pending >"$T/renew-pending.out" 2>&1 \
    || { cat "$T/renew-pending.out" >&2; fail "renew-pending failed"; }
  log "renew-pending: $(tr '\n' ' ' <"$T/renew-pending.out")"
  grep -q renewed "$T/renew-pending.out" || fail "renew-pending renewed nothing"
  adopted() { [ "$(sha256_of "$T/node/node.crt")" != "$old_sha" ] && [ ! -e "$T/node/node.key.next" ]; }
  deadline=$((SECONDS + ${E2E_RENEW_LIVE_WAIT:-0}))
  while [ $SECONDS -lt $deadline ] && ! adopted; do sleep 2; done
  how="by the running agent"
  if ! adopted; then
    log "restarting the agent so it adopts the renewed cert at start"
    kill -TERM "$AGENT_PID"; wait "$AGENT_PID" 2>/dev/null || true
    start_agent
    how="by the restarted agent"
    deadline=$((SECONDS + 30))
    while [ $SECONDS -lt $deadline ] && ! adopted; do sleep 1; done
  fi
  adopted || fail "agent did not adopt the renewed cert"
  grep -q "renewed certificate installed" "$T/agent.log" || fail "agent log does not show the install"
  log "renewed cert adopted $how: $old_sha -> $(sha256_of "$T/node/node.crt")"
  JOB2=$(submit)
  st=$(wait_status "$JOB2" done) || fail "post-renewal job $JOB2 ended as $st"
  api "$BASE/v1/jobs/$JOB2/attestation" >"$T/receipt2.json" || fail "no receipt for $JOB2"
  check_receipt "$T/receipt2.json" "$T/node/node.crt" || fail "post-renewal receipt check failed"
  log "post-renewal job $JOB2 done under the renewed cert"
fi

log "PASS"
