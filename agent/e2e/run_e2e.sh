#!/usr/bin/env bash
# End-to-end proof: the Go blastbox-agent against a REAL `blastbox serve` + `blastbox node-finalizer`.
# Everything is local (127.0.0.1) with throwaway keys in a temp dir; it never touches a deployment.
#
#   AGENT_BIN   path of the built blastbox-agent (required)
#   BLASTBOX    the blastbox CLI (default: blastbox on PATH)
#   PYTHON      python used for JSON parsing and free-port discovery (default: python3)
#   NSJAIL      nsjail binary for the linux sandbox (default: command -v nsjail)
#   AA_PROFILE  AppArmor profile the agent attaches to nsjail (default: blastbox-sandbox)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd -P)
REPO=$(cd "$HERE/../.." && pwd -P)
AGENT_BIN=${AGENT_BIN:?set AGENT_BIN to the blastbox-agent binary}
BLASTBOX=${BLASTBOX:-blastbox}
PYTHON=${PYTHON:-python3}
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

PORT=$("$PYTHON" -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])")
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
"$PYTHON" - "$T/receipt.json" "$NODE" "$T/node/node.crt" "$SAMPLE_SHA" <<'PY'
import hashlib, json, ssl, sys
rcpt, node, crt, sample = sys.argv[1:]
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
print("[e2e] receipt ok:", {k: d[k] for k in ("node_id", "worker_tier", "worker_runtime") if k in d})
PY

# 9. Liveness while the agent runs: node present, heartbeating, no node_silent alert.
api "$BASE/v1/fleet/liveness" >"$T/live.json"
"$PYTHON" - "$T/live.json" "$NODE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); node = sys.argv[2]
rows = [n for n in d["nodes"] if n["node_id"] == node]
assert rows, f"{node} missing from liveness: {d['nodes']}"
assert rows[0]["last_heartbeat_at"], f"{node} never heartbeated"
silent = [a for a in d["alerts"] if a.get("kind") == "node_silent" and a.get("subject") == node]
assert not silent, f"node_silent alert while running: {silent}"
print("[e2e] liveness node:", json.dumps(rows[0], sort_keys=True), "alerts:", d["alerts"])
print("[e2e] liveness ok: heartbeating, no node_silent")
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
sleep 8   # long enough for a (wrong) re-claim to show up
[ "$(status_of "$SLOW")" = failed ] || fail "slow job left the failed state"
log "slow job failed with: $err"

log "PASS"
