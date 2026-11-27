#!/bin/sh
# Trivial e2e engine: engine.sh INPUT OUTDIR. Writes a valid blastbox envelope for engine "e2e".
# With E2E_SLEEP=<seconds> in the environment (a run param) it sleeps first, so a test can
# kill the agent while a job is running.
set -eu
in="$1"
out="$2"
if [ -n "${E2E_SLEEP:-}" ]; then
  sleep "$E2E_SLEEP"
fi
# The driver passes the input's digest as E2E_INPUT_SHA256 (a sandboxed macOS engine cannot run
# perl-based shasum); without it the engine hashes the input itself.
if [ -n "${E2E_INPUT_SHA256:-}" ]; then
  sha="$E2E_INPUT_SHA256"
elif command -v sha256sum >/dev/null 2>&1; then
  sha=$(sha256sum "$in" | cut -d' ' -f1)
else
  sha=$(shasum -a 256 "$in" | cut -d' ' -f1)
fi
cat > "$out/metadata.json" <<JSON
{"engine": "e2e", "status": "ok", "input_sha256": "$sha",
 "detected": {"label": "bin", "mime": "application/octet-stream", "confidence": 0.9, "source": "e2e"},
 "artifacts": [], "warnings": [],
 "payload": {"_type": "extracted_text", "text": "e2e ok", "char_count": 6}}
JSON
