# Blastbox node protocol -- conformance vectors v1

Python (`src/blastbox/...`) is the reference; these files are generated from it by
`scripts/gen_conformance.py`. The Go pull-worker agent consumes the same files, so the JSON
shapes are a contract. **A change to a shape or value means a new directory `v2/`, never an
edit of `v1/`.**

| file | what it pins | reference function |
|---|---|---|
| `challenge.json` | challenge string + verdicts (`ok`, `expired`, `wrong_scope`, `foreign`, `malformed`); the expiry is Python `repr(float)` and is opaque | `node_auth.challenge_for`, `_check_challenge` |
| `signing_payload.json` | exact bytes a node signs | `node_auth.signing_payload` |
| `session_token.json` | `issue` (inputs -> token) and `verify` (token, time -> `ok`/`expired`/`forged`/`malformed`) | `issue_session`, `verify_session` |
| `receipt.json` | `issue` (inputs -> receipt) and `check` (-> `ok`/`refused`) | `claim_receipt`, `check_claim_receipt` |
| `canonical_json.json` | `{input, canonical_hex}` or `{input_repr, error: "float"}` | `attest_wire.canonical` |
| `ecdsa_cross.json` | P-256/SHA-256 DER signatures, base64. `python_signed` is written by Python; the Go agent appends `go_signed`. Every entry must verify unless it has `"valid": false` (absent means true; python_signed only), which is a tampered signature that must be rejected | `node_auth.sign_claim` |
| `node_certs/` | TEST CA, v1 (WireGuard key) and v2 (no key) node certs, and negatives; `cases.json` gives each verdict at the frozen `now` | `pki.node_identity`, `node_auth.admit_identity` |
| `sandbox/seatbelt/*.json` | `request` -> exact SBPL `profile` + `-D` `params` | `seatbelt.build_profile` |
| `sandbox/nsjail/*.json` | `request` -> exact `argv`, with `host_pins` for the host probes that were fixed | `NsjailSandbox._build_argv` |
| `SHA256SUMS` | hash of every other file | |

Notes for consumers:

* `challenge.json`: the Python reference cannot tell a foreign MAC from a wrong scope (both are
  "not issued by this server for this scope"); the vector labels them by construction and an
  implementation may report either as a refusal. `minted_scope` is what the challenge was minted for.
* Times are explicit (`verify_at`, `now`) -- nothing here reads a clock.
* Certificate verdicts are evaluated at `node_certs/cases.json` `now`. Ten-year validity
  except the deliberately `expired` case.
* `canonical_json.json` inputs must be decoded with exact integers (Go: `json.Decoder.UseNumber`), or integers beyond 2^53 lose precision.
* `node_plus_client_auth_eku` (node EKU plus clientAuth) is refused: a node cert must never double as a transport cert.
* `rsa_key` verifies as an identity but its `admit` verdict is `refused` (EC keys only).

Regenerate / check:

```text
python scripts/gen_conformance.py            # rewrite generated files + SHA256SUMS
python scripts/gen_conformance.py --check    # exit 1 on drift (CI)
python scripts/gen_conformance.py --regen-certs   # new test CA + certs (a Go agent's recorded cert verdicts go stale; go_signed is kept)
python scripts/gen_conformance.py --regen-signed  # new python_signed (drops go_signed)
```

`node_certs/**` and `python_signed` are committed once (random keys/serials, randomised ECDSA);
`--check` re-verifies them with the reference rather than regenerating them.
