# Engine requirements

Every blastbox engine, built-in or out-of-tree, ships two things: code that satisfies the engine
seam, and an **engine contract** that says what it emits. The SDK enforces the first; the
contract makes the second checkable.

## 1. The seam (enforced by the worker SDK and host)

- `name`, `formats`, `detonate(input, outdir, limits) -> DetonationResult`
  (`src/blastbox/worker/engine.py`); optional `detect`, `warmup`, `precheck`.
- Every file a consumer should see is declared (`DeclaredArtifact` id/path/kind); an undeclared
  file is never served. The SDK seals sha256/bytes and confines paths; `host/trust` re-validates.
  Engines never hash or path-check. `metadata.json`, `.metadata.json.*`, `attestation.json` and
  `attestation.withheld.json` at the root (and anything under them) are reserved.
- The payload is a typed tree from the shared node library (`Record`, `Page`,
  `EmbeddedResource`, `ExtractedText`) or a `register_node_type` subtype. Files are referenced by
  `ArtifactRef`, never inlined.
- Network is whatever the resolved netpolicy grants; default `none`.

## 2. The contract (`blastbox-engine.toml`, checked by your tests)

At the engine repo root; a repo with several engines uses `blastbox-engine.<engine>.toml` (found by `find_contract(path, engine)`, which looks nearest-first and takes a plain `blastbox-engine.toml` only when its `[engine].name` matches). Built-ins: `src/blastbox/engines/contracts/<name>.toml`. Schema
`blastbox-engine-contract/1`, parsed by `blastbox.contract.engine_contract`:

```text
[engine]        name, formats, network (exit drivers allowed: none drop direct inetsim tor
                socks httpproxy wireguard openvpn), max_input_bytes, statuses
[[artifacts]]   id + path (fnmatch globs), kind, required, max_count (default 1; 0 =
                uncapped), max_bytes, role,
                description — every artifact family the engine can declare
[payload]       root node type, node_types allowed anywhere in the tree (children,
                EmbeddedResource.metadata, Records nested in Record.fields -- a
                root with metadata must list "record"),
                required_root_fields, schema_version (+ schema_field, default
                "schema_version"); checked on a Record root's fields or an
                EmbeddedResource root's metadata fields
[[detections]]  code, severity (info low medium high critical), source — findings a
                consumer is expected to turn into detections, with stable codes
[[gaps]]        id, description — what the output cannot express today (free-text
                findings, missing fields). Recorded, never silently papered over.
[[consumers]]   name, engine, mapper, emits — e.g. Loadout's manifest name and the
                function that maps this engine's output
```

Validate: `python -m blastbox.contract.engine_contract validate blastbox-engine.toml`.
Check a real result: `python -m blastbox.contract.engine_contract check blastbox-engine.toml metadata.json`.
An engine with `register_node_type` payload nodes passes the module that registers them:
`... check --import my_engine.nodes blastbox-engine.toml metadata.json` (repeatable).

## 3. Conformance in the engine's own tests

Wherever an engine test produces a result, assert it conforms:

```python
from blastbox.contract.engine_contract import assert_conforms, load_contract, find_contract

CONTRACT = load_contract(find_contract(__file__))
assert_conforms(CONTRACT, result, outdir)     # DetonationResult, Envelope, or metadata.json dict
```

An artifact the contract does not list (or one declared but never written), a result the
harness's seal or the host trust gate would refuse (`unsealable` / `reserved_path`: a path escaping
`outdir`, a reserved root name, a duplicate id, a payload nested deeper than the host parses;
checked when `outdir` is given; pass `limits=` to also apply that host's metadata-size and
artifact-count caps), a required artifact missing on `ok`, a node type
the contract does not allow (on any status; on `rejected`/`engine_error` the harness's own bare
Record root is allowed, nodes below it are still checked), a wrong root on `ok`, or a missing root field on `ok`
fails the test. An artifact counts toward the first family it matches but must satisfy the
`max_bytes` of, and satisfies `required` for, every family it matches. Checking a sealed
`metadata.json` of an engine whose `network` allows a capturing exit (anything but `none`/`drop`)
ignores the capture pcaps the host appends (`network.capture*.pcap`): they are not engine output. The built-in
engines do this in `tests/engines/`; `tests/contract/test_engine_contract.py` fails if a
built-in engine has no contract.

## 4. Consumer side (not enforced here)

A platform that runs the engine keeps its own registration (Loadout: `EngineManifest`) and an
output mapper, and should test that each registered blastbox engine names a contract and that
its mapper handles every artifact family and detection code the contract lists.
