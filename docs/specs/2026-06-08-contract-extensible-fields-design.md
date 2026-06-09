# Contract: per-engine extensible data fields

**Date:** 2026-06-08
**Status:** approved (design dialogue with Will), ready to implement
**Repos:** blastbox (contract), then ClippyShot (engine + UI), then redtusk (engine)

## Goal

Make the typed contract carry **whatever data an engine wants to emit, as long as it
follows the contract** — the core extensibility promise of the framework — informed by
ClippyShot (rasterize) + redtusk (Tika extract) today and the divergent future engines
box-js / rust-vmonkey / pdf-titan-arum / harrington (JS/macro/PDF malware analysis).

## Key finding (verified by running the contract)

The contract **already has every extension mechanism it needs**. The deliverable is
**governance + a small batch of promoted typed leaves**, NOT a new escape hatch.

- `Record` is the generic per-engine key/value bag, **already capped** (`fields`
  max_length=4096; bounded by the 4 MiB metadata cap + depth-128 re-parse).
  `RecordValue = scalar | list[scalar] | nested Record` (one structural level). It
  **rejects list-of-objects** (verified) — that is the one hard constraint driving which
  things must become typed leaves vs Record.
- Every model is `extra='forbid'` (verified on all 6: `leaf._Frozen`, `nodes._Node`,
  `envelope.DeclaredArtifact/Artifact/Envelope`). This is the security property that lets
  the host **re-parse untrusted worker JSON through a closed discriminated union**
  (`envelope_from_json → parse_node → _NODE_ADAPTER` + `Envelope.model_validate`).
- Registered engine subclasses (`register_node_type`) **already round-trip as nested
  children at any depth** (verified empirically — the `_parse_children` BeforeValidator
  routes children through the live `_NODE_ADAPTER`, not the static class-definition union).
  ClippyShot `engine.py`'s docstring claiming otherwise is **stale**; its `Record`-child
  workaround is now a *choice* (avoid host-image coupling), not a forced framework bug.

### REJECTED options (and why)
- **A free-form `attributes`/`extra: dict[str, JSON]` field** on Envelope/nodes — duplicates
  `Record` with worse placement and an UNcapped default. Strictly dominated. `Record` IS
  option-A done correctly.
- **`model_config extra='allow'`** — a trust-model trap: pydantic applies **no size cap**
  to extras, so a hostile worker smuggles unbounded unknown keys past validation,
  escaping the per-field caps. Inverts the package-wide `extra='forbid'` the host re-seal
  depends on.

## Governance: the 3-rung rule

Encode this in the contract module docstring + CONTRIBUTING:

1. **BOTH engines emit it with stable semantics → typed core leaf/node field.** The host
   re-parse type-checks it; per-engine UIs share one renderer.
2. **One engine, schemaless / one-off, multi-image deploy → `Record`.** No host coupling;
   already in the base union.
3. **One engine wants full pydantic typing AND controls both worker+host images →
   `register_node_type` subclass.** Best safety; the cost is `trust.py` rejects an unknown
   `_type` if the host image lacks the ext module (the real reason ClippyShot avoids it).

Security ranking for the re-seal model: core-typed-field > subclass > `Record` > free-dict
>> `extra='allow'` (rejected).

## Promoted typed leaves (the shared vocabulary)

All subclass `_Frozen` (frozen, `extra='forbid'`); every field carries a cap so the host
re-parse re-asserts bounds. Added to `__init__.__all__` + `json_schema()`.

### Crypto triad — ALWAYS computed by the framework
sha256 + md5 + sha1 for **input + every sealed artifact + page images**. Engines never
hand-roll crypto hashes — `seal_envelope` computes all three in the single read it already
does (one read, three hashers). `Hash.algo` Literal gains `md5`,`sha1`; `_HASH_HEXLEN`
gains `{md5:32, sha1:40}` (the existing `_hex` validator enforces hex+length for free).
The pHash similarity index keeps gating on `algo=='phash'` — md5/sha1 are exact-match only,
never bktree-indexed.

### `Source` — input provenance (URL-ready now)
Discriminated by `kind`. `Envelope.input_sha256` stays "the digest of the bytes we actually
detonated" (file content, or fetched-URL content) so the existing trust/seal/page_hashes
plumbing is untouched; `Source` adds provenance on top.
- `FileSource{ kind='file', sha256, md5, sha1, size_bytes>=0, filename: str|None (<=4096) }`
  — triad always present (bytes known at submit).
- `UrlSource{ kind='url', url (<=8192), final_url: str|None, http_status: int|None,
  content_type: str|None (<=255), fetched_at: float|None, sha256?, md5?, sha1?,
  size_bytes?>=0 }` — URL is the identity; triad describes the fetched content, present
  once resolved (null if egress off / fetch failed).

New source kinds later (`stream`,`email`) just extend the discriminator. NOT built yet but
contract-ready: URL-submission ingress, a fetching/visiting engine, and the **network
egress threat model** (every sandbox is `--network=none` today; a URL-fetching engine is an
opt-in per-engine capability with its own DNS/proxy-pinned egress policy).

### `Indicator` — IOC output (box-js / vmonkey / pdf-titan future)
`Indicator{ kind: Literal[url,domain,ipv4,ipv6,email,sha256,md5,sha1,filepath,regkey,mutex],
value: str (<=8192), source: str|None (<=64), metadata: Record|None }`. Carried as
`list[Indicator]` on a node (capped).

**The per-indicator additional data is extensible via the embedded `Record`** — the same
contract-following mechanism (scalars / list-of-scalars / nested `Record`, capped at 4096
keys, bounded by the global metadata/depth caps), NOT a free-form dict. So each indicator
kind carries the metadata it needs WITHOUT a contract change:
- `url` → `{ http_status, method, contacted, response_bytes, redirected_to }`
- `ipv4`/`ipv6` → `{ port, protocol, asn, geo }`
- `filepath` → `{ operation, size_bytes }` ; `regkey` → `{ operation, data }`

`metadata` is a concrete `Record` field on the leaf, so it validates via normal pydantic on
the host re-parse (it is NOT a `children` discriminated-union member); it carries no
`ArtifactRef`, so no new ref surface. Big extracted blobs (deobfuscated scripts, full
emulation traces) still go by-reference as **artifacts**, never inline. (The same
`metadata: Record|None` extensibility slot is available to other leaves if a future need
arises — added to `Indicator` now because IOC metadata is the clearest variable-by-kind case.)

### Scanner sub-contract (strongest ClippyShot↔redtusk overlap)
- `QrCode{ value (<=8192), format (1..64), raw_bytes_hex: str|None (<=16384, hex),
  ecc: str|None (<=16), is_mirrored: bool=False, position: str|None (<=255) }`.
  position is a STRING (`"x1,y1 x2,y2 x3,y3 x4,y4"`) — both engines emit it that way.
  ClippyShot-shaped; redtusk populates the common subset (no ecc/is_mirrored; maps its
  `data`→`value`).
- `OcrResult{ text (<=10_000_000), char_count: int|None>=0, lang: Lang|None,
  duration_ms: int|None>=0, skipped: str|None ∈ SKIP_REASONS }`. char_count optional so
  redtusk needn't synthesize it.
- `SKIP_REASONS = frozenset{disabled, blank_page, blank_image, no_images, timeout,
  timeout_budget, error, in_progress}` validated by a field_validator (NOT a `Literal` —
  a new Literal member is a wire/version-skew break; a frozenset is forward-compatible).
  Deliberately permissive cross-engine vocabulary (documented).

### Job-level leaves on `Envelope`
- `Timing{ phases: dict[str,int] (max_length=64, each>=0), total_ms: int|None>=0 }`.
- `Truncation{ reason: str|None (<=64), limit: int|None>=0, observed: int|None>=0 }`.
- `Provenance{ runtime: str|None (<=64), sandbox: str|None (<=64),
  insecure_warnings: list[str (<=255)] (max_length=32) }`.
- `Envelope` gains optional `source: Source|None`, `timing: Timing|None`,
  `truncation: Truncation|None`, `provenance: Provenance|None` (retain `extra='forbid'`).
  `seal_envelope` gains matching optional kwargs (default None) so existing callers are
  unaffected.

### `Page` enrichment (it has NO metadata slot today — gap-fill)
Additive/optional, backward-compatible, `extra='forbid'` kept:
- `qr: list[QrCode] = [] (max_length=4096)`
- `ocr: OcrResult|None = None`
- `indicators: list[Indicator] = [] (max_length=…)`
- `metadata: Record|None = None` (per-page engine bag: px-dims, is_blank, sheet_name, …)

(Optionally add `qr`/`ocr`/`indicators` to `EmbeddedResource` too for redtusk per-entry.)

## Security invariants (host re-seal model — MANDATORY)

- Every new field is a typed leaf with built-in `max_length`/`ge` caps → `parse_node` +
  `Envelope.model_validate` re-assert them on the untrusted host re-read.
- The new leaves carry **no `ArtifactRef`** (images stay on `Page.image`), so **no new ref
  surface** and no new path-confinement risk.
- Global backstops unchanged: 4 MiB metadata cap, `_raw_json_max_depth(128)` pre-`json.loads`
  byte scan, `_check_json_depth`, `_MAX_PAYLOAD_DEPTH`.
- Cap-exceed in an engine → truncate-with-`Warning` (code like `qr_truncated`), never fail
  the seal (project rule: scanner failures non-fatal).
- **Do NOT** add a free-form dict; **do NOT** set `extra='allow'`.

## Deferred (contract-ready, separate follow-up)

- **Derivative-child-Pages** (emit trimmed/focused as their own `Page`s so `/v1/similar`
  returns variant rows): expands the `ArtifactRef` surface, and `envelope_from_json` (the
  untrusted host re-read) does **not** re-resolve `ArtifactRef → declared` — only
  `seal_envelope` does. **Prerequisite:** add ref-resolution to the host validate path
  (`validate_envelope`/`envelope_from_json`). Until then derivative hashes stay dropped.

## Migration impact

- **CONTRACT:** all additive/backward-compatible (every new field defaults empty/None; the
  only non-default edit is extending `Hash.algo` — adds members, never removes). Bump
  blastbox minor (0.1.7). `tests/contract/test_smoke.py` only asserts `title=='Envelope'`
  + `properties` presence → additive fields pass. New tests mirror
  `test_nested_registry.py`: round-trip each leaf; reject over-cap `QrCode.value`/
  `raw_bytes_hex`, non-hex `raw_bytes_hex`, `Timing` >64 keys / negative ms; confirm
  default-empty `Page.qr/ocr/metadata/indicators` still parse; `Source` file|url round-trip.
- **CLIPPYSHOT:** `engine.py` `detonate()` is the bulk — delete the stale docstring, stop
  dropping ~30 fields, build `Page.qr=[QrCode…]`/`Page.ocr=OcrResult(…)` (drop the lossy
  `qr_count` + the 10 000-char OCR truncation hack), `Page.metadata=Record{px-dims,…}`,
  move job-level extras (rasterizer/dpi/security/sheets/detection-detail) into the root
  `EmbeddedResource.metadata` Record (sheets.non_rendered as a child-Record subtree, since
  it's a list-of-objects), populate `Envelope.source/timing/truncation/provenance`. Native
  `metadata.json` shape is UNCHANGED (`converter.py` untouched) → `test_metadata_schema_stable`
  stays green. The UI port then reads the now-rich Envelope (no new endpoints).
- **REDTUSK:** `engine.py` adds md5/sha1 to the per-entry `Hash` list, populates `qr`/`ocr`
  leaves + `Envelope.source/timing/truncation/provenance`; keeps `_make_record` for the raw
  Tika bag. No rmeta schema change forced. Neither engine ships a contract-ext module to the
  host → no dispatcher/host image rebuild for registration.

## Sequence

1. **blastbox contract PR** — leaves + `Page` enrichment + `Hash` algos + seal triad +
   tests → **release 0.1.7**.
2. **ClippyShot** — `engine.py` stops dropping fields; UI port reads the rich Envelope
   (folds into the cut-over).
3. **redtusk** — adopt the same leaves (its migration).
4. **Follow-up** — derivative-child-Pages + host-path `ArtifactRef` re-resolution.
