# Upgrading: execution-receipt hardening (unreleased, after 0.1.45)

This branch hardens the execution receipt (`attestation.json`, `GET /v1/jobs/{id}/attestation`)
and the node-share metrics view. Read **Upgrade order** before rolling it out: the ingress must be
upgraded first, and must not be rolled back past this release afterwards.

## Upgrade order (required)

**Upgrade every ingress (API host) before any dispatcher, and before running
`blastbox migrate-results`. Once a dispatcher or migration of this release has uploaded results,
never roll an ingress back past this release.**

Why: the pending-upload sweep and `migrate-results` of this release can upload a result *as-is* —
the worker's own `attestation.json` left in place — when its envelope declares (or cannot rule
out) an artifact at that name. What keeps that file from being served as a receipt is the
`attestation.withheld.json` marker stored beside it, and only this release's attestation route
reads the marker. A 0.1.45 ingress opens `attestation.json` and serves it `200` unless it is a
tombstone. The stored bytes are durable, so this is not limited to the window of a rolling
upgrade: any later ingress rollback to 0.1.45 serves them too.

An upgraded ingress serving results uploaded by 0.1.45 dispatchers treats them as unmarked
(legacy) results and judges their stored envelope before serving. That is **not** fully safe
during the rollout: a 0.1.45 dispatcher neither reserves nor strips `attestation.withheld.json`,
so a worker running under a not-yet-upgraded dispatcher can plant a file at that name beside its
job's genuine receipt. The upgraded ingress reads any marker but the cleared body as the
uploader's verdict and withholds that job's receipt (`404`) permanently, under a reason worded as
this host's own (the worker can copy one). Nothing is forged: a worker can only suppress its own
job's receipt, never get a receipt served. The order is still ingress first because the opposite
order allows forgery: a 0.1.45 ingress serves an as-is upload's worker-written `attestation.json`
as a receipt (above). The window closes once every dispatcher runs this release, so keep the
rollout short: upgrade the dispatchers promptly after the ingresses.

## Changes

1. **Both receipt names are reserved, nested paths included.** The trust gate now refuses an
   artifact declared at or under `attestation.json` *or* `attestation.withheld.json`
   (`attestation.json/page.png`, `./attestation.json`, `//`, trailing slash). It compares path
   parts as the filesystem resolves them, so `' attestation.json/x'` (a different directory) is
   still accepted. An engine that declared output under either name now fails the gate.

2. **Every result carries a withheld marker.** Each upload that ships a receipt or a tombstone
   also stores `attestation.withheld.json` holding the *cleared* body, bound to the sha256 of the
   `metadata.json` it shipped with. An as-is upload stores the *withheld* body (tombstone-shaped,
   with the reason) instead. Expect one extra small object per result in the store.

3. **The attestation route judges what it serves.** In order: any marker other than a
   well-formed cleared body (the withheld body, a near-miss, over 4 KiB) answers `404`; no stored
   `metadata.json` answers `404`; otherwise the stored envelope is read under the ingress's
   ceiling and a declared or unparseable reserved path answers `404`. A cleared marker never
   vouches on its own. A blob-store read error is `503`, never a verdict.

4. **A receipt whose envelope exceeds the ingress's ceiling is withheld (`404`), even if it is
   genuine.** The ceiling is the ingress's `BLASTBOX_MAX_METADATA`, never below 64 MiB. The `404`
   names the fix. **Set `BLASTBOX_MAX_METADATA` on every ingress at least as high as on every
   dispatcher that seals results** (a mismatch only matters for envelopes past 64 MiB). The route
   reads the envelope and the marker only up to the ceiling, on S3 as well as the local store (the
   S3 read streams and stops, inflating a gzip-encoded object incrementally).

5. **Retained trees that used to be stuck now upload.** The pending-upload sweep and
   `migrate-results` used to leave a tree retained forever when its envelope declared, or could
   not be parsed to rule out, an artifact at `attestation.json`. They now upload it as-is, with
   the withheld marker and no receipt, and the sweep repairs the job to `DONE`. A transient read
   error on the envelope is not a verdict: the tree stays retained and is retried. A tree whose
   envelope declares (or cannot rule out) something at `attestation.withheld.json` itself is never
   shipped: it stays retained (sweep) or is counted failed (migration), logged with its job id.

6. **`migrate-results` takes the service's limit.** Run it with the service's
   `BLASTBOX_MAX_METADATA` in the environment or pass `--max-metadata BYTES`. With neither, a
   result whose envelope exceeds 64 MiB is left in place and counted failed. The migration now
   writes a tombstone over a worker's `attestation.json` instead of deleting the file, so an
   earlier interrupted run's stored copy is overwritten.

7. **A seal that cannot complete fails closed.** If a dispatcher cannot write a receipt or
   tombstone together with its cleared marker (ENOSPC, EIO), it does not upload. The job goes
   `FAILED` with the error `result not uploaded: receipt seal incomplete; result retained on this
   worker (no durable copy)`, and the pending-upload sweep ships it later. If only the marker
   failed, the genuine receipt is kept (not tombstoned over) and the sweep ships it with its
   marker. A real upload outage is still reported as `result upload failed after N attempts`.

8. **Deletes are ordered.** `DELETE /v1/jobs/{id}` and retention remove `attestation.json` first,
   the marker last, each step only after the previous one fully succeeded (on S3, separate
   `DeleteObjects` passes). A delete that fails partway (`503`, job left `DONE` for a retry) never
   leaves a stored `attestation.json` without the marker that withholds it. On S3 this costs extra
   API calls per delete.

9. **Hostile output trees no longer wedge the sweeps.** A deep chain of directories at
   `attestation.json` is removed with a bounded iterative walk instead of `shutil.rmtree`
   (which hit `RecursionError`). A FIFO at the receipt or envelope name no longer blocks a sweep.
   Each tree runs behind its own error handler, so one bad tree is logged and left in place
   while the rest of the tick proceeds. On the local blob store a directory at a result key reads
   as absent, as on S3, so such a result is judged instead of answering `503`.

10. **`/metrics` node totals fail closed.** The ingress's `node_*` series are omitted, not
    undercounted, when any dispatcher snapshot cannot be stat'd, opened or read, or exceeds the
    size cap (at listing, at `fstat`, or while being read). The omission warning names the
    unreadable snapshots. A snapshot removed after the listing still just drops out.

## Key rotation

Unchanged, and still important: rotate or unset `BLASTBOX_ATTEST_KEY` only when the host has
no retained pending uploads. The sweep keeps a retained receipt only if it verifies against the
host's current key; results pending at a rotation ship with a tombstone instead.
