**Six weeks of unreleased work.** `v0.1.26` was tagged 2026-07-23; ~250 commits across 110 files have landed on `main` since, all under that same version number. Any consumer pinning `blastbox>=X` installs from PyPI, so every engine built against a published release has been running July-23 code. This release closes that gap.

**Read before deploying:** this is not an incremental bump. It carries the whole warm-pool failure-attribution, brownout-survival and hibernate rework, plus a new dispatcher startup gate. Run the full corpus as the regression gate before promoting it — unit tests and a probe boot are not sufficient for changes in this range.

### Nine PRs

| PR | What |
|---|---|
| **#78** | Bound the unbounded runtime calls on the hot paths; an UNKNOWN liveness tri-state instead of convicting a worker on silence |
| **#82** | Attribute warm-slot failures to the tier that caused them, and bound the blast radius of eviction |
| **#59** | Shared-CA mTLS between dispatcher and workers, plus `import-ca` |
| **#90** | Detect a wedged warm base — it had been costing 48 real jobs before self-repair |
| **#93** | One ACK identity per generation, tied to the published artifact |
| **#83** | Brownout tier survival (#79/#80/#81): a throttled or unanswerable probe is no longer evidence of death, and hibernate/park state is split into evidence and clock |
| **#87** | Startup canary — a dispatcher proves it can store a result before it claims a job |
| **#94** | S3 `delete_job` deletes every version, so a delete on a versioned bucket is actually a delete |
| **#95** | The `Engine` protocol stops requiring the methods it documents as optional |

### The two changes most likely to affect you

**#87 startup canary.** A dispatcher now refuses to claim work until it has proven it can write and read back a result blob. A misconfigured blob target that previously failed at result-upload time now fails at boot, loudly. That is the intent — it is the fix for the class of outage where jobs completed and their results 404'd — but it will surface latent configuration problems as startup failures.

**#94 versioned deletes.** On a bucket with versioning `Enabled` or `Suspended`, `delete_job` now removes every version and delete marker rather than writing a marker over them. This requires **`s3:ListBucketVersions` + `s3:DeleteObjectVersion`** in addition to `s3:DeleteObject`; where they are absent the delete now raises instead of falsely reporting a reclaim. Unversioned buckets are unaffected and take the same path as before. Verified against the MinIO fleet: the `blastbox` bucket reports un-versioned, so the plain path still applies there.

### Also in this range

Retention and reclaim durability (never delete the last copy; a failed result upload becomes a pending upload rather than a coin flip; crash-safe, ownership-fenced pending markers), a rewritten deep-tree purge that could previously spin or go quadratic, concurrent result upload with a per-dispatcher budget, `blastbox migrate-results`, and the node autosizer's proportional warm-floor shrink.

Area breakdown: pool 72 commits, warm 31, cascade 27, aws 26, snapshot 23, canary 19, dispatch 15.
