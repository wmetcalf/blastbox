# Roadmap: detections/signatures, analysis-engine primitives, and the fleet plane

**Date:** 2026-06-08
**Status:** direction captured (Will), most items revisited AFTER the ClippyShot/redtusk port
**Source:** landscape study of AssemblyLine / FAME / Strelka / CAPE / Dangerzone +
agent-sandboxes (nono/e2b/Daytona/gVisor/FC/Landlock) + prompt-injection scanners
(Rebuff/LLM Guard/Lakera/NeMo/garak) + fleet prior art (K8s RuntimeClass/NFD,
cluster-autoscaler, Nomad, KEDA, CC attestation). Adversarially critiqued.

> **Priority note (Will, 2026-06-08):** this is a SECURITY-focused detonation
> framework, so **detections/signatures are first-class and must be supported out
> of the gate** (the `Record` rung is acceptable). We do **not** need a `Verdict`
> score/aggregation. `UnicodeAnomaly` is deprioritized (too niche to lead with).
> Resume the ClippyShot/redtusk port first; revisit the feature work here later.

---

## 1. Detections / Signatures — FIRST-CLASS, out of the gate (Record rung)

The single biggest result-model element blastbox lacks vs AssemblyLine/CAPE/FAME:
blastbox says what a file *is* (`Detection`) and *contains* (payload tree), but not
that **a rule fired**. For a security framework that's the core output.

**Shape** (a rule-fired finding; emit via the `Record` floor or a registered
`type='signature'` node — both keep the host re-seal intact, no `extra='allow'`):
```
Signature {
  rule_id: str            # stable id of the rule/heuristic that fired
  name: str
  description: str | None
  severity: Literal[critical, high, medium, low, info]
  confidence: float       # 0..1 (reuse Detection.confidence convention)
  produced_by_engine: str # per-finding attribution (multi-engine over one file)
  categories: list[str]   # free taxonomy (e.g. macro, exploit, phishing)
  families: list[str]     # optional malware family labels
  attack_ids: list[str]   # optional MITRE ATT&CK ids
  references: list[str]
  marks: list[Mark]        # evidence: Mark{kind: file|url|span|node, ref: ArtifactRef|node_id|str, evidence: str(capped)}
}
```
- **Rung:** `Record` (or `register_node_type('signature')`) — NOT a forced core leaf.
  A `Record`-based convention means engines emit signatures **today**, zero contract
  change; a registered node gives typing but couples the host image. Decide at impl
  time; default to the `Record` convention for no host-coupling. Either way **document
  one canonical shape** so per-engine UIs render detections uniformly.
- **`marks`** tie a rule to exact evidence (an artifact, a text span, a node) — the
  AssemblyLine/CAPE `add_match` model.
- **Routing safety:** engine selection / re-analysis must key on **host-derived
  `Detection`** (label/mime the host trusts), NEVER on worker-emitted tags/signatures
  — else a malicious sample steers its own re-analysis (suppress the engine that
  catches it, or trigger an expensive fan-out as DoS).

## 2. Verdict / scoring — NOT needed
AssemblyLine's score+band MAX-over-tree is well-designed but **we don't want it**
(per Will). Consumers gate on the presence/severity of `Signature`s directly. Skip.

## 3. `NodeId{node_id, parent_id, root_id}` — foundational *if* we want by-reference attribution
Strelka tree-linkage on every node. Lets a `Signature`/`Indicator` attach to a
**specific** node by reference instead of only by inline nesting. **Not a blocker for
detections** (a signature can attach inline as a child of the relevant Page/
EmbeddedResource). Add it when cross-references are needed. If added: host
`validate_envelope` must re-check tree consistency **iteratively + bounded**, rejecting
cycles / duplicate ids / dangling parents in one pass (mirror `_check_json_depth` — it
is adversarial input on the trust gate's hot path, a DoS surface).

## 4. `UnicodeAnomaly` — deprioritized
Deterministic unicode-smuggling leaf (tag blocks, zero-width, bidi, surrogates). Real
and cheap, but too niche to lead with. Park it; it can ride the injection engine later.

## 5. Prompt-injection detonation engine — flagship future capability
A `register_node_type('injection_report')` engine (zero envelope change) that scans
already-extracted text/HTML/links for injection/jailbreak/exfil **before** a RAG
pipeline or agent ingests the document.
- **Core is deterministic/model-free** (unicode/codepoint scan on RAW bytes pre-NFKC,
  regex/heuristic signatures, bounded decoder pass, exfil-link/markdown-image structural
  check) — *because the scanner must itself be immune to prompt-injection* — with an
  optional ML classifier as an additive confidence layer only.
- **Differentiator** hosted APIs (Lakera/Prompt Shields) don't expose: `span` +
  `artifact_ref` provenance per finding, riding the existing zero-trust seal.
- Regression corpus: garak / promptmap fixtures.
- Emits `Signature`/`InjectionFinding` records — the §1 detection mechanism.

## 6. Behavioral effects + AI-native — RESERVED (do not spec fields now)
`FileSystemEffect`/`NetworkEffect`/`ProcessEvent` and `ToolCall`/`LLMInvocation` are
schema for an agent-exec tier + dynamic-detonation engine that **don't exist yet**.
Reserve a one-line note; land at the `Record` floor only when a real emitter ships —
and mandate they be **host/kernel-observed (eBPF/auditd/runsc-trace), never
worker-self-reported** (a compromised worker omits its own exfil event; same reseal
principle).

## 7. Structural lessons adopted (from the analysis frameworks)
- **Service-selection as data, in HOST config (not the sealed contract):** a declarative
  `EngineSelector{accepts/rejects over Detection.label+mime, stage, triggered_by}` routes
  a file + its extracted children to engines by type + prior host-findings.
- **Service-recursion as a re-entrant pipeline:** route `EmbeddedResource` children back
  through engine-selection as new work, with a host-side `(sha256, engine)` visited-set
  + depth budget (contract already carries `EmbeddedResource.depth`).
- **Per-finding attribution:** every Signature/Indicator carries `produced_by_engine`
  (Envelope has only one top-level `engine` today).

---

## 8. Fleet control plane — corrected design (SEPARATE product, after a threat model)

**The flaw in the first framing:** "capability *attestation* by node self-report" is
worthless against a compromised node, and blastbox's OWN threat model proves it —
`container.py` permanently appends `network_egress_not_verified` + forces `secure=False`
because a sandbox cannot trust its own `/proc` introspection. A node running escaped
malware can claim `tier=firecracker` while running `runc`, get admitted, and receive
untrusted samples under no isolation. Self-report is **weaker** than the single-host
posture, not a lift of it.

**The fix = the genuinely novel core:** relocate the trust root from node → **host**.
- `Provenance.effective_tier` = **what the dispatcher invoked** (`select_worker_runtime`
  already chooses + launches the runtime — the host KNOWS), never what the node claims.
  Stamped host-side at reseal, fused into the zero-trust output seal. *No clean prior
  art* (K8s/SLSA provenance is build-time, not "which isolation tier ran this untrusted
  sample"). This is the defensible differentiation.
- **Fail-closed-on-downgrade:** a first-class, refusable event with a distinct terminal
  reason + metric (in K8s a mislabeled node silently runs a "gvisor" pod under runc; for
  malware that's a compromise, not a perf blip).
- Node capability probes = **"operational hints, untrusted"** — used only to avoid
  dispatching an FC job to a box with no `/dev/kvm`, NEVER as the security gate.

**Cut (it's reinvention + the security goal opposes it):** the `FleetAutoscaler` +
secure-tier *scheduler* are ~70% cluster-autoscaler + kube-scheduler. For an
untrusted-malware fleet you want the OPPOSITE of clever bin-packing — a few homogeneous
high-tier nodes, statically partitioned by tier.

**MVP = 3 things, on one host:** (a) `Provenance.effective_tier` stamped host-side at
reseal; (b) fail-closed-on-downgrade with a distinct terminal reason + metric; (c) a
dumb "pick any admitted node ≥ floor" selector. Defer everything else.

**Packaging + threat model:** a **separate product/repo** that depends on blastbox but
doesn't bloat `blastbox.host`. Its threat-model doc must state plainly:
*self-reported-but-policy-verified defends against misconfiguration, NOT a compromised
node; hostile-node / multi-tenant requires measured/TEE attestation (SEV-SNP/TDX),
out of scope.* Autoscaling untrusted-malware nodes also needs an explicit network
posture (per-node egress-deny, no node-to-node reachability, no IMDS/metadata access —
SSRF-to-IMDS is a real cloud-credential-theft path for detonated malware) before any
node autoscaling is built.

---

## 9. Sequencing
1. **NOW:** finish the ClippyShot cut-over (in flight) + redtusk port.
2. Contract-extensible-fields (Source/Indicator/QrCode/OcrResult/Timing/Truncation/
   Provenance/Hash md5+sha1 — separate spec) → blastbox 0.1.7. Fold in a documented
   **`Signature` detection shape** (Record rung) so detections work out of the gate.
3. Prompt-injection engine (flagship).
4. Fleet MVP (host-stamped `effective_tier` + fail-closed-downgrade) as a small separate
   effort; defer the scheduler/autoscaler.
