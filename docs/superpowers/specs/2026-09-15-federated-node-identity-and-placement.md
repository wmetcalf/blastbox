# Federated node identity + placement (design, for argument)

> Status: DRAFT FOR ARGUMENT. Captured 2026-09-15 from the Loadout thread: *"register their
> infra as a blastbox machine, and then based on available resources move
> engines/workers/networks."* Nothing here is built. It spans `pki.py`, the job store and
> Loadout's boundary, so it is written to be attacked before any of those is touched.
>
> The question that started it was "should this be an authed p2p setup?". The answer this
> doc argues is **one identity, no p2p, and the substrate you already have** — with the
> real difficulty being somewhere other than authentication.

## 1. What already exists (do not rebuild any of it)

| surface | what it does | trust model | extends to third-party infra? |
|---|---|---|---|
| `host/pki.py` | private CA; SAN-pinned **server** certs for workers, **client** certs for the dispatcher (`ensure_ca`, `issue_*`, `import_ca`) | CA-rooted mTLS | **yes** — this is the seed |
| `host/jobs/{redis,sql}_store.py` | atomic `claim_next` + `update_if_status` CAS over `WATCH/MULTI/EXEC` / SQL | shared store is trusted infra | **yes** — already network-distributed |
| `host/node_share.py` | dispatchers publish sizing snapshots to a **bind-mounted directory** | *explicitly* a node-local single trust domain, like `/var/run` | **NO — and it says so** |
| `host/node_sizer.py` | `plan_sizes(specs, budget)` — deterministic placement over a node view | pure function | yes, if fed a different view |
| `host/trust.py` | re-seals every artifact hash host-side; worker claims are discarded | worker output is **hostile** | yes — and it is the pattern to copy |
| `host/egress.py` (new) | per-node containment; `enforcement_present()` reports it | node reports on itself | **only if verified centrally** (§5) |

Two of these settle arguments before they start:

* **`node_share` is the wrong substrate and already knows it.** Its docstring calls the share
  "a NODE-LOCAL COORDINATION SURFACE within a SINGLE TRUST DOMAIN" and argues that an HMAC
  among mutually-distrusting dispatchers is theatre, because a compromised dispatcher holds
  the secret. That reasoning is sound *for a shared filesystem* and simply does not reach
  across someone else's hardware, where there is no shared filesystem to permission. Leave
  `node_share` doing node-local sizing. Federation is a different substrate, not a patch to
  this one.
* **`plan_sizes` is already the placement algorithm.** It is a pure function from specs +
  budget to sizes. Federation does not need a new scheduler; it needs a trustworthy *node
  view* to feed the one that exists.

## 2. Three problems that must not be conflated

The phrase "authed p2p" bundles three things with different failure requirements. Every
muddle downstream comes from solving them together.

| | question | must fail | needs consensus? |
|---|---|---|---|
| **Identity** | is this node who it claims to be? | closed | **no** |
| **Membership / liveness** | is it up, and what does it have? | closed | yes (a shared view) |
| **Placement** | what may it run? | closed | no — an authority decision |

**Identity does not need to be online.** A CA is not a runtime single point of failure:
certificates keep verifying while the CA is down. It is needed at enrollment and renewal
only. So "resilient to single-node failure" is not an argument against a CA — it is an
argument for short-lived node certs plus an offline-capable root. Availability pressure
belongs on membership, which is the only part that must be live.

## 3. Why not p2p

Setting aside taste, three concrete objections:

1. **A membership protocol that fails open decides who receives malware.** Gossip converges
   by assuming reachable peers are valid. Under partition that means "keep going" — the
   opposite of what a containment boundary needs. This is the same objection that put
   WireGuard rather than a swarm/VXLAN overlay under the egress tier: *a dead tunnel is a
   dead route*, and fail-closed stays a property of the kernel routing table rather than of
   a control plane's health.
2. **Admission control is inherently an authority statement.** "This operator's node may run
   `boxjs` but may never hold VPN credentials" has no expression in a gossip mesh. Every
   serious p2p system ends up bolting a CA or an allow-list onto the side, at which point
   the mesh is decoration.
3. **Revocation.** A compromised third-party node must stop receiving work *now*. Short-lived
   certs give revocation-by-expiry — a bounded, offline-safe mechanism. Gossip gives you
   an eventually-consistent rumour that the compromised node participates in.

## 4. The proposal

### 4.1 One enrollment, one identity

`blastbox node enroll` → a CSR signed by the existing CA → a **node certificate** whose
subject is the node identity and whose extensions carry its **grants** (which engines, which
netpolicy tiers, whether it may hold credentials). That one cert then:

* authorises the WireGuard peer, **replacing the hand-pasted public-key exchange** currently
  in `egress peer` / `egress peer-add` (the wg key is derived per-node and registered from
  the cert, not copied by an operator);
* authenticates the node to the job store / control plane over mTLS;
* names the node in the federated view.

Short lifetime (hours–days) with automatic renewal. Revocation is "stop renewing", which
needs no CRL distribution and no online check in the hot path.

**Open question for argument:** grants in X.509 extensions vs. a signed grant token
alongside the cert. Extensions bind grants to identity at issuance (good) but make a grant
change require reissuance (annoying at fleet scale).

### 4.2 Membership on the substrate you already run

Node registration, heartbeats and resource snapshots go in **the job store** — Redis or SQL,
whichever the deployment already uses. Reasons:

* every node already depends on it and already coordinates through it (`claim_next` is
  distributed mutual exclusion with CAS fencing, in production, tested);
* its failure semantics are already understood by whoever is on call;
* HA is a solved, boring problem there — Redis Sentinel/Cluster, Postgres replication —
  rather than a second consensus system to reason about at 03:00.

A node's snapshot is `node_share`'s `EngineNode`/`NodeConfig` shape, published to the store
under its **certificate identity** instead of a filename, with a staleness window (the
existing design's self-healing property: a stopped node drops out on its own).

This is the part that satisfies "resilient to failures of a single node": no node is
special, any dispatcher can read the view, and the store is the thing you make redundant.

**Open question:** whether the control plane is a process at all, or whether — as with
`node_share` — every dispatcher reads the same view and runs the same deterministic
`plan_sizes` over it, converging without an elected leader. The latter is truer to the
existing design and has no leader to lose. It needs placement to be a **pure function of
the view**, which `plan_sizes` already is.

### 4.3 Placement

Feed the federated view to `plan_sizes`. The new input is not algorithmic, it is
**eligibility**: a node may only be assigned an engine its cert grants, and a netpolicy tier
its cert grants. Placement then becomes the existing sizing problem over a filtered set.

## 5. The actually hard part: a registered node is untrusted

This is where the design should be attacked hardest, because it is the part the phrase
"global auth mechanism" hides. Authentication tells you *which* stranger's machine you are
talking to. It tells you nothing about whether that machine is doing what it claims.

Loadout hands a third party live malware samples and, if it holds egress, a route out
through your infrastructure. A hostile or merely broken registered node can:

* **lie about its resources** to attract work it cannot isolate;
* **lie about its results** — return a clean verdict for a sample it never detonated, or a
  fabricated one;
* **lie about its containment** — this is the sharp one. `enforcement_present()` was built
  this week and is *self-reported*. Four review rounds went into making it honest about a
  node's own state; none of that matters if the node reporting it is the adversary.
* **exfiltrate the sample**, which may be a customer's confidential binary;
* **use its egress grant as a laundering path** for its own traffic.

**blastbox already solved the same shape one level down.** `trust.py` treats worker output
as hostile: it discards whatever the worker claimed and re-seals every artifact hash from
disk host-side. Federation needs that pattern raised one level — *don't trust the node
either*. Concretely:

| node claim | how it stops being a claim |
|---|---|
| resources | assign against **observed** completion behaviour, not advertised capacity; a node that over-claims simply gets slower and drops in the view |
| results | the node's envelope is already signed; the **verification** must happen off-node. Spot-check by re-running a sampled fraction elsewhere and comparing |
| containment | **verify externally**: the exit host can see a peer's traffic. A node claiming containment while sourcing traffic outside its allocation is observable *from the other end of the tunnel* |
| sample confidentiality | cannot be enforced technically on someone else's hardware — this is a **tiering decision**, not a control (§6) |

That containment row is worth stating plainly: the reason to centralise exits is not only
credential hygiene. It is that **the exit host is the one place a peer's containment can be
externally observed.** The egress tier's shape accidentally already supports this.

## 6. What I do not think you can have

Honesty ahead of enthusiasm, because this bounds the product:

* **You cannot make someone else's hardware confidential.** A registered node has the sample
  in memory. For customer-confidential material the answer is a trust tier — first-party
  nodes only — not a cryptographic trick. Attestation (TPM/SEV-SNP) narrows this and does
  not close it, and it excludes most hardware people would actually register.
* **You cannot fully verify a remote detonation.** Sandbox output is not deterministic;
  re-running elsewhere gives a probabilistic check, not a proof. Spot-checking raises the
  cost of lying; it does not eliminate it.
* **Fail-closed and "resilient to single-node failure" pull against each other.** Every
  ambiguity this design resolves toward *closed* is capacity you lose during a partition.
  That trade should be explicit per tier, not global.

## 7. Suggested order (each independently useful)

1. **Node certs from the existing CA**, and make `egress peer`/`peer-add` consume them
   instead of a pasted public key. Pure win, small, removes a manual step I built by hand.
2. **Node registration + heartbeat in the job store**, read-only at first: a federated view
   that nothing yet acts on. Observable, reversible, no placement risk.
3. **Eligibility filtering in `plan_sizes`** — grants restrict which engines/tiers a node may
   be assigned. Still first-party nodes only.
4. **External containment verification at the exit host** (§5). This is the gate that should
   precede any third-party node holding egress.
5. **Third-party registration**, behind a trust tier, non-confidential samples only.

Nothing before step 4 should be sold as "register your infra".

## 8. Objections I expect and have no answer to yet

* Does putting membership in the job store couple two failure domains that should be
  separate? A store outage currently stops job flow; it would then also blind placement.
* Leaderless convergence (§4.2) assumes every dispatcher sees the same view within a
  staleness window. Across WAN-separated third-party nodes, is that assumption still safe,
  or does it produce oscillating placement?
* Grants in certs vs. tokens (§4.1).
* Is `plan_sizes`' budget model even meaningful when nodes are heterogeneous and
  operator-controlled?
