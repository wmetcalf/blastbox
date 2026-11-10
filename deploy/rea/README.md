# rea-bb: the REA engines on a blastbox host (toolz2)

Two engines from one pinned image (`deploy/docker/Dockerfile.rea-cold-worker`):

```text
rea         pass 0  sweep + Ghidra auto-analysis + IOCs + icons + continuation   network none
rea-agent   pass N  DeepSeek-driven Ghidra pass over the continuation            personality rea_model
```

Both run cold, one disposable gVisor (`runsc`) container per job. The only network either
engine ever gets is `rea-agent`'s single HTTP route to the model, through `rea-model-proxy`.

Deployed on toolz2 (172.18.101.15) on 2026-10-31:

```text
compose project   rea-bb  (~/rea-bb/compose.yml = this directory's compose.yml)
ingress           https://172.18.101.15:8006   (bearer key; CA ~/rea-bb/ca.crt)
bearer key        ~/rea-bb/.env  BLASTBOX_API_KEY   (0600, coz)
attest key        ~/rea-bb-keys/attest.key  (dispatcher only)  key_id 436a71440f08b99f
data              ~/rea-bb-data   (uid 10001)
tls               ~/rea-bb/tls    (uid 10001; CA key in ~/rea-bb/pki-ca, 0700)
containers        rea-bb-{api,dispatcher,postgres,docker-socket-proxy}-1, rea-model-proxy
networks          rea-bb_backend (internal), rea-bb_frontend, rea-bb_model-egress,
                  bb-rea-model (operator-created, --internal, 10.231.200.0/24)
```

Loadout: `LOADOUT_REA_URL=LOADOUT_REA_AGENT_URL=https://172.18.101.15:8006`, and `LOADOUT_REA_API_KEY` and
`LOADOUT_REA_AGENT_API_KEY` = the bearer key. Loadout has no per-engine CA setting: its adapter uses
Python's default TLS verification. Trust the private CA by pointing Loadout's process at a merged
bundle, the system bundle plus `ca.crt`:

```sh
cat /etc/ssl/certs/ca-certificates.crt ~/rea-bb/ca.crt > ~/.config/loadout/ca-bundle.pem
SSL_CERT_FILE=$HOME/.config/loadout/ca-bundle.pem   # in Loadout's environment, not this stack's
```

Keep the system bundle in it: `SSL_CERT_FILE` replaces the default trust store for the whole process,
so a bundle holding only `ca.crt` would break every other HTTPS call Loadout makes. Rebuild it when
either the system bundle or `ca.crt` changes.

## Build

```text
image                         from                                                     toolz2 id
blastbox-rea:dev              Dockerfile.rea-cold-worker @ feat/rea-engine 80308c5      145bcbd61123 (prev: blastbox-rea:dev-d0e82b8 @ d0e82b8)
blastbox-rea-sweep:or2        Dockerfile.stack-worker ENGINE_CLASS=ReaSweepEngine        3ca526ecad09
blastbox-rea-agent:or2        Dockerfile.stack-worker ENGINE_CLASS=ReaAgentEngine        1b80e0eaac97
                              (both with the OpenRouter build args, see "Hosted model")
blastbox-rea-host:0def6b2     Dockerfile.host @ deploy/rea-toolz2 0def6b2                8f6eab0bb0eb
rea-model-proxy               kalaksi/tinyproxy@sha256:fafafc7079ca29c6704564de1353f61d038f2166f09b01d4e460e8e499bf6b57 (tinyproxy 1.11.3)
```

Slots: toolz2 sets `REA_CONCURRENCY=1` (Ruling AN). The DeepSeek endpoint serves one sequence at a
time, so a second agent slot only queues behind the first and burns its wall. The dispatcher has a
single slot count (`BLASTBOX_DISPATCH_CONCURRENCY`) for every engine it serves, so sweeps get one slot
too. A separate rea-agent dispatcher would be needed to give sweeps more.

`deploy/rea-toolz2` is a LOCAL merge branch (feat/rea-engine 4fe5f69 + feat/netpolicy-httpproxy-bridge
fbbbaaf, merge commit 0def6b2). It is not pushed. The host image needs it for the httpproxy `bridge=` key.

```sh
# worker (context = repo root at feat/rea-engine)
docker tag blastbox-rea:dev blastbox-rea:dev-prev
docker build -f deploy/docker/Dockerfile.rea-cold-worker -t blastbox-rea:dev .
# toolz2 runs the hosted model: add the three OpenRouter --build-arg lines from "Hosted model"
# to both stack-worker builds below.
# A digest BASE_IMAGE for a freshly built local image failed to resolve on toolz2 (buildkit tried
# docker.io). After checking that blastbox-rea:dev has the pinned id, pass the tag instead:
docker build -f deploy/rea/Dockerfile.stack-worker -t blastbox-rea-sweep:or2 --build-arg BASE_IMAGE=blastbox-rea:dev \
  --build-arg ENGINE_CLASS=blastbox.engines.rea:ReaSweepEngine --build-arg ENGINE_NAME=rea .
docker build -f deploy/rea/Dockerfile.stack-worker -t blastbox-rea-agent:or2 --build-arg BASE_IMAGE=blastbox-rea:dev \
  --build-arg ENGINE_CLASS=blastbox.engines.rea:ReaAgentEngine --build-arg ENGINE_NAME=rea-agent .
# host (context = repo root at deploy/rea-toolz2)
docker build -f deploy/rea/Dockerfile.host -t blastbox-rea-host:0def6b2 .
```

## Deploy

```sh
docker network create --internal -o com.docker.network.bridge.gateway_mode_ipv4=isolated --subnet 10.231.200.0/24 bb-rea-model   # isolated: the host gets no address on it
mkdir -p ~/rea-bb ~/rea-bb-data/jobs ~/rea-bb-keys ~/rea-bb/tls
cp compose.yml tinyproxy.conf tinyproxy.filter ~/rea-bb/
install -m 600 env.example ~/rea-bb/.env            # fill in every REPLACE_ME
# ingress cert: a private CA + a P-256 server cert with SAN IP:172.18.101.15 -> ~/rea-bb/tls/{ca.crt,ingress.crt,ingress.key}
# data, keys and tls must be owned by uid 10001 (keys 0700)
cd ~/rea-bb && docker compose -p rea-bb -f compose.yml up -d
```

## How the config maps onto blastbox (what the plan said vs. what works)

Three things in the plan's Step 2 cannot work as written. Each was found live:

1. **Personality name.** `parse_personalities` lower-cases the env suffix, so
   `BLASTBOX_NETPOLICY_REA_MODEL` registers `rea_model`. With
   `BLASTBOX_ENGINE_REA_AGENT_NETPOLICY=rea-model` (hyphen) the name is unknown and resolves,
   fail-closed, to `none`. The first live `rea-agent` job ran with `--network=none`
   (`net_policy_resolved ... personality=none driver=none`) and sealed `model_status=unavailable`,
   `warnings=[model_unavailable]`. The compose file uses `rea_model`.
2. **Operator values cannot go in `_DEFAULT_PARAMS`.** Defaults pass the same gate as job params:
   every `BLASTBOX_*`/`LD_*`/`PYTHON*` key is dropped, so `BLASTBOX_ENGINE`,
   `BLASTBOX_DETONATE_NAME`, `BLASTBOX_WORK_DIR` and the in-slot Limits (`BLASTBOX_TIMEOUT`, ...)
   never reach the worker that way. Also, a forwardable key is job-overridable (`{**defaults, **params}`):
   `REA_MODEL_URL` as a default would let a job re-point the model. A reserved key is dropped
   entirely, default included. So the operator values are baked into two derived images
   (`Dockerfile.stack-worker`). The stack sets `_PARAM_KEYS=""` (the empty allowlist blocks every
   client param and every default) and lists every `REA_*`/JVM/proxy/HOME knob in `_RESERVED_KEYS`.
   `BLASTBOX_ENGINES` therefore names two tags (`rea=blastbox-rea-sweep:…`,
   `rea-agent=blastbox-rea-agent:…`), not `blastbox-rea:dev` twice.
3. **Worker Limits and scratch.** The cold worker's `Limits` come only from the image env (the
   dispatcher does not forward them). Without `BLASTBOX_TIMEOUT` the slot gets 120 s. The cold
   dispatcher mounts exactly one writable dir: `/tmp` (`nosuid,noexec,size=512m`, hard-coded in
   `docker.py` `_DEFAULT_TMPFS`). The engine default `/work` does not exist on the read-only rootfs.
   The images therefore set `BLASTBOX_WORK_DIR=/tmp`, `BLASTBOX_TMPFS=536870912`,
   `BLASTBOX_TIMEOUT=840` (dispatcher kill at 900), the 1 GiB / 2 GiB artifact caps, `REA_MODEL_URL`,
   `REA_MODEL_ID`, `REA_PASS_WALL_S=540`, `REA_GHIDRA_SWEEP_S=420` and `REA_MAX_STEPS=16`. Ghidra + REA
   work on the noexec 512 MiB tmpfs under runsc (benign PE sweep: 101 s with this exact flag set).
   The agent's model budgets use the engine defaults (not baked): `REA_TURN_MAX_TOKENS=2048` per
   tool-choice turn, `REA_MAX_COMPLETION_TOKENS=4096` for the final answer, and
   `REA_MODEL_TOKENS_PER_S=30`, which sizes the final-answer reserve (with the report below,
   270 s of the 540 s wall; 171 s before G3). `REA_MODEL_TIMEOUT_S` is unset, so each request's timeout is the time left
   in its phase; set it only as an upper cap. An `unavailable` request is retried once while the
   phase has time. Tool results reach the model cut to 12 KiB (head + tail), and
   `analyze_function` always runs at `detail=summary`. The final answer is schema-constrained
   (`response_format` json_schema from `prompts.final_schema`: at most 20 functions, 16 IOCs, 24 todo
   addresses, a 2000-char summary) and asks for `chat_template_kwargs {"thinking": false}`
   (`REA_FINAL_THINKING=1` keeps reasoning on). Live on 2026-11-03 the reasoning ate the 4096-token
   budget and cut the answer off mid-function. A cut-off answer keeps its complete rows
   (`model_final_salvaged`); an unusable one is asked for once more with the tokens the time left
   allows (`model_final_retry`, at least 512). Transcript turns record `finish_reason` and
   `completion_tokens`.
   **Analysis report (G3).** After an accepted final answer the agent makes one more
   schema-bound call (thinking off, `prompts.report_schema`) that writes `analysis_report`, a
   `rea.analysis/1` object describing what the program does (overview, execution flow,
   capabilities, network, persistence, host activity, anti-analysis, unknowns), each section
   `observed`/`not_observed`/`not_analysed` with function-address evidence, plus an AI-proposed
   verdict. It sees this pass's findings, IOCs and summary, the sweep's kind and first 64 IOCs
   (`State.sweep`) and the previous pass's report (`State.analysis_report`, which pass N+1
   rewrites). Evidence addresses the passes never saw are dropped (`report_evidence_dropped`); an
   `observed` section left without evidence becomes `not_analysed`. It is sealed in `rea.pass/1`
   as compact JSON text (Record values cannot hold lists of objects; see `agent.py`). The call gets
   `REA_REPORT_MAX_TOKENS=3500` (0 turns it off). The final reserve plans for measured use, not
   the caps: `REA_RESERVE_TOKENS=4096` covers the final answer plus the report (the G3 gate's
   largest pass used 1816 + 1601), so 1.25 x 4096 / 30 = 171 s of the 540 s wall. The report is cut to what
   the time left holds at the pass's measured tokens/s, or skipped under 1024 tokens
   (`report_skipped_deadline`). A failed or invalid report (`report_failed`, `report_invalid`)
   never costs the pass its findings; a cut-off one keeps its complete sections (`report_salvaged`).
   To change a knob, add it to the agent
   image's `ENV` in `Dockerfile.stack-worker` (all `REA_*` keys are reserved).
   The sweep's `rea.report/1` carries an optional `chain_stop` (`not_native`, `ghidra_failed`,
   `ghidra_timeout`, `unsupported_arch`, `packed`; see `sweep.py`). When it is set the sweep seals
   `more_pending=false` with no continuation (Ruling AL). `packed` needs the `function_count` line
   that `ghidra_scripts/ListStrings.java` now writes first, so rebuild the base image too.
   **A Ghidra timeout or failure no longer ends the chain** when the sweep collected anything else
   (IOCs, unpacking, emulation, .NET resources, capa, API hashes): the sweep seals `more_pending`
   with a continuation that has no project and no `chain_stop`, and the agent runs ONE pass with no
   MCP session: a single report call over the sweep's evidence. That report is `rea.analysis/1`
   with `basis: evidence` (set by the engine, never taken from the model) and cites sweep sources
   (`{source, item?, note?}`) in place of addresses; a row citing a source the sweep did not
   produce is dropped like an unknown address. The pass seals `stop_reason: evidence_only` and the
   gap `code_unread`: no code was read, so the bar is never met on evidence alone. Needs the
   Loadout companion (`evidence_only`, `code_unread`, source rows) or the pass is refused.
   **Signatures.** Before Ghidra the sweep matches the submitted file, the unpacked image and
   every recovered member (installer payloads, emulation captures, hidden .NET payloads) against
   CAPEv2's family rules with YARA-X (`signatures.py`, at most 60 s, out of process under
   `/opt/yara/bin/python -I` with `ulimit -d/-t/-f`; rules compiled at image build into
   `/opt/yara/cape.yarx`, see `PINS`). Matches go to `State.sweep["signatures"]`, the report
   (`signature_matches`) and the summary (`signatures_status`, `signatures_total`, `signatures`);
   the agent is told to treat a family match as a lead to confirm, and the evidence-only report can
   cite it (`source: signatures`). Measured on the 20 labelled samples (cape5, 2026-11-10): the
   rules name 1 of 20 (SalatStealer), 0 wrong, no match on ~680 benign files, under 1 s a sample.
   CAPE's rules target unpacked payloads; most of the 20 still end in an encrypted stage the sweep
   does not recover, and 11 of the families have no CAPE rule. Needs the Loadout companion (the
   three summary fields) or the sweep is refused.
   **.NET code is read with a decompiler, not Ghidra.** A .NET assembly is decompiled to C# with
   ILSpy's command-line front end (`dotnet_decompile.py`: `/opt/dotnet/dotnet
   /opt/ilspycmd/ilspycmd.dll`, at most 120 s, bounded like every other tool; it reads IL and
   metadata, the assembly never runs), and so are up to 3 .NET executables the resource scan
   recovered from it. The sweep keeps a digest per image (type outline plus the methods ranked most
   telling: entry point, module initialiser, loaders, network, persistence) in
   `State.sweep["decompiled"]` and the report (`decompiled`), feeds the C# string literals to IOC
   extraction (source `decompiled:sample` / `decompiled:member-N`) and reports `decompile_status` /
   `decompiled_images` in the summary. When the assembly's own code was read this way Ghidra is
   skipped (`ghidra_status: skipped`) and the agent writes its report in one call from the sweep's
   evidence (`basis: evidence`, citing `source: decompiled`); the `code_unread` gap is not raised,
   because the code was read. If ILSpy fails or finds no method bodies the assembly goes to Ghidra
   as before, and recovered stages are still decompiled for the agent to read. Measured on the 12
   .NET images of the 20 labelled samples (cape5, 2026-11-10): all decompile in 5-21 s; an
   unprotected RAT is readable whole (C2, command dispatcher, keylogger, persistence), a loader
   shows its loader, and a payload behind a commercial protector stays unreadable: no deobfuscator
   is run. Needs the Loadout companion (the two summary fields) or the sweep is refused.
   **Go string literals.** Go packs literals with no terminator, so a defined-string scan reads
   one literal into the next (live 2026-11-03: `http://loadout-go-fixture.example.org/ping`
   sealed with the strconv digits `1734723475976807094411` glued on, and the agent's byte check
   "verified" it). `gostrings.py` takes the exact bounds from Go's own string headers: static
   `{ptr, len}` pairs in the data sections and, on amd64, `LEA reg,[rip+x]` + `MOV next_reg,len`
   ABI register pairs. The sweep adds those literals as IOC source `gostring:0x<va>`; sweep and
   agent clip an IOC that starts with a literal's IOC but runs past it back to that IOC. A literal
   no header names keeps its old boundary.
   **Ghidra runs a trimmed analysis on PEs.** Five of the 20 labelled samples ended in
   `ghidra_timeout` because auto-analysis alone needed 500-2400 s of the 420 s budget. Every PE,
   and any ELF or Mach-O that is 4 MiB or larger or carries a Go or Rust marker, is now imported
   with the `LightAnalysis.java` pre-script, which switches off Decompiler Parameter ID, Call
   Convention ID, Decompiler Switch Analysis, Stack and the x86 Constant Reference Analyzer. Those
   five then finish in 42-384 s, with the function count within 0.5% (8% lower on the Go binary).
   What the project loses is committed parameter signatures and stack variables; the decompiler
   recovers them when the agent decompiles a function. Ghidra is also given
   `-analysisTimeoutPerFile` 60 s short of the budget: a run that hits it saves an incomplete but
   usable project (`ghidra_status` stays `ok`, warning `ghidra_partial`, and the agent is told to
   treat absences as unknown) instead of being killed with nothing.

   **Limit:** 512 MiB of scratch is the ceiling for a Ghidra project plus REA's private copy, so a
   very large sample can fail in the slot even though `BLASTBOX_MAX_INPUT` is 1 GiB.

One more: **the proxy is named by IP, not by name.** Under runsc a worker cannot reach docker's
embedded DNS (127.0.0.11), so `proxy=http://rea-model-proxy:8888` fails closed with
`curl: (5) Could not resolve proxy: rea-model-proxy`. Under runc the same name resolves to 10.231.200.2.
The personality uses `proxy=http://10.231.200.2:8888`, and compose pins the proxy to that address.

## Network

`rea-agent` slots run on `bb-rea-model`, an operator-created `--internal` bridge. Only
`rea-model-proxy` sits on it with them. The proxy is dual-homed (bb-rea-model 10.231.200.2 +
rea-bb_model-egress 192.168.128.2) and listens on the bb-rea-model address only. The dispatcher
injects `HTTP(S)_PROXY=http://10.231.200.2:8888` (both cases).

tinyproxy (`tinyproxy.conf`, `tinyproxy.filter`):

```text
FilterURLs On / FilterType ERE / FilterCaseSensitive Yes / FilterDefaultDeny Yes
filter      ^http://172\.18\.101\.13:8888/
ConnectPort 1          (any ConnectPort line makes the CONNECT list an allowlist; 1 is never used -> every CONNECT is 403)
Allow       10.231.200.0/24
Listen      10.231.200.2
```

The brief asked for a host filter `^172\.18\.101\.13$` plus port 8888 "if tinyproxy can express
that". A host filter cannot express a port: tinyproxy then forwards to any port on the model host.
With `FilterURLs On`, tinyproxy matches the full request URL (`http://host:port/path`, built from
the Host header for origin-form requests), so the regex pins scheme, host and port. Requests on
port 8888 can use any path.

### Hosted model (OpenRouter) through `rea-model-gw`

The engine never holds a hosted-model key. `rea-model-gw` (nginx, pinned by digest, read-only,
no capabilities) is the only holder: it sits on `model-gw`, an `--internal` /29 shared only with
`rea-model-proxy` (10.231.201.2), and on `model-egress` for the outbound leg. It serves exactly
`POST /api/v1/chat/completions` on 10.231.201.3:8080 (anything else is 403), adds the
`Authorization` header from `model-gw/secret/auth.conf` and forwards to openrouter.ai over
verified TLS with SNI, stripping client identity headers. tinyproxy gets one more filter line,
`^http://10\.231\.201\.3:8080/api/v1/chat/completions$`, so a slot can reach that one URL and
nothing else on the gateway.

Agent images for it are built with `--build-arg REA_MODEL_URL=http://10.231.201.3:8080/api/v1
--build-arg REA_MODEL_ID=deepseek/deepseek-v4.1-flash --build-arg REA_MODEL_DIALECT=openrouter`
(OpenRouter ignores `chat_template_kwargs`; the `openrouter` dialect sends `reasoning` instead).

The key file is one line, mode 0400, owned by the gateway's uid (1000), never committed
(`model-gw/.gitignore`):

```text
proxy_set_header Authorization "Bearer <key>";
```

### Gate inside the dispatcher

The dispatcher's `bridge=` gate runs `docker network inspect` through the socket proxy (which
needs `NETWORKS=1`). It accepts bb-rea-model as internal, and the agent job is launched on it.
This was checked live inside `rea-bb-dispatcher-1` with the real `Dispatcher._bridge_is_internal`:

```text
bb-rea-model verified_internal= True
bb-net0 verified_internal= False
bb-does-not-exist verified_internal= False
['none', 'rea_model']
rea_model -> ['--network', 'bb-rea-model']
```

The dispatcher log and the containers it launched:

```text
net_policy_resolved job=e1327fda-9731-47b4-8b65-eb05e43b1cd5 personality=none driver=none          (rea)
net_policy_resolved job=11dbdb9e-cf7a-4a65-b5f9-22a4ce48a14f personality=rea_model driver=httpproxy (rea-agent)
/blastbox-worker-4842e20a-f73 image=blastbox-rea-sweep:c1ac953 runtime=runsc net=none
/blastbox-worker-11dbdb9e-cf7 image=blastbox-rea-agent:c1ac953 runtime=runsc net=bb-rea-model labels={"blastbox.net.leakguard":"strict",...}
  env: BLASTBOX_NET_EGRESS=1 HTTP_PROXY=HTTPS_PROXY=http_proxy=https_proxy=http://10.231.200.2:8888
```

The dispatcher's signed receipts, checked with `blastbox attest verify --key pub.pem --cacert ca.crt
--engine <e> --input <file>` (rc 0, `verified: true`, `network_attested: true`, `worker_runtime: runsc`):

```text
rea        job e1327fda…  network {"exit": "none",      "policy_effective": "none",      "downgraded": false}
rea-agent  job 11dbdb9e…  network {"exit": "httpproxy", "policy_effective": "rea_model", "downgraded": false}
```

### Acceptance from inside a slot

`egress_check.sh` (in this directory) ran in two places: inside the live, dispatcher-launched `rea-agent` slot
(`docker exec -i blastbox-worker-11dbdb9e-cf7 sh -s`, during job 11dbdb9e), and again in a manual
runsc container on bb-rea-model with the same env. Both gave the same results. Output from the
live slot (rc = the command's own exit status):

```text
slot /blastbox-worker-11dbdb9e-cf7 runtime=runsc net=bb-rea-model
### env (as the dispatcher injects it)
BLASTBOX_NET_EGRESS=1
HTTP_PROXY=http://10.231.200.2:8888   (and HTTPS_PROXY, http_proxy, https_proxy)

### 1. model through the proxy (MUST answer)
$ curl -sS -m 30 http://172.18.101.13:8888/v1/models
http=200 bytes=464  [rc=0]
models: ['deepseek-v4-flash']

### 2. direct, no proxy (MUST fail)
$ curl --noproxy '*' http://1.1.1.1/                 curl: (7) Failed to connect to 1.1.1.1 port 80 after 0 ms   [rc=7]
$ curl --noproxy '*' https://1.1.1.1/                curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms  [rc=7]
$ curl --noproxy '*' http://172.18.101.15:8001/      curl: (7) Failed to connect to 172.18.101.15 port 8001       [rc=7]
$ curl --noproxy '*' http://172.18.101.13:8888/v1/models   curl: (7) Failed to connect to 172.18.101.13 port 8888 [rc=7]
$ curl --noproxy '*' http://192.168.128.1/  (proxy's egress gateway)   curl: (7) Failed to connect               [rc=7]
$ getaddrinfo('example.com')                         socket.gaierror: [Errno -3] Temporary failure in name resolution [rc=1]
$ UDP sendto 1.1.1.1:53                              OSError: [Errno 101] Network is unreachable             [rc=1]

### 3. other destinations via the proxy (MUST fail)
$ curl https://example.com/                          curl: (7) CONNECT tunnel failed, response 403  [rc=7]
$ curl -p http://example.com:443/  (forced CONNECT)  curl: (7) CONNECT tunnel failed, response 403  [rc=7]
$ curl http://example.com/                           http=403  [rc=0]
$ curl http://1.1.1.1/                               http=403  [rc=0]
$ curl http://172.18.101.15:8001/                    http=403  [rc=0]
$ curl https://172.18.101.13:8888/v1/models (CONNECT to the model)   CONNECT tunnel failed, response 403 [rc=7]

### 4. request-line / Host: tricks sent raw to the proxy
CONNECT example.com:443                                        -> HTTP/1.1 403 Access violation
CONNECT 172.18.101.13:8888 (the model itself, still CONNECT)   -> HTTP/1.1 403 Access violation
absolute URI allowed IP, other port :22                        -> HTTP/1.1 403 Filtered
absolute URI allowed IP, no port (:80)                         -> HTTP/1.1 403 Filtered
absolute URI to example.com, Host: says model                  -> HTTP/1.1 403 Filtered
origin-form GET with Host: model                               -> HTTP/1.1 200 OK        (= the model; allowed)
origin-form GET with Host: model host, port 22                 -> HTTP/1.1 403 Filtered
origin-form GET with Host: model:8888@1.1.1.1                  -> HTTP/1.1 404 Not Found (vLLM's 404 for "/": tinyproxy connected to 172.18.101.13:8888, see log)
origin-form GET, two Host: headers (example.com first)         -> HTTP/1.1 403 Filtered
origin-form GET with Host: example.com                         -> HTTP/1.1 403 Filtered
userinfo trick http://172.18.101.13:8888@example.com/          -> HTTP/1.1 403 Filtered
userinfo trick http://172.18.101.13:8888@172.18.101.15:8001/   -> HTTP/1.1 403 Filtered
prefix trick http://172.18.101.13:88880/                       -> HTTP/1.1 403 Filtered
suffix-host trick http://172.18.101.13.nip.io:8888/            -> HTTP/1.1 403 Filtered
hex IP http://0xac12650d:8888/v1/models                        -> HTTP/1.1 403 Filtered
uppercase scheme HTTP://172.18.101.13:22/                      -> HTTP/1.1 403 Filtered
ftp:// scheme to model host                                    -> HTTP/1.1 403 Filtered
control: allowed URL raw (MUST be 200)                         -> HTTP/1.1 200 OK
```

tinyproxy's log for the `@` Host case shows that it connected only to the model:

```text
Request (file descriptor 4): GET / HTTP/1.1
opensock: opening connection to 172.18.101.13:8888
Established connection to host "172.18.101.13" using file descriptor 5.
```

The proxy cannot be used from anywhere other than bb-rea-model:

```text
$ (container on rea-bb_model-egress) curl -x http://192.168.128.2:8888 http://172.18.101.13:8888/v1/models
curl: (7) Failed to connect to 172.18.101.13 port 8888 via 192.168.128.2 after 0 ms   [rc=7]
$ (container on docker's default bridge) curl -x http://10.231.200.2:8888 ...
curl: (28) Connection timed out after 8002 milliseconds                               [rc=28]
```

**The leak guard label is advisory here.** The dispatcher labels the slot
`blastbox.net.leakguard=strict`, but no netd watches rea-bb's jobs (toolz2's `bb-netd` serves the
redtusk job root), and a runsc slot has no host-visible netns anyway. Non-TCP containment comes
from the bridge: on an `--internal` bridge there is no route out, so a UDP send to 1.1.1.1 fails
with `ENETUNREACH`, as shown above.

## Corpus gate

See `CORPUS.md`. Real sealed envelopes and artifacts for Loadout's mapper tests (benign PE sweep and
its `rea-agent` pass) are in `corpus-envelopes/`.

## Operating notes

- `docker compose -p rea-bb -f compose.yml ps`; logs: `docker logs rea-bb-dispatcher-1`.
- The receipt public key comes from `docker exec rea-bb-dispatcher-1 blastbox attest-key --key /keys/attest.key`.
  The ingress itself holds no signing key: `/v1/attestation/key` answers "no attestation key is
  configured for this process".
- The model endpoint is shared. Pass times depend on its load (CORPUS.md).
- Teardown: `docker compose -p rea-bb -f compose.yml down` (keeps volumes), then `docker network rm bb-rea-model`.
