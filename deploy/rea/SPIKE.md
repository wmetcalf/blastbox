# REA spike: MCP over a headless Ghidra project

Spike date: 2026-10-31. Host: toolz2 (`~/rea-spike/`), throwaway containers only,
`--network none` for every analysis run. Benign samples only (a tiny C program
built in the container with mingw for the PE and gcc for the ELF). This file
records the gate decision for the REA engine design. The spike code itself is
throwaway.

## Gate result

**BLOCKED on the published release. PASS on unreleased `main`.**

- `rea-agents@6.8.0` is the npm `latest` and the newest release (2026-10-25).
  It **does not support** `REA_GHIDRA_PROJECT_PATH` or `REA_GHIDRA_PROGRAM_NAME`.
  The strings are not in its `dist/`, and `dist/config/ghidraExistingProject.js`
  does not exist. It ignores the variables without any warning and does a
  **fresh import plus full auto-analysis**:
  ```text
  analysis_profile.parameters.import_mode = "ephemeral-source-immutable"
  analysis_profile.parameters.analyzer_preset = "ghidra-default"
  limitation: "The imported Program and temporary project are ephemeral and deleted on close."
  first provider query (list_procedures): PE 38.8 s (analyzeHeadless alone took 38.9 s), ELF 17.3 s
  ```
  No error is raised. The only signs are the analysis profile and the timing.
- `morluto/rea@cd878ad` (`main`, 2026-10-30, built from source in a container)
  **does** reopen the saved project with no re-import and no GUI:
  ```text
  analysis_profile.parameters.import_mode = "existing-project-private-copy-v1"
  existing_project = {configured_path: /s/work/proj/sample.gpr, project_name: sample,
                      program_name: sample.exe, sha256: e75931aa...}
  limitation: "This session opens a caller-selected existing Ghidra project through a
               private copy, without import, auto-analysis or repair scripts."
  ```
  `procedure_pseudo_code main` returned the expected body
  (`uVar1 = _Argc * 3 + 7; __mingw_printf("hello loadout %d\n", ...)`), and the
  ELF gave the same result.

The design works with REA's current code, but not with any version that can be
pinned from npm today. **Decision for Will:** either wait for a `rea-agents`
release after 6.8.0 that ships `ghidraExistingProject` (then re-run Step 3 against it), or
pin a source commit and build it ourselves (see "Building main" below). The spike
did not change the architecture.

## Versions and pins

```text
rea-agents (npm)        6.8.0  integrity sha512-9QDeRnGqEDzABZyr04eLnBXBv/c6I9/TWu/6M0MD4pEfkySI/BIgwTODIbAReX3C1x6hjw9+Jlx4A2yUSPZ9ww==  (lacks the feature)
rea source (works)      github.com/morluto/rea@cd878ad57d3e27e835d0db533c9603b24ae8607a
                        codeload tarball sha256 44cec1b6be85a8ccf1576ca397594cdab2aacfbfc316cc817e5f568f7b7ad766
                        self-reports version "6.8.0" (version string does not distinguish it; pin by commit
                        + catalog digest tools_sha256 c819d694c65bd1482a0e780ff1848542f2046fe50a6b68fc366066b593d7e58f)
Ghidra                  12.1.4 PUBLIC 20260921
  url                   https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
  sha256                ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  (verified; matches GitHub asset digest)
JDK image               eclipse-temurin:21-jdk@sha256:ebfbb18d11ff163ee83b21258acf12248af48d22a0fdfdc68fa1a1516c05976a
                        (Temurin 21.0.13+9, Ubuntu 26.04.1, linux/amd64)
Node                    v22.23.4 official linux-x64 tarball, SHASUMS256-verified
                        (REA requires ^22.23.4 || ^24.22.1 || >=26.12.1; older 22.x is refused)
extra apt               procps (REA needs procps ps), unzip, gcc, mingw (samples only), python3 (driver only)
```

Ghidra 12.2 also exists (2026-10-16). It was not tested. The brief and REA's docs target 12.1.x.

## Install and postinstall

- `npm install --ignore-scripts rea-agents@6.8.0` into an empty dir took 11.9 s.
  `node_modules` is 168 MB.
- `rea-agents` itself has **no** install or postinstall script. Its only
  dependency with an install script is the **optional** `frida`. With
  `--ignore-scripts` frida's native binding is not fetched, so the frida tools
  stay unavailable, which we want anyway. `@lydell/node-pty` ships a prebuilt
  `pty.node`. **Postinstall is not needed** for the Ghidra path.
- Building main: `npm ci --ignore-scripts` (18.3 s, 739 packages) and then
  `npm run compile` (29.0 s) worked. `npm pack` failed because it runs the
  `prepare` script (`scripts/prepare.mjs`) even with `--ignore-scripts`. The
  spike ran the built tree in place through `node scripts/rea.mjs`. A pinned
  source build would need its own pack or copy step. The source tree with
  dev dependencies is 917 MB.

## Timings and sizes (32-core toolz2, no CPU/heap limits)

```text
sample.exe  PE32+ x86-64 mingw, 265255 B, sha256 acdd80fe04cbe7b414600a4c0517f756f51144cf87d77f8f2846c58eace179a1
sample.elf  ELF64 PIE gcc,       15960 B, sha256 f48b7358652ea57151f09f828136efc7eac85a0175e632d0d7c0f83c16565088

analyzeHeadless <proj> sample -import    PE 38.9 s (maxrss 982 MB)   ELF 13.2 s (maxrss 435 MB)
saved project size                       PE 3.8 MB                   ELF 1.3 MB
rea --mcp initialize                     ~0.7-0.9 s
tools/list                               0.2-0.3 s
open_binary                              ~3.8-4.0 s (lazy: does not start Ghidra)
first provider query, main/reuse         PE 20.7 s cold, 13.5-14.0 s on later runs; ELF 13.2 s
subsequent provider queries              0.05-0.3 s
first provider query, 6.8.0 (re-import)  PE 38.8 s, ELF 17.3 s
whole MCP session container wall         main PE ~19-28 s, maxrss ~450-490 MB
Ghidra install unzipped                  882 MB (zip 544 MB)
```

Reuse removes import and analysis time, which dominates for real samples. A
startup cost of about 13 s per `rea --mcp` session remains: headless JVM
start, the private project copy, and `-process -noanalysis -readOnly`.

## Step 3: MCP over the saved project (main build)

```text
env: REA_ANALYSIS_PROVIDER=ghidra GHIDRA_INSTALL_DIR=/s/opt/ghidra_12.1.4_PUBLIC
     REA_GHIDRA_PROJECT_PATH=/s/work/proj/sample.gpr REA_GHIDRA_PROGRAM_NAME=sample.exe
calls: initialize -> notifications/initialized -> tools/list -> open_binary{path:/s/work/sample.exe}
       -> list_procedures{detail:summary} (179 procedures) -> procedure_pseudo_code{entry|main}
       -> analyze_function{main} -> close_binary
```

- **The stdio server is `rea --mcp`, not `rea mcp`.** `rea mcp` only has
  `add` and `doctor` subcommands, which register the server and check its startup.
- `open_binary` still has to point at the original target file. REA checks
  that the program's recorded import SHA-256 matches the target. A PE project
  opened against the ELF target fails explicitly with `execution_failure`
  (exit 0, generic message, diagnostics attached). It never falls back to a
  re-import.
- The original project is untouched. File hashes of the project tree were
  identical before and after (`bf8b0fdb...`). REA copies the `.gpr`/`.rep` pair
  into `/tmp/rea-ghidra-XXXX/project` and deletes the copy on close.
- In this mode the mutating tools are switched off by REA itself:
  `annotate_native_function`, `set_address_name`, `set_addresses_names` →
  `available:false, "Existing Ghidra project sessions are read-only."`
- tools/list returns 233 tools on main and 229 on 6.8.0. Main adds
  `guided_workflows`, `inspect_android_jni_bindings`, `read_guidance_section`
  and `search_guidance`. The full list is in `tools-snapshot.json`.

## Step 4: continuation unpack and read-only mount (main build)

```text
4a project copied to a new path (/s/work2/unpacked/cont/sample.gpr) ......... PASS (13.5 s first query)
4b dir mounted :ro, normal file modes (0640/0750) .......................... PASS (14.0 s)
4c ELF project ............................................................... PASS (13.2 s)
4d project files chmod a-w (rw mount) ....................................... FAIL
4e :ro mount + chmod a-w ..................................................... FAIL (same error)
```

The failure in 4d/4e is caused by file modes, not by the mount. REA's private
copy keeps the source permission bits, and Ghidra then refuses to open the
copy:

```text
INFO  Opening existing project: /tmp/rea-ghidra-2SFsPY/project/sample (HeadlessAnalyzer)
ERROR Abort due to Headless analyzer error: Project sample is read-only (HeadlessAnalyzer)
ghidra.util.ReadOnlyException: Project sample is read-only
	at ghidra.framework.data.DefaultProjectData.init(DefaultProjectData.java:305)
```

**Rule for continuation unpack:** an `:ro` bind mount is fine, but the unpacked
project files must keep owner-write mode bits (e.g. 0640/0750). Do not
`chmod a-w` them, and do not unpack with a umask or extractor that strips the
owner-write bit.

## Environment and runtime surprises

- REA needs a **writable `/tmp`**. Its runtime root is
  `/tmp/rea-ghidra-XXXX/` and holds the project copy, `ghidra.log`,
  `script.log`, the Ghidra fscache and `bridge.sock`. It also needs a writable
  `HOME` (we set `HOME=/s/home`; npm cache only). The project dir itself can be
  read-only.
- The bridge transport is a **unix socket** (`bridge.sock`). No TCP ports were
  opened, and everything worked under `--network none`.
- With `--network none`, both `analyzeHeadless` and the bridge log a harmless
  `UnknownHostException: <container-id>` / "Could not determine local host
  name" from log4j. Setting a resolvable `--hostname` with an `/etc/hosts`
  entry would silence it.
- Ghidra's `analyzeHeadless` logs `ERROR DWARF un-recoverable expressions` on
  the mingw PE. This is benign, and the import succeeded.
- There are no lock-file problems with the copy. Ghidra only opens REA's
  private copy, so a stale `.lock` in the source project would not be an issue,
  but this was not tested.
- `REA_GHIDRA_PROGRAM_NAME` must be the bare program name in the project root
  (`sample.exe`), with no path or glob. It defaults to the target's basename.
- The configured JVM max heap for the bridge was 2G (REA default).

## CLI facts (6.8.0 and main identical except one added subcommand)

- Every `inspect-*` subcommand takes a positional `<path>`. `--json` is
  accepted as shorthand for `--format json`, and every PE/ELF one tried
  returned an Evidence JSON object with rc 0 (`inspect-pe-imports`,
  `inspect-native-exports`, `inspect-artifact`, `inspect-byte-entropy`,
  `inspect-pe-resources`, `inspect-pe-load-config`, `inspect-pe-certificates`,
  `inspect-elf-notes`). `inspect-binary-layout` needs `REA_PWNTOOLS_PYTHON`
  (pwntools 4.15.0) and otherwise returns rc 1 `provider_unavailable`.
- inspect-* names in main:
  ```text
  inspect-adb-client inspect-adb-device inspect-adb-display inspect-adb-package inspect-adb-window
  inspect-analysis-view inspect-android-class inspect-android-jni-bindings(main only) inspect-android-method
  inspect-android-package inspect-apk-signature inspect-apktool-client inspect-apple-ips inspect-artifact
  inspect-asset-catalog inspect-binary-layout inspect-byte-entropy inspect-dart-aot inspect-desktop-application
  inspect-devicetree inspect-electron-fuses inspect-electron-page inspect-elf-notes inspect-erlang-beam
  inspect-evidence-bundle inspect-evm-interface inspect-firmware-regions inspect-go-binary inspect-gpu-code-objects
  inspect-il2cpp-metadata inspect-jeb-client inspect-kernel-module inspect-keyed-archive inspect-macho
  inspect-managed-artifact inspect-managed-members inspect-managed-native-boundaries inspect-model-artifact
  inspect-native-api inspect-native-data-type inspect-native-dispatch-metadata inspect-native-exports
  inspect-native-instruction inspect-native-load-image inspect-packet-capture inspect-packet-fields
  inspect-pcap-capture inspect-pcap-client inspect-pe-certificates inspect-pe-imports inspect-pe-load-config
  inspect-pe-resources inspect-plist inspect-python-pyc inspect-recorded-crash inspect-rust-binary
  inspect-signal-decoders inspect-signature inspect-sqlite-database inspect-wasm-artifact
  inspect-web-event-listeners inspect-web-network-capture inspect-web-page inspect-with-objdump
  ```
  Not every one of these is a file parser that takes a path. Some talk to
  devices or providers (`inspect-adb-*`, `inspect-jeb-client`, `inspect-web-page`)
  or work on the provider session (`inspect-native-api`, `-data-type`,
  `-instruction`, `-load-image`). Only the static PE/ELF/managed ones were run here.
- `extract-artifact` **exists**:
  `rea extract-artifact <path> [--integrity-policy fail|record-and-continue] --json`.
  It has **no output-dir argument**. REA extracts into a fresh temp dir it
  chooses and reports the location in the result. It only covers archives and
  application packages. A PE returns `unsupported_target: "Artifact format has
  no extraction reader: pe"`. The MCP `extract_artifact` takes only
  `integrity_policy` and acts on the active target.

## Proposed read-only TOOL_ALLOWLIST (54 tools)

The MCP `annotations.readOnlyHint` cannot be used for this: it is `false` for
224 of 233 tools, because REA counts launching its provider process and its
temp writes as not read-only. The list below is curated by hand from the tool
descriptions and the `binary_session` effects inventory. Every tool in it is
present in `tools-snapshot.json` (`_meta.proposed_tool_allowlist`).

```text
address_name
address_to_file_offset
analyze_function
batch_decompile
binary_overview
binary_session
build_call_path
comment
compare_functions
find_xrefs_to_name
get_call_graph
get_evidence_bundle
inline_comment
inspect_address_context
inspect_byte_entropy
inspect_elf_notes
inspect_go_binary
inspect_managed_artifact
inspect_managed_members
inspect_managed_native_boundaries
inspect_native_api
inspect_native_data_type
inspect_native_exports
inspect_native_instruction
inspect_native_load_image
inspect_pe_certificates
inspect_pe_imports
inspect_pe_load_config
inspect_pe_resources
inspect_rust_binary
list_documents
list_names
list_procedures
list_segments
list_strings
list_unknowns
procedure_address
procedure_assembly
procedure_callees
procedure_callers
procedure_info
procedure_pseudo_code
procedure_references
read_bytes
read_function_instructions
resolve_containing_procedure
resolve_native_call_targets
search_bytes
search_procedures
search_strings
trace_call_path
trace_feature
trace_native_values
xrefs
```

Excluded on purpose:

- Lifecycle tools the engine drives itself: `open_binary`, `close_binary`
  (`close_binary` can also write `snapshot_path`).
- Edits: `annotate_native_function`, `set_*`, `unset_bookmark`,
  `record_unknown`, `update_unknown`, `update_analysis_settings`.
- Filesystem writers: `decompile_all` (writes `output_directory`), `extract_*`,
  `export_*`, `import_*`.
- Anything that executes code or touches a runtime, device or network:
  `capture_*`, `observe_*`, `instrument_with_frida` and the other frida tools,
  gdb, rizin debug, `cutter_command`, `execute_rizin_command`, `*_adb_*`,
  web/browser/electron/javascript-runtime tools, JEB, `inspect_with_objdump`
  (runs an external binary).
- Hopper-only cursor tools (`goto_address`, `current_*`, `next_address`,
  `prev_address`, `list_bookmarks`).
- `inspect_artifact`, which declares the `launches_process` and
  `may_write_filesystem` effects. Use it as a separate CLI pass if wanted.

The 12 allowlisted static `inspect_*` tools take an arbitrary `path` argument.
Inside the sandbox they can read any file the worker user can read, so the
engine should check that `path` equals the admitted sample.

## Artifacts on toolz2 (`~/rea-spike/`)

`img/Dockerfile` (image `rea-spike:local`), `scripts/{hello.c,mcp_drive.py,run_mcp.sh,run_mcp2.sh}`,
`out/*.jsonl|*.stderr|*.tools.json` (raw MCP transcripts per run: `s3*` = 6.8.0, `m3*`/`m4*` = main),
`work/` (samples + projects), `src-main/` (main source build), `npm/` (6.8.0 install).

## Image

Built 2026-10-31 on toolz2 from `deploy/docker/Dockerfile.rea-cold-worker`
(`docker build -f deploy/docker/Dockerfile.rea-cold-worker -t blastbox-rea:dev .`,
context synced to `~/rea-build/ctx`). Pins are in `deploy/rea/PINS`. REA is built from
source at `cd878ad`.

```text
image                blastbox-rea:dev  sha256:328f42938158cc4b486eeea795cb7eaf39d11beabcdbc6f09898e3284237832c
size                 925 MB content (compressed), 2.86 GB on disk
largest parts        /opt/ghidra 882M   /opt/node 203M   /opt/rea 178M   /opt/blastbox (venv) 57M
python in image      3.14.4 (Ubuntu 26.04 python3; venv /opt/blastbox)
blastbox[rea]        pefile 2024.8.26, Pillow 13.0.0
user                 uid 10001 (worker); ENTRYPOINT python -m blastbox.worker.cold
cold build           ~4 min; Dockerfile-only change ~1 min (smoke itself ~37 s)
```

The REA runtime tree is copied from package.json's `files` list plus pruned production
`node_modules`. These entries are absent from a source tree because only `prepack`
makes them: `skills`, `npm-shrinkwrap.json`, and `native/windows/build/*` (Windows only).
The smoke shows the Ghidra path does not need them.

Build smoke output (the RUN fails the build on any miss):

```text
== rea --version --json
{"name":"rea-agents","version":"6.8.0","runtime":{"id":"node","version":"22.23.4"},"platform":"linux","architecture":"x64","supported_runtime":{"range":"^22.23.4 || ^24.22.1 || >=26.12.1","satisfied":true}}
== rea providers --json | grep ghidra
== analyzeHeadless (ELF fixture)
INFO  REPORT: Save succeeded for: /sample.elf (sample:/sample.elf) (HeadlessAnalyzer)
INFO  REPORT: Import succeeded (HeadlessAnalyzer)
== rea --mcp over the saved project
tools/list: 233 tools
tools_sha256: c819d694c65bd1482a0e780ff1848542f2046fe50a6b68fc366066b593d7e58f
import_mode: existing-project-private-copy-v1
procedure_pseudo_code main: decompiled, fixture string present
runtime roots under TMPDIR=/home/worker/smoke/tmp: ['/home/worker/smoke/tmp/rea-ghidra-jXla8h']
new runtime roots under /tmp: []
runtime root contents: ['bridge.sock', 'cache', 'config', 'data', 'ghidra.log', 'home', 'ownership.json', 'project', 'script.log', 'target-c0f94b8533d8.elf', 'tmp']
REA MCP smoke OK (17.7s)
== import blastbox.engines.rea
blastbox rea worker ready
== nothing written outside HOME/TMPDIR
only /tmp/hsperfdata_worker (JVM perf counters, non-fatal if unwritable)
```

**Catalog digest.** `tools_sha256` is REA's own field. It appears in the
`binary_session` result as `server_identity.catalog.digests.tools_sha256`. The value
for this commit is also recorded statically in `dist/recordedCatalogDigests.js`
(profile `compact`/`full`). The smoke reads the live value over MCP and compares it with
the pinned ARG `REA_TOOLS_SHA256`.

**TMPDIR and HOME (findings for the engine).**

- `rea --mcp` honours `TMPDIR`. Its runtime root lands at `$TMPDIR/rea-ghidra-XXXX`,
  and it gives Ghidra `-Duser.home`/`-Djava.io.tmpdir`/`XDG_*` inside that root. REA does
  not hardcode `/tmp`. One residue: on Linux its JVM creates `/tmp/hsperfdata_<user>`.
  REA adds `-XX:-UsePerfData` only on win32, and it strips `JAVA_TOOL_OPTIONS`,
  `_JAVA_OPTIONS` and `JDK_JAVA_OPTIONS` from the environment it passes on, so this
  cannot be switched off from outside. The write is non-fatal: with a read-only rootfs
  and `/tmp`, the full MCP session still passed.
- A **bare `analyzeHeadless` ignores `$HOME` and `$TMPDIR`**:
  - `user.home` comes from /etc/passwd, so it writes `~/.config/ghidra/.../java_home.save`.
  - `java.io.tmpdir` defaults to `/tmp`, giving `/tmp/<user>-ghidra` and `/tmp/hsperfdata_<user>`.
  - Without `XDG_CACHE_HOME`, the cache goes to `/var/tmp/<user>-ghidra`.

  On a read-only rootfs it fails (`java_home.save (Read-only file system)`, then
  `Unable to prompt user for JDK path`). The engine must run it with
  `XDG_CACHE_HOME=$HOME/.cache XDG_CONFIG_HOME=$HOME/.config
  JAVA_TOOL_OPTIONS="-Djava.io.tmpdir=$TMPDIR -Duser.home=$HOME -XX:-UsePerfData"`.
  With those set, a read-only rootfs (writable work tmpfs only) passes, and `/tmp`
  and `/var/tmp` stay empty.

**JRE rejected.** Ghidra 12.1.4 headless on `eclipse-temurin:21-jre`
(`sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a`) refuses to
start: `JAVA_HOME environment specifies unsupported java version` and then
`Unable to prompt user for JDK path, no TTY detected`. The image keeps the pinned
21-jdk.

**Fixtures** (`deploy/rea/fixtures/`, built by `build.sh` in the `rea-fixtures` stage).
Two `--no-cache` builds were byte-identical.

```text
sample.exe  PE32+ x86-64 mingw, 75185 B, TimeDateStamp 0, sha256 dd4fc087aa16a9519990d49e2232c82d3f35630f7619bd9a677a263bde888531
            resources: RT_ICON[1] (16x16 32bpp, 1128 B), RT_GROUP_ICON[1], RT_VERSION[1]
sample.elf  ELF64 PIE gcc, not stripped, 15960 B, sha256 c0f94b8533d83d06773c56719db67bc8dee06df36b63ae89f92edfec48be2388
```
