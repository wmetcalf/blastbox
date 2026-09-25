# Warm tiers: the rootfs, and how to keep it honest

A warm tier does not run your image. It boots a **rootfs artifact** exported from
that image — an `ext4` file for Firecracker, a directory tree for gVisor. That
export is where deployments rot, and the rot is silent.

## The failure this page exists to prevent

Measured on toolz2, 2026-09-18. Three engines — clippyshot, redtusk, titanarum —
were each booting a rootfs exported **by hand** from an image generation that no
longer matched their host tier. What that looks like:

* the microVM boots fine, and Firecracker logs a clean snapshot restore;
* the guest never sends `fc_guest.ready_sent`;
* every warm job dies on `warm worker timed out after 300s`;
* the **cold** tier serves the same input in seconds, so the engine looks fine;
* the ingress answers `200`, so every health check upstream says healthy.

It had been that way for two months. Nothing compared the rootfs to anything,
because nothing could: `docker export` writes a filesystem and **drops the image
config**, so the OCI labels `stamp.py` attaches do not survive into the artifact
the guest boots.

The tell, if you ever see it: **cold works and warm times out at exactly 300s.**
That is a guest/host mismatch until proven otherwise.

## 1. Declare the chain

Put `blastbox-images.toml` beside your Dockerfiles. Every image is built FROM the
previous one, ending in the artifact a tier boots:

```toml
[engine]
name = "myengine"

[[image]]
name       = "myengine"                       # host/API tier
dockerfile = "deploy/docker/Dockerfile"
base       = "ubuntu:24.04"                   # upstream: pulled, then pinned
context    = "."

[[image]]
name       = "myengine-cold-worker"
dockerfile = "deploy/docker/Dockerfile.myengine-cold-worker"
base       = "myengine"                       # a name from THIS chain
context    = "$BLASTBOX_SRC"                  # Dockerfile lives in blastbox
source_repo = "$BLASTBOX_SRC"                 # stamp records THAT tree

[[image]]
name        = "myengine-fc-worker"
dockerfile  = "deploy/firecracker/Dockerfile.myengine"
base        = "myengine-cold-worker"
context     = "$BLASTBOX_SRC"
source_repo = "$BLASTBOX_SRC"

[[rootfs]]
kind     = "ext4"                             # or "dir" for gVisor
image    = "myengine-fc-worker"
dest     = "$MYENGINE_FC_DIR/rootfs.ext4"
size_mib = 4096
requires = ["/init", "/opt/blastbox/run_guest.py", "/opt/blastbox/engine"]
```

`requires` is the guard worth having: an image that cannot boot is refused at
**build** time instead of timing out every job at runtime.

## 2. Build it

```bash
BLASTBOX_SRC=/path/to/blastbox \
MYENGINE_FC_DIR=/var/lib/myengine-fc \
blastbox build-images /path/to/myengine --tag <tag> --dry-run   # inspect first
```

Drop `--dry-run` to build. Every image is stamped, verified, and only then
published; the previous rootfs is kept beside the new one as `*.bak`.

**Run it detached.** The build outlives your shell and a broken pipe kills it
mid-verify, publishing nothing:

```bash
setsid nohup blastbox build-images … > /tmp/build.log 2>&1 < /dev/null &
```

## 3. What you get, and what checks it

Every export writes `/opt/blastbox/rootfs-stamp.json` **into** the rootfs — a
file, because labels do not survive `docker export`. It records what the IMAGE
says about itself — its blastbox version, revision and architecture, read from
the verified image rather than from the exporting CLI — plus the image id, the
tier it is for (`firecracker` for ext4, `gvisor` for a directory) and the export
time. It deliberately records nothing about the exporting machine's CPU: a rootfs
holds no CPU state; the snapshot is taken later, on the deploying host.

Read it back without mounting anything:

```python
from blastbox.host import rootfs_stamp
rootfs_stamp.read("/var/lib/myengine-fc/rootfs.ext4")   # debugfs; no loop device
```

Both warm tiers read it at tier selection — `firecracker_available()` for the
cold and snapshot Firecracker tiers, `select_gvisor_snapshot_runtime()` for the
gVisor tier — and **refuse a rootfs whose guest disagrees with this host** (a
different blastbox release, another architecture, or the other tier's format),
naming the remedy. Versions are compared as releases: `0.2`, `0.2.0` and
`0.2.0+gabc` agree. The severity split is deliberate:

| rootfs state | what happens | why |
| --- | --- | --- |
| stamped, matches host | boots | nothing to say |
| stamped, mismatched | **tier refuses** | a definite fault with a known fix; one log line beats 300s per job |
| unstamped / unreadable | warns, boots | every artifact exported before stamping is unstamped; refusing them would take a whole fleet offline on upgrade |

"I could not look" is never reported as "it is wrong".

The stamp comes out of an image, so it is treated as untrusted: it is read only
from a regular file (never through a symlink, FIFO or device node), capped at
64 KiB, and debugfs runs under a deadline.

**Republishing while a dispatcher runs.** `build-images` publishes the rootfs in
place, so the check also runs where the rootfs is BOOTED, cached on the file's
identity (one `stat` per boot): every plain Firecracker spawn, and every snapshot
base build on both tiers. A snapshot also records the rootfs it was checkpointed
against, and a restore refuses if the file has changed since — restoring would pair
the old memory image with a different disk, the ext4-checksum corruption the
per-generation outdisk already guards against. Those restores fail fast, and the
pool rebuilds the base from the current rootfs. A newer guest than the dispatcher
is refused at boot until the dispatcher is upgraded, so upgrade the dispatcher and
publish the rootfs together.

**Survey a host.** `blastbox doctor --rootfs PATH` adds each artifact to the
container survey; `--json` emits the whole fleet for monitoring, with the same
exit code as the text report. On a host running several products, pair each
rootfs with its compose project so it is checked against *that* project's
containers:

```sh
blastbox doctor --allow-mixed \
  --rootfs clippyshot=/var/lib/clippyshot-fc/rootfs.ext4 \
  --rootfs redtusk=/var/lib/redtusk-gvisor/rootfs
```

`--allow-mixed` allows separate products on different releases; it never
excuses a rootfs that disagrees with its host, an unreadable artifact, or docker
being unreachable. An unpaired rootfs is only checked against the host's
versions as a whole.

## 4. Things that will bite you

Each of these was hit for real, and `build-images` now refuses rather than
producing a plausible-looking artifact:

* **A hardcoded `FROM`.** Without `ARG BASE_IMAGE` docker silently discards
  `--build-arg BASE_IMAGE`, and the stamp names a base digest the build never
  used. Five Dockerfiles across three engines had this.
* **A rootfs from an image the chain never builds** — "exporting an image the
  chain does not produce is how a rootfs ends up made from something nobody
  verified".
* **An `ext4` with no `size_mib`.** Guessing wastes the difference or fails to fit.
* **A dirty tree**, or no tree at all. A deploy directory that is not a git
  checkout needs `.blastbox-revision` naming the commit it came from. If you do
  not know it, recover it by content — hash the deploy files and find the commit
  whose blobs match — rather than stamping a guess.
* **More than one place pinning blastbox.** One engine pinned it in four:
  `pyproject.toml`, a hashed `requirements.lock`, `ARG BLASTBOX_VERSION` in a
  Dockerfile, and the running image. The Dockerfile ARG installs `--no-deps`, so
  the pyproject floor never upgrades it. Fixing three of four still produced
  "label says 0.1.40, image contains 0.1.27" — caught only by the verify step.
  Declare it in the plan (`build_args = { BLASTBOX_VERSION = "…" }`) so it is
  version-controlled rather than a default someone has to remember.
* **compose `-f` ordering.** Tier overlays set `image:`; whichever file comes
  last wins. Put the overlay that pins your tag last.

## 5. Verify it actually runs

A pool that builds is not a pool that works. Submit a burst, not one job:
the first job can succeed against a single good slot while the rest hang.

Healthy looks like `warm_pool_built … warm_snapshot=True` followed by
`fc_guest.ready_sent`, and a burst that completes in full. If `warm_snapshot` is
`False` the tier is pre-spawning sandboxes rather than restoring a checkpoint —
it saves container start, not application init, which for a JVM or LibreOffice
engine is nearly all of the cost.
