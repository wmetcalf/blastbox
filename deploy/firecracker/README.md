# Firecracker worker rootfs

A minimal ext4 rootfs that boots inside a blastbox Firecracker microVM and runs
the guest warm agent: it warms an engine, signals **READY** to the host over
AF_VSOCK (which `host.runtime.firecracker.VsockReadySignal` listens for), then
blocks until the host reaps the slot.

## Build

Needs Docker + e2fsprogs (`mke2fs -d`) + coreutils. No root, no mount.

```sh
# ENGINE: probe (hash→text, default) | pdf (poppler PDF→PNGs)
ENGINE=probe deploy/firecracker/build-rootfs.sh /path/to/rootfs.ext4
ENGINE=pdf   deploy/firecracker/build-rootfs.sh /path/to/rootfs-pdf.ext4   # ROOTFS_MIB=1024 default
```

The engine is baked in at build time (`BLASTBOX_FC_ENGINE`), so a rootfs is
engine-specific — build one per engine. Example engines live in `engines.py`;
real adopters bake their own (ClippyShot's LibreOffice, etc.).

## Boot it

```sh
export BLASTBOX_FC_BIN=/opt/kata/bin/firecracker
export BLASTBOX_FC_KERNEL=/path/to/vmlinux          # needs virtio-blk + virtio-vsock
export BLASTBOX_FC_ROOTFS=/path/to/rootfs.ext4
# Keep BLASTBOX_FC_SCRATCH SHORT (default /tmp/blastbox-fc-slots): the vsock
# UDS lives under it and AF_UNIX paths cap at ~108 bytes — a long scratch root
# silently breaks vsock (FC's control plane AND the readiness signal).
pytest tests/host/runtime/test_firecracker.py::TestFirecrackerLiveBoot::test_live_is_ready_after_warmup
```

## Pieces

| file              | role |
|-------------------|------|
| `Dockerfile.worker` | python-slim + blastbox core (pydantic) + agent + init |
| `init`              | PID 1: mounts /proc,/sys,/dev,/dev/vdb → execs the agent |
| `run_guest.py`      | `ProbeEngine` warmup → `run_fc_guest` (vsock READY) → block |
| `build-rootfs.sh`   | docker export → `mke2fs -d` (no mount/root) |

The job round-trip (GO + input + DONE over vsock, output on `/dev/vdb`) is the
documented follow-on; it reuses this same vsock channel and the slot the agent
already holds.
