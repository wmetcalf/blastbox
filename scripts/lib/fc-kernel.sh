#!/usr/bin/env bash
# Guest-kernel selection and verification for install-firecracker.sh, as a function so it can be
# TESTED without downloading firecracker (tests/host/test_install_firecracker.py). It had three
# defects in three days -- a 404 URL that fell back to a kernel which cannot boot, a version
# probe that aborted the installer under `set -euo pipefail`, and a refusal that ignored the very
# override it recommended -- and not one of them had a test.
#
# Expects DEST and ARCH set by the caller; honours BLASTBOX_FC_KERNEL. Returns non-zero (via
# `exit 1` inside, so callers get the installer's behaviour) when the kernel is refused.
fc_kernel_setup() {
  # best-effort guest kernel; override with BLASTBOX_FC_KERNEL.
  # Must be >= 5.18 (VMGenID) for the warm-SNAPSHOT tier: restoring a snapshot clones
  # the base VM's kernel CRNG, and only a VMGenID-aware guest reseeds it on restore
  # (otherwise restored clones can repeat random output). 5.10 is too old and the
  # snapshot-runtime selector now refuses it; fetch a 6.1 CI kernel instead.
  # THE QUICKSTART KERNEL IS NOT AN ACCEPTABLE FALLBACK, and it used to be the second
  # entry in this list. That URL serves the 5.10 image from 2021, which is the kernel the
  # paragraph above says the snapshot selector refuses -- and against a current firecracker
  # (tested on v1.16.0) it does not merely lack VMGenID, it cannot boot at all:
  #
  #   VFS: Cannot open root device "vda" or unknown-block(0,0): error -6
  #   Kernel panic - not syncing: VFS: Unable to mount root fs
  #
  # The microVM then dies in ~0.5 s, so the symptom an operator sees is "guest never
  # signalled READY within 45s" from a test that looks like a blastbox bug. Measured
  # 2026-09-22: the first URL below 404s (the drift this script's header warns about), the
  # fallback quietly installed that 5.10 kernel, and every live FC test failed for a reason
  # nothing in the output named. A missing kernel is a clear error; a kernel that panics is
  # a wild goose chase.
  # BLASTBOX_FC_KERNEL WINS, exactly as it does in test-fc.sh. The refusal below tells an operator
  # to set it -- and the first version never read it, so with a good kernel exported the installer
  # re-checked the stale file on every run, exited 1 forever, and never printed its next steps.
  if [[ -n "${BLASTBOX_FC_KERNEL:-}" ]]; then
    kern="$BLASTBOX_FC_KERNEL"
    [[ -s "$kern" ]] || { echo "!! BLASTBOX_FC_KERNEL=$kern does not exist or is empty"; exit 1; }
    echo ">> using BLASTBOX_FC_KERNEL=$kern (not fetching)"
  else
    kern="$DEST/vmlinux"
  fi
  if [[ ! -s "$kern" ]]; then
    echo ">> fetching a guest kernel (>= 5.18 required for VMGenID)"
    for u in \
      "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/${ARCH}/vmlinux-6.1.128" \
      "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/${ARCH}/vmlinux-6.1.102" \
      "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/${ARCH}/vmlinux-6.1.102" ; do
      if curl -fsSL "$u" -o "$kern" 2>/dev/null && [[ -s "$kern" ]]; then
        echo "   kernel -> $kern  (from $u)"; break
      fi
      rm -f "$kern"
    done
  fi
  # VERIFY WHAT IS ON DISK, whether we fetched it or found it already there: an operator who
  # ran this script months ago has whatever the URLs served THEN.
  if [[ -s "$kern" ]]; then
    # grep -a, not `strings`: no binutils dependency. And `|| true`, because under
    # `set -euo pipefail` a kernel with no matching banner made grep exit 1 and the whole
    # installer ABORTED here -- after firecracker was already installed, and without printing
    # either the kernel warning or the next steps.
    kver="$(grep -aoE 'Linux version [0-9]+\.[0-9]+' "$kern" 2>/dev/null | head -1 | awk '{print $3}' || true)"
    if [[ -n "$kver" ]]; then
      kmaj="${kver%%.*}"; kmin="${kver#*.}"
      if (( kmaj < 5 || (kmaj == 5 && kmin < 18) )); then
        echo "!! $kern is Linux $kver, which is too old: the warm-snapshot tier needs >= 5.18 for"
        echo "   VMGenID, and against a current firecracker it panics on boot (no root device),"
        echo "   which surfaces much later as 'guest never signalled READY'."
        if [[ -z "${BLASTBOX_FC_KERNEL:-}" ]]; then
          # OUR OWN CACHED FILE, so move it aside rather than leave it. Left in place, it is what
          # scripts/test-fc.sh boots next time: that script runs this installer only when the
          # firecracker BINARY is missing, and the binary was already installed above -- so the
          # second run skipped the installer and booted the panicking kernel anyway. Renamed, not
          # deleted: it is evidence, and the next run fetches a good one. An operator's own
          # BLASTBOX_FC_KERNEL file is never touched.
          aside="$kern.refused-linux-$kver"
          mv -f "$kern" "$aside"
          echo "   Moved it aside to $aside; re-run this script to fetch a >= 5.18 kernel."
        else
          echo "   BLASTBOX_FC_KERNEL points at it, so it is left alone: point that at a >= 5.18"
          echo "   image and re-run."
        fi
        exit 1
      fi
      echo "   guest kernel: Linux $kver"
    else
      echo "!! could not read a version banner from $kern, so it cannot be checked against the"
      echo "   >= 5.18 requirement. If live FC tests then fail with 'guest never signalled READY',"
      echo "   suspect the kernel first: run the VM by hand and read its console for a panic."
    fi
  else
    echo "!! kernel download failed — every published URL 404'd (they drift between firecracker"
    echo "   releases). Fetch a >= 5.18 vmlinux per the firecracker getting-started guide and set"
    echo "   BLASTBOX_FC_KERNEL, or run the FC test on a host that already has one."
  fi
}
