"""TLS decrypt of a captured pcap via GoGoRoboCap (the P5 inspect/decrypt step).

GoGoRoboCap (github.com/wmetcalf/GoGoRoboCap) replays a pcap's TLS flows into cleartext given the
session keys, producing a fully-decrypted pcap and a "mixed" (encrypted + decrypted) pcap. The
CLI here is grounded in CAPE's ``decryptpcap.py`` and a live toolz2 run (curl + SSLKEYLOGFILE →
NSS keylog → ``-tlsmode decrypted`` → decrypted.pcap, "replayed 1 decrypted flows").

Two invocations:
  * keylog:        ``ggrc -i <pcap> -keylog <keys> -tlsmode {decrypted|mixed} -o <out>``
  * sslproxy-clean ``ggrc -sslproxy-clean -i <synth.pcap> -o <out>`` (strip the prepended
    ClientHello from an sslproxy synthetic pcap).

Key MATERIAL acquisition (SSLKEYLOGFILE from the worker / an sslproxy MITM sidecar / the fakenet
CA) is engine/deployment-specific — this module consumes a keylog that already sits in the job's
capture dir and turns it into sealed decrypted artifacts. The orchestration takes an injected
``run_fn`` so it is unit-testable without the binary.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

_log = logging.getLogger("blastbox.host.decrypt")

_VALID_TLS_MODES = ("decrypted", "mixed")
# A pcap with only a global header (24 bytes) carries no packets — treat as "no output".
_PCAP_HEADER_SIZE = 24


@dataclass(frozen=True)
class DecryptResult:
    decrypted_path: str | None
    mixed_path: str | None


def gogorobocap_keylog_argv(
    binary: str, pcap_path: str, keylog_path: str, mode: str, output_path: str
) -> list[str]:
    """Build the keylog-decrypt argv. ``mode`` ∈ {decrypted, mixed} (allow-listed)."""
    if mode not in _VALID_TLS_MODES:
        raise ValueError(f"invalid tlsmode {mode!r}; use one of {', '.join(_VALID_TLS_MODES)}")
    return [
        binary,
        "-i", pcap_path,
        "-keylog", keylog_path,
        "-tlsmode", mode,
        "-o", output_path,
    ]


def gogorobocap_sslproxy_clean_argv(binary: str, input_pcap: str, output_pcap: str) -> list[str]:
    """Build the sslproxy-clean argv (strip the prepended ClientHello from a synthetic pcap)."""
    return [binary, "-sslproxy-clean", "-i", input_pcap, "-o", output_pcap]


def _usable(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.path.getsize(path) > _PCAP_HEADER_SIZE
    except OSError:
        return False


def decrypt_capture(
    *,
    binary: str,
    pcap_path: str,
    keylog_path: str,
    out_dir: str,
    run_fn: Callable[[list[str]], int],
) -> DecryptResult | None:
    """Decrypt ``pcap_path`` with the keys in ``keylog_path`` into ``out_dir``, returning the
    produced artifact paths or ``None`` if nothing usable was produced.

    Best-effort: a missing keylog, an empty output, or a runner error returns ``None`` and never
    raises — TLS decrypt is an enrichment, it must never fail the job. Produces both a fully
    ``decrypted.pcap`` and a ``mixed.pcap`` (encrypted + decrypted) à la CAPE."""
    # A keylog just needs to be non-empty (a single line is valid key material) — the _PCAP_HEADER
    # size floor that _usable() applies is for pcap outputs, not the keylog.
    if not (os.path.isfile(keylog_path) and os.path.getsize(keylog_path) > 0):
        return None  # no keys → nothing to do
    decrypted = os.path.join(out_dir, "decrypted.pcap")
    mixed = os.path.join(out_dir, "mixed.pcap")
    # Remove any pre-existing outputs first so we never accept a STALE file from a prior attempt
    # (retries reuse out_dir) and only treat a file as a result if THIS run produced it with rc 0.
    for stale in (decrypted, mixed):
        try:
            os.unlink(stale)
        except OSError:
            pass
    try:
        rc_dec = run_fn(gogorobocap_keylog_argv(binary, pcap_path, keylog_path, "decrypted", decrypted))
        rc_mix = run_fn(gogorobocap_keylog_argv(binary, pcap_path, keylog_path, "mixed", mixed))
    except Exception as exc:  # noqa: BLE001 — decrypt is best-effort enrichment
        _log.warning("decrypt: GoGoRoboCap run failed for %s: %s", pcap_path, exc)
        return None
    # Only accept an output the run actually generated successfully (rc 0) AND that is a usable pcap.
    dec = decrypted if (rc_dec == 0 and _usable(decrypted)) else None
    mix = mixed if (rc_mix == 0 and _usable(mixed)) else None
    if dec is None and mix is None:
        return None  # ran but no TLS flows / no output
    _log.info("decrypt: produced %s%s for %s",
              "decrypted.pcap " if dec else "", "mixed.pcap" if mix else "", pcap_path)
    return DecryptResult(decrypted_path=dec, mixed_path=mix)
