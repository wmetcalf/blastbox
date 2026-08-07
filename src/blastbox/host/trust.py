"""Host-side output-trust validator.

The single public function ``validate_worker_output`` reads a worker's
``metadata.json`` + output directory, re-seals every artifact hash from disk
(discarding whatever the worker claimed), enforces Limits caps, and returns a
host-trusted ``Envelope`` — or raises ``OutputTrustError`` on any violation.

**No worker-controlled string is ever propagated raw**; every exception message
is scrubbed through ``sanitize_public_error`` before being surfaced.
"""
from __future__ import annotations

import logging
from pathlib import Path

from blastbox.contract.envelope import (
    DeclaredArtifact,
    Envelope,
    envelope_from_json,
    read_confined_regular_bytes,
    seal_envelope,
    validate_envelope,
)
from blastbox.errors import OutputTrustError, OutputTrustUnknown, sanitize_public_error
from blastbox.limits import Limits

_log = logging.getLogger("blastbox.host.trust")


def validate_worker_output(
    *,
    output_dir: Path,
    input_sha256: str,
    engine: str,
    limits: Limits,
) -> Envelope:
    """Read + validate a worker's output.

    Returns a host-trusted ``Envelope`` or raises ``OutputTrustError``.

    Steps (each step rejects on violation):
    1. Metadata path safety: must exist, be a regular non-symlink file, and be
       within ``limits.max_metadata_bytes``.
    2. Parse: ``envelope_from_json`` validates the typed payload tree + bounds.
    3. Engine match: ``parsed.engine`` must equal the ``engine`` arg.
    4. Re-seal from disk: rebuild ``DeclaredArtifact`` list from id/path/kind
       only (discard worker-reported sha256/bytes), call ``seal_envelope`` so
       hashes + sizes are recomputed from real files and paths are re-confined.
    5. Input-SHA round-trip: ``parsed.input_sha256`` must equal ``input_sha256``.
    6. Caps: ``validate_envelope`` enforces count/size bounds.
    7. Return the sealed (host-trusted) Envelope.
    """
    # ------------------------------------------------------------------
    # Step 1: metadata path safety
    # ------------------------------------------------------------------
    # Read metadata.json TOCTOU-safely: one fd opened O_NOFOLLOW|O_NONBLOCK, required to be a
    # regular file within output_dir and <= max_metadata_bytes — so a worker on a still-live
    # shared dir cannot swap it for a symlink (read a host file) or a FIFO (block the dispatcher)
    # between an is_symlink() check and a read_bytes(). Confinement + type + size + read are one
    # operation on one inode.
    try:
        raw = read_confined_regular_bytes(
            output_dir, "metadata.json", max_bytes=limits.max_metadata_bytes
        )
    except FileNotFoundError as exc:
        raise OutputTrustError("metadata.json not found in output directory") from exc
    except ValueError as exc:
        # A ValueError here IS a verdict: the worker wrote something that is not a regular file
        # inside the output dir, or exceeded the declared size.
        raise OutputTrustError(
            sanitize_public_error(
                "metadata.json must be a regular file inside the output dir within the size "
                f"limit ({exc})"
            )
        ) from exc
    except OSError as exc:
        # ...but an OSError is OUR failure to read it (EMFILE/EIO/ENOMEM), not proof the output
        # is bad. Attributing it convicts every worker at once during a host outage.
        raise OutputTrustUnknown(
            sanitize_public_error(f"could not read metadata.json ({exc})")
        ) from exc

    # ------------------------------------------------------------------
    # Step 2: parse
    # ------------------------------------------------------------------
    try:
        parsed = envelope_from_json(raw, max_bytes=limits.max_metadata_bytes)
    except Exception as exc:
        # Do NOT echo the exception: a pydantic ValidationError embeds the worker's input_value
        # verbatim (worker-controlled). Log the detail server-side; surface a fixed message.
        _log.warning("metadata.json parse/validation failed: %s", exc)
        raise OutputTrustError("metadata.json failed schema validation") from exc

    # ------------------------------------------------------------------
    # Step 3: engine match
    # ------------------------------------------------------------------
    if parsed.engine != engine:
        raise OutputTrustError(
            f"engine mismatch: expected {engine!r}, worker reported {parsed.engine!r}"
        )

    # ------------------------------------------------------------------
    # Step 4: re-seal from disk (do NOT trust worker-reported sha256/bytes)
    # ------------------------------------------------------------------
    # Build DeclaredArtifact list using only id/path/kind — drop sha256/bytes.
    declared = [
        DeclaredArtifact(id=a.id, path=a.path, kind=a.kind)
        for a in parsed.artifacts
    ]

    try:
        sealed = seal_envelope(
            engine=engine,
            outdir=output_dir,
            input_sha256=input_sha256,
            detected=parsed.detected,
            declared=declared,
            warnings=parsed.warnings,
            payload=parsed.payload,
            status=parsed.status,
            # Reject an oversized declared artifact at stat() time, before re-hashing reads it.
            max_artifact_bytes=limits.max_artifact_bytes,
            # Reject an over-COUNT artifact list BEFORE the hashing loop runs (the
            # count cap previously only ran in validate_envelope, AFTER every
            # declared artifact had already been opened + hashed).
            max_artifacts=limits.max_artifacts,
        )
    except (ValueError, Exception) as exc:
        raise OutputTrustError(
            sanitize_public_error(f"re-seal failed: {exc}")
        ) from exc

    # ------------------------------------------------------------------
    # Step 5: input-SHA round-trip
    # ------------------------------------------------------------------
    # The worker's claimed input hash must match what we dispatched.
    if parsed.input_sha256 != input_sha256:
        raise OutputTrustError(
            "input_sha256 mismatch: worker processed a different document"
        )

    # ------------------------------------------------------------------
    # Step 6: caps
    # ------------------------------------------------------------------
    try:
        validate_envelope(
            sealed,
            outdir=output_dir,
            max_artifact_bytes=limits.max_artifact_bytes,
            max_total_bytes=limits.max_total_artifact_bytes,
            max_artifacts=limits.max_artifacts,
        )
    except (ValueError, Exception) as exc:
        raise OutputTrustError(
            sanitize_public_error(f"output caps violated: {exc}")
        ) from exc

    # ------------------------------------------------------------------
    # Step 7: return the host-trusted sealed Envelope
    # ------------------------------------------------------------------
    return sealed
