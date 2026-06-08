"""Generic ``GET /v1/similar`` perceptual-hash search route (capability-gated).

``build_app`` mounts this router ONLY when the configured ``JobStore`` implements
the page-hash search capability (``find_similar_phash`` et al. — the SQL store).
For memory/redis stores the route is simply absent, so a client gets a 404 — the
honest signal that "this deployment does not index page hashes".

The endpoint is product-agnostic: it queries already-indexed page hashes (written
on-DONE by the dispatcher via ``index_page_hashes``).  It does NOT compute a hash
from an uploaded image — the caller passes a known ``phash`` / ``colorhash`` /
``sha256``.  Both ClippyShot and redtusk reuse it unchanged; the only thing that
varies per product is how the page hashes get into the envelope in the first place.
"""
from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, HTTPException

from blastbox.contract import int8_to_phash_hex, phash_hex_to_int8

# colorhash uses binbits=4: each of the 14 hex nibbles is a 0-15 count, so the
# per-bin L1 delta is ≤ 15.  Group ceilings (cumulative bins):
#   total = 14 bins → 210, frac = bins 0-1 → 30, faint/bright = 6 bins → 90 each.
_FUZZY_CAP_CEILINGS = {
    "total_max": 210,
    "frac_max": 30,
    "faint_max": 90,
    "bright_max": 90,
}

_PHASH_RE = re.compile(r"[0-9a-fA-F]{16}")
_COLORHASH_RE = re.compile(r"[0-9a-fA-F]{14}")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def _rows_to_response(rows: list[dict]) -> list[dict]:
    """Normalize raw store rows into the public ``/v1/similar`` result shape.

    The stored ``phash`` is a signed int64 (its index form); re-render it as the
    16-char hex the caller queried with.  ``variant`` defaults to ``"original"``
    for stores that index one row per page (the generalized table has no variant
    column; a product that adds one will surface it here automatically).
    """
    out: list[dict] = []
    for r in rows:
        ph = r.get("phash")
        out.append(
            {
                "job_id": r["job_id"],
                "page_index": r["page_index"],
                "variant": r.get("variant", "original"),
                "filename": r.get("filename"),
                "phash": int8_to_phash_hex(int(ph)) if ph is not None else None,
                "colorhash": r.get("colorhash"),
                "sha256": r.get("sha256"),
                "distance": r.get("distance"),
            }
        )
    return out


def build_similar_router(job_store: object) -> APIRouter | None:
    """Return a router exposing ``GET /v1/similar``, or ``None`` if unsupported.

    Capability probe: search is **Postgres + pg_bktree only**, so gate on the
    runtime ``supports_hash_search()`` flag — NOT mere structural presence. A SQL
    store on SQLite (or Postgres without the extension) has the search methods but
    they raise, so a ``hasattr`` probe would wrongly mount a route that 500s. When
    unsupported, ``build_app`` skips mounting the route entirely (so the surface
    honestly reflects whether page-hash search is available in this deployment).
    """
    supports = getattr(job_store, "supports_hash_search", None)
    if supports is None or not supports():
        return None

    router = APIRouter()

    # phash bktree + colorhash L1 seq-scan run directly in the DB.  A handful of
    # concurrent fuzzy colorhash calls (the L1 scan has no usable index) can
    # saturate the pg connection pool, so gate ALL /v1/similar traffic through
    # one small semaphore: large enough for normal UI use (a couple of tabs, one
    # in flight), not enough for an authenticated client to pin the database.
    gate = asyncio.Semaphore(3)

    @router.get("/v1/similar")
    async def get_similar(
        phash: str | None = None,
        colorhash: str | None = None,
        sha256: str | None = None,
        max_hamming: int = 5,
        colorhash_distance: int | None = None,
        colorhash_frac_max: int | None = None,
        colorhash_faint_max: int | None = None,
        colorhash_bright_max: int | None = None,
        limit: int = 50,
    ) -> dict:
        """Find indexed pages similar to a given hash.

        Exactly one of ``phash`` / ``colorhash`` / ``sha256`` must be set.

        - ``phash``: 16-char hex; pages within ``max_hamming`` Hamming bits
          (``max_hamming`` in ``[0, 64]``).
        - ``colorhash``: 14-char hex; exact match by default.  Switch to per-bin
          L1 fuzzy search by passing any of ``colorhash_distance`` (total L1,
          ≤210), ``colorhash_frac_max`` (bins 0-1, ≤30), ``colorhash_faint_max``
          (bins 2-7, ≤90), ``colorhash_bright_max`` (bins 8-13, ≤90).  Caps are
          cumulative — a row must satisfy every cap set.
        - ``sha256``: 64-char hex; exact match (byte-identical rendered page).

        ``limit`` is clamped to ``[1, 500]``.
        """
        provided = [p for p in (phash, colorhash, sha256) if p]
        if len(provided) != 1:
            raise HTTPException(400, "provide exactly one of phash, colorhash, sha256")
        if limit < 1 or limit > 500:
            raise HTTPException(400, "limit must be in [1, 500]")

        # Validate first so malformed requests fail fast without consuming a gate
        # slot. The store APIs are synchronous (psycopg pool under the hood), so
        # the DB work runs off the event loop via asyncio.to_thread inside the gate.
        if phash:
            if not _PHASH_RE.fullmatch(phash):
                raise HTTPException(400, "phash must be 16 hex chars")
            if not (0 <= max_hamming <= 64):
                raise HTTPException(400, "max_hamming must be in [0, 64]")
            async with gate:
                rows = await asyncio.to_thread(
                    job_store.find_similar_phash,  # type: ignore[attr-defined]
                    phash_hex_to_int8(phash),
                    max_hamming,
                    limit=limit,
                )
        elif colorhash:
            if not _COLORHASH_RE.fullmatch(colorhash):
                raise HTTPException(400, "colorhash must be 14 hex chars")
            fuzzy_caps = {
                "total_max": colorhash_distance,
                "frac_max": colorhash_frac_max,
                "faint_max": colorhash_faint_max,
                "bright_max": colorhash_bright_max,
            }
            for name, cap in fuzzy_caps.items():
                if cap is None:
                    continue
                ceiling = _FUZZY_CAP_CEILINGS[name]
                if not (0 <= cap <= ceiling):
                    raise HTTPException(400, f"{name} must be in [0, {ceiling}]")
            use_fuzzy = any(v is not None for v in fuzzy_caps.values())
            if use_fuzzy and not hasattr(job_store, "find_similar_colorhash"):
                raise HTTPException(
                    501, "current job store does not support colorhash fuzzy search"
                )
            async with gate:
                if use_fuzzy:
                    rows = await asyncio.to_thread(
                        job_store.find_similar_colorhash,  # type: ignore[attr-defined]
                        colorhash,
                        limit=limit,
                        **fuzzy_caps,
                    )
                else:
                    rows = await asyncio.to_thread(
                        job_store.find_by_colorhash,  # type: ignore[attr-defined]
                        colorhash,
                        limit=limit,
                    )
        else:
            assert sha256 is not None  # narrowed by the exactly-one check above
            if not _SHA256_RE.fullmatch(sha256):
                raise HTTPException(400, "sha256 must be 64 hex chars")
            async with gate:
                rows = await asyncio.to_thread(
                    job_store.find_by_page_sha256,  # type: ignore[attr-defined]
                    sha256,
                    limit=limit,
                )
        return {"results": _rows_to_response(rows)}

    return router
