"""Leaf types: the shared vocabulary every engine can reuse."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_SAFE_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,128}\Z")
# Expected hex length per hash algorithm (None = any positive hex length).
_HASH_HEXLEN: dict[str, int | None] = {
    "sha256": 64, "phash": 16, "dhash": 16, "ahash": 16, "colorhash": None,
}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Hash(_Frozen):
    algo: Literal["sha256", "phash", "dhash", "ahash", "colorhash"]
    value: str

    @field_validator("value")
    @classmethod
    def _hex(cls, v: str, info) -> str:
        if not _HEX_RE.match(v):
            raise ValueError("hash value must be hex")
        expected = _HASH_HEXLEN.get(info.data.get("algo"))
        if expected is not None and len(v) != expected:
            raise ValueError(f"expected {expected} hex chars, got {len(v)}")
        return v.lower()


def phash_hex_to_int8(hex_str: str) -> int:
    """Convert a 16-char unsigned-64-bit hex pHash to a signed int64.

    A ``phash`` ``Hash.value`` is a 16-char unsigned 64-bit hex string, but the
    similarity index stores it as a signed two's-complement int64 (Postgres
    ``BIGINT``) so pg_bktree's SP-GiST opclass can range-scan it for Hamming
    distance. Values with the high bit set are reinterpreted as negative. The
    same mapping is applied on query so round-trips are exact, and the Hamming
    math is masked back to unsigned 64-bit so the sign reinterpretation never
    affects distance. Consolidated here from the two identical ClippyShot
    bodies (dispatcher + api).
    """
    val = int(hex_str, 16)
    if val >= 1 << 63:
        val -= 1 << 64
    return val


def int8_to_phash_hex(value: int) -> str:
    """Inverse of :func:`phash_hex_to_int8`: signed int64 -> 16-char unsigned hex."""
    return f"{value & ((1 << 64) - 1):016x}"


class ArtifactRef(_Frozen):
    """A reference into the Envelope's artifact set by id (never a path)."""
    id: str

    @field_validator("id")
    @classmethod
    def _safe(cls, v: str) -> str:
        if not _SAFE_ID_RE.match(v):
            raise ValueError("artifact id must match [A-Za-z0-9._-]{1,128}")
        return v


class Detection(_Frozen):
    label: str = Field(min_length=1, max_length=64)
    mime: str = Field(max_length=255)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1, max_length=32)


class Warning(_Frozen):
    code: str = Field(min_length=1, max_length=64)
    message: str = Field(max_length=2000)
    context: str | None = Field(default=None, max_length=255)


class Dimensions(_Frozen):
    width: float = Field(gt=0)
    height: float = Field(gt=0)
    unit: Literal["mm", "px", "pt"]


class Lang(_Frozen):
    code: str = Field(min_length=2, max_length=64)
