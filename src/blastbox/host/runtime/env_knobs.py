"""Validated environment knobs shared by the snapshot tiers.

One implementation, because the validation is the whole point: a knob that silently
accepts a value it cannot honour is worse than no knob, and two copies of that check
drift. See `positive_float_env` for what "cannot honour" means here.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping

_log = logging.getLogger(__name__)


def positive_float_env(env: Mapping[str, str], key: str, default: float) -> float:
    """A finite, strictly positive float from ``env``, or ``default`` with a warning.

    Both halves of that are load-bearing for a timeout:

    * ``float()`` accepts ``"inf"`` and ``"nan"``. Neither is a deadline --
      ``subprocess.run(timeout=inf)`` never expires, and ``nan`` compares false against
      everything, so both slip past a bare ``value <= 0`` check and silently restore the
      unbounded call the knob exists to bound.
    * ``0`` and negatives expire instantly, turning every call into an immediate failure --
      a worse outage than the value being ignored.

    Refusing loudly and keeping the default is the safe direction for both.
    """
    raw = str(env.get(key, "")).strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        _log.warning("invalid %s=%r; using %g", key, raw, default)
        return default
    if not math.isfinite(value) or value <= 0:
        _log.warning("%s=%r must be a finite value > 0; using %g", key, raw, default)
        return default
    return value
