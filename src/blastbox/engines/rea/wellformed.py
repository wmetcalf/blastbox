"""Text that can be written down.

JSON admits a lone UTF-16 surrogate (``"\\ud800"``), and ``json.loads`` hands it back as a ``str``
that no encoder accepts: one such character in a sealed payload makes the whole result
unwritable. Samples supply them (a .NET resource name, a string literal the model copies into
its answer), so everything parsed from a model response or a continuation goes through
:func:`well_formed` before the engine keeps it.
"""

from __future__ import annotations

import re
from typing import Any

_SURROGATE = re.compile("[\ud800-\udfff]")


def well_formed(value: Any) -> Any:
    """``value`` (parsed JSON) with every lone surrogate in its strings and keys replaced by
    U+FFFD. Well-formed text is returned as it is; an escaped pair split across two escapes that
    the parser left apart is joined."""
    if isinstance(value, str):
        if _SURROGATE.search(value):
            return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
        return value
    if isinstance(value, list):
        return [well_formed(v) for v in value]
    if isinstance(value, dict):
        return {well_formed(k): well_formed(v) for k, v in value.items()}
    return value
