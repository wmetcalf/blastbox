"""Which models' reasoning may be kept in the pass transcript (the reasoning ledger).

A row is added by a person after reading what the provider's API returns and what its terms
allow; a model id that is not here keeps nothing. Kept reasoning is a side record only: it is
written to the sealed transcript and never sent back to the model.

```text
returned     full | summary | encrypted | none   what the API gives back
allowed      the provider's terms permit keeping it
```
"""

from __future__ import annotations

__all__ = ["ROWS", "capture_allowed"]

ROWS: dict[str, tuple[str, bool, str]] = {
    "deepseek/deepseek-v4.1-flash": (
        "full", True,
        "MIT-licensed open weights; via the OpenRouter ZDR gateway message.reasoning is text "
        "(measured 2026-11-17); Will 2026-11-17: keep where the model allows"),
    "meta/muse-ember": (
        "encrypted", False,
        "OpenRouter returns only reasoning_details of type reasoning.encrypted (measured 2026-11-17)"),
}


def capture_allowed(model_id: str) -> bool:
    row = ROWS.get(model_id)
    return row is not None and row[1] and row[0] in ("full", "summary")
