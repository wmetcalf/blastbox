"""`blastbox serve` must survive a SET-BUT-EMPTY BLASTBOX_SERVE_WORKERS.

Compose renders `- BLASTBOX_SERVE_WORKERS=${BLASTBOX_SERVE_WORKERS:-}` as the empty STRING, not
as an absent variable (verified with `docker compose config`: `BLASTBOX_SERVE_WORKERS: ""`). So
`os.environ.get(KEY, "1")` returns "" -- the default never applies -- and a bare `int()` raises
ValueError before uvicorn starts. With `restart: unless-stopped` that is a crash loop on every
deploy whose .env does not happen to define the variable.

Every sibling knob in this codebase already tolerates empty (`_int_env`, `_upload_concurrency`,
`BLASTBOX_BLOB_URL`'s `.strip()`); this one parsed bare, which is why it was the one that broke.
Fixing the PARSER rather than only the compose file covers every deployment path -- k8s, systemd,
a hand-run container -- not just the one compose file that happened to expose it.
"""

from __future__ import annotations

import pytest

from blastbox.host.cli import _serve_workers


@pytest.mark.parametrize("raw", ["", "   ", None])
def test_absent_or_empty_means_one(raw, monkeypatch):
    """MUTATION: `int(os.environ.get(KEY, "1"))` -> ValueError on "" and the api crash-loops."""
    if raw is None:
        monkeypatch.delenv("BLASTBOX_SERVE_WORKERS", raising=False)
    else:
        monkeypatch.setenv("BLASTBOX_SERVE_WORKERS", raw)
    assert _serve_workers(None) == 1


def test_a_real_value_is_honoured(monkeypatch):
    monkeypatch.setenv("BLASTBOX_SERVE_WORKERS", "8")
    assert _serve_workers(None) == 8


def test_an_explicit_flag_beats_the_env(monkeypatch):
    """--workers is the operator being specific; it must win over a deployment default."""
    monkeypatch.setenv("BLASTBOX_SERVE_WORKERS", "8")
    assert _serve_workers(4) == 4


@pytest.mark.parametrize("raw", ["banana", "0", "-3", "2.5"])
def test_a_nonsense_value_falls_back_instead_of_crashing(raw, monkeypatch):
    """A typo in a deployment env must not take the ingress down -- it is the only way IN.

    MUTATION: drop the except/range guard -> "banana" raises and "0"/"-3" reach uvicorn, which
    treats <1 workers as its own error.
    """
    monkeypatch.setenv("BLASTBOX_SERVE_WORKERS", raw)
    assert _serve_workers(None) == 1
