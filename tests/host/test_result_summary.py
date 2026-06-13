"""_build_result_summary — the small envelope derivative persisted on the Job for
list views. Restored the generic detection label + bounded scalar engine fields so
the engines' list columns (Detection, page counts) work without fetching /metadata.
"""
from __future__ import annotations

import types

from blastbox.host.dispatch import _build_result_summary


def _env(fields):
    return types.SimpleNamespace(
        status="ok",
        artifacts=[1, 2, 3],
        warnings=[],
        detected=types.SimpleNamespace(label="application/pdf"),
        payload=types.SimpleNamespace(metadata=types.SimpleNamespace(fields=fields)),
    )


def test_adds_detected_label_and_counts():
    s = _build_result_summary(_env({}))
    assert s["detected"] == "application/pdf"
    assert s["artifact_count"] == 3
    assert s["warning_count"] == 0


def test_surfaces_scalar_meta_excludes_large_strings():
    s = _build_result_summary(_env({
        "page_count_total": 6,
        "page_count_rendered": 5,
        "label": "PDF",
        "truncated": False,
        "clippyshot_metadata": "x" * 5000,   # large embedded JSON — excluded
        "nested": {"a": 1},                   # non-scalar — excluded
    }))
    assert s["meta"]["page_count_total"] == 6
    assert s["meta"]["page_count_rendered"] == 5
    assert s["meta"]["label"] == "PDF"
    assert s["meta"]["truncated"] is False
    assert "clippyshot_metadata" not in s["meta"]
    assert "nested" not in s["meta"]


def test_robust_to_missing_payload():
    env = types.SimpleNamespace(status="rejected", artifacts=[], warnings=[],
                                detected=None, payload=None)
    s = _build_result_summary(env)
    assert s["detected"] is None
    assert "meta" not in s  # no payload → no meta, no crash
