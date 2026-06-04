"""Render a Report as a human table or stable JSON."""
from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from blastbox.bench.harness import Report


def to_json(report: Report) -> dict[str, Any]:
    """Stable JSON schema for CLI --json output + CI baselines."""
    results = [
        {"label": label, "stats": asdict(report.summary(label))}
        for label in report.labels()
    ]
    return {"scenario": report.scenario, "results": results}


def to_table(report: Report, *, baseline: str | None = None) -> str:
    """Human-readable table; if ``baseline`` is given, append overhead-vs-baseline."""
    labels = report.labels()
    base_p50 = report.summary(baseline).p50 if baseline in labels else None
    lines = [f"=== {report.scenario} ==="]
    header = f"  {'label':<14} {'p50':>9} {'p90':>9} {'p99':>9} {'n':>4}"
    if base_p50 is not None:
        header += f" {'overhead':>9}"
    lines.append(header)
    for label in labels:
        s = report.summary(label)
        row = (
            f"  {label:<14} {s.p50 * 1000:>8.1f}m {s.p90 * 1000:>8.1f}m "
            f"{s.p99 * 1000:>8.1f}m {s.n:>4}"
        )
        if base_p50 is not None:
            ov = (s.p50 / base_p50 - 1.0) * 100.0
            row += f" {ov:>+8.1f}%"
        lines.append(row)
    return "\n".join(lines)
