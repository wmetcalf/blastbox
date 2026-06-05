"""Render a Report as a human table or stable JSON."""
from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from blastbox.bench.harness import Report


def to_json(report: Report) -> dict[str, Any]:
    """Stable JSON schema for CLI --json output + CI baselines.

    A label with no samples (a failed/insufficient measurement) renders with
    ``stats: null`` rather than crashing on ``summarize`` of an empty list."""
    results = []
    for label in report.labels():
        stats = asdict(report.summary(label)) if report.samples(label) else None
        results.append({"label": label, "stats": stats})
    return {"scenario": report.scenario, "results": results}


def to_table(report: Report, *, baseline: str | None = None) -> str:
    """Human-readable table; if ``baseline`` is given, append overhead-vs-baseline.

    Empty-sample labels render as ``(no samples)`` instead of crashing."""
    labels = report.labels()
    base_p50 = (
        report.summary(baseline).p50
        if baseline in labels and report.samples(baseline)
        else None
    )
    lines = [f"=== {report.scenario} ==="]
    header = (
        f"  {'label':<14} {'p50(ms)':>9} {'p90(ms)':>9} {'p99(ms)':>9} "
        f"{'mean(ms)':>9} {'n':>4}"
    )
    if base_p50 is not None:
        header += f" {'overhead':>9}"
    lines.append(header)
    for label in labels:
        if not report.samples(label):
            lines.append(f"  {label:<14} {'(no samples)':>44}")
            continue
        s = report.summary(label)
        row = (
            f"  {label:<14} {s.p50 * 1000:>9.1f} {s.p90 * 1000:>9.1f} "
            f"{s.p99 * 1000:>9.1f} {s.mean * 1000:>9.1f} {s.n:>4}"
        )
        if base_p50 is not None:
            ov = (s.p50 / base_p50 - 1.0) * 100.0
            row += f" {ov:>+8.1f}%"
        lines.append(row)
    return "\n".join(lines)
