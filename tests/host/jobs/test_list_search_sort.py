"""list(q=, sort=, order=) + count(q=) — filename substring search + whitelist
column sort, restored from the engines' bespoke list views (the generic /v1/jobs
had only status filtering, so both engines' search boxes + sort headers were dead)."""
from __future__ import annotations

from blastbox.host.jobs.base import Job, JobStatus
from blastbox.host.jobs.memory import InMemoryJobStore


def _store() -> InMemoryJobStore:
    s = InMemoryJobStore()
    for fn, created in [("report.docx", 1.0), ("Invoice.pdf", 2.0), ("report_v2.xlsx", 3.0)]:
        j = Job.new(engine="e", filename=fn)
        j.created_at = created
        j.status = JobStatus.DONE
        s.create(j)
    return s


def test_q_filters_filename_case_insensitive():
    s = _store()
    assert {j.filename for j in s.list(q="report")} == {"report.docx", "report_v2.xlsx"}
    assert s.count(q="report") == 2
    assert {j.filename for j in s.list(q="INVOICE")} == {"Invoice.pdf"}
    assert s.count(q="nope") == 0


def test_q_metachars_are_literal():
    # a user's "%"/"_" must not act as a wildcard (LIKE-escaped)
    s = InMemoryJobStore()
    for fn in ("a%b.txt", "axxb.txt"):
        s.create(Job.new(engine="e", filename=fn))
    assert {j.filename for j in s.list(q="a%b")} == {"a%b.txt"}


def test_sort_by_filename_asc():
    fns = [j.filename for j in _store().list(sort="filename", order="asc")]
    assert fns == sorted(fns, key=str.lower)


def test_default_newest_first_and_unknown_sort_falls_back():
    s = _store()
    assert [j.filename for j in s.list(newest_first=True)] == [
        "report_v2.xlsx", "Invoice.pdf", "report.docx",
    ]
    # a non-whitelisted sort field is ignored (no injection) → newest-first
    assert [j.filename for j in s.list(sort="bogus", newest_first=True)][0] == "report_v2.xlsx"
