"""`doctor` must see the warm rootfs, not just the containers.

A rootfs is a file, not a process, and `docker export` drops the image config —
so the container survey structurally cannot see it. Three engines drifted inside
that blind spot for two months while every health check reported healthy.
"""

from __future__ import annotations

from pathlib import Path

from blastbox.host import doctor, platform_id as plat, rootfs_stamp as rfs


def _stamped(tmp: Path, name: str, **over) -> str:
    p = plat.host_platform(runtime=over.pop("runtime", "firecracker")).to_dict()
    p.update(over.pop("platform", {}))
    rfs.write_into_tree(
        tmp / name,
        rfs.RootfsStamp(
            blastbox_version=over.pop("version", "0.1.42"),
            image=over.pop("image", "eng-fc:1"),
            platform=p,
        ),
    )
    return str(tmp / name)


def test_survey_reads_version_and_platform(tmp_path: Path) -> None:
    got = doctor.survey_rootfs([_stamped(tmp_path, "a")])
    assert len(got) == 1
    assert got[0].version == "0.1.42"
    assert got[0].runtime == "firecracker"
    assert got[0].arch
    # A rootfs is bound to arch + runtime only; the exporter's CPU is not its property
    # (the snapshot is taken on the deploying host), so it is not surveyed as one.
    assert got[0].cpu_vendor == ""
    assert got[0].known


def test_an_unreadable_artifact_is_unknown_not_absent(tmp_path: Path) -> None:
    got = doctor.survey_rootfs([str(tmp_path / "nope")])
    assert got[0].version == doctor.UNKNOWN
    assert not got[0].known
    assert got[0].detail


def test_unreadable_detail_keeps_the_path_readable(tmp_path: Path) -> None:
    """The reason names a path; stripping its separators makes it unusable."""
    got = doctor.survey_rootfs([str(tmp_path / "nope")])
    assert "/" in got[0].detail


def test_a_survey_does_not_die_on_one_bad_row(tmp_path: Path) -> None:
    good = _stamped(tmp_path, "good")
    got = doctor.survey_rootfs([str(tmp_path / "nope"), good])
    assert [a.known for a in got] == [False, True]


def test_artifact_problems_flags_a_foreign_architecture(tmp_path: Path) -> None:
    alien = _stamped(tmp_path, "alien", platform={"arch": "s390x"})
    problems = doctor.artifact_problems(doctor.survey_rootfs([alien]))
    assert len(problems) == 1
    assert "s390x" in problems[0][1]


def test_artifact_problems_ignores_unknown_artifacts(tmp_path: Path) -> None:
    """An artifact that could not be read is not an artifact that is wrong."""
    assert doctor.artifact_problems(doctor.survey_rootfs([str(tmp_path / "nope")])) == []


def test_fleet_report_is_not_ok_when_an_artifact_cannot_boot(tmp_path: Path) -> None:
    alien = _stamped(tmp_path, "alien", platform={"arch": "s390x"})
    report = doctor.fleet_report([], doctor.survey_rootfs([alien]))
    assert report["ok"] is False
    assert report["unbootable"] and report["unbootable"][0]["path"] == alien


def test_fleet_report_is_not_ok_on_a_version_split(tmp_path: Path) -> None:
    a = doctor.survey_rootfs([_stamped(tmp_path, "a", version="0.1.42")])
    b = doctor.survey_rootfs([_stamped(tmp_path, "b", version="0.1.26")])
    report = doctor.fleet_report([], a + b)
    assert report["versions"] == ["0.1.26", "0.1.42"]
    assert report["ok"] is False


def test_fleet_report_is_ok_on_a_single_healthy_artifact(tmp_path: Path) -> None:
    report = doctor.fleet_report([], doctor.survey_rootfs([_stamped(tmp_path, "a")]))
    assert report["ok"] is True
    assert report["unknown"] == [] and report["unbootable"] == []


def test_fleet_report_is_json_serialisable(tmp_path: Path) -> None:
    import json

    report = doctor.fleet_report([], doctor.survey_rootfs([_stamped(tmp_path, "a")]))
    assert json.loads(json.dumps(report))["versions"] == ["0.1.42"]
