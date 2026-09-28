"""A warm artifact is valid for a (blastbox, arch, CPU, runtime) tuple."""

from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host import platform_id as plat

CPUINFO = """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model name\t: Intel(R) Xeon(R) Gold 6338N CPU @ 2.20GHz
flags\t\t: fpu vme de

processor\t: 1
vendor_id\t: AuthenticAMD
model name\t: should not be read — second block
"""


def _p(**kw: str) -> plat.HostPlatform:
    base = dict(
        arch="x86_64",
        cpu_vendor="GenuineIntel",
        cpu_model="Xeon Gold 6338N",
        runtime="firecracker",
        runtime_version="1.16.0",
        kernel="6.8.0",
    )
    base.update(kw)
    return plat.HostPlatform(**base)  # type: ignore[arg-type]


def test_cpuinfo_reads_only_the_first_processor_block(tmp_path: Path) -> None:
    f = tmp_path / "cpuinfo"
    f.write_text(CPUINFO)
    got = plat.host_platform(cpuinfo=f)
    assert got.cpu_vendor == "GenuineIntel"
    assert "6338N" in got.cpu_model


def test_host_platform_never_raises_on_an_unreadable_cpuinfo(tmp_path: Path) -> None:
    got = plat.host_platform(cpuinfo=tmp_path / "missing")
    assert got.cpu_vendor == "" and got.arch  # arch still comes from the stdlib


def test_identical_platforms_have_no_objection() -> None:
    assert plat.compare(_p(), _p()) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [("arch", "aarch64"), ("cpu_vendor", "AuthenticAMD"), ("runtime", "gvisor")],
)
def test_incompatible_fields_refuse(field: str, value: str) -> None:
    findings = plat.compare(_p(**{field: value}), _p())
    assert [f.field for f in findings] == [field]
    assert findings[0].severity == plat.REFUSE
    assert plat.refusals(findings) == findings


@pytest.mark.parametrize("field", ["runtime_version", "cpu_model", "kernel"])
def test_survivable_differences_only_warn(field: str) -> None:
    findings = plat.compare(_p(**{field: "something-else"}), _p())
    assert [f.field for f in findings] == [field]
    assert findings[0].severity == plat.WARN
    assert plat.refusals(findings) == []


def test_an_unrecorded_platform_warns_rather_than_refusing() -> None:
    """Every artifact exported before platform capture records nothing.

    Refusing those would take a fleet offline on upgrade — worse than the
    failure being prevented.
    """
    findings = plat.compare(plat.HostPlatform(), _p())
    assert len(findings) == 1
    assert findings[0].severity == plat.WARN
    assert "build-images" in findings[0].message
    assert plat.refusals(findings) == []


def test_a_field_absent_on_either_side_is_not_compared() -> None:
    """"" means "not recorded", never "different"."""
    assert plat.compare(_p(cpu_model=""), _p()) == []
    assert plat.compare(_p(), _p(cpu_model="")) == []


def test_fc_and_gvisor_artifacts_are_not_interchangeable() -> None:
    fc_art = _p(runtime="firecracker")
    gvisor_host = _p(runtime="gvisor")
    fatal = plat.refusals(plat.compare(fc_art, gvisor_host))
    assert fatal and "runsc directory tree" in fatal[0].message


def test_summarise_puts_refusals_first() -> None:
    findings = plat.compare(_p(arch="aarch64", kernel="old"), _p())
    text = plat.summarise(findings)
    assert text.index("arch:") < text.index("kernel:")


def test_round_trip_through_dict() -> None:
    assert plat.HostPlatform.from_dict(_p().to_dict()) == _p()
    assert plat.HostPlatform.from_dict("not a dict").is_empty()
