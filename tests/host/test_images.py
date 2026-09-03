"""The declared image chain must be trustworthy before anything is built.

Every failure encoded here happened for real while porting three engines'
hand-written build scripts.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host.images import (
    PlanError,
    build_command,
    describe,
    load_plan,
    missing_dockerfiles,
    resolve_chain,
)

TITANARUM = """
[engine]
name = "titanarum"

[[image]]
name = "titanarum-base"
dockerfile = "deploy/docker/Dockerfile.titanarum-base"
base = "eclipse-temurin:25-jre"
build_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk", ZXING_BUILD_IMAGE = "debian:12-slim" }

[[image]]
name = "titanarum-cold-worker"
dockerfile = "deploy/docker/Dockerfile.titanarum-cold-worker"
base = "titanarum-base"

[[image]]
name = "titanarum-fc-worker"
dockerfile = "deploy/firecracker/Dockerfile.titanarum"
base = "titanarum-cold-worker"

[[rootfs]]
kind = "ext4"
image = "titanarum-fc-worker"
dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"
size_mib = 3072
requires = ["/init"]
"""


def _plan(tmp_path: Path, text: str) -> Path:
    (tmp_path / "blastbox-images.toml").write_text(text)
    return tmp_path


def test_a_real_chain_parses_in_declaration_order(tmp_path: Path) -> None:
    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert plan.engine == "titanarum"
    assert [i.name for i in plan.images] == [
        "titanarum-base", "titanarum-cold-worker", "titanarum-fc-worker",
    ]


def test_a_base_naming_an_earlier_image_is_internal(tmp_path: Path) -> None:
    """An upstream base is pulled; a chain base is what this run just built."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert plan.image("titanarum-base").internal is False
    assert plan.image("titanarum-cold-worker").internal is True


def test_the_chain_pins_to_the_tag_being_built(tmp_path: Path) -> None:
    """Never a stale tag of the same name from a previous run.

    That is how a "rebuild" quietly ships a mixture of two builds.
    """
    plan = load_plan(_plan(tmp_path, TITANARUM))
    refs = dict((s.name, b) for s, b in resolve_chain(plan, "t9"))
    assert refs["titanarum-base"] == "eclipse-temurin:25-jre"
    assert refs["titanarum-cold-worker"] == "titanarum-base:t9"
    assert refs["titanarum-fc-worker"] == "titanarum-cold-worker:t9"


def test_a_base_that_is_neither_upstream_nor_earlier_is_still_accepted_as_upstream(
    tmp_path: Path,
) -> None:
    """Only a name declared EARLIER counts as internal.

    Forward references would let the chain claim to build on something that does
    not exist yet, so a name appearing later is treated as an upstream
    reference and pulled -- where it fails loudly and immediately.
    """
    text = TITANARUM.replace('base = "titanarum-base"\n', 'base = "titanarum-fc-worker"\n', 1)
    plan = load_plan(_plan(tmp_path, text))
    assert plan.image("titanarum-cold-worker").internal is False


def test_an_image_with_no_base_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace('base = "eclipse-temurin:25-jre"\n', "")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "declares no base" in str(e.value)


def test_duplicate_image_names_are_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace('name = "titanarum-cold-worker"', 'name = "titanarum-base"', 1)
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "two images are named" in str(e.value)


def test_a_rootfs_from_an_image_the_chain_never_builds_is_refused(tmp_path: Path) -> None:
    """Exporting something the chain does not produce is how a rootfs gets made
    from an image nobody verified."""
    text = TITANARUM.replace('image = "titanarum-fc-worker"\ndest', 'image = "somewhere-else"\ndest')
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "never builds" in str(e.value)


def test_an_unknown_rootfs_kind_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace('kind = "ext4"', 'kind = "squashfs"')
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "kind must be one of" in str(e.value)


def test_a_missing_spec_says_so(tmp_path: Path) -> None:
    with pytest.raises(PlanError) as e:
        load_plan(tmp_path)
    assert "declares no image chain" in str(e.value)


def test_a_plan_with_no_images_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, '[engine]\nname = "x"\n'))
    assert "nothing to build" in str(e.value)


def test_missing_dockerfiles_are_reported_before_any_build(tmp_path: Path) -> None:
    """Otherwise the failure surfaces deep inside a docker build."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert len(missing_dockerfiles(plan)) == 3
    (tmp_path / "deploy" / "docker").mkdir(parents=True)
    (tmp_path / "deploy" / "docker" / "Dockerfile.titanarum-base").write_text("FROM x\n")
    assert len(missing_dockerfiles(plan)) == 2


def test_the_build_command_is_argv_not_a_string(tmp_path: Path) -> None:
    """A label value with a space would word-split into loose docker arguments."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(
        plan.image("titanarum-base"), "t9", ["--label", "org.x=a b c"]
    )
    assert isinstance(argv, list)
    assert "--label" in argv and "org.x=a b c" in argv
    assert argv[-2:] == ["-t", "titanarum-base:t9"][-1:] + ["."]


def test_declared_build_args_reach_the_command(tmp_path: Path) -> None:
    """The builder-stage pins: their OUTPUT ships, so they must be passed."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(plan.image("titanarum-base"), "t9", [])
    joined = " ".join(argv)
    assert "JDK_BUILD_IMAGE=eclipse-temurin:25-jdk" in joined
    assert "ZXING_BUILD_IMAGE=debian:12-slim" in joined


def test_the_rootfs_destination_expands_host_variables(tmp_path: Path) -> None:
    """Destinations are per-host, so they are declared as variables."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    rf = plan.rootfs[0]
    assert rf.resolved_dest({"TITANARUM_FC_DIR": "/srv/fc"}) == "/srv/fc/titanarum-rootfs.ext4"


def test_an_unset_variable_is_left_visible_rather_than_emptied(tmp_path: Path) -> None:
    """`/titanarum-rootfs.ext4` would be a plausible-looking path at the root."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert plan.rootfs[0].resolved_dest({}) == "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"


def test_describe_names_every_build_and_export(tmp_path: Path) -> None:
    plan = load_plan(_plan(tmp_path, TITANARUM))
    text = describe(plan, "t9", {"TITANARUM_FC_DIR": "/srv/fc"})
    assert "titanarum-cold-worker:t9  <- titanarum-base:t9 (chain)" in text
    assert "export ext4 3072 MiB from titanarum-fc-worker:t9" in text
    assert "requires ['/init']" in text
    # The destination is RESOLVED: a dry-run printing `$TITANARUM_FC_DIR` has
    # not answered the question it exists to answer.
    assert "-> /srv/fc/titanarum-rootfs.ext4" in text
    assert "UNRESOLVED" not in text


def test_an_unresolved_destination_is_flagged_in_the_dry_run(tmp_path: Path) -> None:
    """Silently printing `$VAR` invites running it anyway."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert "[UNRESOLVED]" in describe(plan, "t9", {})


def test_a_destination_default_is_honoured(tmp_path: Path) -> None:
    """These paths are copied from compose files that already use `${X:-y}`.

    A spec that dropped the default would resolve to a path with a hole in it.
    """
    text = TITANARUM.replace(
        'dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"',
        'dest = "${TITANARUM_FC_DIR:-/var/lib/titan-fc}/titanarum-rootfs.ext4"',
    )
    plan = load_plan(_plan(tmp_path, text))
    rf = plan.rootfs[0]
    assert rf.resolved_dest({}) == "/var/lib/titan-fc/titanarum-rootfs.ext4"
    assert rf.resolved_dest({"TITANARUM_FC_DIR": "/srv"}) == "/srv/titanarum-rootfs.ext4"


def test_a_dockerfile_in_another_context_is_found_there(tmp_path: Path) -> None:
    """An engine legitimately builds from another tree's Dockerfiles.

    redtusk's warm images come from blastbox's own deploy/, with
    `context = "$BLASTBOX_SRC"`. Resolving those against the consumer repo
    reports every one of them missing.
    """
    other = tmp_path / "elsewhere" / "deploy" / "gvisor"
    other.mkdir(parents=True)
    (other / "Dockerfile.x").write_text("ARG BASE\nFROM ${BASE}\n")
    text = '''
[engine]
name = "e"

[[image]]
name = "a"
dockerfile = "deploy/gvisor/Dockerfile.x"
base = "upstream:1"
base_arg = "BASE"
context = "$OTHER_SRC"
'''
    plan = load_plan(_plan(tmp_path, text))
    env = {"OTHER_SRC": str(tmp_path / "elsewhere")}
    assert missing_dockerfiles(plan, env) == []
    # ...and against the plan root alone it is correctly reported missing.
    assert missing_dockerfiles(plan, {}) != []
