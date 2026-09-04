"""The declared image chain must be trustworthy before anything is built.

Every failure encoded here happened for real while porting three engines'
hand-written build scripts.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from blastbox.host.images import (
    Plan,
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


def test_a_forward_reference_is_refused(tmp_path: Path) -> None:
    """A base naming an image declared LATER is a mistake, not an upstream ref.

    Treating it as upstream makes docker try to pull an image this very plan
    builds, failing with "pull access denied" -- a message that sends you
    looking at registry credentials.
    """
    text = TITANARUM.replace('base = "titanarum-base"\n', 'base = "titanarum-fc-worker"\n', 1)
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "declares LATER" in str(e.value)


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


def test_an_uppercase_image_name_is_refused(tmp_path: Path) -> None:
    """Docker repository names are lowercase; this would fail at tag time."""
    text = TITANARUM.replace('name = "titanarum-base"', 'name = "Titanarum-Base"', 1)
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "no usable name" in str(e.value)


def test_an_empty_variable_takes_the_default(tmp_path: Path) -> None:
    """`${VAR:-x}` with VAR="" selects x, as the shell does.

    A compose env routinely carries `TITANARUM_FC_DIR=` for an unset knob, and
    treating that as "set" resolves the destination to a hole.
    """
    text = TITANARUM.replace(
        'dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"',
        'dest = "${TITANARUM_FC_DIR:-/var/lib/titan-fc}/titanarum-rootfs.ext4"',
    )
    plan = load_plan(_plan(tmp_path, text))
    assert plan.rootfs[0].resolved_dest({"TITANARUM_FC_DIR": ""}) == (
        "/var/lib/titan-fc/titanarum-rootfs.ext4"
    )


def test_a_nonsense_rootfs_size_is_a_plan_error(tmp_path: Path) -> None:
    """`"3GiB"` must refuse with a reason, not raise ValueError from int()."""
    text = TITANARUM.replace("size_mib = 3072", 'size_mib = "3GiB"')
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "whole number of MiB" in str(e.value)


def test_the_build_command_passes_the_base_it_claims_to_pin(tmp_path: Path) -> None:
    """Otherwise the plan says pinned and the Dockerfile uses its own default."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(plan.image("titanarum-cold-worker"), "t9", [], "titanarum-base:t9")
    assert "--build-arg" in argv
    assert "BASE_IMAGE=titanarum-base:t9" in argv


def test_the_base_is_not_passed_twice_when_stamp_already_carries_it(tmp_path: Path) -> None:
    """`blastbox stamp` emits that build-arg itself; two copies can disagree."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(
        plan.image("titanarum-cold-worker"), "t9",
        ["--build-arg", "BASE_IMAGE=titanarum-base@sha256:" + "a" * 64],
        "titanarum-base:t9",
    )
    assert sum(1 for a in argv if a.startswith("BASE_IMAGE=")) == 1
    assert "BASE_IMAGE=titanarum-base:t9" not in argv


def test_the_build_context_is_expanded(tmp_path: Path) -> None:
    """`$BLASTBOX_SRC` handed to docker literally is a directory that does not exist."""
    text = TITANARUM.replace(
        'dockerfile = "deploy/firecracker/Dockerfile.titanarum"',
        'dockerfile = "deploy/firecracker/Dockerfile.titanarum"\ncontext = "$OTHER_SRC"',
    )
    plan = load_plan(_plan(tmp_path, text))
    argv = build_command(
        plan.image("titanarum-fc-worker"), "t9", [], None, {"OTHER_SRC": "/srv/bb"}
    )
    assert argv[-1] == "/srv/bb"


def test_the_default_form_works_without_an_explicit_env(tmp_path: Path, monkeypatch) -> None:
    """`os.path.expandvars` does not understand `${VAR:-default}`.

    Falling back to it made default handling depend on whether the caller
    happened to pass an env -- so `describe()` resolved a destination that
    `resolved_dest()` left with a hole in it.
    """
    text = TITANARUM.replace(
        'dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"',
        'dest = "${TITANARUM_FC_DIR:-/var/lib/titan-fc}/titanarum-rootfs.ext4"',
    )
    plan = load_plan(_plan(tmp_path, text))
    monkeypatch.delenv("TITANARUM_FC_DIR", raising=False)
    assert plan.rootfs[0].resolved_dest() == "/var/lib/titan-fc/titanarum-rootfs.ext4"
    monkeypatch.setenv("TITANARUM_FC_DIR", "/srv/fc")
    assert plan.rootfs[0].resolved_dest() == "/srv/fc/titanarum-rootfs.ext4"


@pytest.mark.parametrize("bad", ["worker-", "worker.", "worker..base", "-worker", "worker!x"])
def test_invalid_repository_names_are_refused(tmp_path: Path, bad: str) -> None:
    """Separators sit BETWEEN alphanumerics; accepting these moves the failure
    to `docker tag`, which is the wrong place to find out."""
    text = TITANARUM.replace('name = "titanarum-base"', f'name = "{bad}"', 1)
    with pytest.raises(PlanError):
        load_plan(_plan(tmp_path, text))


def test_a_fractional_size_is_refused_not_truncated(tmp_path: Path) -> None:
    """Truncating would silently build a smaller filesystem than declared."""
    text = TITANARUM.replace("size_mib = 3072", "size_mib = 3072.9")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "truncating" in str(e.value)


def test_an_integral_float_size_is_accepted(tmp_path: Path) -> None:
    """`3072.0` means 3072; only a real fraction is a mistake."""
    text = TITANARUM.replace("size_mib = 3072", "size_mib = 3072.0")
    assert load_plan(_plan(tmp_path, text)).rootfs[0].size_mib == 3072


def test_a_build_arg_may_not_override_the_pinned_base(tmp_path: Path) -> None:
    """Whichever won, the stamp would record a base the build may not have used."""
    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk", ZXING_BUILD_IMAGE = "debian:12-slim" }',
        'build_args = { BASE_IMAGE = "something:else" }',
    )
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "pins its base" in str(e.value)


def test_malformed_build_args_are_a_plan_error(tmp_path: Path) -> None:
    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE = "eclipse-temurin:25-jdk", ZXING_BUILD_IMAGE = "debian:12-slim" }',
        'build_args = { NESTED = { a = 1 } }',
    )
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "must be a scalar" in str(e.value)


def test_an_unresolved_destination_is_reported_for_refusal(tmp_path: Path) -> None:
    """The dry run must FAIL on these, not note them and continue.

    The export would write to a literal `$VAR` directory, or to a path that
    merely looks plausible.
    """
    from blastbox.host.images import unresolved_destinations

    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert unresolved_destinations(plan, {}) != []
    assert unresolved_destinations(plan, {"TITANARUM_FC_DIR": "/srv"}) == []


@pytest.mark.parametrize("ok", ["my__worker", "a--b", "worker.base", "w0rker-1"])
def test_docker_valid_names_are_accepted(tmp_path: Path, ok: str) -> None:
    """`__` and repeated dashes ARE valid docker repository components.

    Refusing names docker accepts is its own kind of wrong -- an earlier,
    stricter pattern here did exactly that.
    """
    text = TITANARUM.replace('name = "titanarum-base"', f'name = "{ok}"', 1)
    text = text.replace('base = "titanarum-base"', f'base = "{ok}"', 1)
    assert load_plan(_plan(tmp_path, text)).images[0].name == ok


def test_a_single_image_table_is_refused(tmp_path: Path) -> None:
    """`[image]` instead of `[[image]]` declares one image and drops the rest."""
    spec = '[engine]\nname = "e"\n[image]\nname = "a"\ndockerfile = "D"\nbase = "u:1"\n'
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, spec))
    assert "ARRAY of tables" in str(e.value)


def test_requires_as_a_bare_string_is_refused(tmp_path: Path) -> None:
    """Iterating a string yields one requirement per CHARACTER."""
    text = TITANARUM.replace('requires = ["/init"]', 'requires = "/init"')
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "must be an ARRAY" in str(e.value)


def test_an_ext4_without_a_size_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace("size_mib = 3072\n", "")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "declares no size_mib" in str(e.value)


def test_two_rootfs_entries_may_not_share_a_destination(tmp_path: Path) -> None:
    """The second would overwrite the first, decided by declaration order."""
    extra = (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "titanarum-base"\n'
        'dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"\nsize_mib = 512\n'
    )
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, TITANARUM + extra))
    assert "would overwrite" in str(e.value)


def test_an_empty_variable_without_a_default_stays_unresolved(tmp_path: Path) -> None:
    """`$X/file` with X empty gives `/file`, a plausible path at the root."""
    from blastbox.host.images import unresolved_destinations

    plan = load_plan(_plan(tmp_path, TITANARUM))
    assert unresolved_destinations(plan, {"TITANARUM_FC_DIR": ""}) != []


@pytest.mark.parametrize("bad", ["", "a:b", "a/b", ".lead", "-lead"])
def test_an_unusable_tag_is_refused(bad: str) -> None:
    from blastbox.host.images import check_tag

    with pytest.raises(PlanError):
        check_tag(bad)


def test_a_misspelled_build_arg_is_reported(tmp_path: Path) -> None:
    """A misspelled builder pin is discarded by docker, so the stage keeps its
    mutable default while the plan reads as if it were pinned."""
    from blastbox.host.images import arg_problems

    d = tmp_path / "deploy" / "docker"
    d.mkdir(parents=True)
    (d / "Dockerfile.titanarum-base").write_text(
        "ARG BASE_IMAGE\nARG JDK_BUILD_IMAGE\nFROM ${BASE_IMAGE}\n"
    )
    text = TITANARUM.replace("ZXING_BUILD_IMAGE", "ZXING_BUILD_IMGE")
    plan = load_plan(_plan(tmp_path, text))
    problems = [x for x in arg_problems(plan, {}) if "titanarum-base" in x]
    assert any("ZXING_BUILD_IMGE" in x for x in problems), problems


def test_the_dry_run_shows_an_external_context(tmp_path: Path) -> None:
    text = TITANARUM.replace(
        'dockerfile = "deploy/firecracker/Dockerfile.titanarum"',
        'dockerfile = "deploy/firecracker/Dockerfile.titanarum"\ncontext = "$OTHER"',
    )
    plan = load_plan(_plan(tmp_path, text))
    out = describe(plan, "t9", {"OTHER": "/srv/bb", "TITANARUM_FC_DIR": "/f"})
    assert "[context /srv/bb]" in out


def test_an_unknown_image_key_is_refused(tmp_path: Path) -> None:
    """A misspelled optional field is otherwise ignored in silence, and the pin
    it was meant to express never happens."""
    text = TITANARUM.replace("build_args = {", "base_args = {", 1)
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "unknown key" in str(e.value) and "base_args" in str(e.value)


def test_an_unknown_rootfs_key_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace("size_mib = 3072", "size_mib = 3072\nsizemib = 1")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "unknown key" in str(e.value)


def test_a_single_rootfs_table_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace("[[rootfs]]", "[rootfs]")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "ARRAY of tables" in str(e.value)


def test_a_boolean_size_is_refused(tmp_path: Path) -> None:
    """bool is a subclass of int, so `true` would quietly become 1 MiB."""
    text = TITANARUM.replace("size_mib = 3072", "size_mib = true")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "boolean" in str(e.value)


@pytest.mark.parametrize("bad", ["b:", "UPPER:1", "a b", ":tag"])
def test_an_unusable_base_reference_is_refused(tmp_path: Path, bad: str) -> None:
    text = TITANARUM.replace('base = "eclipse-temurin:25-jre"', f'base = "{bad}"', 1)
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "usable reference" in str(e.value) or "no usable name" in str(e.value)


@pytest.mark.parametrize(
    "ok",
    [
        "eclipse-temurin:25-jre",
        "python:3.12-slim-bookworm",
        "ghcr.io/tecnativa/docker-socket-proxy:0.3.0",
        "registry.example:5000/team/img:tag",
        "base@sha256:" + "a" * 64,
    ],
)
def test_real_upstream_references_are_accepted(tmp_path: Path, ok: str) -> None:
    """These are references this fleet actually uses."""
    text = TITANARUM.replace('base = "eclipse-temurin:25-jre"', f'base = "{ok}"', 1)
    assert load_plan(_plan(tmp_path, text)).images[0].base == ok


def test_a_lowercase_arg_keyword_is_recognised(tmp_path: Path) -> None:
    """Dockerfile instruction keywords are case-insensitive.

    The same trap already fixed once in stamp.py: `arg BASE_IMAGE` is valid and
    reporting it as undeclared would refuse a Dockerfile docker builds fine.
    """
    from blastbox.host.images import arg_problems

    d = tmp_path / "deploy" / "docker"
    d.mkdir(parents=True)
    (d / "Dockerfile.titanarum-base").write_text(
        "arg BASE_IMAGE\narg JDK_BUILD_IMAGE\narg ZXING_BUILD_IMAGE\nfrom ${BASE_IMAGE}\n"
    )
    plan = load_plan(_plan(tmp_path, TITANARUM))
    # Only BASE_IMAGE is at issue; the stub omits the other two on purpose.
    problems = [p for p in arg_problems(plan, {}) if "`ARG BASE_IMAGE`" in p]
    assert problems == [], problems


def test_the_dry_run_shows_declared_build_args(tmp_path: Path) -> None:
    """They are pins; an operator reading the plan should see them."""
    plan = load_plan(_plan(tmp_path, TITANARUM))
    out = describe(plan, "t9", {"TITANARUM_FC_DIR": "/f"})
    assert "--build-arg JDK_BUILD_IMAGE=eclipse-temurin:25-jdk" in out


@pytest.mark.parametrize("ok", ["my__base:1", "a--b/c--d:tag", "reg.io:5000/a__b:1"])
def test_repeated_separators_in_a_base_reference_are_accepted(tmp_path: Path, ok: str) -> None:
    """Same grammar as image names. My first reference pattern over-rejected
    these, which is the mistake I had already made once on names."""
    text = TITANARUM.replace('base = "eclipse-temurin:25-jre"', f'base = "{ok}"', 1)
    assert load_plan(_plan(tmp_path, text)).images[0].base == ok


def test_an_unknown_top_level_section_is_refused(tmp_path: Path) -> None:
    """`[[images]]` parses fine as TOML and declares nothing."""
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, TITANARUM.replace("[[image]]", "[[images]]", 1)))
    assert "unknown top-level section" in str(e.value)


def test_a_non_table_engine_section_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, 'engine = "titanarum"\n[[image]]\nname = "a"\ndockerfile = "D"\nbase = "u:1"\n'))
    assert "must be a table" in str(e.value)


def test_a_non_string_requirement_is_refused(tmp_path: Path) -> None:
    text = TITANARUM.replace('requires = ["/init"]', "requires = [1]")
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, text))
    assert "must be paths" in str(e.value)


def test_destinations_colliding_after_resolution_are_refused(
    tmp_path: Path, monkeypatch
) -> None:
    """`$A/x` and `$B/x` are different strings and the same path."""
    monkeypatch.setenv("TITANARUM_FC_DIR", "/shared")
    monkeypatch.setenv("OTHER_DIR", "/shared")
    extra = (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "titanarum-base"\n'
        'dest = "$OTHER_DIR/titanarum-rootfs.ext4"\nsize_mib = 512\n'
    )
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, TITANARUM + extra))
    assert "would overwrite" in str(e.value)


def _base_dockerfile(tmp_path: Path, body: str) -> Plan:
    d = tmp_path / "deploy" / "docker"
    d.mkdir(parents=True, exist_ok=True)
    (d / "Dockerfile.titanarum-base").write_text(
        "ARG BASE_IMAGE\n" + body + "FROM ${BASE_IMAGE}\n"
    )
    return load_plan(_plan(tmp_path, TITANARUM))


def test_an_arg_split_across_a_continuation_is_read_correctly(tmp_path: Path) -> None:
    """`ARG \\` + `JDK_BUILD_IMAGE` is ONE instruction declaring that arg.

    Line-by-line, the first line is an ARG with no name and the second is a
    bare word, so a correctly-declared build arg gets reported missing.
    """
    from blastbox.host.images import arg_problems

    plan = _base_dockerfile(tmp_path, "ARG \\\n    JDK_BUILD_IMAGE\n")
    problems = [p for p in arg_problems(plan, {}) if "`ARG JDK_BUILD_IMAGE`" in p]
    assert problems == [], problems


def test_a_continuation_line_is_not_mistaken_for_an_arg_instruction(
    tmp_path: Path,
) -> None:
    """The dangerous direction. A RUN continuation whose next line begins with
    the word ARG is not an ARG instruction; reading it as one reports a
    misspelled --build-arg as correctly declared, which is exactly the silent
    failure this function exists to catch."""
    from blastbox.host.images import arg_problems

    plan = _base_dockerfile(tmp_path, "RUN echo hello \\\n    ARG JDK_BUILD_IMAGE\n")
    problems = [p for p in arg_problems(plan, {}) if "`ARG JDK_BUILD_IMAGE`" in p]
    assert problems, "a continuation line was read as an ARG instruction"


def test_an_unreadable_dockerfile_is_reported_not_raised(tmp_path: Path) -> None:
    """This function's job is to REPORT problems with the plan."""
    from blastbox.host.images import arg_problems

    d = tmp_path / "deploy" / "docker"
    d.mkdir(parents=True)
    f = d / "Dockerfile.titanarum-base"
    f.write_text("ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n")
    f.chmod(0o000)
    plan = load_plan(_plan(tmp_path, TITANARUM))
    try:
        problems = arg_problems(plan, {})
    finally:
        f.chmod(0o644)
    assert any("cannot read" in p for p in problems), problems
