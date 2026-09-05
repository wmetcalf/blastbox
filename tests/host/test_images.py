"""The declared image chain must be trustworthy before anything is built.

Every failure encoded here happened for real while porting three engines'
hand-written build scripts.
"""
from __future__ import annotations

from pathlib import Path

import pytest

def _sized(path: Path, nbytes: int) -> Path:
    """A SPARSE file of exactly ``nbytes``.

    These tests only need the logical length that `stat` reports. Writing the
    bytes allocated the whole thing in RAM and then wrote it to disk -- a 5 GiB
    buffer in one case, which can OOM a CI runner outright.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.truncate(nbytes)
    return path

from blastbox.host.images import (
    SPEC_NAME,
    Plan,
    PlanError,
    _is_secret,
    build_command,
    describe,
    load_plan,
    missing_dockerfiles,
    resolve_chain,
    unresolved_names,
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


def test_source_repo_defaults_to_the_context_not_the_plan_root(tmp_path: Path) -> None:
    """An image built from another tree is stamped with THAT tree's revision.

    Defaulting to the plan root would record a commit that does not contain the
    Dockerfile which built the image — the un-rebuildable state this module
    exists to prevent, re-created by the tool meant to prevent it.
    """
    from blastbox.host.images import source_repo_path

    text = TITANARUM + (
        '\n[[image]]\nname = "titanarum-warm"\n'
        'dockerfile = "deploy/gvisor/Dockerfile.titanarum"\n'
        'base = "titanarum-base"\ncontext = "$BLASTBOX_SRC"\n'
    )
    plan = load_plan(_plan(tmp_path, text))
    env = {"BLASTBOX_SRC": "/srv/blastbox"}
    warm = next(i for i in plan.images if i.name == "titanarum-warm")
    home = next(i for i in plan.images if i.name == "titanarum-base")
    assert source_repo_path(plan, warm, env) == Path("/srv/blastbox")
    assert source_repo_path(plan, home, env) == plan.root


def test_an_explicit_source_repo_overrides_the_context(tmp_path: Path) -> None:
    """Context and source tree are not always the same: docker can be handed a
    build context that is not the repo the Dockerfile is versioned in."""
    from blastbox.host.images import source_repo_path

    text = TITANARUM.replace(
        'dockerfile = "deploy/docker/Dockerfile.titanarum-base"',
        'dockerfile = "deploy/docker/Dockerfile.titanarum-base"\n'
        'source_repo = "/srv/other"',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    assert source_repo_path(plan, plan.images[0], {}) == Path("/srv/other")


def test_load_plan_accepts_the_spec_file_itself(tmp_path: Path) -> None:
    """Appending the filename unconditionally produced
    `blastbox-images.toml/blastbox-images.toml` and a NotADirectoryError naming
    a path the caller never wrote."""
    spec = _plan(tmp_path, TITANARUM) / SPEC_NAME
    plan = load_plan(spec)
    assert plan.engine == "titanarum"
    assert plan.root == spec.parent


def test_load_plan_still_accepts_the_directory(tmp_path: Path) -> None:
    d = _plan(tmp_path, TITANARUM)
    assert load_plan(d).root == d


def test_build_command_resolves_a_dockerfile_from_another_tree(tmp_path: Path) -> None:
    """docker resolves `-f` against the CWD, not the build context.

    Passing it raw looks for the consumer repo's copy of the path — missing in
    the ordinary case, and if a file of that name does exist there, it silently
    builds the WRONG Dockerfile under the intended tag.
    """
    from blastbox.host.images import build_command

    text = TITANARUM + (
        '\n[[image]]\nname = "titanarum-warm"\n'
        'dockerfile = "deploy/gvisor/Dockerfile.titanarum"\n'
        'base = "titanarum-base"\ncontext = "$BLASTBOX_SRC"\n'
    )
    plan = load_plan(_plan(tmp_path, text))
    env = {"BLASTBOX_SRC": "/srv/blastbox"}
    warm = next(i for i in plan.images if i.name == "titanarum-warm")
    argv = build_command(warm, "t1", [], "titanarum-base:t1", env, plan)
    assert argv[argv.index("-f") + 1] == "/srv/blastbox/deploy/gvisor/Dockerfile.titanarum"
    assert argv[-1] == "/srv/blastbox"


def test_build_command_resolves_a_same_tree_dockerfile_too(tmp_path: Path) -> None:
    """Resolved in the ordinary case as well, so the argv does not depend on
    which directory it is run from."""
    from blastbox.host.images import build_command

    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(plan.images[0], "t1", [], "u:1", {}, plan)
    assert argv[argv.index("-f") + 1] == str(
        plan.root / "deploy/docker/Dockerfile.titanarum-base"
    )


def test_build_arg_values_are_expanded(tmp_path: Path) -> None:
    """A spec that had to write the blastbox version as a literal would carry a
    second copy of the pyproject pin, and the two would drift — the very
    failure this module exists to catch, one level up."""
    from blastbox.host.images import build_command

    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { BLASTBOX_VERSION = "$BLASTBOX_VERSION", JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    argv = build_command(plan.images[0], "t1", [], "u:1", {"BLASTBOX_VERSION": "0.1.34"}, plan)
    assert "BLASTBOX_VERSION=0.1.34" in argv


def test_an_unresolved_build_arg_is_marked_in_the_dry_run(tmp_path: Path) -> None:
    """An operator reading `=$BLASTBOX_VERSION` should see a hole, not a value
    docker will somehow work out — the same standard destinations are held to."""
    from blastbox.host.images import describe

    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { BLASTBOX_VERSION = "$BLASTBOX_VERSION", JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    out = describe(plan, "t1", {})
    assert "BLASTBOX_VERSION=$BLASTBOX_VERSION [UNRESOLVED]" in out, out
    ok = describe(plan, "t1", {"BLASTBOX_VERSION": "0.1.34"})
    # Scoped to the build-arg line: the rootfs DESTINATION is legitimately
    # unresolved under this env, and asserting on the whole output would pass
    # or fail for that instead.
    arg_line = next(ln for ln in ok.splitlines() if "BLASTBOX_VERSION" in ln)
    assert "BLASTBOX_VERSION=0.1.34" in arg_line and "UNRESOLVED" not in arg_line


def test_a_default_may_itself_contain_a_variable(tmp_path: Path) -> None:
    """`${TITANARUM_FC_DIR:-$HOME/titanarum-bb-fc}` is ordinary shell, and it is
    what the engine's compose files and its old export script already wrote.

    One substitution pass put the default in verbatim and left `$HOME` in the
    result, which then read as an unresolved destination and refused a perfectly
    good plan.
    """
    text = TITANARUM.replace(
        'dest = "$TITANARUM_FC_DIR/titanarum-rootfs.ext4"',
        'dest = "${TITANARUM_FC_DIR:-$HOME/titanarum-bb-fc}/titanarum-rootfs.ext4"',
    )
    plan = load_plan(_plan(tmp_path, text))
    rf = next(r for r in plan.rootfs if r.kind == "ext4")
    assert rf.resolved_dest({"HOME": "/home/coz"}) == (
        "/home/coz/titanarum-bb-fc/titanarum-rootfs.ext4"
    )
    # and the variable still wins when it is set
    assert rf.resolved_dest({"HOME": "/home/coz", "TITANARUM_FC_DIR": "/srv/fc"}) == (
        "/srv/fc/titanarum-rootfs.ext4"
    )


def test_a_substituted_value_is_not_re_expanded(tmp_path: Path) -> None:
    """The shell does not re-read a variable's VALUE as a template, and neither
    does this.

    It matters for more than fidelity: this function also builds docker
    `--build-arg`s, so re-expanding values would rewrite a literal `$` inside a
    token or a password into whatever variable happened to share its name.
    """
    from blastbox.host.images import _expand

    env = {"TOKEN": "abc$HOME", "HOME": "/home/coz"}
    assert _expand("$TOKEN", env) == "abc$HOME"


def test_expansion_terminates_on_a_self_referential_default(tmp_path: Path) -> None:
    """`${A:-$A}` terminates: the inner `$A` is unset with no default of its
    own, so it is left visible.

    It terminates because values are never re-expanded, NOT because of the
    depth bound — removing that bound leaves this passing. The bound is a
    backstop for pathological nesting, and this test does not cover it.
    """
    from blastbox.host.images import _expand

    assert _expand("${A:-$A}/f", {}) == "$A/f"


@pytest.mark.parametrize(
    ("text", "env", "want"),
    [
        # the finding: a regex `[^}]*` stops at the FIRST `}` and hands the
        # recursion `${B:-/tmp`, leaving a good destination reported unresolved
        ("${A:-${B:-/tmp}}/x", {"B": "/srv"}, "/srv/x"),
        ("${A:-${B:-/tmp}}/x", {}, "/tmp/x"),
        ("${A:-${B:-/tmp}}/x", {"A": "/opt"}, "/opt/x"),
        # three deep, because two could pass by accident
        ("${A:-${B:-${C:-/tmp}}}/x", {"C": "/c"}, "/c/x"),
        # unbalanced braces are literal text, not a half-parsed expansion
        ("${A:-x/f", {}, "${A:-x/f"),
        # a name that is not an identifier is left alone
        ("${not-a-name}/f", {}, "${not-a-name}/f"),
    ],
)
def test_nested_braced_defaults_are_parsed_by_balance(
    text: str, env: dict[str, str], want: str
) -> None:
    """A default can hold a braced default of its own, and a regex cannot
    balance braces."""
    from blastbox.host.images import _expand

    assert _expand(text, env) == want


def test_the_dry_run_shows_the_resolved_rootfs_size(tmp_path: Path) -> None:
    """A dry run printing `${ROOTFS_MIB:-3072} MiB` has not said how big the
    filesystem will be, which is the one question it exists to answer — the
    same standard destinations and build args are already held to."""
    from blastbox.host.images import describe

    text = TITANARUM.replace("size_mib = 3072", 'size_mib = "${ROOTFS_MIB:-3072}"')
    plan = load_plan(_plan(tmp_path, text))
    assert " 3072 MiB" in describe(plan, "t1", {})
    assert " 4096 MiB" in describe(plan, "t1", {"ROOTFS_MIB": "4096"})
    assert "ROOTFS_MIB" not in describe(plan, "t1", {})


def test_the_dry_run_reports_the_size_it_will_actually_build(
    tmp_path: Path, monkeypatch
) -> None:
    """A defaulted size keeps whatever is already in place, so printing the
    declaration would name a filesystem the run will not build — in exactly the
    scenario preservation exists for."""
    from blastbox.host.images import describe

    dest = tmp_path / "fc"
    dest.mkdir()
    _sized(dest / "titanarum-rootfs.ext4", 5000 * 1024 * 1024)
    env = {"TITANARUM_FC_DIR": str(dest)}
    text = TITANARUM.replace("size_mib = 3072", 'size_mib = "${ROOTFS_MIB:-3072}"')
    plan = load_plan(_plan(tmp_path, text))
    out = describe(plan, "t1", env)
    assert "5000 MiB (keeping the existing 5000, declared 3072)" in out, out
    # with an override the operator's number is what runs, and is what is shown
    out2 = describe(plan, "t1", {**env, "ROOTFS_MIB": "6000"})
    assert " 6000 MiB" in out2 and "keeping" not in out2, out2


def test_a_literal_brace_in_a_default_is_not_a_nesting_level(tmp_path: Path) -> None:
    """`${DIR:-/tmp/{scratch}/cache` is valid shell whose `{` is literal.

    Counting it as a nesting level left the expression unterminated, so the
    destination or build arg using it was refused outright.
    """
    from blastbox.host.images import _expand

    assert _expand("${DIR:-/tmp/{scratch}/cache", {"DIR": "/srv"}) == "/srv/cache"
    assert _expand("${DIR:-/tmp/{scratch}/cache", {}) == "/tmp/{scratch/cache"
    # a genuine nested expansion still works
    assert _expand("${A:-${B:-/tmp}}/x", {"B": "/srv"}) == "/srv/x"


def test_a_literal_dollar_in_a_value_is_not_reported_unresolved(tmp_path: Path) -> None:
    """Scanning the RESULT for `$` cannot tell an unset placeholder from a
    literal dollar in data — and a token containing one was then reported
    unresolved and aborted the build, turning corruption into a hard failure.
    """
    from blastbox.host.images import unresolved_build_args

    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { TOKEN = "$SECRET", JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    env = {"SECRET": "abc$HOME", "JDK_BUILD_IMAGE": "x", "ZXING_BUILD_IMAGE": "y"}
    assert unresolved_build_args(plan, env) == []
    # a genuinely unset variable is still reported, by NAME
    problems = unresolved_build_args(plan, {})
    assert problems and "SECRET" in problems[0]


def test_a_boolean_build_arg_keeps_tomls_spelling(tmp_path: Path) -> None:
    """`str(False)` hands docker `False`; a Dockerfile comparing against
    `false` then sees something else. Docker passes these verbatim."""
    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { FEATURE = false, JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    assert plan.images[0].build_args["FEATURE"] == "false"


def test_a_non_utf8_plan_is_a_plan_error(tmp_path: Path) -> None:
    """UnicodeDecodeError is neither OSError nor TOMLDecodeError, so it escaped
    to the CLI as a traceback instead of the normal validation message."""
    d = tmp_path / "repo"
    d.mkdir(parents=True)
    (d / SPEC_NAME).write_bytes(b'[engine]\nname = "\xff\xfe"\n')
    with pytest.raises(PlanError) as e:
        load_plan(d)
    assert "UTF-8" in str(e.value)


def test_destinations_that_normalise_to_one_path_collide(tmp_path: Path, monkeypatch) -> None:
    """`/srv/images/rootfs` and `/srv/images/./rootfs` are the same artifact and
    were two different dictionary keys, so the second silently overwrote the
    first while the dry run reported success."""
    monkeypatch.setenv("TITANARUM_FC_DIR", "/srv/images")
    monkeypatch.setenv("OTHER", "/srv/images/.")
    extra = (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "titanarum-base"\n'
        'dest = "$OTHER/titanarum-rootfs.ext4"\nsize_mib = 512\n'
    )
    with pytest.raises(PlanError) as e:
        load_plan(_plan(tmp_path, TITANARUM + extra))
    assert "would overwrite" in str(e.value)


def test_an_over_long_upstream_tag_is_refused(tmp_path: Path) -> None:
    """docker's grammar caps a tag at 128, so the dry run was reporting a plan
    the build would then reject on its own base."""
    long_tag = "a" * 129
    text = TITANARUM.replace('base = "eclipse-temurin:25-jre"', f'base = "ubuntu:{long_tag}"', 1)
    with pytest.raises(PlanError):
        load_plan(_plan(tmp_path, text))
    ok = TITANARUM.replace('base = "eclipse-temurin:25-jre"', f'base = "ubuntu:{"a" * 128}"', 1)
    assert load_plan(_plan(tmp_path, ok))


def test_a_relative_context_resolves_against_the_plan_root(tmp_path: Path) -> None:
    """docker resolves a relative context against the CALLER's directory, so
    `COPY` reads from the wrong repository — or finds nothing."""
    from blastbox.host.images import build_command

    plan = load_plan(_plan(tmp_path, TITANARUM))
    argv = build_command(plan.images[0], "t1", [], "u:1", {}, plan)
    assert argv[-1] == str(plan.root), argv[-1]


def test_an_all_numeric_tag_does_not_slip_past_the_length_bound(tmp_path: Path) -> None:
    """`ubuntu:<129 digits>` was consumed by the optional PORT branch, so the
    tag bound never saw it — the dry run called the plan runnable and the build
    then rejected its own base."""
    long_numeric = "1" * 129
    text = TITANARUM.replace(
        'base = "eclipse-temurin:25-jre"', f'base = "ubuntu:{long_numeric}"', 1
    )
    with pytest.raises(PlanError):
        load_plan(_plan(tmp_path, text))
    # a real registry port, which is what that branch exists for, still works
    ok = TITANARUM.replace(
        'base = "eclipse-temurin:25-jre"', 'base = "reg.example.io:5000/ubuntu:24.04"', 1
    )
    assert load_plan(_plan(tmp_path, ok))


def test_an_unbalanced_expansion_is_reported(tmp_path: Path) -> None:
    """`${SECRET` with no closing brace: `_expand` leaves it verbatim, so
    skipping it reported no problem and handed the literal placeholder to
    docker — which the older result-based check at least refused."""
    from blastbox.host.images import unresolved_build_args

    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { BROKEN = "${SECRET", JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    problems = unresolved_build_args(
        plan, {"JDK_BUILD_IMAGE": "x", "ZXING_BUILD_IMAGE": "y", "SECRET": "s"}
    )
    assert problems and "BROKEN" in problems[0], problems


def test_a_symlinked_parent_is_not_a_false_collision(tmp_path: Path, monkeypatch) -> None:
    """`normpath` collapses `..` lexically, so with `/base/link -> /other/child`
    it reads `/base/link/../rootfs` as `/base/rootfs` and calls two genuinely
    distinct artifacts a collision."""
    other = tmp_path / "other" / "child"
    other.mkdir(parents=True)
    base = tmp_path / "base"
    base.mkdir()
    (base / "link").symlink_to(other)
    monkeypatch.setenv("TITANARUM_FC_DIR", str(base))
    monkeypatch.setenv("OTHER", f"{base}/link/..")
    extra = (
        '\n[[rootfs]]\nkind = "ext4"\nimage = "titanarum-base"\n'
        'dest = "$OTHER/titanarum-rootfs.ext4"\nsize_mib = 512\n'
    )
    # base/…/rootfs.ext4 vs other/…/rootfs.ext4 are different files, so the
    # plan must LOAD; the lexical comparison called them a collision.
    plan = load_plan(_plan(tmp_path, TITANARUM + extra))
    dests = {r.resolved_dest() for r in plan.rootfs if r.kind == "ext4"}
    assert len(dests) == 2, dests


def test_a_secret_build_argument_is_not_printed(tmp_path: Path) -> None:
    """The plan holds a variable REFERENCE; describe() resolved it and printed
    the value, so a token reached terminal history and CI logs even though the
    spec never contained it."""
    from blastbox.host.images import describe

    text = TITANARUM.replace(
        'build_args = { JDK_BUILD_IMAGE',
        'build_args = { REGISTRY_TOKEN = "$TOK", JDK_BUILD_IMAGE',
        1,
    )
    plan = load_plan(_plan(tmp_path, text))
    out = describe(plan, "t1", {"TOK": "hunter2-super-secret"})
    assert "hunter2-super-secret" not in out, out
    assert "REGISTRY_TOKEN=<redacted>" in out, out
    # a non-secret name is still shown, because that is what makes a dry run useful
    assert "JDK_BUILD_IMAGE=eclipse-temurin:25-jdk" in out



@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_PAT",
        "SSH_PRIVATE_KEY",
        "REGISTRY_PASS",
        "DEPLOY_KEY",
        "NPM_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "DB_PASSPHRASE",
    ],
)
def test_conventional_credential_names_are_redacted(name: str) -> None:
    """`describe()` prints before every dry run AND every real build.

    A value that reaches it reaches terminal scrollback and CI logs, so the
    names operators actually use for credentials have to be covered -- none of
    these carried a denylisted substring, and all three of PAT, PRIVATE_KEY and
    PASS were printed in full.
    """
    assert _is_secret(name), name


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "PATCH_LEVEL",
        "COMPATIBILITY",
        "CACHE_KEY",
        "BLASTBOX_VERSION",
        "JDK_BUILD_IMAGE",
        "BUILD_PASSTHROUGH",
    ],
)
def test_ordinary_build_args_are_still_shown(name: str) -> None:
    """Redaction has a cost: a hidden value is one an operator cannot check.

    `PAT` is matched as a whole segment precisely so `PATH`, `PATCH_LEVEL` and
    `COMPATIBILITY` stay readable, and bare `KEY` needs a qualifier so
    `CACHE_KEY` does too.
    """
    assert not _is_secret(name), name


def test_a_secret_value_is_not_printed_by_describe(tmp_path: Path) -> None:
    """End to end, since that is where the leak would happen."""
    plan_file = tmp_path / "blastbox-images.toml"
    plan_file.write_text(
        '[engine]\nname = "demo"\n\n[[image]]\nname = "demo"\nbase = "debian:12"\n'
        'dockerfile = "Dockerfile"\nbuild_args = { GITHUB_PAT = "$GITHUB_PAT" }\n'
    )
    plan = load_plan(plan_file)
    text = describe(plan, "t1", {"GITHUB_PAT": "ghp_reallysecretvalue"})
    assert "ghp_reallysecretvalue" not in text
    assert "GITHUB_PAT" in text


@pytest.mark.parametrize("expr", ["${not-a-name}", "${A:+fallback}", "${1FOO}"])
def test_a_balanced_but_unsupported_expansion_is_reported(expr: str) -> None:
    """Balanced braces are not the same as an expansion we can perform.

    `_expand` keeps these verbatim, so staying silent handed docker the literal
    placeholder while pre-build validation reported no problem at all.
    """
    assert unresolved_names(expr, {}) == [expr]


def test_a_supported_expansion_is_still_not_reported() -> None:
    """The new report must not fire on the forms that do resolve."""
    assert unresolved_names("${DIR:-/tmp}", {"DIR": "/srv"}) == []
    assert unresolved_names("${DIR:-/tmp}", {}) == []
    assert unresolved_names("$SET", {"SET": "x"}) == []


def test_a_destination_containing_a_literal_dollar_is_not_called_unresolved(
    tmp_path: Path,
) -> None:
    """The dry run must agree with the run it previews.

    `describe()` judged the destination by looking for `$` in the RESULT, so a
    directory whose expansion legitimately contains one was reported unresolved
    while the real export considered it fine.
    """
    plan_file = tmp_path / "blastbox-images.toml"
    plan_file.write_text(
        '[engine]\nname = "demo"\n\n[[image]]\nname = "demo"\nbase = "debian:12"\n'
        'dockerfile = "Dockerfile"\n\n'
        '[[rootfs]]\nkind = "dir"\nimage = "demo"\ndest = "$ODD/rootfs"\n'
    )
    plan = load_plan(plan_file)
    text = describe(plan, "t1", {"ODD": "/srv/we$rd"})
    assert "/srv/we$rd/rootfs" in text
    assert "UNRESOLVED" not in text


def test_a_missing_dockerfile_names_an_unset_context_variable(tmp_path):
    """"My repo lost these files" is the wrong conclusion to invite.

    The chains that build from blastbox's own deploy/ declare
    `context = "$BLASTBOX_SRC"`. With it unset EVERY one of their Dockerfiles
    reports as missing, and the operator goes looking in the wrong repository.
    `unresolved_destinations` already names its variables; this is the same
    courtesy on the path reached first.
    """
    from blastbox.host.images import load_plan, missing_dockerfiles

    (tmp_path / "blastbox-images.toml").write_text(
        '[engine]\nname = "demo"\n\n'
        '[[image]]\nname = "demo"\ndockerfile = "deploy/Dockerfile.demo"\n'
        'context = "$BLASTBOX_SRC"\nbase = "python:3.12-slim"\n'
    )
    plan = load_plan(tmp_path)

    unset = missing_dockerfiles(plan, env={})
    assert unset, "an unset context makes the Dockerfile unfindable"
    assert "BLASTBOX_SRC is unset" in unset[0], unset

    # Set but genuinely absent: the ordinary message, not the variable one.
    absent = missing_dockerfiles(plan, env={"BLASTBOX_SRC": str(tmp_path / "elsewhere")})
    assert absent, "the file is still missing"
    assert "is unset" not in absent[0], absent


def test_a_present_dockerfile_under_a_set_context_is_not_reported(tmp_path):
    """The control: with the variable set and the file there, nothing is missing."""
    from blastbox.host.images import load_plan, missing_dockerfiles

    src = tmp_path / "bbsrc" / "deploy"
    src.mkdir(parents=True)
    (src / "Dockerfile.demo").write_text("FROM python:3.12-slim\n")
    (tmp_path / "blastbox-images.toml").write_text(
        '[engine]\nname = "demo"\n\n'
        '[[image]]\nname = "demo"\ndockerfile = "deploy/Dockerfile.demo"\n'
        'context = "$BLASTBOX_SRC"\nbase = "python:3.12-slim"\n'
    )
    plan = load_plan(tmp_path)
    assert missing_dockerfiles(plan, env={"BLASTBOX_SRC": str(tmp_path / "bbsrc")}) == []


def test_a_context_value_containing_a_dollar_is_not_an_unset_variable(tmp_path):
    """Asked of the TEMPLATE, never the expanded result.

    A directory whose NAME holds a dollar -- `/srv/$stage/src` is a legal path --
    would otherwise be reported as an unset variable, sending the operator to
    fix an environment that is already correct. `unresolved_destinations`
    documents this same distinction.
    """
    from blastbox.host.images import load_plan, missing_dockerfiles

    weird = tmp_path / "srv" / "$stage" / "bbsrc"
    (weird / "deploy").mkdir(parents=True)
    (weird / "deploy" / "Dockerfile.demo").write_text("FROM python:3.12-slim\n")
    (tmp_path / "blastbox-images.toml").write_text(
        '[engine]\nname = "demo"\n\n'
        '[[image]]\nname = "demo"\ndockerfile = "deploy/Dockerfile.demo"\n'
        'context = "$BLASTBOX_SRC"\nbase = "python:3.12-slim"\n'
    )
    plan = load_plan(tmp_path)
    # The file IS there under that context; nothing may be reported.
    assert missing_dockerfiles(plan, env={"BLASTBOX_SRC": str(weird)}) == []

    # And when it is genuinely absent, the report must not blame `$stage`.
    (weird / "deploy" / "Dockerfile.demo").unlink()
    reported = missing_dockerfiles(plan, env={"BLASTBOX_SRC": str(weird)})
    assert reported and "is unset" not in reported[0], reported
