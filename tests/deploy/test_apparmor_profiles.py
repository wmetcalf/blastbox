"""Every AppArmor profile this repo ships must COMPILE.

A profile is data until a parser reads it, and the parser only runs on a host during
deployment -- so a syntax error here is discovered by an operator, at the moment they are
trying to fix something else. `apparmor_parser -Q` preprocesses and compiles without loading
(no root, no kernel change), which is exactly the half that can be wrong in a text file.

`blastbox-sandbox` is the child profile the backends attach to the detonated workload. Until
#160 the code demanded it by default and this directory did not contain it, so every host
reported `apparmor_missing` -- and once that became a real insecurity reason, a bare-metal
host had no selectable inner backend at all.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_PROFILE_DIR = Path(__file__).resolve().parents[2] / "deploy" / "apparmor"
_PROFILES = sorted(p for p in _PROFILE_DIR.glob("blastbox-*") if p.is_file())


def test_the_directory_is_not_empty() -> None:
    """Guards the glob itself: a rename that stops matching would otherwise turn every
    parametrised test below into zero tests, silently."""
    assert _PROFILES, f"no blastbox-* profiles found in {_PROFILE_DIR}"


def test_the_child_profile_is_shipped() -> None:
    """The one the code asks for BY DEFAULT (apparmor.DEFAULT_PROFILE)."""
    from blastbox.worker.sandbox.apparmor import DEFAULT_PROFILE

    assert (_PROFILE_DIR / DEFAULT_PROFILE).is_file(), (
        f"the backends attach {DEFAULT_PROFILE!r} by default and this repo does not ship it"
    )


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser not installed on this host")
@pytest.mark.parametrize("profile", _PROFILES, ids=lambda p: p.name)
def test_the_profile_compiles(profile: Path, tmp_path: Path) -> None:
    res = subprocess.run(
        ["apparmor_parser", "-Q", f"--cache-loc={tmp_path}", str(profile)],
        capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, f"{profile.name} does not compile:\n{res.stderr}"


@pytest.mark.parametrize("profile", _PROFILES, ids=lambda p: p.name)
def test_the_profile_declares_its_own_name(profile: Path) -> None:
    """`aa-exec -p <name>` and `profile_loaded(<name>)` both key on the NAME, so a file whose
    profile is declared under a different one loads fine and is then never found."""
    text = profile.read_text()
    assert f"profile {profile.name} " in text, (
        f"{profile.name} does not declare `profile {profile.name}`"
    )


def _aa_glob_to_regex(pattern: str) -> re.Pattern[str]:
    """One AppArmor path glob as a regex, with the distinction that matters.

    `*` does NOT cross a `/`; `**` does. That is the whole defect this guards: the first
    version of this profile wrote `deny /proc/*/mem`, which compiles to `/proc/[^/]+/mem` and
    therefore leaves `/proc/self/task/<tid>/mem` -- the same address-space write interface --
    to be allowed by the blanket rule. Confirmed against `apparmor_parser -D rule-exprs`,
    which prints exactly those two expansions; this translator exists so the test can assert
    on the PROFILE's own rules rather than on the parser's dump of every included
    abstraction (whose permission masks it cannot compare).
    """
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                out.append("[^\x00]*")        # crosses /
                i += 2
                continue
            out.append("[^/\x00]*")           # does not cross /
        elif c == "?":
            out.append("[^/\x00]")
        elif c == "{":
            j = pattern.index("}", i)
            out.append("(?:" + "|".join(re.escape(a) for a in pattern[i + 1:j].split(",")) + ")")
            i = j + 1
            continue
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z")


def _profile_denies(profile: Path) -> list[re.Pattern[str]]:
    """The profile's own `deny`/`audit deny` PATH rules, compiled."""
    rules = []
    for line in profile.read_text().splitlines():
        line = line.strip()
        m = re.match(r"^(?:audit\s+)?deny\s+(/\S+)\s+[a-z]+\s*,$", line)
        if m:
            rules.append(_aa_glob_to_regex(m.group(1)))
    assert rules, f"no deny path rules found in {profile.name}"
    return rules


@pytest.mark.parametrize("path", [
    "/proc/self/mem",
    "/proc/self/task/1/mem",                 # the one the first version of this profile missed
    "/proc/1/task/7/mem",
    "/proc/self/clear_refs",
    "/proc/self/task/1/clear_refs",
    "/proc/self/coredump_filter",
    "/proc/self/oom_score_adj",
    "/proc/self/uid_map",
    "/proc/self/gid_map",
    "/proc/self/attr/current",
    "/proc/self/attr/exec",
    "/proc/self/task/1/attr/exec",
    "/proc/sys/kernel/core_pattern",
    "/proc/sysrq-trigger",
])
def test_the_profile_denies_the_proc_surface_that_proc_rw_opens(path: str) -> None:
    """The reason this profile is not optional hardening -- and the reason this test looks at
    glob SEMANTICS rather than at the text.

    Attaching a profile is what makes the nsjail backend pass `--proc_rw`, and that flag makes
    these paths writable for the child. The previous version of this check asserted the literal
    string `deny /proc/*/mem` appeared in the file, which is true of a rule that denies nothing
    reachable: a child under that profile wrote 8 bytes into a PROT_READ page through
    /proc/self/task/1/mem and read them back. A profile that misses it is strictly worse than
    no profile, because no profile means no --proc_rw and a read-only /proc
    (claude-security lens, round 2 of #177).
    """
    denies = _profile_denies(_PROFILE_DIR / "blastbox-sandbox")
    assert any(rx.match(path) for rx in denies), f"the profile allows {path}"


@pytest.mark.parametrize("path", [
    "/proc/meminfo", "/proc/self/status", "/proc/self/maps", "/usr/bin/true",
    "/usr/lib/x86_64-linux-gnu/libc.so.6", "/tmp/work/input.bin",
])
def test_the_denies_do_not_swallow_what_the_workload_needs(path: str) -> None:
    """A deny wide enough to cover everything would satisfy the test above and break every
    job -- including the selector's own /usr/bin/true probe, which takes the whole backend
    down with it."""
    denies = _profile_denies(_PROFILE_DIR / "blastbox-sandbox")
    assert not any(rx.match(path) for rx in denies), f"the profile denies {path}"


def test_the_translator_itself_distinguishes_the_two_globs() -> None:
    """If this translator were wrong in the same direction as the bug, the tests above would
    pass for the same reason the original did."""
    one = _aa_glob_to_regex("/proc/*/mem")
    two = _aa_glob_to_regex("/proc/**/mem")
    assert one.match("/proc/self/mem") and not one.match("/proc/self/task/1/mem")
    assert two.match("/proc/self/mem") and two.match("/proc/self/task/1/mem")
    assert not two.match("/proc/self/memory")


def test_the_child_profile_denies_the_transition_and_the_debug_interfaces() -> None:
    """Not path rules, so they cannot be checked the same way: change_profile, ptrace and
    mount are operation rules."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    for needed in ("change_profile", "ptrace", "mount"):
        assert f"deny {needed}" in text or f"audit deny {needed}" in text, (
            f"blastbox-sandbox does not deny {needed}"
        )


def test_the_child_profile_permits_the_selector_probe() -> None:
    """`select_sandbox` smoketests each backend by running /usr/bin/true through it, with the
    profile attached. A child profile that denies the probe takes the backend down -- which is
    a real failure mode, diagnosed in detect.py, and not one the SHIPPED profile may have."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    assert "/** rwlkmix," in text, (
        "the shipped profile no longer permits the workload (and the selector probe) to exec"
    )


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser not installed on this host")
@pytest.mark.parametrize("allow_rule", ["network netlink raw,", "network inet stream,"])
def test_every_network_allow_in_the_profile_actually_survives_compilation(
        allow_rule: str, tmp_path: Path) -> None:
    """A deny can silently swallow an allow, and the text gives no hint.

    `raw` is a socket TYPE in AppArmor's network grammar, so `audit deny network raw,` denied
    SOCK_RAW in every family -- AF_NETLINK included, which is what glibc opens for
    getaddrinfo(AI_ADDRCONFIG), getifaddrs() and if_nameindex(). Compiling the profile with
    the `network netlink raw,` allow DELETED produced a byte-identical policy: the allow was
    dead, and every DNS lookup in the workload would have taken an audit denial while the
    profile appeared to permit netlink explicitly (claude-code-review lens, round 2 of #177).

    So: removing an allow must CHANGE the compiled policy. If it does not, that allow is
    decoration.
    """
    profile = _PROFILE_DIR / "blastbox-sandbox"
    assert allow_rule in profile.read_text(), f"{allow_rule!r} is no longer in the profile"

    stripped = tmp_path / "stripped"
    stripped.write_text("\n".join(
        ln for ln in profile.read_text().splitlines() if ln.strip() != allow_rule
    ) + "\n")

    def _policy(path: Path) -> bytes:
        res = subprocess.run(
            ["apparmor_parser", "-Q", "-S", f"--cache-loc={tmp_path / 'c'}", str(path)],
            capture_output=True, timeout=120,
        )
        assert res.returncode == 0, res.stderr.decode()
        return res.stdout

    assert _policy(profile) != _policy(stripped), (
        f"{allow_rule!r} compiles to nothing -- a deny rule is swallowing it"
    )


_MOUNT_CLASS = 0x7    # AA_CLASS_MOUNT: the policy DFA's first byte for mount/umount/pivot_root


def _policy_start_classes(text: str) -> list[set[int]]:
    """Per compiled POLICY DFA in `--dump=dfa-states` (one per profile, hat or child), the
    class bytes its start state has a transition for. The kernel mediates a class only if that
    transition exists (RULE_MEDIATES): without it, every operation of the class is allowed,
    whatever the rules say. File and xmatch DFAs are told apart by their start state: it
    transitions on path bytes ('/'), a policy DFA's on class bytes."""
    res = subprocess.run(
        ["apparmor_parser", "-Q", "-K", "--skip-cache", "--dump=dfa-states", "-S"],
        input=text.encode(), capture_output=True, timeout=120,
    )
    assert res.returncode == 0, res.stderr.decode()
    lines = res.stderr.decode().splitlines()
    starts = [i for i, ln in enumerate(lines) if "<== " in ln] + [len(lines)]
    policies: list[set[int]] = []
    for lo, hi in zip(starts, starts[1:]):
        section = lines[lo:hi]
        first = next((i for i, ln in enumerate(section) if ln.startswith("{1} perms")), None)
        if first is None:
            continue
        classes: set[int] = set()
        for ln in section[first + 1:]:
            if ln.startswith("{"):
                break
            m = re.search(r"\b0x([0-9a-fA-F]+) ->", ln)
            if m:
                classes.add(int(m.group(1), 16))
        if 0x2F not in classes:                  # not a file / xmatch DFA
            policies.append(classes)
    assert policies, "no policy DFA in the dump"
    return policies


def _mediates_mount(text: str) -> bool:
    return all(_MOUNT_CLASS in classes for classes in _policy_start_classes(text))


_PARSER = pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                             reason="apparmor_parser not installed on this host")


@_PARSER
def test_the_child_profile_mediates_the_mount_class() -> None:
    """A non-quiet umount deny that can match the EMPTY mountpoint -- bare `audit deny umount,`,
    or `umount *,` / `umount **,` -- clears the mount class's mediation marker, and the compiled
    policy then has no mount class at all: the kernel allows every mount, umount and
    pivot_root. The shipped profile was in that state on apparmor_parser 4.0.1; only its
    `audit deny capability sys_admin,` stood between a workload and mount. Measured live
    (kernel 7.0): with that capability deny replaced by an allow plus `mount, umount,` allows,
    the old profile let a confined process mount and umount; this one denies both (EACCES).
    The check is on the compiled DFA, so it catches every spelling."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    assert _mediates_mount(text), (
        "the compiled child profile does not mediate the mount class: a umount deny is matching "
        "the empty mountpoint -- spell it with a path (`audit deny umount /,` and "
        "`audit deny umount /**,`)"
    )


def _parser_has_the_marker_bug() -> bool:
    """apparmor_parser <= 4.0.x adds the class mediation markers as ordinary allows, so a deny
    matching the empty mountpoint wipes the mount one; >= 4.1 adds them at an internal priority
    above any rule ("a deny rule wiping these out could result in the dfa allowing stuff as
    unmediated"), so that spelling is harmless there."""
    probe = "abi <abi/3.0>,\nprofile bb-probe {\n  /tmp/bb-probe r,\n  audit deny umount,\n}\n"
    return not _mediates_mount(probe)


@_PARSER
@pytest.mark.parametrize("extra,mediated", [
    ("", True),
    ("  audit deny umount,", False),          # the old spelling
    ("  audit deny umount **,", False),       # matches the empty mountpoint too
    ("  umount,", True),                      # an ALLOW keeps the class mediated
])
def test_the_mediation_check_tells_the_spellings_apart(extra: str, mediated: bool) -> None:
    """The oracle above, pinned against the spellings it must distinguish. The unmediated cases
    are a property of the parser (<= 4.0.x), so they are checked only where it has the bug."""
    if not mediated and not _parser_has_the_marker_bug():
        pytest.skip("this apparmor_parser compiles mediation markers above any deny (>= 4.1)")
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text().replace(
        "  network netlink raw,", "  network netlink raw,\n" + extra if extra else
        "  network netlink raw,")
    assert _mediates_mount(text) is mediated


_CANONICAL_UMOUNT = ("audit deny umount /,", "audit deny umount /**,")


def _umount_rules_ok(text: str) -> bool:
    """A strict allowlist that does not try to tell comments from rules (the parser's lexer is
    stateful: `#` is a comment only at some token boundaries, and a list, escape, quote or
    open statement can carry it into a rule). Anywhere in the file, comments included, the
    keyword `umount` (or its synonym `unmount`) may appear ONLY in the two canonical denies,
    each alone on its line. Any other umount rule -- or prose naming the keyword -- must first
    be checked against the compiled DFA on a parser <= 4.0.x and then allowed here."""
    lines = [ln.strip() for ln in text.split("\n")]
    # `deny all,` implies a bare umount deny without naming the keyword (rule-shaped only, so
    # prose such as "would deny all SOCK_RAW" in a comment does not trip it).
    if any(re.fullmatch(r"(audit\s+|quiet\s+)*deny\s+all\s*,", ln) for ln in lines):
        return False
    # Every line naming the keyword must be exactly a canonical deny (a hat or child profile
    # may repeat them), each line naming it once; both canonical denies must be present.
    named = [ln for ln in lines if re.search(r"\b(?:umount|unmount)\b", ln, re.ASCII)]
    mentions = re.findall(r"\b(?:umount|unmount)\b", text, re.ASCII)
    return (all(ln in _CANONICAL_UMOUNT for ln in named) and len(mentions) == len(named)
            and all(rule in named for rule in _CANONICAL_UMOUNT))


def test_umount_denies_are_spelled_with_a_path() -> None:
    """The text-level tripwire, for hosts without apparmor_parser AND for parsers >= 4.1, where
    the compiled check cannot see the bug. It catches the ways a maintainer would plausibly
    reintroduce it; the AUTHORITY is the compiled check, which CI's sandbox job runs on Ubuntu
    24.04 (apparmor_parser 4.0.x, which has the bug). The bug: a umount deny that can match
    the empty mountpoint unmediates the mount class on apparmor_parser <= 4.0.x."""
    assert _umount_rules_ok((_PROFILE_DIR / "blastbox-sandbox").read_text()), (
        f"blastbox-sandbox may name the umount keyword only on lines that are exactly one of "
        f"{_CANONICAL_UMOUNT} (comments count too), and may not hold a `deny all,` rule: check "
        "any other umount rule against the compiled DFA (test_the_child_profile_mediates_the_mount_class on a "
        "<= 4.0.x parser) and extend _CANONICAL_UMOUNT deliberately"
    )


@pytest.mark.parametrize("extra", [
    "  audit deny umount,",
    "  audit deny unmount,",
    "  audit deny umount {/a,**},",
    "  audit deny umount fstype= /x,",
    '  "/tmp/#x" r, audit deny umount,',
    '  "/mnt/x(y" r,\n  audit deny umount,',
    "  audit deny pivot_root, audit deny umount /,",
    "  audit deny\n    umount,",
    "  umount,",
    "  /tmp/#x r, audit deny umount,",
    '  "/tmp/a\\"#" r, audit deny umount,',
    '  "/tmp/a\n#" r, audit deny umount,',
    "  /tmp/a\x0c# r, audit deny umount,",
    "  change_profile ->\n#x, audit deny umount,",
    "  change_profile ->\n\x0c#x, audit deny umount,",
    "  #include if exists <local/blastbox-sandbox> audit deny umount,",
    "  #include <abstractions/base>audit deny umount,",
    "  audit deny mount fstype=(proc,\n  # sysfs), audit deny umount,",
    "  audit deny mount fstype=a\\,\n  # -> /m/, audit deny umount,",
    "  profile helper {\n    deny all,\n  }",
    "  audit deny umount\u00b2,",
])
def test_the_text_guard_rejects_any_other_umount_rule(extra: str) -> None:
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text().replace(
        "  network netlink raw,", "  network netlink raw,\n" + extra)
    assert not _umount_rules_ok(text)


def test_the_text_guard_counts_comments_too() -> None:
    """A '#' line is not always a comment to the parser, so the guard does not exempt any."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text() + "\n# audit deny umount,\n"
    assert not _umount_rules_ok(text)


def test_the_child_profile_loads_on_the_oldest_supported_apparmor() -> None:
    """The child profile must compile on an AppArmor 3.x parser, and only it.

    `blastbox-{bwrap,nsjail,runsc}` declare `abi <abi/4.0>` because they need the `userns` rule,
    which exists only there. This profile needs nothing newer than 3.0 -- and an AppArmor 3.x
    host (Ubuntu 22.04 LTS) has no `/etc/apparmor.d/abi/4.0`, so pinning 4.0 would make the ONE
    profile a host must load for any inner backend to be `secure` fail to compile on a supported
    LTS (glm, round 6 of #177).
    """
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    assert "abi <abi/3.0>," in text, "the child profile pins an abi newer than 3.0"
    # RULES, not prose: the file's comments discuss userns (explaining why the OTHER profiles
    # need abi 4.0), and a substring check over the whole text would read those as a rule.
    rules = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    assert not any("userns" in r for r in rules), (
        "a userns rule needs abi 4.0; if this profile now needs one, the abi pin must change "
        "with it and the LTS compatibility note above is no longer true"
    )


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser not installed on this host")
def test_the_per_binary_profiles_still_declare_the_abi_their_rules_need(tmp_path: Path) -> None:
    """The converse: dropping THEIR abi to 3.0 would silently break the `userns` grant that is
    the whole reason those profiles exist."""
    for name in ("blastbox-bwrap", "blastbox-nsjail"):
        text = (_PROFILE_DIR / name).read_text()
        assert "userns" in text, f"{name} no longer grants userns -- why does it exist?"
        assert "abi <abi/4.0>," in text, f"{name} needs abi 4.0 for its userns rule"


def test_the_snake_case_rule_is_actually_enforced() -> None:
    """AGENTS.md mandates snake_case and, until #168, nothing checked it -- the rule existed only
    as prose a reviewer had to remember.

    Pinned as a test rather than trusted to stay in pyproject.toml, because a `select` list is
    exactly the kind of thing a later edit drops while tidying. The test exemption is asserted
    too: the shouted words in test names are deliberate emphasis, and silently enforcing N802
    there would rename ~70 tests to satisfy a linter by deleting information.
    """
    import tomllib

    root = Path(__file__).resolve().parents[2]
    with (root / "pyproject.toml").open("rb") as fh:
        cfg = tomllib.load(fh)
    selected = cfg["tool"]["ruff"]["lint"].get("extend-select", [])
    assert "N802" in selected, "function names are no longer checked for snake_case"
    assert "N806" in selected, "variable names are no longer checked for snake_case"

    ignored = cfg["tool"]["ruff"]["lint"]["per-file-ignores"]["tests/**"]
    assert "N802" in ignored, "the deliberate emphasis in test names lost its exemption"


@_PARSER
def test_the_oracle_reads_the_policy_dfa_of_a_profile_with_an_attachment() -> None:
    """An attachment adds an xmatch DFA in front of the file DFA; the policy DFA is still last."""
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text().replace(
        "profile blastbox-sandbox flags=", "profile blastbox-sandbox /opt/detonate/run flags=")
    assert _mediates_mount(text)


@_PARSER
def test_the_oracle_checks_every_profile_in_the_file() -> None:
    """A child, hat or second profile adds its own policy DFA; the parent's must still count."""
    bare = (_PROFILE_DIR / "blastbox-sandbox").read_text().replace(
        "  audit deny umount /,\n  audit deny umount /**,", "  audit deny umount,")
    if not _parser_has_the_marker_bug():
        pytest.skip("this apparmor_parser compiles mediation markers above any deny (>= 4.1)")
    child = bare.rstrip().rstrip("}") + "  profile helper {\n    /usr/bin/true rix,\n  }\n}\n"
    assert not _mediates_mount(bare) and not _mediates_mount(child)
    # and the converse: a clean parent with a bad child is not mediated either
    shipped = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    bad_child = shipped.rstrip().rstrip("}") + (
        "  profile helper {\n    /usr/bin/true rix,\n    audit deny umount,\n  }\n}\n")
    assert _mediates_mount(shipped) and not _mediates_mount(bad_child)



def test_the_text_guard_allows_a_hat_repeating_the_canonical_denies() -> None:
    shipped = (_PROFILE_DIR / "blastbox-sandbox").read_text()
    hat = shipped.rstrip().rstrip("}") + (
        "  ^detonate {\n    /** rwlkmix,\n    audit deny mount,\n    audit deny umount /,\n"
        "    audit deny umount /**,\n  }\n}\n")
    assert _umount_rules_ok(hat)


def test_the_text_guard_ignores_deny_all_in_prose() -> None:
    text = (_PROFILE_DIR / "blastbox-sandbox").read_text().replace(
        "denies SOCK_RAW in EVERY family", "would deny all SOCK_RAW, in EVERY family")
    assert _umount_rules_ok(text)
