""".NET assemblies as C#: ILSpy's command-line front end (``ilspycmd``) over the sample and the .NET
stages the resource scan recovers, reduced to the code that says what the program does.

Ghidra reads CIL poorly, and the stages ``dotnet_resources`` recovers from hidden resources were
never read at all. ``ilspycmd`` (ICSharpCode.Decompiler) turns IL + metadata back into C#; the
assembly is read, never run. It runs out of process under the pinned .NET runtime
(``/opt/dotnet/dotnet /opt/ilspycmd/ilspycmd.dll``: no SDK, no tool install, no network):

* whole-file mode to stdout (``ilspycmd <file>``), not project mode (``-p -o``): the same C#
  in the same time on the samples measured, but project mode also writes every embedded resource
  (the hidden payloads) to disk. stdout is capped while reading (``MAX_SOURCE_BYTES``); a capped
  or timed-out run keeps the C# read so far (``status`` says which);
* ``-lv CSharp7_3``: no file-scoped namespaces or raw string literals, so ILSpy's output is laid out
  one declaration per line, indented with one tab per nesting level, with every string literal on
  one line. :func:`parse` relies on exactly that layout (it is not a C# parser);
* ``ulimit -v`` caps the address space, ``ulimit -f`` any file it might write, the GC heap is hard
  limited, the process group is killed on timeout. ``HOME``/``TMPDIR`` are the job's, diagnostics
  (IPC sockets, perf maps) are off, globalization is invariant (no ICU);
* the entry point comes from the CLI header (``EntryPointToken``, read here from the PE headers);
  a second, short run decompiles that one method (``-m <token>``) and its text names the member.

:func:`digest` is the bounded evidence for the model: an outline of the types and members and
whole-method excerpts, entry point first, then ranked by what they reference (``SIGNALS``, a small
table: resource loading, decryption, ``Assembly.Load``/``Invoke``, P/Invoke, process creation,
persistence, network/C2, credential and wallet paths, keylogging/clipboard/screen capture,
anti-analysis, WMI). Compiler noise (designer ``InitializeComponent``, resource/settings designer
classes, compiler-generated types, attributes) goes last. Every name and line is
attacker-controlled: control and format characters are escaped, names, lines and string literals
capped. Obfuscated names stay as they are.
"""

from __future__ import annotations

import json
import re
import struct
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from blastbox.engines.rea.runner import RunFn, bounded_run

ILSPY_VERSION = "11.1.0.9782"
DOTNET = "/opt/dotnet/dotnet"
ILSPYCMD = "/opt/ilspycmd/ilspycmd.dll"
TOOL = f"ilspy {ILSPY_VERSION}"

MAX_SOURCE_BYTES = 48 * 1024 * 1024  # C# read from stdout; past it the run is killed (too_large)
MAX_KB = 6 * 1024 * 1024  # ulimit -v: the runtime reserves address space well past its heap
GC_HEAP_LIMIT = 0x60000000  # 1.5 GiB managed heap (DOTNET_GCHeapHardLimit)
# ulimit -f: whole-file mode writes nothing, but the limit also refuses MAPPING a file larger than
# it (measured under gVisor: CoreLib (15 MB) failed to load with -f 1 MiB), so it covers the runtime's
# own assemblies and the input image.
MIN_FILE_BYTES = 64 * 1024 * 1024
ENTRY_TIMEOUT_S = 20.0  # the -m <entry token> run
MAX_ENTRY_BYTES = 1024 * 1024
MAX_HEAD = 1024 * 1024  # PE headers are read from this much of the file

MAX_TYPES = 20000
MAX_MEMBERS = 100000
MAX_NAME = 160
MAX_LINE = 400
MAX_LITERAL = 160
MAX_LITERALS = 20000  # distinct string literals kept whole for IOC extraction (Decompiled.literals)
MIN_LITERAL_CHARS = 4
MAX_LITERAL_CHARS = 4096
MAX_OUTLINE = 200
MAX_OUTLINE_MEMBERS = 12
MAX_WHY = 8
MIN_BUDGET = 2000
CUT_CONTEXT = 2
MIN_EXCERPT = 300  # stop looking for an excerpt that fits when less room than this is left

Status = Literal["ok", "unavailable", "timeout", "failed", "too_large"]


# --------------------------------------------------------------------- signals

# (tag, weight, regex over a member's C#). A member's score is the sum of the weights of the tags
# it matches; the matched text becomes its "why" (``tag:match``). Extend by adding rows.
SIGNALS: tuple[tuple[str, int, str], ...] = (
    ("loader", 6, r"\bAssembly\.(?:Load|LoadFrom|LoadFile|UnsafeLoadFrom)\b|\b(?:AppDomain\.\w+|GetDomain\(\))\.Load\b"
                  r"|\.EntryPoint\b|\bGetMethod\(|\.Invoke\(|\bActivator\.CreateInstance\b"
                  r"|\bDynamicMethod\b|\bILGenerator\b|\bMarshal\.GetDelegateForFunctionPointer\b"),
    ("resource", 4, r"\bGetManifestResource(?:Stream|Names)\b|\bResourceManager\b|\.GetObject\(\"|\bGetResourceString\b"),
    ("decrypt", 4, r"\bCreateDecryptor\b|\bTransformFinalBlock\b|\bRijndael\w*|\bAes\w*\.Create\b|\bTripleDES\w*"
                   r"|\bDESCryptoServiceProvider\b|\bRC4\b|\bFromBase64String\b|\bGZipStream\b|\bDeflateStream\b"
                   r"|\bRfc2898DeriveBytes\b|\bPasswordDeriveBytes\b|\bMD5\w*\.Create\b|\bProtectedData\.Unprotect\b"),
    ("injection", 6, r"\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory"
                     r"|CreateRemoteThread|NtUnmapViewOfSection|ZwUnmapViewOfSection|SetThreadContext"
                     r"|Wow64SetThreadContext|GetThreadContext|ResumeThread|QueueUserAPC|NtWriteVirtualMemory"
                     r"|RtlMoveMemory|CreateProcessA|CreateProcessW|CreateProcess|LoadLibrary\w*|GetProcAddress)\b"),
    ("pinvoke", 2, r"\[DllImport\(\"[^\"]{1,40}\"|\bextern\b"),
    ("process", 3, r"\bProcess\.Start\b|\bProcessStartInfo\b|\bcmd(?:\.exe)?\b|\bpowershell\b|\bschtasks\b"
                   r"|\bShellExecute\w*|\bWinExec\b"),
    ("persistence", 4, r"\bRegistry(?:Key)?\b|CurrentVersion\\\\Run|SpecialFolder\.Startup\b|\bStartup\b"
                       r"|\bschtasks\b|\\\\Start Menu\\\\"),
    ("network", 4, r"\bWebClient\b|\bHttpClient\b|\bHttp(?:Web)?Request\b|\bWebRequest\b|\bTcpClient\b|\bSocket\b"
                   r"|\bSmtpClient\b|\bMailMessage\b|\bFtpWebRequest\b|\bDownload(?:String|Data|File)\b"
                   r"|\bUpload(?:String|Data|File|Values)\b|\bDns\.\w+|\bSslStream\b|\bNetworkStream\b"),
    # URLs other than XML/schema namespaces (decoy apps are full of those); IPv4 literals other
    # than version strings ("Version=4.0.0.0", "1.0.0.0").
    ("c2", 5, r"api\.telegram\.org|discord(?:app)?\.com/api/webhooks|\bsendMessage\b|\bsendDocument\b"
              r"|https?://(?!(?:www\.)?(?:w3\.org|tempuri\.org|schemas\.(?:microsoft|xmlsoap|openxmlformats)\.\w+"
              r"|microsoft\.com/(?:winfx|xml|GroupPolicy)|xml\.org|purl\.org)/)[^\s\"'\\]{0,60}"
              r"|\bsmtp\.|\bftp://|pastebin\.com|(?<![\w.=])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\w.])(?<!\.0\.0)"),
    ("credentials", 5, r"Login Data|\bCookies\b|Web Data|Local State|logins\.json|key[34]\.db|signons\.sqlite"
                       r"|\bwallet\w*|\bExodus\b|\bElectrum\b|\bMetaMask\b|\btdata\b|FileZilla|\bOutlook\b"
                       r"|\bThunderbird\b|\bencrypted_key\b|\bCryptUnprotectData\b|\bBCryptDecrypt\b"
                       r"|Google\\\\Chrome|Mozilla\\\\Firefox|\bv10\b"),
    ("spying", 5, r"\bSetWindowsHookEx\w*|\bGetAsyncKeyState\b|\bGetKeyState\b|\bGetForegroundWindow\b"
                  r"|\bGetWindowText\w*|\bClipboard\b|\bCopyFromScreen\b|\bScreen\.PrimaryScreen\b|\bWH_KEYBOARD"
                  r"|\bKeylog\w*|\bwebcam\w*|\bcapCreateCaptureWindow\w*"),
    ("evasion", 4, r"\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b|\bDebugger\.IsAttached\b"
                   r"|\bVirtualBox\b|\bVMware\b|\bvbox\w*|\bSbieDll\b|\bwine_get_unix_file_name\b"
                   r"|\bNtQueryInformationProcess\b|\bAmsiScanBuffer\b|\bEtwEventWrite\b|\bsandbox\w*"),
    ("wmi", 3, r"\bManagementObjectSearcher\b|\bManagementClass\b|\bWin32_\w+"),
    ("crypto", 2, r"\bSHA\d+\w*|\bHMAC\w*|\bRSACryptoServiceProvider\b|\^\s*\w+\[|\bxor\b"),
    ("files", 1, r"\bFile\.(?:Copy|Move|WriteAllBytes|Delete|SetAttributes)\b|\bSpecialFolder\.\w+"),
)
_SIGNALS = tuple((tag, w, re.compile(p, re.IGNORECASE if tag in ("credentials", "c2") else 0))
                 for tag, w, p in SIGNALS)

# Names that are compiler or designer noise (dropped first when the budget is tight).
NOISE_MEMBERS = frozenset({"InitializeComponent", "Dispose"})
_NOISE_TYPE = re.compile(r"(?:^|\.)(?:Properties\.(?:Resources|Settings)|My\.(?:MyProject|MySettings\w*|Resources"
                         r"\.Resources|MyApplication|MyComputer|InternalXmlHelper)|Microsoft\.CodeAnalysis\.\w+"
                         r"|System\.Runtime\.CompilerServices\.\w+Attribute)$|^<(?!Module>)")


# ---------------------------------------------------------------------- model


@dataclass(frozen=True)
class Member:
    type: str  # full name of the declaring type ("Ns.Outer.Inner")
    name: str  # "Main", ".ctor", ".cctor", "this[]", "<fields>" (the type's field lines), "<extern>"
    kind: str  # method | ctor | cctor | property | event | indexer | operator | fields | extern
    header: str
    code: str
    noise: bool = False


@dataclass(frozen=True)
class TypeInfo:
    name: str
    kind: str  # class | struct | interface | enum | delegate
    noise: bool
    members: tuple[str, ...]


@dataclass
class Decompiled:
    status: Status
    reason: str = ""
    tool: str = TOOL
    types_total: int = 0
    methods_total: int = 0
    source_chars: int = 0
    entry_point: str | None = None  # "Ns.Type.Method"
    entry_token: int | None = None
    mixed_mode: bool = False  # CLI header without ILONLY: native code next to the IL
    seconds: float = 0.0
    types: list[TypeInfo] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    literals: list[str] = field(default_factory=list)  # whole string literals, for IOC extraction


# ------------------------------------------------------------------- strings

_LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"')


_ESCAPE = re.compile(r"\\(u[0-9a-fA-F]{4}|.)")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\x00"}


def literals(source: str, limit: int = MAX_LITERALS) -> list[str]:
    """The distinct string literals of C# ``source`` in order of first use, unescaped: at least
    ``MIN_LITERAL_CHARS`` characters each, cut to ``MAX_LITERAL_CHARS``, at most ``limit`` of them.
    Members' code carries them shortened (``MAX_LITERAL``); IOC extraction needs them whole."""

    def unescape(m: re.Match[str]) -> str:
        esc = m.group(1)
        return chr(int(esc[1:], 16)) if len(esc) == 5 else _ESCAPES.get(esc, esc)

    seen: dict[str, None] = {}
    for m in _LITERAL.finditer(source):
        raw = m.group(0)[1:-1]
        if len(raw) < MIN_LITERAL_CHARS:
            continue
        value = _ESCAPE.sub(unescape, raw[: MAX_LITERAL_CHARS * 6])[:MAX_LITERAL_CHARS]
        if len(value) >= MIN_LITERAL_CHARS and value not in seen:
            seen[value] = None
            if len(seen) >= limit:
                break
    return list(seen)


def clean(text: str, limit: int) -> str:
    """``text`` with control/format/private-use characters escaped (``\\uXXXX``; newlines and tabs
    kept) and at most ``limit`` characters."""
    out: list[str] = []
    n = 0
    for ch in text:
        if ch not in "\n\t" and unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp"):
            ch = f"\\u{ord(ch):04x}"
        out.append(ch)
        n += len(ch)
        if n >= limit:
            break
    s = "".join(out)
    return s if len(s) <= limit else s[: max(0, limit - 1)] + "…"


def _short_literals(line: str) -> str:
    def cut(m: re.Match[str]) -> str:
        s = m.group(0)
        return s if len(s) <= MAX_LITERAL else s[: MAX_LITERAL - 20] + f'…(+{len(s) - MAX_LITERAL + 20} chars)"'

    line = _LITERAL.sub(cut, line) if len(line) > MAX_LITERAL else line
    return line if len(line) <= MAX_LINE else line[: MAX_LINE - 1] + "…"


def _code(lines: Iterable[str], dedent: int) -> str:
    out = []
    for ln in lines:
        if ln[:dedent].strip("\t") == "":
            ln = ln[dedent:]
        out.append(_short_literals(ln.rstrip()))
    return clean("\n".join(out), 1 << 30)


# --------------------------------------------------------------------- parse

_TYPE_DECL = re.compile(r"(?:^|\s)(class|struct|interface|enum)\s+([^\s:{(]+(?:<[^>]*>)?)")
_DELEGATE = re.compile(r"(?:^|\s)delegate\s+.+?\s([^\s(<]+)(?:<[^>]*>)?\s*\(")
_GENERIC = re.compile(r"(?<=[\w>])<[^<>]*>")  # type arguments, not "<Module>" itself


def _depth(line: str) -> int:
    return len(line) - len(line.lstrip("\t"))


def _member_name(header: str, type_short: str) -> tuple[str, str]:
    """(name, kind) of a member declaration header."""
    h = header.strip()
    if " operator " in f" {h}" and "(" in h:
        return "operator " + h.split("operator", 1)[1].split("(", 1)[0].strip(), "operator"
    if "this[" in h:
        return "this[]", "indexer"
    if re.search(r"(?:^|\s)event\s", h):
        return h.rstrip(";").split()[-1], "event"
    # cut a constructor initializer (" : base(...)") and generic constraints
    h = re.split(r"\)\s*:\s*(?:base|this)\s*\(", h, maxsplit=1)[0]
    flat = h
    for _ in range(4):
        flat = _GENERIC.sub("", flat)
    if "(" in flat:
        before = flat.split("(", 1)[0].strip()
        name = before.split()[-1] if before.split() else before
        name = name.rsplit(".", 1)[-1] if "." in name else name  # explicit interface impl
        if name.startswith("~"):
            return name, "method"
        if name == type_short:
            return (".cctor" if re.search(r"(?:^|\s)static\s", before) else ".ctor"), (
                "cctor" if re.search(r"(?:^|\s)static\s", before) else "ctor")
        return name, "method"
    words = flat.split("=", 1)[0].split()
    return (words[-1].rsplit(".", 1)[-1] if words else "?"), "property"


@dataclass
class _Scope:
    kind: str  # ns | type | member | field | other
    name: str
    depth: int
    start: int
    type_kind: str = ""
    header: str = ""
    noise: bool = False


def parse(source: str) -> tuple[list[TypeInfo], list[Member], int]:
    """ILSpy's whole-file C# -> (types, members, methods_total). Depends on ILSpy's layout (one
    tab per nesting level, ``{``/``}`` alone on their lines); an unclosed tail (a capped run) is
    closed at the end of the text."""
    lines = source.split("\n")
    stack: list[_Scope] = []
    pending: list[int] = []  # attribute/header line numbers at the current level
    types: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    members: list[Member] = []
    methods = 0

    def ns_name() -> str:  # scopes hold full names
        return next((s.name for s in reversed(stack) if s.kind in ("ns", "type")), "")

    def qualify(name: str) -> str:
        base = ns_name()
        return f"{base}.{name}" if base else name

    def type_scope() -> _Scope | None:
        return stack[-1] if stack and stack[-1].kind == "type" else None

    def add_type(name: str, kind: str) -> dict[str, Any] | None:
        if name not in types and len(types) < MAX_TYPES:
            types[name] = {"kind": kind, "members": [], "fields": [], "noise": bool(_NOISE_TYPE.search(name))}
            order.append(name)
        return types.get(name)

    def add_line_to_type(i: int) -> None:
        ts = type_scope()
        if ts is None:
            return
        t = types.get(ts.name)
        if t is not None:
            t["fields"].append(i)

    def close(s: _Scope, end: int) -> None:
        nonlocal methods
        if s.kind == "member":
            owner = stack[-1] if stack else None
            if owner is None or owner.kind != "type" or len(members) >= MAX_MEMBERS:
                return
            last = owner.name.rsplit(".", 1)[-1]
            short = last if last.startswith("<") else last.split("<", 1)[0]
            name, mkind = _member_name(s.header, short)
            if mkind in ("method", "ctor", "cctor", "operator"):
                methods += 1
            t = types.get(owner.name)
            noise = bool(t and t["noise"]) or name in NOISE_MEMBERS
            body = [ln for ln in lines[s.start:end + 1] if not (_depth(ln) == s.depth and ln.strip().startswith("["))]
            members.append(Member(type=clean(owner.name, MAX_NAME * 2), name=clean(name, MAX_NAME), kind=mkind,
                                  header=clean(s.header.strip(), MAX_LINE), code=_code(body, s.depth), noise=noise))
            if t is not None:
                t["members"].append(name)
        elif s.kind == "field":
            add_line_to_type_range(s.start, end)

    def add_line_to_type_range(a: int, b: int) -> None:
        for i in range(a, b + 1):
            add_line_to_type(i)

    for i, raw in enumerate(lines):
        line = raw.rstrip()
        s = line.strip()
        d = _depth(line)
        top = stack[-1] if stack else None
        if top is not None and top.kind in ("member", "field", "other") and (d > top.depth or not s):
            continue
        if not s:
            pending = []
            continue
        if s in ("}", "};") or (s.startswith("}") and top is not None and d == top.depth):
            while stack and stack[-1].depth > d:
                close(stack.pop(), i)
            if stack and stack[-1].depth == d:
                close(stack.pop(), i)
            pending = []
            continue
        if s == "{":
            hdr_lines = [j for j in pending if not lines[j].strip().startswith("[")]
            header = lines[hdr_lines[-1]].strip() if hdr_lines else ""
            start = pending[0] if pending else i
            pending = []
            if top is not None and top.kind in ("member", "field", "other"):
                continue
            if header.startswith("namespace "):
                stack.append(_Scope("ns", qualify(header[10:].strip()), d, start))
                continue
            m = _TYPE_DECL.search(_GENERIC.sub("", header) if "(" in header else header)
            if m and "(" not in header.split(m.group(1), 1)[0] and " = " not in header:
                name = qualify(m.group(2))
                stack.append(_Scope("type", name, d, start, type_kind=m.group(1), header=header))
                add_type(name, m.group(1))
                continue
            if type_scope() is None:
                stack.append(_Scope("other", "", d, start))
                continue
            if re.search(r"\s=\s|^=\s", header) and not re.search(r"\)\s*$", header.split("=", 1)[0]):
                stack.append(_Scope("field", "", d, start, header=header))
                continue
            stack.append(_Scope("member", "", d, start, header=header))
            continue
        # a declaration line in a namespace or type body
        if s.startswith("[") and s.endswith("]"):
            pending.append(i)
            continue
        if s.startswith("namespace ") and s.endswith(";"):
            stack.append(_Scope("ns", qualify(s[10:-1].strip()), -1, i))
            pending = []
            continue
        dm = _DELEGATE.search(s)
        if dm and s.endswith(";") and "(" in s:
            add_type(qualify(dm.group(1)), "delegate")
            pending = []
            continue
        ts = type_scope()
        if ts is not None and (s.endswith(";") or s.endswith("}") or s.endswith(",") or ts.type_kind == "enum"):
            # field, enum member, extern/abstract method, one-line property
            if re.search(r"(?:^|\s)extern\s", s):
                methods += 1
                t = types.get(ts.name)
                if t is not None:
                    t["fields"].extend(pending)
                    t.setdefault("extern", []).append(i)
            else:
                if "(" in s and s.endswith(");") and " = " not in s and "=>" not in s:
                    methods += 1  # abstract / interface method
                add_line_to_type_range(pending[0] if pending else i, i)
            pending = []
            continue
        if ts is None and (s.startswith("using ") or s.endswith(";")):
            pending = []
            continue
        pending.append(i)
    while stack:
        close(stack.pop(), len(lines) - 1)

    infos: list[TypeInfo] = []
    for name in order:
        t = types[name]
        infos.append(TypeInfo(name=clean(name, MAX_NAME * 2), kind=t["kind"], noise=t["noise"],
                              members=tuple(clean(n, MAX_NAME) for n in t["members"])))
        fl = [ln for ln in sorted(set(t["fields"]))]
        if fl:
            dep = min(_depth(lines[j]) for j in fl)
            code = _code((lines[j] for j in fl if not lines[j].strip().startswith("[")), dep)
            if code.strip():
                members.append(Member(type=clean(name, MAX_NAME * 2), name="<fields>", kind="fields",
                                      header="", code=code, noise=t["noise"]))
        ex = t.get("extern")
        if ex:
            dep = min(_depth(lines[j]) for j in ex)
            members.append(Member(type=clean(name, MAX_NAME * 2), name="<extern>", kind="extern", header="",
                                  code=_code((lines[j] for j in ex), dep), noise=t["noise"]))
    return infos, members, methods


# ------------------------------------------------------------------ PE header


def cli_header(path: Path) -> tuple[int, int] | None:
    """``(flags, entry_point_token)`` of a PE's CLI (COR20) header, or None when it has none."""
    try:
        with path.open("rb") as f:
            head = f.read(MAX_HEAD)
    except OSError:
        return None
    try:
        if head[:2] != b"MZ":
            return None
        (lfanew,) = struct.unpack_from("<I", head, 0x3C)
        if head[lfanew:lfanew + 4] != b"PE\0\0":
            return None
        nsec, = struct.unpack_from("<H", head, lfanew + 6)
        optsz, = struct.unpack_from("<H", head, lfanew + 20)
        opt = lfanew + 24
        magic, = struct.unpack_from("<H", head, opt)
        dirs = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else -1 << 30)
        nrva, = struct.unpack_from("<I", head, dirs - 4)
        if nrva <= 14:
            return None
        rva, size = struct.unpack_from("<II", head, dirs + 14 * 8)
        if not rva or size < 72:
            return None
        sec = opt + optsz
        for k in range(min(nsec, 96)):
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", head, sec + 40 * k + 8)
            if vaddr <= rva < vaddr + max(vsize, rsize):
                off = rva - vaddr + rptr
                break
        else:
            return None
        with path.open("rb") as f:
            f.seek(off)
            cor = f.read(24)
        if len(cor) < 24:
            return None
        flags, token = struct.unpack_from("<II", cor, 16)
        return flags, token
    except (struct.error, ValueError):
        return None


# ---------------------------------------------------------------- decompile


def dotnet_env(workdir: Path) -> dict[str, str]:
    """Environment for the .NET runtime, every writable path under ``workdir``."""
    home, tmp = workdir / "home", workdir / "tmp"
    for d in (home, tmp):
        d.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "DOTNET_CLI_HOME": str(home),
        "DOTNET_BUNDLE_EXTRACT_BASE_DIR": str(tmp),
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1",
        "DOTNET_EnableDiagnostics": "0",
        "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT": "1",
        "DOTNET_gcServer": "0",
        "DOTNET_GCHeapHardLimit": f"{GC_HEAP_LIMIT:#x}",
        "DOTNET_TieredPGO": "0",
    }


def _argv(image: Path, extra: list[str], max_kb: int, dotnet: str, ilspycmd: str) -> list[str]:
    try:
        size = image.stat().st_size
    except OSError:
        size = 0
    blocks = max(MIN_FILE_BYTES, 2 * size) // 512
    return ["sh", "-c", 'ulimit -v "$1" || exit 1; ulimit -f "$2" || exit 1; shift 2; exec "$@"',
            "sh", str(max_kb), str(blocks), dotnet, ilspycmd, "--disable-updatecheck",
            "-lv", "CSharp7_3", "--ignore-decompilation-errors", *extra, str(image.resolve())]


def _body(text: str) -> str:
    """Decompiled text without leading ``using`` lines, normalized for comparison."""
    lines = [ln.rstrip() for ln in text.split("\n")]
    while lines and (not lines[0].strip() or lines[0].startswith("using ")):
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ""
    dep = min(_depth(ln) for ln in lines if ln.strip())
    return "\n".join(ln[dep:] if ln.strip() else "" for ln in lines if not ln.strip().startswith("["))


def _entry(image: Path, token: int, members: list[Member], env: dict[str, str], cwd: Path, timeout_s: float,
           run: RunFn, argv: Callable[[list[str]], list[str]]) -> str | None:
    out = run(argv(["-m", f"{token:#010x}"]), env=env, cwd=cwd, timeout_s=timeout_s,
              max_stdout=MAX_ENTRY_BYTES)
    if out.rc != 0 or out.capped or out.timed_out or not out.stdout:
        return None
    want = _body(clean(out.stdout.decode("utf-8", "replace"), 1 << 30))
    if not want:
        return None
    # members' code is literal-shortened; compare the same way
    want = "\n".join(_short_literals(ln) for ln in want.split("\n"))
    hits = [m for m in members if m.kind not in ("fields", "extern") and _body(m.code) == want]
    if len(hits) != 1:
        first = want.split("\n", 1)[0].strip()
        hits = [m for m in members if m.kind not in ("fields", "extern") and m.header == first]
    return f"{hits[0].type}.{hits[0].name}" if len(hits) == 1 else None


def decompile(image: Path, workdir: Path, *, timeout_s: float, run: RunFn = bounded_run,
              dotnet: str = DOTNET, ilspycmd: str = ILSPYCMD, max_kb: int = MAX_KB) -> Decompiled:
    """``image`` (a .NET PE) to C# with ilspycmd, parsed into types and members.

    Never raises. ``status``: ``ok``; ``unavailable`` (no runtime/ilspycmd in this image);
    ``failed`` (not a .NET assembly, or ilspycmd failed: ``reason`` says which); ``timeout`` /
    ``too_large`` keep whatever C# was read before the run was killed.
    """
    t0 = time.monotonic()
    if not Path(dotnet).is_file() or not Path(ilspycmd).is_file():
        return Decompiled("unavailable", "ilspycmd is not installed in this image")
    cli = cli_header(image)
    if cli is None:
        return Decompiled("failed", "not a .NET assembly (no CLI header)")
    flags, token = cli
    mixed = not flags & 0x1
    workdir.mkdir(parents=True, exist_ok=True)
    env = dotnet_env(workdir)
    entry_reserve = min(ENTRY_TIMEOUT_S, timeout_s * 0.15)

    def argv(extra: list[str]) -> list[str]:
        return _argv(image, extra, max_kb, dotnet, ilspycmd)

    try:
        out = run(argv([]), env=env, cwd=workdir, timeout_s=max(1.0, timeout_s - entry_reserve),
                  max_stdout=MAX_SOURCE_BYTES)
    except Exception as exc:  # spawn failure
        return Decompiled("failed", f"exception:{type(exc).__name__}", mixed_mode=mixed)
    status: Status = "ok"
    reason = ""
    if out.timed_out:
        status, reason = "timeout", f"killed after {timeout_s - entry_reserve:.0f}s"
    elif out.capped:
        status, reason = "too_large", f"C# output past {MAX_SOURCE_BYTES // (1024 * 1024)} MiB"
    elif out.rc != 0:
        status, reason = "failed", f"ilspycmd exit {out.rc}"
    text = out.stdout.decode("utf-8", "replace")
    if status == "ok" and not text.strip():
        status, reason = "failed", "no output"
    d = Decompiled(status, reason, mixed_mode=mixed, source_chars=len(text))
    if text.strip():
        try:
            d.types, d.members, d.methods_total = parse(text)
        except (RecursionError, ValueError, IndexError) as exc:
            d.status, d.reason = "failed", f"parse:{type(exc).__name__}"
        d.types_total = len(d.types)
        d.literals = literals(text)
    if not flags & 0x10 and token >> 24 == 0x06:
        d.entry_token = token
        left = timeout_s - (time.monotonic() - t0)
        if d.members and left >= 2:
            try:
                d.entry_point = _entry(image, token, d.members, env, workdir, min(left, ENTRY_TIMEOUT_S), run, argv)
            except Exception:
                d.entry_point = None
    d.seconds = round(time.monotonic() - t0, 2)
    return d


# -------------------------------------------------------------------- digest


def score(m: Member) -> tuple[int, list[str]]:
    """(score, why) of one member from ``SIGNALS``."""
    total = 0
    why: list[str] = []
    for tag, weight, rx in _SIGNALS:
        hit = rx.search(m.code)
        if hit is None:
            continue
        total += weight
        why.append(clean(f"{tag}:{hit.group(0)}", 60))
    return total, why


def _calls(code: str) -> set[str]:
    return set(re.findall(r"([A-Za-z_\u0080-￿][\w\u0080-￿]*)\s*\(", code))


def rank(d: Decompiled) -> list[tuple[Member, list[str]]]:
    """Members in excerpt order with their reasons: the entry point, then the module initializer,
    then by score (callees of the entry point get a bonus), then the unscored, noise last."""
    entry = d.entry_point
    entry_m = next((m for m in d.members if f"{m.type}.{m.name}" == entry), None)
    callees = _calls(entry_m.code) if entry_m is not None else set()
    keyed: list[tuple[tuple[int, int, int, int], Member, list[str]]] = []
    for idx, m in enumerate(d.members):
        s, why = score(m)
        if m is entry_m:
            tier = 0
            why = ["entry_point", *why]
        elif m.type == "<Module>" and m.kind == "cctor":
            tier = 1
            why = ["module_initializer", *why]
        elif m.noise and (s == 0 or _NOISE_TYPE.search(m.type)):
            tier = 4
            why = ["noise", *why]
        elif s > 0:
            tier = 2
            if m.noise:  # behaviour in designer code (InitializeComponent): a classic hiding place
                s += 4
                why.insert(0, "in_designer_code")
            if m.name in callees:
                s += 3
                why.append("called_from_entry")
        else:
            tier = 3
        keyed.append(((tier, -s, len(m.code) if tier == 3 else 0, idx), m, why[:MAX_WHY]))
    keyed.sort(key=lambda k: k[0])
    return [(m, why) for _, m, why in keyed]


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False))


def digest(d: Decompiled, *, label: str, budget_chars: int) -> dict[str, Any] | None:
    """The bounded C# evidence for the model, about ``budget_chars`` characters of JSON:

    ``{"label", "tool", "status", "types_total", "methods_total", "entry_point", "outline": [str],
    "excerpts": [{"type", "member", "why": [str], "code"}], "omitted": int}``. ``outline`` is one
    line per non-noise type (``Name (kind): member, member, ...``), capped to a sixth of the budget;
    ``omitted`` counts the members left out. None when nothing was decompiled.
    """
    if not d.members and not d.types:
        return None
    budget = max(MIN_BUDGET, budget_chars)
    out: dict[str, Any] = {"label": clean(label, MAX_NAME), "tool": d.tool, "status": d.status,
                           "types_total": d.types_total, "methods_total": d.methods_total,
                           "entry_point": d.entry_point, "outline": [], "excerpts": [], "omitted": 0}
    if d.mixed_mode:
        out["mixed_mode"] = True
    outline_budget = budget // 6
    used = 0
    weight: dict[str, int] = {}
    for m in d.members:
        weight[m.type] = weight.get(m.type, 0) + score(m)[0]
    shown = [t for t in d.types if not t.noise and t.kind != "delegate"]
    for t in sorted(shown, key=lambda t: (-weight.get(t.name, 0), -len(t.members)))[:MAX_OUTLINE]:
        names = [n for n in t.members if n not in NOISE_MEMBERS]
        more = len(names) - MAX_OUTLINE_MEMBERS
        line = clean(f"{t.name} ({t.kind}): " + ", ".join(names[:MAX_OUTLINE_MEMBERS])
                     + (f", …(+{more})" if more > 0 else ""), MAX_LINE)
        if used + len(line) + 4 > outline_budget:
            break
        out["outline"].append(line)
        used += len(line) + 4
    hidden_types = len(shown) - len(out["outline"])
    if hidden_types > 0:
        out["outline"].append(f"…(+{hidden_types} more types)")
    size = _size(out)
    per = max(1000, budget // 3)  # one method takes at most a third of the budget
    for m, why in rank(d):
        if budget - size < MIN_EXCERPT:
            break
        ex = {"type": m.type, "member": m.name, "why": why, "code": _cut(m.code, per)}
        need = _size(ex) + 2
        if size + need > budget:
            if why[:1] not in (["entry_point"], ["module_initializer"]):
                continue  # whole methods only; a smaller one further down may still fit
            ex["code"] = _cut(m.code, max(200, budget - size - (need - len(ex["code"])) - 60))
            need = _size(ex) + 2
            if size + need > budget:
                continue
        out["excerpts"].append(ex)
        size += need
    out["omitted"] = len(d.members) - len(out["excerpts"])
    return out


def _cut(code: str, limit: int) -> str:
    """``code`` within ``limit`` characters. A long method keeps its first lines, the lines that
    match ``SIGNALS`` (with ``CUT_CONTEXT`` lines around each) and its last line, the gaps elided
    (designer ``InitializeComponent`` methods bury a loader at the end of thousands of lines);
    failing that, its head."""
    if len(code) <= limit:
        return code
    lines = code.split("\n")
    keep = {0, 1, len(lines) - 1}
    for i, ln in enumerate(lines):
        if any(rx.search(ln) for _, _, rx in _SIGNALS):
            keep.update(range(max(0, i - CUT_CONTEXT), min(len(lines), i + CUT_CONTEXT + 1)))
    if len(keep) < len(lines):
        out: list[str] = []
        last = -1
        for i in sorted(keep):
            if i > last + 1:
                out.append(f"\t…[{i - last - 1} lines]")
            out.append(lines[i])
            last = i
        text = "\n".join(out)
        if len(text) <= limit:
            return text
        code = text
    head = max(0, limit - 40)
    return code[:head] + f"\n…[cut {len(code) - head} chars]"
