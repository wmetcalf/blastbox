"""``blastbox macos {prepare,doctor}`` -- set up and verify the macOS sandbox backends.

Lives in the lean worker package (no ``blastbox[host]`` needed) because it runs on the Mac
worker; also reachable as ``python -m blastbox.worker.sandbox.macos_tool``.

``doctor`` proves confinement by trying to break it, with a control for every probe so a
check cannot pass vacuously: the canary is readable unsandboxed and must NOT be readable
sandboxed; a loopback listener the doctor opens itself accepts an unsandboxed connect and must
refuse a sandboxed one (no internet needed). ``--self-test`` additionally runs an engine's
own known-positive check (e.g. "decode this generated QR") under the backend, because the
failure mode that matters most for an accelerator-backed engine is not a crash but a silent
empty result when a grant is missing.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from blastbox.errors import SandboxError, SandboxUnavailable
from blastbox.limits import Limits
from blastbox.worker.sandbox.appsandbox import AppSandboxNotPrepared
from blastbox.worker.sandbox.base import Mount, Sandbox, SandboxRequest


@dataclass
class Check:
    backend: str
    name: str
    ok: bool
    detail: str = ""
    # Set on an appsandbox "backend available" failure that only means "not prepared" (no
    # manifest): not a failure unless the backend was asked for explicitly.
    unprepared: bool = False


def _probe_backend(sb: Sandbox, self_test: list[str] | None,
                   accelerators: frozenset[str], ro: list[Path],
                   out: list[Check] | None = None) -> list[Check]:
    """Run the probes, appending each result to ``out`` as it completes (so a caller that
    catches a probe raising still has the results that came before it)."""
    name = sb.name
    out = [] if out is None else out
    lim = Limits(timeout_s=30)

    def run(argv: list[str], **kw) -> tuple[int, str]:
        r = sb.run(SandboxRequest(argv=argv, limits=lim, **kw))
        return r.exit_code, (r.stderr or r.stdout).decode(errors="replace").strip()[-300:]

    rc, msg = run(["/usr/bin/true"])
    out.append(Check(name, "runs /usr/bin/true", rc == 0, msg))

    with tempfile.TemporaryDirectory(prefix="bb-doctor-") as td:
        tdir = Path(td).resolve()
        canary = tdir / "canary"
        canary.write_text("host-only")
        ctrl = subprocess.run(["/bin/cat", str(canary)], capture_output=True)
        rc, msg = run(["/bin/cat", str(canary)])
        out.append(Check(name, "ungranted file is unreadable",
                         ctrl.returncode == 0 and rc != 0, msg or f"rc={rc}"))

        victim = tdir / "escape"
        run(["/bin/sh", "-c", f"echo x > '{victim}'"])
        out.append(Check(name, "write outside grants is denied", not victim.exists()))

        rwdir = tdir / "rw"
        rwdir.mkdir()
        rc, msg = run(["/bin/sh", "-c", 'echo ok > "$0/f"', str(rwdir)],
                      rw_mounts=[Mount(rwdir, rwdir)])
        ok = rc == 0 and (rwdir / "f").exists() and (rwdir / "f").read_text() == "ok\n"
        out.append(Check(name, "granted rw mount is writable", ok, msg))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = str(srv.getsockname()[1])
        ctrl = subprocess.run(["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", port],
                              capture_output=True)
        rc, msg = run(["/usr/bin/nc", "-z", "-w", "2", "127.0.0.1", port])
        out.append(Check(name, "network connect is denied (loopback listener)",
                         ctrl.returncode == 0 and rc != 0,
                         f"control rc={ctrl.returncode} sandboxed rc={rc} {msg}"))

    if self_test:
        r = sb.run(SandboxRequest(argv=self_test, limits=Limits(timeout_s=120),
                                  accelerators=accelerators,
                                  ro_mounts=[Mount(p, p) for p in ro]))
        detail = (r.stdout + b"\n" + r.stderr).decode(errors="replace").strip()[-400:]
        out.append(Check(name, f"self-test {Path(self_test[0]).name}",
                         r.exit_code == 0 and not r.killed, detail))
    return out


def doctor(*, backends: list[str], self_test: list[str] | None, accelerators: frozenset[str],
           ro: list[Path], appsandbox_root: Path | None = None,
           make: Callable[[str], Sandbox] | None = None) -> list[Check]:
    if sys.platform != "darwin":
        return [Check("-", "host is macOS", False, sys.platform)]

    def _make(name: str) -> Sandbox:
        if name == "seatbelt":
            from blastbox.worker.sandbox.seatbelt import SeatbeltSandbox
            return SeatbeltSandbox()
        from blastbox.worker.sandbox.appsandbox import AppSandboxSandbox
        return AppSandboxSandbox(root=appsandbox_root)

    checks: list[Check] = []
    for name in backends:
        try:
            sb = (make or _make)(name)
        except (SandboxUnavailable, SandboxError) as exc:
            checks.append(Check(name, "backend available", False, str(exc),
                                unprepared=isinstance(exc, AppSandboxNotPrepared)))
            continue
        except Exception as exc:  # noqa: BLE001 -- a broken install is what doctor diagnoses
            checks.append(Check(name, "backend available", False,
                                f"{type(exc).__name__}: {exc}"[:400]))
            continue
        checks.append(Check(name, "backend available", True))
        probes: list[Check] = []
        try:
            _probe_backend(sb, self_test, accelerators, ro, out=probes)
        except Exception as exc:  # noqa: BLE001 -- a broken runtime is what doctor diagnoses
            # e.g. cleanup can't prove a slot empty, or process enumeration fails: report it as
            # a failed check and go on to the next backend instead of aborting with a traceback.
            probes.append(Check(name, "probes ran to completion", False,
                                f"{type(exc).__name__}: {exc}"[:400]))
        checks.extend(probes)
    return checks


def _cmd_prepare(args: argparse.Namespace) -> int:
    from blastbox.worker.sandbox.appsandbox import default_root, prepare
    root = Path(args.root) if args.root else default_root()
    try:
        m = prepare(root, slots=args.slots, ro_paths=[Path(p) for p in args.ro],
                    bundle_prefix=args.bundle_prefix)
    except (SandboxError, OSError) as exc:
        print(f"prepare failed: {exc}", file=sys.stderr)
        return 1
    print(f"prepared {len(m.slots)} App Sandbox slot(s) under {m.root}")
    print(f"  bundle ids : {m.slots[0].bundle_id} .. {m.slots[-1].bundle_id}")
    print(f"  ro paths   : {', '.join(map(str, m.ro_paths)) or '(system only)'}")
    print("  use with   : BLASTBOX_SANDBOX=appsandbox"
          + ("" if root == default_root() else f" BLASTBOX_APPSANDBOX_ROOT={m.root}"))
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    backends = args.backend or ["seatbelt", "appsandbox"]
    checks = doctor(
        backends=backends,
        self_test=args.self_test or None,
        accelerators=frozenset(a for a in args.accelerator),
        ro=[Path(p).resolve() for p in args.ro],
        appsandbox_root=Path(args.root) if args.root else None,
    )
    if args.json:
        print(json.dumps([asdict(c) for c in checks], indent=2))
    else:
        for c in checks:
            mark = "PASS" if c.ok else "FAIL"
            line = f"[{mark}] {c.backend:<10} {c.name}"
            if c.detail and not c.ok:
                line += f"\n         {c.detail}"
            print(line)
    # An appsandbox that is merely not prepared is not a failure unless it was asked for; a
    # prepared one that is broken (launcher missing, bad signature, old manifest) always is.
    failed = [c for c in checks if not c.ok and not (not args.backend and c.unprepared)]
    return 1 if failed else 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    pm = sub.add_parser("macos", help="set up / verify the macOS sandbox backends")
    pms = pm.add_subparsers(dest="macos_action", required=True)

    pp = pms.add_parser("prepare", help="build + ad-hoc sign the App Sandbox launcher slots")
    pp.add_argument("--root", help="slot root (default $BLASTBOX_APPSANDBOX_ROOT or "
                    "~/Library/Application Support/blastbox/appsandbox)")
    pp.add_argument("--slots", type=int, default=4,
                    help="concurrent sandboxed runs (one bundle id each; default 4)")
    pp.add_argument("--ro", action="append", default=[], metavar="PATH",
                    help="read-only path children may read/exec (an engine install dir, a "
                    "Python prefix). Repeatable; baked into the signature")
    pp.add_argument("--bundle-prefix", help="bundle id prefix (default derived from --root)")
    pp.set_defaults(func=_cmd_prepare)

    pd = pms.add_parser("doctor", help="prove the macOS sandbox confines (and an engine works)")
    pd.add_argument("--backend", action="append", choices=["seatbelt", "appsandbox"],
                    help="check only this backend (repeatable; default both)")
    pd.add_argument("--root", help="appsandbox slot root")
    pd.add_argument("--accelerator", action="append", default=[], choices=["gpu", "ane"],
                    help="grant this accelerator to --self-test (seatbelt)")
    pd.add_argument("--ro", action="append", default=[], metavar="PATH",
                    help="read-only grant for --self-test (seatbelt)")
    pd.add_argument("--json", action="store_true")
    pd.add_argument("self_test", nargs=argparse.REMAINDER,
                    help="after --: an engine's known-positive self-test command; must exit 0")
    pd.set_defaults(func=_cmd_doctor)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blastbox")
    add_parser(p.add_subparsers(dest="command", required=True))
    args = p.parse_args(["macos", *(argv if argv is not None else sys.argv[1:])])
    if getattr(args, "self_test", None) and args.self_test[0] == "--":
        args.self_test = args.self_test[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
