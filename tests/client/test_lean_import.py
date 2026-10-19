"""The client verifier must work on a LEAN install (core + `cryptography`): it may never import
the host stack. Proven in a fresh interpreter in which every host-extra package is UNIMPORTABLE,
so a stray import fails here rather than in a consumer's minimal environment."""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"

#: The [host]/[s3]/[dev] packages a lean client does not have.
_HOST_ONLY = ["fastapi", "starlette", "uvicorn", "multipart", "python_multipart", "structlog",
              "prometheus_client", "psycopg", "psycopg_pool", "redis", "pyzipper", "boto3",
              "botocore", "sqlalchemy", "httpx", "requests"]


def _run(body: str) -> subprocess.CompletedProcess:
    prelude = textwrap.dedent(f"""
        import sys
        BLOCKED = {_HOST_ONLY!r}

        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in BLOCKED:
                    raise ImportError(f"{{name}} is not installed (lean client)")
                return None

        sys.meta_path.insert(0, _Block())
        sys.path.insert(0, {str(_SRC)!r})
    """)
    return subprocess.run([sys.executable, "-c", prelude + textwrap.dedent(body)],
                          capture_output=True, text=True, timeout=120)


def test_the_verifier_imports_without_the_host_stack():
    r = _run("""
        import blastbox.client.verify as v
        loaded = sorted(m for m in sys.modules
                        if m.startswith("blastbox.host") or m.split(".")[0] in BLOCKED)
        assert loaded == [], loaded
        assert v.verify_receipt and v.fetch_and_verify and v.load_pinned_keys
        print("ok")
    """)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ok"


def test_blastbox_attest_verify_runs_without_the_host_stack(tmp_path):
    """The `blastbox` entry point registers `attest verify`; it must parse and run (here: refuse
    an unreadable key with exit 2) with no host extras installed."""
    r = _run(f"""
        from blastbox.host.cli import main
        rc = main(["attest", "verify", "--url", "http://127.0.0.1:9", "--job",
                   "0b9d6a0e-6c1d-4f43-9d55-0f6a3c1c7e21", "--key", {str(tmp_path / "no.pem")!r}])
        assert rc == 2, rc
        loaded = sorted(m for m in sys.modules if m.split(".")[0] in BLOCKED)
        assert loaded == [], loaded
        print("ok")
    """)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "ok"


def test_the_client_cli_runs_as_a_module():
    r = _run("""
        import runpy
        sys.argv = ["blastbox.client.cli", "attest", "verify", "--help"]
        try:
            runpy.run_module("blastbox.client.cli", run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0, exc.code
    """)
    assert r.returncode == 0, r.stderr
    assert "--key" in r.stdout and "--input" in r.stdout
