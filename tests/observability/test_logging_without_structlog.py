"""structlog is in the `host` extra; the `blastbox` console script is not.

`[project.scripts]` installs `blastbox` for every install, and its import path reaches
`blastbox.observability.logging`. When that module hard-imported structlog, a plain
`pip install blastbox` produced a CLI that could not start -- and the build wrappers in the
adopter engines print exactly that plain install as their remediation.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

_SRC = str(Path(__file__).resolve().parents[2] / "src")

# `sys.modules[name] = None` makes a later `import name` raise ImportError. That is how these
# tests simulate an install without the extras WITHOUT uninstalling anything.
#
# EVERY optional distribution, not just structlog. Blocking one module is not a lean install: the
# first version of this test blocked structlog alone, went green, and the real lean install on
# toolz2 still failed -- on prometheus_client, the very next import in the same package. A
# simulation narrower than the environment it claims to reproduce will keep passing while the
# thing it is about stays broken.
_OPTIONAL_MODULES = (
    "structlog",
    "prometheus_client",
    "fastapi",
    "starlette",
    "uvicorn",
    "multipart",
    "psycopg",
    "psycopg_pool",
    "redis",
    "pyzipper",
    "cryptography",
    "boto3",
    "botocore",
)
_BLOCK = "import sys\n" + "".join(
    f"sys.modules[{m!r}] = None\n" for m in _OPTIONAL_MODULES
)


def _run(snippet: str) -> subprocess.CompletedProcess[str]:
    """Run in a SUBPROCESS: structlog is already imported in this one, and a module that has
    been imported cannot be un-imported convincingly enough to trust the result."""
    return subprocess.run(
        [sys.executable, "-c", _BLOCK + snippet],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PYTHONPATH": _SRC, "PATH": "/usr/bin:/bin"},
    )


class TestTheConsoleScriptStartsWithoutTheHostExtra:
    def test_the_cli_module_imports(self) -> None:
        r = _run("import blastbox.host.cli; print('IMPORTED')")
        assert "IMPORTED" in r.stdout, r.stderr[-600:]

    def test_version_actually_prints_a_version(self) -> None:
        """The wrapper parses this output; an empty stdout is what it misreported."""
        r = _run(
            "import sys; sys.argv = ['blastbox', 'version']\n"
            "from blastbox.host.cli import main\n"
            "raise SystemExit(main())\n"
        )
        assert r.returncode == 0, r.stderr[-600:]
        import re

        assert re.search(r"\d+\.\d+", r.stdout), (
            f"no version in stdout {r.stdout!r} -- this is the exact shape the wrapper "
            f"reports as 'no usable version output'"
        )

    @pytest.mark.parametrize("cmd", ["pins", "build-images", "stamp", "doctor"])
    def test_each_build_time_command_is_reachable(self, cmd: str) -> None:
        r = _run(
            f"import sys; sys.argv = ['blastbox', {cmd!r}, '--help']\n"
            "from blastbox.host.cli import main\n"
            "try: main()\n"
            "except SystemExit as e: raise SystemExit(e.code or 0)\n"
        )
        assert r.returncode == 0, r.stderr[-600:]
        assert "structlog" not in r.stderr


class TestTheFallbackLoggerBehaves:
    def test_configure_logging_is_quiet_without_structlog(self, monkeypatch) -> None:
        import blastbox.observability.logging as mod

        monkeypatch.setattr(mod, "structlog", None)
        mod.configure_logging("json", "INFO")  # must not raise

    def test_get_logger_returns_a_usable_logger(self, monkeypatch, caplog) -> None:
        import blastbox.observability.logging as mod

        monkeypatch.setattr(mod, "structlog", None)
        log = mod.get_logger("blastbox.test.fallback")
        with caplog.at_level(logging.INFO):
            log.info("an_event")
        assert "an_event" in caplog.text

    def test_structlog_style_keywords_do_not_raise(self, monkeypatch, caplog) -> None:
        """`log.info("event", key=value)` is a TypeError on a stdlib logger. Those call sites
        live in the host stack, which has real structlog -- the shim is so that an unexpected
        one degrades into a rendered message rather than a crash."""
        import blastbox.observability.logging as mod

        monkeypatch.setattr(mod, "structlog", None)
        log = mod.get_logger("blastbox.test.kwargs")
        with caplog.at_level(logging.WARNING):
            log.warning("api_auth_enabled", scheme="bearer", metrics_public=False)
        assert "api_auth_enabled" in caplog.text
        assert "scheme='bearer'" in caplog.text

    def test_exc_info_and_extra_still_reach_the_stdlib(self, monkeypatch, caplog) -> None:
        import blastbox.observability.logging as mod

        monkeypatch.setattr(mod, "structlog", None)
        log = mod.get_logger("blastbox.test.exc")
        with caplog.at_level(logging.ERROR):
            try:
                raise ValueError("boom")
            except ValueError:
                log.exception("it_failed")
        assert "it_failed" in caplog.text
        assert "ValueError: boom" in caplog.text
