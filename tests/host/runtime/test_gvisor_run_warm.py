"""Unit coverage for the gVisor warm entrypoint deploy/gvisor/run_warm.py.

It lives under deploy/ (not the package), so load it by path. The lazy `engines` import
(inside main()) keeps the module importable here without engines.py present."""

import importlib.util
from pathlib import Path

_RUN_WARM = Path(__file__).resolve().parents[3] / "deploy" / "gvisor" / "run_warm.py"


def _load_run_warm():
    spec = importlib.util.spec_from_file_location("gvisor_run_warm", _RUN_WARM)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_idle_timeout_parsing():
    m = _load_run_warm()
    assert m._idle_timeout_s("") == 86400.0
    assert m._idle_timeout_s(None) == 86400.0
    assert m._idle_timeout_s("30") == 30.0
    assert m._idle_timeout_s("  45.5 ") == 45.5
    assert (
        m._idle_timeout_s("garbage") == 86400.0
    )  # bad value falls back, must not raise


def test_engine_name_baked_file_then_env_then_default(monkeypatch, tmp_path):
    m = _load_run_warm()
    engine_file = tmp_path / "engine"
    monkeypatch.setattr(m, "ENGINE_FILE", str(engine_file))

    # baked file wins
    engine_file.write_text("clippyshot.engine:ClippyShotEngine\n")
    assert m._engine_name() == "clippyshot.engine:ClippyShotEngine"

    # no baked file → env override
    engine_file.unlink()
    monkeypatch.setenv("BLASTBOX_GVISOR_ENGINE", "probe")
    assert m._engine_name() == "probe"

    # neither → default
    monkeypatch.delenv("BLASTBOX_GVISOR_ENGINE", raising=False)
    assert m._engine_name() == "probe"


def test_setup_breadcrumb_is_written(monkeypatch, tmp_path):
    m = _load_run_warm()
    monkeypatch.setattr(m, "CTRL_DIR", str(tmp_path / "ctrl"))
    m._write_setup_breadcrumb("engine setup failed: boom")
    assert (
        tmp_path / "ctrl" / "setup_error"
    ).read_text() == "engine setup failed: boom"
