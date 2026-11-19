from __future__ import annotations

import base64
import importlib.util
import os
import stat
from pathlib import Path

import pytest

KEYGEN = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "model-gw" / "keygen.py"


def _keygen():
    spec = importlib.util.spec_from_file_location("rea_model_gw_keygen", KEYGEN)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_keygen_writes_a_0400_key_and_prints_only_the_public_key(tmp_path, capsys):
    kg = _keygen()
    path = tmp_path / "gateway.key"
    assert kg.main(["keygen.py", str(path)]) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    priv = path.read_text().strip()
    out = capsys.readouterr().out.strip()
    assert len(base64.urlsafe_b64decode(priv + "=")) == 32
    assert len(base64.urlsafe_b64decode(out + "=")) == 32
    assert priv not in out


def test_keygen_refuses_to_overwrite(tmp_path):
    kg = _keygen()
    path = tmp_path / "gateway.key"
    path.write_text("x")
    assert kg.main(["keygen.py", str(path)]) == 1
    assert path.read_text() == "x"


def test_keygen_removes_a_partial_key_file_and_reraises_when_the_write_fails(tmp_path, monkeypatch,
                                                                             capsys):
    kg = _keygen()
    path = tmp_path / "gateway.key"

    def boom(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(kg.os, "write", boom)
    with pytest.raises(OSError):
        kg.main(["keygen.py", str(path)])
    assert not path.exists()
    assert capsys.readouterr().out == ""  # no public key for a key that was not kept


def test_keygen_removes_the_file_after_a_short_write(tmp_path, monkeypatch):
    kg = _keygen()
    path = tmp_path / "gateway.key"
    real = os.write
    calls = []

    def short(fd, data):
        calls.append(len(data))
        if len(calls) == 1:
            return real(fd, bytes(data[:5]))
        raise OSError(5, "I/O error")

    monkeypatch.setattr(kg.os, "write", short)
    with pytest.raises(OSError):
        kg.main(["keygen.py", str(path)])
    assert not path.exists()
