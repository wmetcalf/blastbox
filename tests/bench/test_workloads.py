# tests/bench/test_workloads.py
from blastbox.bench._workloads import available_sandbox_backends, soffice_argv


def test_soffice_argv_is_a_list_with_convert_to():
    argv = soffice_argv("/tmp/in.txt", "/tmp/out")
    assert isinstance(argv, list)
    assert "--convert-to" in argv and "pdf" in argv


def test_available_sandbox_backends_includes_none_first():
    backends = available_sandbox_backends()
    assert backends[0] == "none"  # the unsandboxed baseline is always present
