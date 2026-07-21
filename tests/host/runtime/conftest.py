import pytest


@pytest.fixture
def vm_dispatcher_factory(tmp_path):
    """Build a VmJobDispatcher with injected stores and a stub validator."""
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    def _factory(*, store, blob_store, validate_ok=False):
        def _validate(in_path):
            out = in_path.parent.parent / "output"
            out.mkdir(parents=True, exist_ok=True)
            (out / "metadata.json").write_bytes(b'{"status":"ok"}')
            return ({"detected": "test"}, validate_ok)

        return VmJobDispatcher(
            store=store,
            job_root=tmp_path,
            validate=_validate,
            blob_store=blob_store,
        )

    return _factory
