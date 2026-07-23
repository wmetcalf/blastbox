import pytest


@pytest.fixture
def vm_dispatcher_factory(tmp_path):
    """Build a VmJobDispatcher with injected stores and a stub validator."""
    from blastbox.host.runtime.vm_dispatch import VmJobDispatcher

    def _factory(*, store, blob_store, validate_ok=False, **dispatcher_kwargs):
        def _validate(in_path):
            out = in_path.parent.parent / "output"
            out.mkdir(parents=True, exist_ok=True)
            (out / "metadata.json").write_bytes(b'{"status":"ok"}')
            return ({"detected": "test"}, validate_ok)

        # Tests exercising the upload-retry policy want a fast, deterministic
        # in-line backoff rather than the production default (1s) — let callers
        # override via dispatcher_kwargs, but keep the suite fast by default.
        dispatcher_kwargs.setdefault("put_output_retry_backoff_s", 0.0)

        return VmJobDispatcher(
            store=store,
            job_root=tmp_path,
            validate=_validate,
            blob_store=blob_store,
            **dispatcher_kwargs,
        )

    return _factory
