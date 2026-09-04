def test_package_imports():
    import blastbox.contract as c

    assert c.__doc__ is not None


def test_public_api_and_schema():
    from blastbox.contract import (  # noqa: F401
        Hash,
        Detection,
        Page,
        EmbeddedResource,
        Record,
        Envelope,
        seal_envelope,
        find_by_type,
        json_schema,
    )

    schema = json_schema()
    assert schema["title"] == "Envelope"
    assert "properties" in schema
