from blastbox.host.netpolicy import (
    NONE,
    VALID_EXIT_DRIVERS,
    Personality,
)


def test_none_builtin_is_no_egress():
    assert NONE.name == "none"
    assert NONE.exit_driver == "none"
    assert NONE.inspect is False


def test_valid_exit_drivers_set():
    assert VALID_EXIT_DRIVERS == (
        "none", "drop", "direct", "inetsim", "socks", "wireguard", "openvpn",
    )


def test_personality_carries_opaque_config():
    p = Personality(name="p", exit_driver="socks", inspect=True, config={"endpoint": "h:1"})
    assert p.config["endpoint"] == "h:1"
    assert p.inspect is True
