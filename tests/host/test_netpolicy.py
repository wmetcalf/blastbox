from blastbox.host.netpolicy import (
    NONE,
    VALID_EXIT_DRIVERS,
    Personality,
    parse_personalities,
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


def test_registry_always_has_none():
    reg = parse_personalities({})
    assert reg["none"].exit_driver == "none"


def test_parse_declares_personality_lowercased_name():
    reg = parse_personalities({"BLASTBOX_NETPOLICY_FAKENET": "exit=inetsim"})
    assert "fakenet" in reg
    assert reg["fakenet"].exit_driver == "inetsim"


def test_parse_inspect_flag_and_config():
    reg = parse_personalities(
        {"BLASTBOX_NETPOLICY_PIA": "exit=wireguard,inspect=true,conf=/run/pia.conf"}
    )
    p = reg["pia"]
    assert p.exit_driver == "wireguard"
    assert p.inspect is True
    assert p.config == {"conf": "/run/pia.conf"}


def test_parse_unknown_driver_skipped_failclosed(capsys):
    reg = parse_personalities({"BLASTBOX_NETPOLICY_BAD": "exit=teleport"})
    assert "bad" not in reg
    assert "teleport" in capsys.readouterr().err


def test_parse_missing_exit_skipped(capsys):
    reg = parse_personalities({"BLASTBOX_NETPOLICY_NOEXIT": "inspect=true"})
    assert "noexit" not in reg
