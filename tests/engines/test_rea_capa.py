from blastbox.engines.rea import capa


def _a(v, t="absolute"):
    return {"type": t, "value": v}


def _rule(ns, matches, *, attack=(), mbc=(), lib=False, sub=False):
    meta = {"name": "x", "lib": lib, "is_subscope_rule": sub,
            "attack": [{"id": i} for i in attack], "mbc": [{"id": i} for i in mbc]}
    if ns is not None:
        meta["namespace"] = ns
    return {"meta": meta, "matches": [[m, {"success": True}] for m in matches]}


def _doc(rules, functions=(), base=0x2000000):
    layout = {"functions": [{"address": _a(f), "matched_basic_blocks": [{"address": _a(b)} for b in bbs]}
                            for f, bbs in functions]}
    return {"meta": {"analysis": {"base_address": _a(base), "layout": layout}}, "rules": rules}


def test_summarize_maps_matches_to_functions_and_drops_building_blocks():
    doc = _doc({
        "encrypt data using RC4": _rule("data-manipulation/encryption/rc4", [_a(0x2001010)], attack=["T1027"],
                                        mbc=["C0027.009"]),
        "create process": _rule("host-interaction/process/create", [_a(0x2002000), _a(0x2002000)]),
        "contain loop": _rule(None, [_a(0x2001000)]),
        "lib rule": _rule("lib/x", [_a(0x2001000)], lib=True),
        "sub rule": _rule("a/b", [_a(0x2001000)], sub=True),
        "embed pe": _rule("executable/subfile/pe", [_a(0, "no address")]),
    }, functions=[(0x2001000, [0x2001008]), (0x2002000, [])])
    out = capa.summarize(doc)
    assert [r["rule"] for r in out] == ["encrypt data using RC4", "embed pe", "create process"]
    rc4 = out[0]
    # The instruction at 0x2001010 sits in the block at 0x2001008, which belongs to 0x2001000.
    assert rc4 == {"rule": "encrypt data using RC4", "namespace": "data-manipulation/encryption/rc4",
                   "attack": ["T1027"], "mbc": ["C0027.009"], "functions": ["0x2001000"]}
    assert out[1]["functions"] == [] and out[2]["functions"] == ["0x2002000"]


def test_summarize_rebases_into_ghidras_image():
    doc = _doc({"r": _rule("n/s", [_a(0x2001234)])}, functions=[(0x2001200, [])])
    out = capa.summarize(doc, rebase=lambda va: va - 0x2000000 + 0x100000)
    assert out[0]["functions"] == ["0x101200"]
    assert capa.base_address(doc) == 0x2000000


def test_dotnet_tokens_are_labelled_not_addresses():
    doc = _doc({"r": _rule("n/s", [_a(0x06000012, "dn token"), _a([0x06000013, 4], "dn token offset")])})
    assert capa.summarize(doc)[0]["functions"] == ["token:0x6000012", "token:0x6000013"]


def test_summarize_caps_and_tolerates_junk():
    rules = {f"r{i}": _rule("n/s", [_a(0x1000 + j) for j in range(50)]) for i in range(300)}
    rules["bad"] = {"meta": "nope"}
    rules["x" * 1000] = _rule("n/" + "y" * 1000, [["not", "an", "address"]])
    out = capa.summarize(_doc(rules))
    assert len(out) == capa.MAX_RULES
    assert all(len(r["functions"]) <= capa.MAX_FUNCTIONS_PER_RULE for r in out)
    assert all(len(r["rule"]) <= capa.MAX_TEXT and len(r["namespace"]) <= capa.MAX_TEXT for r in out)
    assert capa.summarize(None) == [] and capa.summarize({"rules": []}) == []
    assert capa.base_address({"meta": {"analysis": {"base_address": _a(1, "relative")}}}) is None
