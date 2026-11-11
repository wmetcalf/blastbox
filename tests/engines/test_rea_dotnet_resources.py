""".NET embedded resources: hidden payloads, decoys and the benign bar."""

import gzip
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from blastbox.engines.rea import dotnet_resources as dr
from blastbox.engines.rea import sufficiency
from blastbox.engines.rea import sweep as sw
from blastbox.engines.rea.continuation import State, unpack
from blastbox.engines.rea.prompts import Framer
from blastbox.engines.rea.runner import rea_env, run_dotnet_resources
from blastbox.limits import Limits
from tests.engines.test_rea_sweep import (  # noqa: F401  (_workdir is an autouse fixture)
    FIXTURES,
    FakeGhidra,
    FakeUnpack,
    _codes,
    _fields,
    _workdir,
    factory,
)

DLL = FIXTURES / "dotnet.dll"
SAMPLE = (FIXTURES / "sample.exe").read_bytes()
dnfile = pytest.importorskip("dnfile")


def _by_name(doc):
    return {r["name"]: r for r in doc["resources"]}


def _hidden(doc):
    return {(h["resource"], h.get("entry")): h for h in doc["hidden"]}


# ------------------------------------------------------------------ the scanner


def test_scan_lists_every_resource_with_size_and_entropy(tmp_path):
    doc = dr.scan(DLL, tmp_path)
    assert doc["resources_total"] == 6
    res = _by_name(doc)
    assert res["Fixture.blob.bin"]["size"] == 72 * 1024 and res["Fixture.blob.bin"]["entropy"] > 7.9
    assert res["Fixture.blob.bin"]["container"] is False
    props = res["Fixture.Properties.Resources.resources"]
    assert props["container"] is True and props["entries_total"] == 3
    entries = {e["name"]: e for e in props["entries"]}
    assert entries["AppTitle"]["type"] == "System.String"
    assert entries["Blob"]["size"] == 66 * 1024 and entries["Blob"]["type"] == "System.ByteArray"
    assert entries["Pad"]["entropy"] == 0.0
    assert res["Fixture.logo.png"]["format"] == "png"


def test_scan_flags_large_high_entropy_resources_and_container_entries(tmp_path):
    hidden = _hidden(dr.scan(DLL, tmp_path))
    blob = hidden[("Fixture.blob.bin", None)]
    assert "decoded" not in blob and (tmp_path / blob["file"]).read_bytes() == dr_bytes("blob")
    entry = hidden[("Fixture.Properties.Resources.resources", "Blob")]
    assert entry["size"] == 66 * 1024 and (tmp_path / entry["file"]).stat().st_size == 66 * 1024
    assert ("Fixture.logo.png", None) not in hidden  # media, not a payload
    assert ("Fixture.Properties.Resources.resources", "Pad") not in hidden


def dr_bytes(seed: str) -> bytes:
    out = bytearray()
    h = seed.encode()
    while len(out) < 72 * 1024:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[: 72 * 1024])


def test_scan_decodes_gzip_xor_and_base64_pes(tmp_path):
    hidden = _hidden(dr.scan(DLL, tmp_path))
    gz = hidden[("Fixture.payload.gz", None)]
    assert gz["decoded"] == "gzip" and (tmp_path / gz["decoded_file"]).read_bytes() == SAMPLE
    x = hidden[("Fixture.x.dat", None)]
    assert x["decoded"] == "xor:0x5a" and (tmp_path / x["decoded_file"]).read_bytes() == SAMPLE[:1024]
    b = hidden[("Fixture.b64.txt", None)]
    assert b["decoded"] == "base64" and (tmp_path / b["decoded_file"]).read_bytes() == SAMPLE[:1024]


def test_scan_notes_loader_member_references(tmp_path):
    refs = dr.scan(DLL, tmp_path)["loader_refs"]
    assert {"Assembly.Load", "Assembly.GetManifestResourceStream", "SymmetricAlgorithm.CreateDecryptor"} <= set(refs)
    assert "Console.WriteLine" not in refs


def test_scan_caps_counts_and_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "MAX_RESOURCES", 2)
    monkeypatch.setattr(dr, "MAX_HIDDEN", 1)
    doc = dr.scan(DLL, tmp_path)
    assert len(doc["resources"]) == 2 and doc["resources_total"] == 6 and len(doc["hidden"]) == 1
    assert len(list(tmp_path.iterdir())) <= 2
    # Everything after the one payload the cap kept: 4 resources and the 3 entries of the container.
    assert doc["items_unread"] == 7


def test_decode_only_accepts_a_real_pe_header():
    assert dr.decode(gzip.compress(b"MZ not a pe" * 100)) is None
    assert dr.decode(bytes(b ^ 0x11 for b in b"MZ" + b"\x00" * 200)) is None
    assert dr.decode(SAMPLE) == ("plain", SAMPLE)


def test_decode_caps_decompressed_output(monkeypatch):
    monkeypatch.setattr(dr, "MAX_DECODED_BYTES", 1024)
    assert dr.decode(gzip.compress(SAMPLE)) is None  # the PE is over the cap: not decoded


def test_scan_of_a_non_dotnet_file_is_an_error_not_a_crash(tmp_path):
    doc = dr.scan(FIXTURES / "sample.exe", tmp_path)
    assert doc["error"] == "not_dotnet" and doc["resources"] == []


def test_the_scanner_runs_as_an_isolated_subprocess(tmp_path):
    out = tmp_path / "o"
    status, data = run_dotnet_resources(DLL, out, 60, env=rea_env(tmp_path / "e", {"PATH": "/usr/bin:/bin"}),
                                        python=sys.executable, max_kb=4 * 1024 * 1024, max_stdout=1 << 20,
                                        max_write_bytes=1 << 26)
    assert status == "ok"
    doc = json.loads(data)
    assert doc["resources_total"] == 6 and any(h.get("decoded") == "gzip" for h in doc["hidden"])
    assert all((out / h["file"]).is_file() for h in doc["hidden"] if "file" in h)


def test_the_scanner_subprocess_fails_without_its_python(tmp_path):
    status, _ = run_dotnet_resources(DLL, tmp_path / "o", 60, env={}, python="/nonexistent/python",
                                     max_kb=1 << 20, max_stdout=1 << 20, max_write_bytes=1 << 20)
    assert status == "failed"


# ------------------------------------------------------------------ the sweep


class FakeDotnet:
    """Stands in for run_dotnet_resources: the real scan, in-process (or a fixed status)."""

    def __init__(self, status="ok", doc=None):
        self.status, self.doc = status, doc
        self.calls: list[dict] = []

    def __call__(self, sample, outdir, timeout_s, *, env, python, max_kb, max_stdout, max_write_bytes):
        self.calls.append(dict(sample=sample, outdir=outdir, python=python))
        if self.status != "ok":
            return self.status, b""
        outdir.mkdir(parents=True, exist_ok=True)
        doc = self.doc if self.doc is not None else dr.scan(DLL, outdir)
        return "ok", json.dumps(doc).encode()


def _drun(sample, tmp_path, dotnet):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=FakeGhidra(), unpack_fn=FakeUnpack("failed"),
                            capa_fn=lambda *a, **k: ("ok", b'{"rules": {}}'), dotnet_fn=dotnet)
    return eng.detonate(sample, out, Limits(timeout_s=600)), out


def test_hidden_payloads_become_members_warnings_and_evidence(tmp_path):
    fd = FakeDotnet()
    res, out = _drun(DLL, tmp_path, fd)
    f = _fields(res)
    assert fd.calls and f["kind"] == "dotnet" and f["hidden_payloads"] == 5
    assert _codes(res).count("hidden_payload") == 5
    members = {(out / a.path).read_bytes() for a in res.artifacts if a.id.startswith("member-")}
    assert SAMPLE in members and SAMPLE[:1024] in members and dr_bytes("blob") in members
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    ev = state.sweep["dotnet_resources"]
    assert ev["resources_total"] == 6 and "Assembly.Load" in ev["loader_refs"]
    gz = next(h for h in ev["hidden_payloads"] if h["resource"] == "Fixture.payload.gz")
    assert gz["decoded"] == "gzip" and gz["decoded_sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    assert gz["decoded_member"].startswith("member-") and gz["member"].startswith("member-")
    report = json.loads((out / "report.json").read_text())
    assert report["dotnet_resources"]["resources_total"] == 6


def test_no_hidden_payload_is_zero_and_no_warning(tmp_path):
    doc = {"resources_total": 1, "resources": [{"name": "a", "size": 3, "entropy": 1.0, "container": False}],
           "loader_refs": [], "hidden": []}
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    assert _fields(res)["hidden_payloads"] == 0 and "hidden_payload" not in _codes(res)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dotnet_resources"]["hidden_payloads"] == []


@pytest.mark.parametrize("status", ["failed", "timeout", "too_large"])
def test_a_failed_scan_is_a_warning(tmp_path, status):
    res, _out = _drun(DLL, tmp_path, FakeDotnet(status))
    assert "dotnet_resources_failed" in _codes(res) and "hidden_payloads" not in _fields(res)


def test_a_malformed_scanner_document_is_a_warning(tmp_path):
    res, _out = _drun(DLL, tmp_path, FakeDotnet(doc={"resources": "nope", "hidden": [{"file": "../../etc/x"}]}))
    assert "dotnet_resources_failed" in _codes(res) and "hidden_payloads" not in _fields(res)


def test_scanner_file_names_cannot_escape_its_dir(tmp_path):
    doc = {"resources_total": 1, "resources": [], "loader_refs": [],
           "hidden": [{"resource": "r", "size": 1, "entropy": 8.0, "file": "../../../etc/passwd"}]}
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    for a in res.artifacts:
        if a.id.startswith("member-"):
            assert b"root:" not in (out / a.path).read_bytes()


def test_native_pes_are_not_scanned(tmp_path):
    fd = FakeDotnet()
    _drun(FIXTURES / "sample.exe", tmp_path, fd)
    assert fd.calls == []


# ------------------------------------------------------------------ payloads carried in image pixels


def _png(w, h, rgba):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    rows = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 1)) + chunk(b"IEND", b""))


def _bmp(w, h, rgb):
    """A bottom-up 24-bit BMP from top-down RGB rows, as System.Drawing saves one."""
    pad = b"\x00" * (-w * 3 % 4)
    body = b""
    for y in range(h - 1, -1, -1):
        row = rgb[y * w * 3:(y + 1) * w * 3]
        body += b"".join(row[i + 2:i + 3] + row[i + 1:i + 2] + row[i:i + 1] for i in range(0, len(row), 3)) + pad
    return (b"BM" + struct.pack("<IHHI", 54 + len(body), 0, 0, 54)
            + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body), 2835, 2835, 0, 0) + body)


def _columns(stream, w, h, channels):
    """``stream`` laid column-major into a ``w``x``h`` image, as top-down row-major pixel bytes."""
    stream = stream.ljust(w * h * channels, b"\x00")
    assert len(stream) == w * h * channels
    out = bytearray(len(stream))
    for x in range(w):
        for y in range(h):
            src = (x * h + y) * channels
            out[(y * w + x) * channels:(y * w + x + 1) * channels] = stream[src:src + channels]
    return bytes(out)


def _noise(n, seed=b"n"):
    out = bytearray()
    while len(out) < n:
        seed = hashlib.sha256(seed).digest()
        out += seed
    return bytes(out[:n])


def _serialized(image):
    return b"\x00\x01\x00\x00\x00\xff\xff\xff\xff" + b"System.Drawing.Bitmap".ljust(153, b"\x00") + image


def _stage1_bmp(payload=SAMPLE):
    h = 97
    w = -(-len(payload) // (3 * h)) + 3  # trailing all-zero columns, as the real carriers have
    return _bmp(w, h, _columns(payload, w, h, 3))


def _stage2_png(payload, key=b"\x42\x29\x42"):
    """A two-block canvas: block 0 (top-left) is a length-prefixed XORed PE read column-major as
    little-endian ARGB ints; block 1 (bottom-right) is opaque noise."""
    stream = struct.pack("<I", len(payload)) + dr._xor(payload, key)
    bh = 301
    bw = -(-len(stream) // (4 * bh))
    block0 = bytearray(_columns(stream, bw, bh, 4))
    block0[0::4], block0[2::4] = block0[2::4], block0[0::4]  # the int's low byte is blue
    nw, nh = 150, 120
    w, h = bw + nw, bh + nh
    canvas = bytearray(w * h * 4)
    for y in range(bh):
        canvas[y * w * 4:(y * w + bw) * 4] = block0[y * bw * 4:(y + 1) * bw * 4]
    noise = _noise(nw * nh * 3)
    for y in range(nh):
        for x in range(nw):
            at = ((bh + y) * w + bw + x) * 4
            canvas[at:at + 4] = noise[(y * nw + x) * 3:(y * nw + x) * 3 + 3] + b"\xff"
    return _png(w, h, bytes(canvas))


def test_decode_recovers_a_repeating_xor_key_from_the_dos_header():
    assert dr.decode(dr._xor(SAMPLE, b"\x42\x29\x42")) == ("xor:0x422942", SAMPLE)
    assert dr.decode(dr._xor(SAMPLE, b"\x5a")) == ("xor:0x5a", SAMPLE)
    assert dr.decode(dr._xor(SAMPLE, _noise(31))) is None  # longer than the header can confirm


def test_a_pe_stored_as_bitmap_pixels_is_recovered():
    image = dr.load_image(_serialized(_stage1_bmp()))
    assert image is not None and image.fmt == "bmp" and image.a is None
    method, pe = dr.image_payload(image)
    # sample.exe ends in an overlay (its COFF symbols), so the carrier's zero padding cannot be told from it
    assert method == "image:col-rgb/plain" and pe.startswith(SAMPLE) and not pe[len(SAMPLE):].strip(b"\x00")
    dll = DLL.read_bytes()  # no overlay: the padding is trimmed and the recovery is exact
    assert dr.image_payload(dr.load_image(_stage1_bmp(dll))) == ("image:col-rgb/plain", dll)


def test_a_length_prefixed_xored_pe_in_a_padded_png_canvas_is_recovered():
    payload = DLL.read_bytes()
    image = dr.load_image(_stage2_png(payload))
    assert image is not None and image.fmt == "png"
    found = dr.blocks(image)
    assert len(found) == 2 and (found[1].w, found[1].h) == (150, 120)
    assert dr.image_payload(image) == ("image:col-bgra+len/xor:0x422942", payload)


def test_a_block_edge_that_is_zero_in_its_first_rows_is_not_cut_short():
    w, h = 80, 60
    px = bytearray(_noise(w * h * 4))
    for y in range(dr.BLOCK_PROBE + 4):  # the right third is zero wherever the probe looks
        px[(y * w + 50) * 4:(y + 1) * w * 4] = bytes((w - 50) * 4)
    canvas = bytearray(100 * 90 * 4)
    for y in range(h):
        canvas[y * 100 * 4:(y * 100 + w) * 4] = px[y * w * 4:(y + 1) * w * 4]
    for y in range(h, 90):
        canvas[(y * 100 + w) * 4:(y + 1) * 100 * 4] = b"\x07" * 80
    first = dr.blocks(dr.load_image(_png(100, 90, bytes(canvas))))[0]
    assert (first.w, first.h) == (w, h)


def test_noise_pixels_are_flagged_and_pictures_are_not():
    w, h = 200, 160
    noisy = dr.load_image(_png(w, h, b"".join(_noise(w * h * 3)[i:i + 3] + b"\xff" for i in range(0, w * h * 3, 3))))
    assert dr.image_payload(noisy) is None and dr.image_noise(noisy) >= dr.NOISE_MIN_ENTROPY
    picture = bytearray()
    for y in range(h):
        for x in range(w):
            picture += bytes(((x * 255) // w, (y * 255) // h, ((x + y) * 7) & 255, 255))
    smooth = dr.load_image(_png(w, h, bytes(picture)))
    assert dr.image_payload(smooth) is None and dr.image_noise(smooth) is None
    assert dr.image_noise(dr.load_image(_png(40, 40, _noise(40 * 40 * 4)))) is None  # too small to carry one


@pytest.mark.parametrize("blob", [
    b"\x89PNG\r\n\x1a\n", b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, b"BM", b"BM" + b"\xff" * 64,
    _png(64, 64, _noise(64 * 64 * 4))[:300],
    b"BM" + struct.pack("<IHHI", 0, 0, 0, 54) + struct.pack("<IiiHHI", 40, 1 << 30, 1 << 30, 1, 32, 0),
    b"\x89PNG\r\n\x1a\n" + struct.pack(">I4s", 13, b"IHDR") + struct.pack(">IIBBBBB", 1 << 31, 1 << 31, 8, 6, 0, 0, 0),
    b"\x89PNG\r\n\x1a\n" + struct.pack(">I4s", 13, b"IHDR") + b"\x00\x00\x00",  # the header chunk is cut short
])
def test_malformed_images_are_not_images(blob):
    assert dr.load_image(blob) is None


def test_png_filters_are_undone():
    w, h = 16, 8
    px = _noise(w * h * 4)
    rows, prev = b"", bytes(w * 4)
    for y in range(h):
        line = px[y * w * 4:(y + 1) * w * 4]
        kind = y % 5
        left = bytes(4) + line[:-4]
        corner = bytes(4) + prev[:-4]

        def paeth(a, b, c):
            pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
            return a if pa <= pb and pa <= pc else b if pb <= pc else c
        pred = {0: bytes(w * 4), 1: left, 2: prev, 3: bytes((a + b) >> 1 for a, b in zip(left, prev)),
                4: bytes(paeth(a, b, c) for a, b, c in zip(left, prev, corner))}[kind]
        rows += bytes([kind]) + bytes((v - q) & 255 for v, q in zip(line, pred))
        prev = line

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))
    image = dr.load_image(png)
    assert image is not None and (image.r, image.g, image.b, image.a) == (px[0::4], px[1::4], px[2::4], px[3::4])


def test_a_recovered_stage_is_described_and_its_own_resources_scanned(tmp_path):
    state = dr._Scan(tmp_path)
    carrier = _serialized(_stage2_png(DLL.read_bytes()))
    state.consider(carrier, dr.entropy(carrier), "App.Properties.Resources.resources", "wwXf", 0)
    top = state.hidden[0]
    assert top["image"].startswith("png ") and top["decoded"] == "image:col-bgra+len/xor:0x422942"
    assert (tmp_path / top["decoded_file"]).read_bytes() == DLL.read_bytes()
    stage = top["stage"]
    assert stage["dotnet"] is True and stage["module"] and stage["types"] > 0 and stage["methods"] > 0
    assert "Assembly.Load" in stage["loader_refs"]
    inner = {h["resource"] for h in state.hidden[1:]}
    assert f"{stage['module']}!Fixture.blob.bin" in inner and f"{stage['module']}!Fixture.payload.gz" in inner
    assert len(state.hidden) <= dr.MAX_HIDDEN


def test_stages_are_not_followed_past_the_depth_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "MAX_DEPTH", 0)
    state = dr._Scan(tmp_path)
    carrier = _stage2_png(DLL.read_bytes())
    state.consider(carrier, dr.entropy(carrier), "r", None, 0)
    assert len(state.hidden) == 1 and state.hidden[0]["stage"]["dotnet"] is True


def test_a_native_stage_is_described_as_not_dotnet(tmp_path):
    state = dr._Scan(tmp_path)
    carrier = _serialized(_stage1_bmp())
    state.consider(carrier, dr.entropy(carrier), "r", "dzh", 0)
    assert [h.get("stage") for h in state.hidden] == [{"dotnet": False}]


def test_a_noise_image_is_a_hidden_payload_and_a_picture_is_not(tmp_path):
    state = dr._Scan(tmp_path)
    noisy = _png(200, 160, b"".join(_noise(96000)[i:i + 3] + b"\xff" for i in range(0, 96000, 3)))
    state.consider(noisy, dr.entropy(noisy), "r", "pic", 0)
    assert state.hidden[0]["noise"] >= dr.NOISE_MIN_ENTROPY and "decoded" not in state.hidden[0]
    flat = _png(200, 160, bytes(200 * 160 * 4))
    state.consider(flat, dr.entropy(flat), "r", "flat", 0)
    assert len(state.hidden) == 1


def _png_header(w, h, *, depth=8, colour=6, interlace=0):
    """A PNG that declares ``w`` x ``h`` over one small IDAT: the size check reads only the header."""
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, colour, 0, 0, interlace))
            + chunk(b"IDAT", zlib.compress(bytes(64))) + chunk(b"IEND", b""))


def _bmp_header(w, h):
    return b"BM" + struct.pack("<IHHI", 54, 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, 0, 0, 0, 0, 0)


def test_images_over_the_pixel_limit_are_counted_not_read(tmp_path):
    """A readable kind of image too large to decode may carry anything: it is unread, like one past
    the time budget, so a benign verdict cannot rest on the scan."""
    side = int(dr.MAX_IMAGE_PIXELS ** 0.5) + 1
    state = dr._Scan(tmp_path)
    for carrier in (_png_header(side, side), _bmp_header(side, side), _bmp_header(side, -side),
                    _serialized(_bmp_header(side, side))):
        assert dr.load_image(carrier) is None
        state.consider(carrier, dr.entropy(carrier), "r", "big", 0)
    assert state.hidden == [] and state.items_unread == 4


def test_images_of_an_unreadable_kind_or_broken_are_not_counted(tmp_path):
    """Only size is counted: a palette or interlaced PNG, a truncated one and a picture that was
    read leave the count alone, so an ordinary program's icons do not hold its verdict."""
    state = dr._Scan(tmp_path)
    flat = _png(20, 16, bytes(20 * 16 * 4))
    for carrier in (_png_header(64, 64, colour=3), _png_header(64, 64, interlace=1), _png_header(64, 64),
                    _png_header(0, 64), _bmp_header(64, 64), flat, b"BM" + bytes(64), b"plain text"):
        state.consider(carrier, dr.entropy(carrier), "r", "pic", 0)
    assert state.hidden == [] and state.items_unread == 0


def test_images_past_the_time_budget_are_counted_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "IMAGE_BUDGET_S", 0.0)
    state = dr._Scan(tmp_path)
    # Only what the scanner would have read counts: "BM" somewhere in a text is not a bitmap.
    for carrier in (_stage1_bmp(), _serialized(_stage1_bmp()), b"BM" + bytes(64), b"an IBM mainframe"):
        state.consider(carrier, dr.entropy(carrier), "r", "dzh", 0)
    assert state.hidden == [] and state.items_unread == 2
    doc = {"resources_total": 1, "resources": [], "loader_refs": [], "hidden": [], "items_unread": 3}
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    assert any(w.code == "dotnet_resources_failed" and "3 resource item(s) not read" in w.message
               for w in res.warnings)
    # ... and the evidence says so: the verdict rule will not call the program benign over them.
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dotnet_resources"]["items_unread"] == 3


def test_a_scan_that_read_every_image_says_nothing_of_unread_ones(tmp_path):
    _res, out = _drun(DLL, tmp_path, FakeDotnet())
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert not {"items_unread", "scan_failed"} & set(state.sweep["dotnet_resources"])


def _pe(*resources):
    return SimpleNamespace(net=SimpleNamespace(resources=list(resources)))


def _res(name, data):
    return SimpleNamespace(name=name, data=data, size=len(data) if isinstance(data, bytes) else 0)


def _container(entries):
    return SimpleNamespace(_data=b"", entries=[SimpleNamespace(name=n, value=v, type_name="System.Byte[]")
                                               for n, v in entries])


def _found(state):
    return {(h["resource"], h.get("entry")): str(h.get("decoded", ""))[:6] for h in state.hidden}


def test_a_carrier_past_the_listing_caps_is_still_found(tmp_path):
    """The caps bound what the scan lists, not what it reads: a payload behind 64 dull resources,
    or behind 64 dull entries of one container, was never looked at."""
    dull = [_res(f"r{i}", b"text %d" % i) for i in range(dr.MAX_RESOURCES + 5)]
    entries = [(f"e{i}", b"text %d" % i) for i in range(dr.MAX_ENTRIES + 5)] + [("late", _stage1_bmp())]
    state, doc = dr._Scan(tmp_path), {"resources": []}
    state.resources(_pe(*dull, _res("last.bin", _stage1_bmp()), _res("App.resources", _container(entries))),
                    doc, "", 0)
    assert doc["resources_total"] == dr.MAX_RESOURCES + 7 and len(doc["resources"]) == dr.MAX_RESOURCES
    assert _found(state) == {("last.bin", None): "image:", ("App.resources", "late"): "image:"}
    assert state.items_unread == 0
    # A listed container lists MAX_ENTRIES of its entries and says how many it has.
    (tmp_path / "second").mkdir()
    state, doc = dr._Scan(tmp_path / "second"), {"resources": []}
    state.resources(_pe(_res("App.resources", _container(entries))), doc, "", 0)
    row = doc["resources"][0]
    assert row["entries_total"] == dr.MAX_ENTRIES + 6 and len(row["entries"]) == dr.MAX_ENTRIES
    assert _found(state) == {("App.resources", "late"): "image:"}


def test_items_the_scan_did_not_reach_are_counted_unread(tmp_path, monkeypatch):
    """Past the hidden-payload cap or the scan's time budget nothing is decoded, so every item
    left may be a payload: the count holds a benign verdict back."""
    pe = _pe(_res("a", _stage1_bmp()), _res("b", b"plain text"), _res("c", _container([("x", _stage1_bmp())])))
    monkeypatch.setattr(dr, "MAX_HIDDEN", 1)
    state = dr._Scan(tmp_path)
    state.resources(pe, None, "", 0)
    assert _found(state) == {("a", None): "image:"} and state.items_unread == 2
    monkeypatch.setattr(dr, "SCAN_BUDGET_S", 0.0)
    state = dr._Scan(tmp_path)
    state.resources(pe, None, "", 0)
    assert state.hidden == [] and state.items_unread == 3


def test_an_item_that_breaks_the_scanner_costs_that_item_not_the_scan(tmp_path, monkeypatch):
    real = dr.decode

    def decode(data):
        if data == b"boom":
            raise ValueError("a parser bug")
        return real(data)

    monkeypatch.setattr(dr, "decode", decode)
    state = dr._Scan(tmp_path)
    state.resources(_pe(_res("bad", b"boom"), _res("late", _stage1_bmp())), None, "", 0)
    assert _found(state) == {("late", None): "image:"} and state.items_unread == 1
    # One entry of a container costs that entry, not the entries after it.
    (tmp_path / "entries").mkdir()
    state = dr._Scan(tmp_path / "entries")
    state.resources(_pe(_res("App.resources", _container([("bad", b"boom"), ("late", _stage1_bmp())]))), None, "", 0)
    assert _found(state) == {("App.resources", "late"): "image:"} and state.items_unread == 1


def test_a_resource_the_parser_cannot_give_costs_that_resource_not_the_scan(tmp_path):
    """dnfile reads lazily: asking for one resource's data can raise on a crafted table."""

    class Broken:
        name = "broken"

        @property
        def data(self):
            raise ValueError("a bad resource offset")

    state = dr._Scan(tmp_path)
    state.resources(_pe(Broken(), _res("late", _stage1_bmp())), {"resources": []}, "", 0)
    assert _found(state) == {("late", None): "image:"} and state.items_unread == 1


def test_entries_that_share_one_slice_of_the_container_are_read_once(tmp_path, monkeypatch):
    """500 user-typed entries at one offset are one slice: reading it 500 times is the sample
    spending the scan's time budget for it."""
    read = []
    monkeypatch.setattr(dr, "decode", lambda data: read.append(len(data)))
    entries = [SimpleNamespace(name=f"e{i}", value=None, data=None, type_name="System.Drawing.Bitmap",
                               struct=SimpleNamespace(DataOffset=0)) for i in range(500)]
    container = SimpleNamespace(entries=entries, _data=b"HDR-" + bytes(4096),
                                struct=SimpleNamespace(DataSectionOffset=4))
    state, doc = dr._Scan(tmp_path), {"resources": []}
    state.resources(_pe(_res("c", container)), doc, "", 0)
    assert read == [4096] and state.items_unread == 0
    assert [e["size"] for e in doc["resources"][0]["entries"]] == [4096] * dr.MAX_ENTRIES


_FAILED = {"resources_total": 0, "resources": [], "loader_refs": [], "hidden_payloads": [], "scan_failed": True}


def _raising(*_a, **_k):
    raise OSError("no scanner")


@pytest.mark.parametrize("dotnet", [
    FakeDotnet("failed"), FakeDotnet("timeout"), FakeDotnet("too_large"), _raising,
    FakeDotnet(doc={"resources": "nope", "hidden": []}),
    FakeDotnet(doc={"resources_total": 0, "resources": [], "loader_refs": [], "hidden": [], "error": "parse_failed"}),
])
def test_a_scan_that_read_nothing_is_recorded_as_failed_not_as_clean(tmp_path, dotnet):
    """Nothing looked for a hidden payload, so the evidence says so (the verdict rule will not call
    the program benign) and the summary does not count zero hidden payloads."""
    res, out = _drun(DLL, tmp_path, dotnet)
    assert "dotnet_resources_failed" in _codes(res) and "hidden_payloads" not in _fields(res)
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dotnet_resources"] == _FAILED


def test_a_scan_there_was_no_time_for_is_recorded_as_failed(tmp_path):
    fd, warnings = FakeDotnet(), []
    eng = sw.ReaSweepEngine(runner_factory=factory(), ghidra_fn=FakeGhidra(), unpack_fn=FakeUnpack("failed"),
                            dotnet_fn=fd)
    assert eng._dotnet(DLL, tmp_path, tmp_path / "members", 0, 0.5, warnings) == (_FAILED, [])
    assert not fd.calls and [w.code for w in warnings] == ["dotnet_resources_failed"]


def test_the_sweep_keeps_the_dimensions_of_the_widest_image_the_scanner_reads(tmp_path):
    """One row of MAX_IMAGE_PIXELS pixels is a 7-digit width: the scanner reads it, so the sweep
    must not drop its ``image`` (the pixel-hidden-executable ground and the prompts key on it)."""
    wide = f"png {dr.MAX_IMAGE_PIXELS}x1"
    assert sw._IMAGE.fullmatch(wide) and not sw._IMAGE.fullmatch(f"png {dr.MAX_IMAGE_PIXELS * 10}x1")
    hidden = {"resource": "r.resources", "entry": "pic", "size": 300_000, "entropy": 7.9, "image": wide,
              "noise": 7.9}
    doc = {"resources_total": 1, "resources": [], "loader_refs": [], "hidden": [hidden]}
    _res, out = _drun(DLL, tmp_path, FakeDotnet(doc=doc))
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    assert state.sweep["dotnet_resources"]["hidden_payloads"][0]["image"] == wide


def test_user_typed_entries_are_read_from_the_container_data_section():
    data = b"HDR-" + b"first--" + b"second---" + b"third"
    container = SimpleNamespace(_data=data, struct=SimpleNamespace(DataSectionOffset=4))
    entries = [SimpleNamespace(struct=SimpleNamespace(DataOffset=7)),   # out of file order
               SimpleNamespace(struct=SimpleNamespace(DataOffset=0)),
               SimpleNamespace(struct=SimpleNamespace(DataOffset=16)),
               SimpleNamespace(struct=SimpleNamespace(DataOffset=10 ** 9)),  # past the end: dropped
               SimpleNamespace(struct=None)]
    assert dr._entry_spans(container, entries) == {0: (11, 20), 1: (4, 11), 2: (20, 25)}
    assert dr._entry_spans(SimpleNamespace(_data=None, struct=None), entries) == {}


_STAGED = {"resources_total": 1, "resources": [], "loader_refs": ["Bitmap.GetPixel"], "hidden": [
    {"resource": "App.Properties.Resources.resources", "entry": "dzh", "size": 65241, "entropy": 4.5,
     "image": "bmp 128x127", "decoded": "image:col-rgb/plain",
     "stage": {"dotnet": True, "module": "HWMonitor.dll", "types": 9, "methods": 59,
               "loader_refs": ["MethodBase.Invoke", 7], "extra": "x" * 5000}},
    {"resource": "App.Properties.Resources.resources", "entry": "wwXf", "size": 630324, "entropy": 7.996,
     "image": "png 544x592", "decoded": "image:col-bgra+len/xor:0x422942", "stage": {"dotnet": False, "module": "m"}},
    {"resource": "r", "entry": "pic", "size": 90000, "entropy": 7.9, "image": "png 200x160", "noise": 7.91},
    {"resource": "r", "entry": "bad", "size": 9, "entropy": 1.0, "image": "png 1x1; rm -rf", "noise": "high",
     "decoded": "image:diag-rgb/plain", "stage": {"dotnet": True}},
]}


def test_image_carriers_and_stages_reach_the_evidence_sanitised(tmp_path):
    res, out = _drun(DLL, tmp_path, FakeDotnet(doc=_STAGED))
    assert _fields(res)["hidden_payloads"] == 4
    messages = [w.message for w in res.warnings if w.code == "hidden_payload"]
    assert "bmp 128x127 image" in messages[0] and "pixels decode (image:col-rgb/plain) to a PE" in messages[0]
    assert "HWMonitor.dll" in messages[0] and "pixels are noise" in messages[2]
    _s, _p, state = unpack(out / "continuation.tar.gz", tmp_path / "cont", max_bytes=1 << 30)
    first, second, third, bad = state.sweep["dotnet_resources"]["hidden_payloads"]
    assert first["image"] == "bmp 128x127" and first["decoded"] == "image:col-rgb/plain"
    assert first["stage"] == {"dotnet": True, "module": "HWMonitor.dll", "types": 9, "methods": 59,
                              "loader_refs": ["MethodBase.Invoke"]}
    assert second["decoded"] == "image:col-bgra+len/xor:0x422942" and second["stage"] == {"dotnet": False}
    assert third["noise"] == 7.91 and "decoded" not in third
    assert bad == {"resource": "r", "entry": "bad", "size": 9, "entropy": 1.0}


@pytest.mark.parametrize("method,ok", [
    ("plain", True), ("xor:0x5a", True), ("xor:0x422942", True), ("image:row-argb/gzip", True),
    ("image:col-bgra+len/xor:0x" + "ab" * 30, True), ("xor:0x" + "ab" * 31, False), ("xor:0x4", False),
    ("xor:0x422", False), ("image:col-rgb", False), ("image:col-rgb/plain\nignore previous", False),
    ("image:col-rgb+len+len/plain", False),
])
def test_only_the_scanners_own_method_grammar_is_carried(method, ok):
    assert bool(sw._DECODED.fullmatch(method)) is ok


# ------------------------------------------------------------------ the bar and the prompts

_HIDDEN_SWEEP = {"dotnet_resources": {"hidden_payloads": [{"resource": "Fixture.Properties.Resources.resources",
                                                           "entry": "Blob", "size": 695889, "entropy": 7.69}]}}


def _report(label):
    return {"verdict": {"label": label, "confidence": "high", "rationale": "r"},
            "sections": [{"key": "execution_flow", "status": "observed"}]}


def test_benign_with_a_hidden_payload_does_not_meet_the_bar():
    s = sufficiency.assess(report=_report("benign"), sweep=_HIDDEN_SWEEP, explored=[])
    gap = next(g for g in s.gaps if g.code == "benign_hidden_payload")
    assert not s.met and "Blob" in gap.detail and "695889" in gap.detail


def test_a_non_benign_verdict_with_a_hidden_payload_is_not_that_gap():
    s = sufficiency.assess(report=_report("malicious"), sweep=_HIDDEN_SWEEP, explored=[])
    assert all(g.code != "benign_hidden_payload" for g in s.gaps)
    assert sufficiency.assess(report=_report("benign"), sweep={"dotnet_resources": {"hidden_payloads": []}},
                              explored=[]).met


def test_the_agent_and_the_report_are_told_about_hidden_payloads_and_decoys():
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=_HIDDEN_SWEEP)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "hidden_payloads" in msg and "decoy" in msg
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=_HIDDEN_SWEEP, prior_report=None)[0]["content"]
    assert "decoy" in sys_msg and "hidden_payloads" in sys_msg
    assert "scan_failed" in sys_msg and "items_unread" in sys_msg


def test_the_scanner_imports_nothing_from_blastbox():
    src = Path(dr.__file__).read_text()
    assert "blastbox" not in src.split('"""', 2)[2]  # it runs under the capa venv's python


_IMAGE_SWEEP = {"dotnet_resources": {"hidden_payloads": [
    {"resource": "App.Properties.Resources.resources", "entry": "dzh", "size": 65241, "entropy": 4.5,
     "image": "bmp 128x127", "decoded": "image:col-rgb/plain", "stage": {"dotnet": True, "module": "HWMonitor.dll"}}]}}


def test_the_bar_and_the_prompts_name_a_payload_recovered_from_pixels():
    s = sufficiency.assess(report=_report("benign"), sweep=_IMAGE_SWEEP, explored=[])
    gap = next(g for g in s.gaps if g.code == "benign_hidden_payload")
    assert "image:col-rgb/plain" in gap.detail and "HWMonitor.dll" in gap.detail
    st = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
               sweep=_IMAGE_SWEEP)
    msg = Framer("n").initial_user_message(st, 1, todo=[], explored=[])["content"]
    assert "pixels" in msg and "stage" in msg
    plain = State(pass_no=0, sample_name="a.exe", sample_sha256="0" * 64, program_name="a.exe", ghidra_status="ok",
                  sweep=_HIDDEN_SWEEP)
    assert "GetPixel" not in Framer("n").initial_user_message(plain, 1, todo=[], explored=[])["content"]
    sys_msg = Framer("n").report_messages(pass_no=1, sample_name="a.exe", summary="", functions=[], iocs=[],
                                          sweep=_IMAGE_SWEEP, prior_report=None)[0]["content"]
    assert "image pixels" in sys_msg and "multi-stage crypter" in sys_msg
