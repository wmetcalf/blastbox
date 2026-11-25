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
    logo = hidden[("Fixture.logo.png", None)]  # starts like a PNG and is not one: no excuse
    assert "decoded" not in logo and "image" not in logo and logo["size"] == 8 + 80 * 1024
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
    assert fd.calls and f["kind"] == "dotnet" and f["hidden_payloads"] == 6
    assert _codes(res).count("hidden_payload") == 6
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


@pytest.fixture
def unhurried(monkeypatch):
    """The scan budgets are wall-clock (40 s of image decoding): a stalled CI runner trips them
    and the scan skips the image it was asked about. A test about what a scan finds must not
    depend on how fast the machine is, so it runs with budgets that cannot expire."""
    monkeypatch.setattr(dr, "IMAGE_BUDGET_S", 1e9)
    monkeypatch.setattr(dr, "SCAN_BUDGET_S", 1e9)


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


@pytest.mark.usefixtures("unhurried")
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


@pytest.mark.usefixtures("unhurried")
def test_stages_are_not_followed_past_the_depth_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(dr, "MAX_DEPTH", 0)
    state = dr._Scan(tmp_path)
    carrier = _stage2_png(DLL.read_bytes())
    state.consider(carrier, dr.entropy(carrier), "r", None, 0)
    assert len(state.hidden) == 1 and state.hidden[0]["stage"]["dotnet"] is True


@pytest.mark.usefixtures("unhurried")
def test_a_native_stage_is_described_as_not_dotnet(tmp_path):
    state = dr._Scan(tmp_path)
    carrier = _serialized(_stage1_bmp())
    state.consider(carrier, dr.entropy(carrier), "r", "dzh", 0)
    assert [h.get("stage") for h in state.hidden] == [{"dotnet": False}]


@pytest.mark.usefixtures("unhurried")
def test_a_noise_image_is_a_hidden_payload_and_a_picture_is_not(tmp_path):
    state = dr._Scan(tmp_path)
    noisy = _png(200, 160, b"".join(_noise(96000)[i:i + 3] + b"\xff" for i in range(0, 96000, 3)))
    state.consider(noisy, dr.entropy(noisy), "r", "pic", 0)
    assert state.hidden[0]["noise"] >= dr.NOISE_MIN_ENTROPY and "decoded" not in state.hidden[0]
    flat = _png(200, 160, bytes(200 * 160 * 4))
    state.consider(flat, dr.entropy(flat), "r", "flat", 0)
    assert len(state.hidden) == 1


@pytest.mark.parametrize("hurried", [True, False])
def test_a_stalled_clock_costs_a_noise_image_only_when_the_budgets_are_real(tmp_path, monkeypatch, hurried):
    """The 2026-11 CI flake: a runner stall past IMAGE_BUDGET_S between building the scan and
    reading the image made the scan skip it (counted in items_unread), leaving ``hidden`` empty."""
    if not hurried:
        monkeypatch.setattr(dr, "IMAGE_BUDGET_S", 1e9)
        monkeypatch.setattr(dr, "SCAN_BUDGET_S", 1e9)
    state = dr._Scan(tmp_path)
    real = dr.time.monotonic
    monkeypatch.setattr(dr.time, "monotonic", lambda: real() + 1000.0)  # the runner stalled
    n = _noise(96000)
    state.consider(_png(200, 160, b"".join(n[i:i + 3] + b"\xff" for i in range(0, 96000, 3))), None, "r", "pic", 0)
    assert bool(state.hidden) is (not hurried)
    assert (state.items_unread >= 1) is hurried


def _png_header(w, h, *, depth=8, colour=6, interlace=0):
    """A PNG that declares ``w`` x ``h`` over one small IDAT: the size check reads only the header."""
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, colour, 0, 0, interlace))
            + chunk(b"IDAT", zlib.compress(bytes(64))) + chunk(b"IEND", b""))


def _bmp_header(w, h):
    return b"BM" + struct.pack("<IHHI", 54, 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, 0, 0, 0, 0, 0)


@pytest.mark.usefixtures("unhurried")
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


@pytest.mark.usefixtures("unhurried")
def test_one_item_is_counted_unread_once(tmp_path, monkeypatch):
    """An oversize image is counted where it is met; a parser that then breaks on the same item
    must not count it a second time."""
    side = int(dr.MAX_IMAGE_PIXELS ** 0.5) + 1

    def broken(self, kind, data):
        raise RuntimeError("parser bug")

    monkeypatch.setattr(dr._Writer, "write", broken)
    state = dr._Scan(tmp_path)
    state.consider(_bmp_header(side, side) + _noise(70 * 1024), 7.9, "r", "big", 0)
    assert state.hidden == [] and state.items_unread == 1


@pytest.mark.usefixtures("unhurried")
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


def _leb(n):
    out = bytearray()
    while True:
        out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(out)


def _lstr(raw):
    return _leb(len(raw)) + raw


def _container(entries, *, types=(), tail=b"", lost=()):
    """A real v2 ``.resources`` container. An entry is (name, value): bytes are a ByteArray, a str
    a String, (code, bytes) a type code and what lies behind it, an int an offset into the data
    section that another entry already put bytes at. ``lost`` entries have an unreadable name."""
    data, offsets = bytearray(), []
    for _, value in entries:
        offsets.append(value if isinstance(value, int) else len(data))
        if isinstance(value, bytes):
            data += b"\x20" + struct.pack("<I", len(value)) + value
        elif isinstance(value, str):
            data += b"\x01" + _lstr(value.encode())
        elif isinstance(value, tuple):
            data += _leb(value[0]) + value[1]
    data += tail
    names, positions = bytearray(), []
    for i, (name, _) in enumerate(entries):
        positions.append(0x7FFFFFF0 if i in lost else len(names))
        names += _lstr(name.encode("utf-16-le")) + struct.pack("<I", offsets[i])
    readers = _lstr(b"System.Resources.ResourceReader, mscorlib") + _lstr(b"System.Resources.RuntimeResourceSet")
    head = dr._RES_MAGIC + struct.pack("<II", 1, len(readers)) + readers
    head += struct.pack("<III", 2, len(entries), len(types)) + b"".join(_lstr(t.encode()) for t in types)
    head += bytes(-len(head) % 8)
    head += bytes(4 * len(entries)) + b"".join(struct.pack("<I", p) for p in positions)
    return head + struct.pack("<I", len(head) + 4 + len(names)) + bytes(names) + bytes(data)


def _found(state):
    return {(h["resource"], h.get("entry")): str(h.get("decoded", ""))[:6] for h in state.hidden}


@pytest.mark.usefixtures("unhurried")
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


@pytest.mark.usefixtures("unhurried")
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


@pytest.mark.usefixtures("unhurried")
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


def test_bytes_of_a_container_that_no_entry_covers_are_read(tmp_path):
    """A payload need not be an entry: it can lie in the data section with no entry over it, after
    the last one, or behind an entry whose stated length stops short of it."""
    carrier = _stage1_bmp()
    cases = {"no-entries": (_container([], tail=carrier), []),
             "after-the-last": (_container([("a", b"text")], tail=carrier), [4]),
             "behind-a-short-length": (_container([("a", (0x20, struct.pack("<I", 4) + b"text" + carrier)),
                                                   ("b", "next")]), [4, 4])}
    for tag, (raw, sizes) in cases.items():
        (tmp_path / tag).mkdir()
        state, doc = dr._Scan(tmp_path / tag), {"resources": []}
        state.resources(_pe(_res("App.resources", raw)), doc, "", 0)
        [(key, how)] = _found(state).items()
        assert key[0] == "App.resources" and key[1].startswith("(bytes outside entries at 0x"), tag
        assert how == "image:" and state.items_unread == 0, tag
        assert [e["size"] for e in doc["resources"][0]["entries"]] == sizes, tag


@pytest.mark.usefixtures("unhurried")
def test_an_entry_whose_name_cannot_be_read_is_counted_and_its_bytes_still_read(tmp_path):
    raw = _container([("a", b"text"), ("lost", _stage1_bmp()), ("c", b"more")], lost={1})
    state, doc = dr._Scan(tmp_path), {"resources": []}
    state.resources(_pe(_res("App.resources", raw)), doc, "", 0)
    row = doc["resources"][0]
    assert state.items_unread == 1 and row["entries_total"] == 3
    assert [e["name"] for e in row["entries"]] == ["a", "c"]
    [(key, how)] = _found(state).items()
    assert key[1].startswith("(bytes outside entries at 0x") and how == "image:"


@pytest.mark.usefixtures("unhurried")
def test_a_container_that_does_not_parse_is_counted_and_read_as_one_blob(tmp_path):
    raw = dr._RES_MAGIC + struct.pack("<II", 2, 0x7FFFFF00) + _noise(70 * 1024)
    state, doc = dr._Scan(tmp_path), {"resources": []}
    state.resources(_pe(_res("App.resources", raw), _res("late", _stage1_bmp())), doc, "", 0)
    assert state.items_unread == 1 and doc["resources"][0]["container"] is False
    assert _found(state) == {("App.resources", None): "", ("late", None): "image:"}


def test_one_malformed_container_does_not_fail_the_scan(tmp_path):
    """dnfile parses every container while it opens the assembly and lets a bad header's error
    out, which cost the whole scan: the scanner reads containers itself."""
    raw = bytearray(DLL.read_bytes())
    pe = dnfile.dnPE(str(DLL))
    [res] = [r for r in pe.net.resources if str(r.name) == "Fixture.Properties.Resources.resources"]
    at = pe.get_offset_from_rva(res.rva)
    pe.close()
    assert raw[at:at + 4] == dr._RES_MAGIC
    raw[at + 8:at + 12] = struct.pack("<I", 0x7FFFFF00)  # a size .NET skips over and dnfile trusts
    bad = tmp_path / "bad.dll"
    bad.write_bytes(bytes(raw))
    with pytest.raises(Exception):  # noqa: B017,PT011  (whatever dnfile lets out)
        dnfile.dnPE(str(bad))
    (tmp_path / "out").mkdir()
    doc = dr.scan(bad, tmp_path / "out")
    assert "error" not in doc and "items_unread" not in doc
    assert set(_hidden(doc)) == set(_hidden(dr.scan(DLL, tmp_path)))
    assert _by_name(doc) == _by_name(dr.scan(DLL, None))


def test_entries_that_share_one_slice_of_the_container_are_read_once(tmp_path, monkeypatch):
    """500 user-typed entries at one offset are one slice: reading it 500 times is the sample
    spending the scan's time budget for it."""
    read = []
    monkeypatch.setattr(dr, "decode", lambda data: read.append(len(data)))
    bitmaps = _container([("e0", (0x40, bytes(4095)))] + [(f"e{i}", 0) for i in range(1, 500)],
                         types=["System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0"])
    arrays = _container([("b0", bytes(4096))] + [(f"b{i}", 0) for i in range(1, 500)])
    for raw, kind in ((bitmaps, "System.Drawing.Bitmap"), (arrays, "System.ByteArray")):
        read.clear()
        state, doc = dr._Scan(tmp_path), {"resources": []}
        state.resources(_pe(_res("c", raw)), doc, "", 0)
        assert read == [4096] and state.items_unread == 0, kind
        row = doc["resources"][0]
        assert row["entries_total"] == 500 and len(row["entries"]) == dr.MAX_ENTRIES
        assert {(e["size"], e["type"]) for e in row["entries"]} == {(4096, kind)}
    # Past the time budget the one slice is one item unread, and is not copied to say so.
    monkeypatch.setattr(dr, "SCAN_BUDGET_S", 0.0)
    state, doc = dr._Scan(tmp_path), {"resources": []}
    state.resources(_pe(_res("c", arrays)), doc, "", 0)
    assert state.items_unread == 1 and doc["resources"][0]["entries"] == []


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


def test_container_entries_get_the_bytes_the_format_gives_them():
    """Typed entries end where their type says; a user type (Bitmap, Icon) and a code the format
    does not define run to the next entry."""
    raw = _container([("s", "h\u00e9llo"), ("b", b"bytes"), ("u", (0x40, b"user-typed")), ("n", (0, b"")),
                      ("i", (8, struct.pack("<i", 7))), ("far", 10 ** 9), ("z", (0x41, b"tail"))],
                     types=["System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0"])
    box = dr._container(raw)
    assert {e.name: (e.type, raw[e.body:e.end]) for e in box.entries} == {
        "s": ("System.String", "h\u00e9llo".encode()), "b": ("System.ByteArray", b"bytes"),
        "u": ("System.Drawing.Bitmap", b"\x40user-typed"), "n": ("Null", b""),
        "i": ("System.Int32", struct.pack("<i", 7)), "far": ("", b""), "z": ("", b"\x41tail")}
    assert box.total == 7 and box.unread == 0
    for broken in (raw[:40], dr._RES_MAGIC + struct.pack("<II", 2, 0x7FFFFF00) + bytes(64),
                   raw.replace(struct.pack("<III", 2, 7, 1), struct.pack("<III", 3, 7, 1)),
                   raw.replace(struct.pack("<III", 2, 7, 1), struct.pack("<III", 2, 10 ** 8, 1))):
        with pytest.raises(dr._Broken):
            dr._container(broken)


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


_BITMAP = "System.Drawing.Bitmap, System.Drawing, Version=4.0.0.0"


def test_a_bitmap_cut_short_by_another_entrys_offset_is_read_whole(tmp_path, monkeypatch):
    """A typed entry ends where its object ends, not where the next entry's offset points: an
    offset aimed into a Bitmap must not hide the picture."""
    raw = _container([("img", (0x40, _serialized(_stage1_bmp()))), ("decoy", 300)], types=[_BITMAP])
    state = dr._Scan(tmp_path)
    state.resources(_pe(_res("App.resources", raw)), None, "", 0)
    assert _found(state)[("App.resources", "img")] == "image:" and state.items_unread == 0
    [item] = [h for h in state.hidden if h.get("entry") == "img"]
    assert item["size"] > 300  # the picture, not the 300 bytes the offsets leave the entry
    # ... and past the image budget it is counted like any other picture that was not read.
    monkeypatch.setattr(dr, "IMAGE_BUDGET_S", 0.0)
    (tmp_path / "late").mkdir()
    late = dr._Scan(tmp_path / "late")
    late.resources(_pe(_res("App.resources", raw)), None, "", 0)
    assert late.hidden == [] and late.items_unread == 1


@pytest.mark.usefixtures("unhurried")
def test_the_first_image_header_that_holds_decides(tmp_path):
    """A small picture planted inside a carrier's header must not be the one that is read: not a
    16x16 bitmap in the gap an oversize bitmap leaves before its pixels, and not a PNG there."""
    side = int(dr.MAX_IMAGE_PIXELS ** 0.5) + 1
    for decoy in (_bmp_header(16, 16) + bytes(1024), _png(16, 16, bytes(16 * 16 * 4))):
        assert dr.load_image(decoy) is not None  # alone, the decoy is a picture
        big = (b"BM" + struct.pack("<IHHI", 0, 0, 0, 54 + len(decoy))
               + struct.pack("<IiiHHIIiiII", 40, side, side, 1, 24, 0, 0, 0, 0, 0, 0) + decoy)
        state = dr._Scan(tmp_path)
        state.consider(big, dr.entropy(big), "r", "big", 0)
        assert state.hidden == [] and state.items_unread == 1


def _palette_png(body):
    """An 8-bit palette PNG over ``body``: a kind the scanner does not read the pixels of."""
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 3, 0, 0, 0))
            + chunk(b"PLTE", bytes(3)) + chunk(b"IDAT", body) + chunk(b"IEND", b""))


def _jpeg(body):
    return (b"\xff\xd8\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + bytes(9) + b"\xff\xda"
            + struct.pack(">H", 8) + bytes(6) + body.replace(b"\xff", b"\xff\x00") + b"\xff\xd9")


def _gif(body):
    blocks = b"".join(bytes([len(body[i:i + 255])]) + body[i:i + 255] for i in range(0, len(body), 255))
    return (b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0) + b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0)
            + b"\x08" + blocks + b"\x00\x3b")


def _ico(body):
    image = b"\x28\x00\x00\x00" + body
    return b"\x00\x00\x01\x00" + struct.pack("<HBBBBHHII", 1, 32, 32, 0, 0, 1, 32, len(image), 22) + image


def _riff(body):
    return b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WAVE" + body


def _woff(body):
    return b"wOFFOTTO" + struct.pack(">I", 12 + len(body)) + body


_MEDIA_FILES = {"png": _palette_png, "jpeg": _jpeg, "gif": _gif, "ico": _ico, "riff": _riff, "woff": _woff}


@pytest.mark.usefixtures("unhurried")
def test_whole_media_files_are_not_payloads(tmp_path):
    """Compressed media is high-entropy by nature: a file whose framing holds to its end is not
    reported, alone, inside a serialized object or with a few bytes after it."""
    state = dr._Scan(tmp_path)
    for kind, make in _MEDIA_FILES.items():
        media = make(_noise(70 * 1024))
        assert dr.media_format(media) == kind and dr.media_extent(media) == len(media), kind
        assert dr.media_extent(media[:-1]) is None, kind
        wrapped = [_serialized(media)] if kind in ("png", "jpeg", "gif") else []
        for blob in [media, media + bytes(32), *wrapped]:
            assert dr.entropy(blob) >= dr.HIDDEN_MIN_ENTROPY
            state.consider(blob, dr.entropy(blob), "r", kind, 0)
    assert state.hidden == [] and state.items_unread == 0


def test_a_media_magic_does_not_excuse_a_payload(tmp_path):
    """Only a media file's own bytes are excused: bytes that merely start like one, and bytes
    after one, are read like any others."""
    payload = _noise(70 * 1024)
    small = _png(16, 16, bytes(16 * 16 * 4))
    fronts = {"gif-magic": b"GIF89a", "jpeg-magic": b"\xff\xd8\xff", "png-magic-inside": bytes(100) + small[:8],
              "small-png": small, "small-bmp": _bmp(4, 4, bytes(48)), "small-gif": _gif(b"x"),
              "small-jpeg": _jpeg(b"x"), "small-riff": _riff(b"x" * 8)}
    for tag, front in fronts.items():
        (tmp_path / tag).mkdir()
        state = dr._Scan(tmp_path / tag)
        blob = front + payload
        state.consider(blob, dr.entropy(blob), "r", "e", 0)
        assert [(h["resource"], h.get("entry"), "decoded" in h) for h in state.hidden] == [("r", "e", False)], tag
        assert state.hidden[0]["size"] >= dr.HIDDEN_MIN_BYTES and state.items_unread == 0, tag


@pytest.mark.usefixtures("unhurried")
def test_bytes_between_a_bitmaps_header_and_its_pixels_are_read(tmp_path):
    clean = _bmp(40, 40, bytes(40 * 40 * 3))
    blob = clean[:10] + struct.pack("<I", 54 + len(SAMPLE)) + clean[14:54] + SAMPLE + clean[54:]
    assert dr.load_image(blob) is not None
    state = dr._Scan(tmp_path)
    state.consider(blob, dr.entropy(blob), "r", "pic", 0)
    assert _found(state) == {("r", "pic"): "plain"} and state.items_unread == 0


@pytest.mark.usefixtures("unhurried")
def test_an_item_of_too_many_parts_is_counted(tmp_path):
    small = _png(16, 16, bytes(16 * 16 * 4))
    for count, unread in ((dr.MAX_PARTS, 0), (dr.MAX_PARTS + 1, 1)):
        state = dr._Scan(tmp_path)
        state.consider(small * count, 0.0, "r", "many", 0)
        assert state.hidden == [] and state.items_unread == unread, count


# ------------------------------------------------------------------ rows dnfile drops, and the budget
def test_a_resource_row_dnfile_cannot_read_is_counted_unread(tmp_path):
    raw = bytearray(DLL.read_bytes())
    at = raw.find(dr_bytes("blob")[:64])
    assert at > 4 and int.from_bytes(raw[at - 4:at], "little") == len(dr_bytes("blob"))
    raw[at - 4:at] = (0x7FFFFFF0).to_bytes(4, "little")  # a size that runs past the file
    bad = tmp_path / "bad.dll"
    bad.write_bytes(bytes(raw))
    for name in ("o", "whole"):
        (tmp_path / name).mkdir()
    doc = dr.scan(bad, tmp_path / "o")
    assert "error" not in doc
    assert doc["resources_total"] == 6 and doc["items_unread"] == 1
    assert "Fixture.blob.bin" not in {r["name"] for r in doc["resources"]}
    assert "items_unread" not in dr.scan(DLL, tmp_path / "whole")


def test_the_scan_budget_is_what_the_caller_gives_counted_from_its_start(tmp_path):
    state = dr._Scan(tmp_path, budget_s=9.0, since=100.0)
    assert state._deadline == 109.0 and state._image_deadline == 106.0
    state = dr._Scan(tmp_path, budget_s=600.0, since=100.0)
    assert state._deadline == 700.0 and state._image_deadline == 100.0 + dr.IMAGE_BUDGET_S
    for name in ("late", "whole"):
        (tmp_path / name).mkdir()
    spent = dr.scan(DLL, tmp_path / "late", budget_s=5.0, since=dr.time.monotonic() - 10.0)
    assert spent["hidden"] == [] and spent["items_unread"] >= 1 and "error" not in spent
    whole = dr.scan(DLL, tmp_path / "whole", budget_s=30.0, since=dr.time.monotonic())
    assert "items_unread" not in whole and len(whole["hidden"]) == 6


@pytest.mark.parametrize("budget", ["nope", "0", "-3", "nan", "inf"])
def test_the_scanner_refuses_a_budget_that_is_not_a_time(tmp_path, capsys, budget):
    assert dr.main(["dotnet_resources.py", str(DLL), str(tmp_path / "o"), budget]) == 2
    assert capsys.readouterr().out == ""


def test_the_scanner_takes_its_budget_as_a_third_argument(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(dr, "_T0", dr.time.monotonic())  # as a script: the process has just started
    assert dr.main(["dotnet_resources.py", str(DLL), str(tmp_path / "o"), "30"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["resources_total"] == 6 and "items_unread" not in doc
    monkeypatch.setattr(dr, "_T0", dr.time.monotonic() - 31.0)  # the budget counts from the start
    assert dr.main(["dotnet_resources.py", str(DLL), str(tmp_path / "q"), "30"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["hidden"] == [] and doc["items_unread"] >= 1
    assert dr.main(["dotnet_resources.py", str(DLL), str(tmp_path / "p"), "30", "extra"]) == 2


@pytest.mark.parametrize(("timeout_s", "budget"), [(90, "60.0"), (60, "40.0"), (6, "4.0"), (0.5, "1.0"), (600, "60.0")])
def test_the_runner_gives_the_scanner_a_budget_inside_its_timeout(tmp_path, timeout_s, budget):
    from blastbox.engines.rea.runner import RunOutcome

    seen = {}

    def run(argv, *, env, cwd, timeout_s, max_stdout):
        seen["argv"] = argv
        return RunOutcome(0, b"{}")

    status, _ = run_dotnet_resources(DLL, tmp_path / "o", timeout_s, env={}, python="/py", max_kb=1, max_stdout=1,
                                     max_write_bytes=1024, run_fn=run)
    assert status == "ok"
    assert seen["argv"][2].endswith('exec "$3" -I "$4" "$5" "$6" "$7"') and seen["argv"][-1] == budget
    assert seen["argv"][-3:-1] == [str(DLL.resolve()), str((tmp_path / "o").resolve())]


def test_an_empty_resource_is_not_a_resource_left_unread(tmp_path):
    raw = bytearray(DLL.read_bytes())
    at = raw.find(dr_bytes("blob")[:64])
    raw[at - 4:at] = bytes(4)  # a resource of no bytes: dnfile gives none, and there is nothing to read
    bad = tmp_path / "empty.dll"
    bad.write_bytes(bytes(raw))
    (tmp_path / "o").mkdir()
    doc = dr.scan(bad, tmp_path / "o")
    assert "error" not in doc and "items_unread" not in doc and doc["resources_total"] == 5


@pytest.mark.usefixtures("unhurried")
def test_stretches_outside_entries_past_the_cap_are_counted_unread(tmp_path, monkeypatch):
    """A container cut into more uncovered stretches than the scan reads has bytes nobody read."""
    raw = _container([("a", b"text")], tail=_stage1_bmp())
    monkeypatch.setattr(dr, "MAX_GAPS", 0)
    state = dr._Scan(tmp_path)
    state.resources(_pe(_res("App.resources", raw)), None, "", 0)
    assert _found(state) == {} and state.items_unread == 1
