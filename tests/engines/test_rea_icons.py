import io
import zipfile
from pathlib import Path

from PIL import Image

from blastbox.engines.rea.icons import extract_icons

FIXTURE = Path(__file__).resolve().parents[2] / "deploy" / "rea" / "fixtures" / "sample.exe"


def _png(size: int) -> bytes:
    b = io.BytesIO()
    Image.new("RGBA", (size, size), (255, 0, 0, 255)).save(b, "PNG")
    return b.getvalue()


def test_ico_picks_largest(tmp_path: Path) -> None:
    ico = tmp_path / "a.ico"
    Image.new("RGBA", (48, 48), (0, 255, 0, 255)).save(ico, sizes=[(16, 16), (48, 48)])
    out = extract_icons(ico, tmp_path / "o")
    assert [p.name for p in out] == ["icon-0.png"]
    with Image.open(out[0]) as im:
        assert im.size == (48, 48)


def test_apk_picks_largest(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("res/mipmap-hdpi/ic_launcher.png", _png(72))
        z.writestr("res/mipmap-mdpi/ic_launcher.png", _png(48))
        z.writestr("AndroidManifest.xml", b"x")
    out = extract_icons(apk, tmp_path / "o")
    assert len(out) == 1
    with Image.open(out[0]) as im:
        assert im.size == (72, 72)


def test_pe_fixture(tmp_path: Path) -> None:
    out = extract_icons(FIXTURE, tmp_path / "o")
    assert len(out) >= 1 and all(p.suffix == ".png" and p.stat().st_size > 0 for p in out)


def test_non_image(tmp_path: Path) -> None:
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello")
    assert extract_icons(f, tmp_path / "o") == []


def test_corrupt_ico(tmp_path: Path) -> None:
    f = tmp_path / "bad.ico"
    f.write_bytes(b"\x00\x00\x01\x00\x05\x00" + b"\xff" * 40)
    assert extract_icons(f, tmp_path / "o") == []


def test_oversize_dimensions_skipped(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("res/mipmap-xxhdpi/ic_launcher.png", _png(2000))
    assert extract_icons(apk, tmp_path / "o") == []


def test_max_icons(tmp_path: Path) -> None:
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("res/mipmap-hdpi/ic_launcher.png", _png(72))
    assert extract_icons(apk, tmp_path / "o", max_icons=0) == []


def test_icns_picks_largest(tmp_path: Path) -> None:
    icns = tmp_path / "a.icns"
    Image.new("RGBA", (128, 128), (0, 0, 255, 255)).save(icns, format="ICNS", sizes=[(32, 32), (128, 128)])
    out = extract_icons(icns, tmp_path / "o")
    assert len(out) == 1
    with Image.open(out[0]) as im:
        assert 128 <= im.width <= 1024 and im.width == im.height
