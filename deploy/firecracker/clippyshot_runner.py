"""LibreOffice invocation through the sandbox."""

from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

from clippyshot.errors import LibreOfficeEmptyOutputError, LibreOfficeError
from clippyshot.libreoffice.profile import HardenedProfile
from clippyshot.libreoffice.uno import UnoServer, convert_via_uno
from clippyshot.limits import Limits
from clippyshot.sandbox.base import Mount, Sandbox, SandboxRequest


_FIXED_FLAGS = (
    "--headless",
    "--safe-mode",
    "--norestore",
    "--nologo",
    "--nofirststartwizard",
    "--nocrashreport",
    "--nodefault",
)

# Suffixes that should use the Calc PDF export filter rather than Writer's.
# This gives correct sheet-aware output (sheet names, print areas, etc.)
# for all spreadsheet family formats LibreOffice supports.
_CALC_SUFFIXES = frozenset(
    {
        ".xls",
        ".xlsm",
        ".xlsx",
        ".xlsb",
        ".ods",
        ".fods",
        ".csv",
        ".tsv",
    }
)
_RENDERABLE_ALTCHUNK_TYPES = frozenset(
    {
        "message/rfc822",
        "text/html",
        "application/xhtml+xml",
    }
)


class LibreOfficeRunner:
    """Build the soffice invocation and dispatch it through a Sandbox."""

    def __init__(
        self,
        sandbox: Sandbox,
        soffice_path: str = "/usr/bin/soffice",
        uno_server: UnoServer | None = None,
    ) -> None:
        self._sandbox = sandbox
        self._soffice = soffice_path
        # When set + ready (the FC warm tier, where unoserver shares this
        # filesystem), convert_to_pdf tries unoconvert first and falls back to the
        # cold sandbox path on any failure. None on the bare-metal/docker tier.
        self._uno_server = uno_server
        # Populated by ``convert_to_pdf`` when the final staged form of
        # the input was an OOXML spreadsheet. The converter reads this
        # immediately after the call to surface sheet names in metadata.
        # Each worker process handles one job sequentially, so a single
        # instance attribute is safe here.
        self.last_run_sheets: list[dict] = []
        # Populated when a docx-family input contains <w:altChunk>
        # references to embedded content (MHT / HTML / nested Word).
        # Entries are lightweight summaries (no raw bytes) for surfacing
        # as warnings in metadata.
        self.last_altchunks: list[dict] = []

    def convert_to_pdf(
        self,
        input_path: Path,
        output_dir: Path,
        limits: Limits,
        label: str,
    ) -> Path:
        input_path = Path(input_path)
        output_dir = Path(output_dir)
        if not input_path.is_file():
            raise LibreOfficeError(f"input not found: {input_path}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Select the correct PDF export filter based on the detected label.
        label = label.lower()
        file_ext = input_path.suffix.lstrip(".").lower()
        _needs_binary_conversion = False
        # SinglePageSheets fits each sheet onto one page. The OOXML patch
        # sets landscape orientation so wide sheets render naturally.
        _CALC_FILTER = (
            'calc_pdf_Export:{"SinglePageSheets":{"type":"boolean","value":"true"}}'
        )
        if label in ("xlsx", "xlsm"):
            pdf_filter = _CALC_FILTER
        elif label in ("xls", "ods", "fods", "csv", "xlsb"):
            pdf_filter = _CALC_FILTER
            _needs_binary_conversion = True
        elif label in ("pptx", "pptm", "ppt", "pps", "ppsx", "odp", "fodp"):
            pdf_filter = "impress_pdf_Export"
        elif label in ("odg", "fodg", "xps", "oxps"):
            pdf_filter = "draw_pdf_Export"
        else:
            pdf_filter = "writer_pdf_Export"

        # Only force --infilter when the detected format FAMILY differs from
        # the extension's family. E.g., label="pptx" but ext="doc" (a
        # presentation disguised as a Word file) needs the forced filter.
        # But label="pptx" + ext="ppsx" are the SAME family (both OOXML
        # Impress), so no forced filter needed.
        _FAMILY = {
            # OOXML Word
            "docx": "word-ooxml",
            "docm": "word-ooxml",
            "dotx": "word-ooxml",
            "dotm": "word-ooxml",
            # Legacy Word
            "doc": "word-ole",
            "dot": "word-ole",
            # OOXML Excel
            "xlsx": "calc-ooxml",
            "xlsm": "calc-ooxml",
            "xltx": "calc-ooxml",
            "xltm": "calc-ooxml",
            "xlam": "calc-ooxml",
            # Legacy Excel + binary
            "xls": "calc-ole",
            "xlt": "calc-ole",
            "xla": "calc-ole",
            "xlsb": "calc-bin",
            # OOXML Impress
            "pptx": "impress-ooxml",
            "pptm": "impress-ooxml",
            "ppsx": "impress-ooxml",
            "ppsm": "impress-ooxml",
            "potx": "impress-ooxml",
            "potm": "impress-ooxml",
            "ppam": "impress-ooxml",
            # Legacy Impress
            "ppt": "impress-ole",
            "pps": "impress-ole",
            "pot": "impress-ole",
            "ppa": "impress-ole",
            # RTF
            "rtf": "rtf",
            # ODF
            "odt": "odf-text",
            "ott": "odf-text",
            "fodt": "odf-text",
            "ods": "odf-calc",
            "ots": "odf-calc",
            "fods": "odf-calc",
            "odp": "odf-impress",
            "otp": "odf-impress",
            "fodp": "odf-impress",
            "odg": "odf-draw",
            "otg": "odf-draw",
            "fodg": "odf-draw",
            # Text
            "txt": "text",
            "csv": "text",
            "md": "text",
        }
        label_family = _FAMILY.get(label, label)
        ext_family = _FAMILY.get(file_ext, file_ext)

        # Reset per-call capture; populated by subsequent pre- or
        # post-processing steps.
        self.last_run_sheets = []
        self.last_altchunks = []

        # Stage input into a per-call dir so we can mount its parent
        with tempfile.TemporaryDirectory(prefix="clippyshot-stage-") as stage_str:
            stage = Path(stage_str)
            preserve_rewritten_input = False

            # When the detected content type family differs from the file
            # extension (e.g., PPTX content in a .ppt file), rename the
            # staged copy to match the detected type. This is more reliable
            # than --infilter because soffice's auto-detection from extension
            # handles edge cases in damaged files better than a forced filter
            # name, which can be version-specific and finicky.
            rewrite_active = label_family != ext_family and label != file_ext
            original_name = input_path.name
            if rewrite_active:
                staged_name = input_path.stem + "." + label
            else:
                staged_name = original_name
            staged_input = stage / staged_name
            shutil.copy2(input_path, staged_input)
            if rewrite_active:
                original_staged_input = stage / original_name
                shutil.copy2(input_path, original_staged_input)
            else:
                original_staged_input = staged_input

            profile_root = stage / f"lo-profile-{uuid.uuid4().hex}"
            HardenedProfile(profile_root).write()
            (profile_root / "tmp").mkdir(parents=True, exist_ok=True)

            # For spreadsheets, set landscape + fit-all-columns-on-one-page
            # on the STAGED COPY (original is never touched). Like hitting
            # Page Setup → Landscape → Fit Columns before printing.
            #
            # OOXML (.xlsx/.xlsm): patch the sheet XML directly in the zip.
            # Binary (.xls/.xlsb/.ods/csv): two-pass — convert to xlsx via
            #   soffice, patch the xlsx, then use it for PDF export.
            #   Falls back to direct conversion if the two-pass fails.
            # MHT pre-processing: LO's MHTML importer garbles Word-flavored
            # MHTs into a raw MIME dump, so we unpack the archive ourselves
            # (stdlib email module) and feed LO the extracted HTML + image
            # resources instead. See libreoffice/mht_unpack.py for detail.
            # Flatten everything into ``stage`` so soffice's sandbox mount
            # (Mount(stage, /sandbox/in)) can reach the HTML at
            # /sandbox/in/<name>.html without needing a nested subdir.
            if label == "mht":
                try:
                    from clippyshot.libreoffice.mht_unpack import unpack_mht

                    mht_dir = stage / "_mht_unpack"
                    mht_dir.mkdir()
                    html_path = unpack_mht(staged_input, mht_dir)
                    if html_path is not None:
                        # Move the HTML + sibling resources to stage root
                        # without prefixing — the HTML references images
                        # by their Content-Location basename, so preserving
                        # those names keeps the ``<img src="...">`` links
                        # resolvable. Collisions with the original staged
                        # input aren't a concern because we don't need it
                        # anymore past this point.
                        for entry in mht_dir.iterdir():
                            dest = stage / entry.name
                            if dest.exists():
                                dest.unlink()
                            shutil.move(str(entry), str(dest))
                        mht_dir.rmdir()
                        staged_input = stage / html_path.name
                        staged_name = staged_input.name
                        preserve_rewritten_input = True
                except Exception:
                    # Fall through to raw-file attempt — worst case LO
                    # produces the same text dump we started with, but
                    # a parse error here is never fatal.
                    pass

            # altChunk inspection for docx-family inputs. Word's
            # ``<w:altChunk>`` feature embeds alternate-format content
            # (MHT, HTML, legacy Word) that gets inlined when Word opens
            # the file. LO's docx importer ignores altChunks, so the
            # rendered output is whatever's in document.xml — typically
            # an empty shell when the file is a malware wrapper. We
            # detect these, surface them via ``last_altchunks``, and
            # (for MHT payloads) swap the staged input to the unpacked
            # MHT so the attacker-visible content actually renders.
            if label in ("docx", "docm", "dotx", "dotm"):
                altchunks = []
                try:
                    from clippyshot.libreoffice.altchunk import inspect_altchunks

                    altchunks = inspect_altchunks(staged_input)
                    self.last_altchunks = [
                        {
                            "part_name": a.part_name,
                            "content_type": a.content_type,
                            "size": a.size,
                        }
                        for a in altchunks
                    ]
                except Exception:
                    pass
                unsupported_altchunks = [
                    a
                    for a in altchunks
                    if a.content_type not in _RENDERABLE_ALTCHUNK_TYPES
                ]
                if unsupported_altchunks:
                    details = ", ".join(
                        f"{a.content_type} at {a.part_name}"
                        for a in unsupported_altchunks
                    )
                    raise LibreOfficeError(
                        "unsupported Word altChunk payload(s): "
                        f"{details}; faithful rendering is not supported"
                    )
                renderable_altchunks = [
                    a for a in altchunks if a.content_type in _RENDERABLE_ALTCHUNK_TYPES
                ]
                if len(renderable_altchunks) > 1:
                    raise LibreOfficeError(
                        "multiple renderable Word altChunk payloads detected; "
                        "faithful rendering is ambiguous"
                    )
                altchunk = renderable_altchunks[0] if renderable_altchunks else None
                if altchunk is not None:
                    if altchunk.content_type == "message/rfc822":
                        from clippyshot.libreoffice.mht_unpack import unpack_mht

                        alt_mht = stage / "_altchunk.mht"
                        alt_mht.write_bytes(altchunk.data)
                        alt_dir = stage / "_altchunk_unpack"
                        alt_dir.mkdir()
                        html_path = unpack_mht(alt_mht, alt_dir)
                        if html_path is None:
                            raise LibreOfficeError(
                                f"failed to unpack altChunk payload at {altchunk.part_name}"
                            )
                        for entry in alt_dir.iterdir():
                            dest = stage / entry.name
                            if dest.exists():
                                dest.unlink()
                            shutil.move(str(entry), str(dest))
                        alt_dir.rmdir()
                        rewritten_html = stage / f"{input_path.stem}.html"
                        if rewritten_html.exists():
                            rewritten_html.unlink()
                        (stage / html_path.name).rename(rewritten_html)
                        staged_input = rewritten_html
                        staged_name = staged_input.name
                        label = "mht"
                        preserve_rewritten_input = True
                    else:
                        suffix = (
                            ".xhtml"
                            if altchunk.content_type == "application/xhtml+xml"
                            else ".html"
                        )
                        alt_html = stage / f"{input_path.stem}{suffix}"
                        alt_html.write_bytes(altchunk.data)
                        staged_input = alt_html
                        staged_name = alt_html.name
                        preserve_rewritten_input = True

            from clippyshot.libreoffice.sheet_prep import patch_ooxml_for_print

            _patched = False
            if label in ("xlsx", "xlsm"):
                try:
                    patch_ooxml_for_print(staged_input)
                    _patched = True
                except Exception:
                    # Patch failed — file might be encrypted OLE with .xlsx
                    # extension (e.g., VelvetSweatshop). Fall through to the
                    # binary two-pass path to convert → patch → export.
                    _needs_binary_conversion = True

            if _needs_binary_conversion:
                try:
                    xlsx_dir = stage / "_xlsx_conv"
                    xlsx_dir.mkdir()
                    import logging as _logging

                    _log = _logging.getLogger("clippyshot.libreoffice.runner")
                    _log.info("two_pass: converting %s to xlsx", staged_name)
                    conv_result = self._sandbox.run(
                        SandboxRequest(
                            argv=[
                                self._soffice,
                                *_FIXED_FLAGS,
                                "-env:UserInstallation=file:///sandbox/profile",
                                "--convert-to",
                                "xlsx",
                                "--outdir",
                                "/sandbox/xlsx_conv",
                                str(Path("/sandbox/in") / staged_name),
                            ],
                            ro_mounts=[
                                Mount(stage, Path("/sandbox/in"), read_only=True)
                            ],
                            rw_mounts=[
                                Mount(
                                    xlsx_dir,
                                    Path("/sandbox/xlsx_conv"),
                                    read_only=False,
                                ),
                                Mount(
                                    profile_root,
                                    Path("/sandbox/profile"),
                                    read_only=False,
                                ),
                            ],
                            limits=limits,
                            env={"HOME": "/sandbox/profile", "SAL_NO_DBUS": "1"},
                        )
                    )
                    xlsx_files = list(xlsx_dir.glob("*.xlsx"))
                    _log.info(
                        "two_pass: exit=%d xlsx_count=%d",
                        conv_result.exit_code,
                        len(xlsx_files),
                    )
                    if conv_result.exit_code == 0 and xlsx_files:
                        converted = xlsx_files[0]
                        patch_ooxml_for_print(converted)
                        # Move the patched xlsx to the stage root so the
                        # sandbox can reach it via /sandbox/in/
                        final = stage / converted.name
                        shutil.move(str(converted), str(final))
                        staged_input = final
                        staged_name = final.name
                        _log.info(
                            "two_pass: patched %s, using for PDF export", staged_name
                        )
                except Exception as e:
                    import logging as _logging

                    _logging.getLogger("clippyshot.libreoffice.runner").warning(
                        "two_pass failed: %s", e
                    )
                    pass  # fall through: convert original directly to PDF

            # Build the fallback chain: try the best filter first, then
            # progressively simpler ones. Always try to produce SOMETHING.
            filters_to_try = [pdf_filter]
            if label in ("xlsx", "xlsm", "xls", "ods", "fods", "csv", "xlsb"):
                if (
                    pdf_filter
                    != 'calc_pdf_Export:{"SinglePageSheets":{"type":"boolean","value":"true"}}'
                ):
                    filters_to_try.append(
                        'calc_pdf_Export:{"SinglePageSheets":{"type":"boolean","value":"true"}}'
                    )
                if "calc_pdf_Export" not in filters_to_try:
                    filters_to_try.append("calc_pdf_Export")
            if pdf_filter != "writer_pdf_Export":
                filters_to_try.append("writer_pdf_Export")

            # Optimistic warm-UNO fast path. When a ready unoserver shares this
            # filesystem (the FC warm tier — soffice boot already paid), convert via
            # unoconvert: same LibreOffice engine + filters as the cold path, with no
            # per-job soffice boot. On ANY failure, fall through to the untouched cold
            # sandbox-retry loop below (a UNO hiccup must never fail the job).
            if self._uno_server is not None and self._uno_server.is_ready():
                warm_pdf = output_dir / (input_path.stem + ".pdf")
                try:
                    convert_via_uno(self._uno_server, staged_input, warm_pdf, label)
                except LibreOfficeError as exc:
                    import logging as _logging

                    _logging.getLogger("clippyshot.libreoffice.runner").warning(
                        "warm unoconvert failed (%s); falling back to cold soffice", exc
                    )
                else:
                    if staged_input.suffix.lower() in (".xlsx", ".xlsm"):
                        try:
                            from clippyshot.libreoffice.sheet_prep import (
                                read_sheet_list,
                            )

                            self.last_run_sheets = read_sheet_list(staged_input)
                        except Exception:
                            self.last_run_sheets = []
                    return warm_pdf

            last_error = None
            for attempt, filt in enumerate(filters_to_try):
                # Clean output dir between attempts
                for old_pdf in output_dir.glob("*.pdf"):
                    old_pdf.unlink()

                if (
                    attempt > 0
                    and staged_input.name != original_name
                    and not preserve_rewritten_input
                ):
                    staged_input = original_staged_input
                    staged_name = staged_input.name

                name_attempts = [(staged_input, staged_name)]
                if (
                    rewrite_active
                    and staged_name != original_name
                    and not preserve_rewritten_input
                ):
                    name_attempts.append((original_staged_input, original_name))

                for name_idx, (attempt_input, attempt_name) in enumerate(name_attempts):
                    sandbox_input = Path("/sandbox/in") / attempt_name
                    argv = [
                        self._soffice,
                        *_FIXED_FLAGS,
                        "-env:UserInstallation=file:///sandbox/profile",
                        "--convert-to",
                        f"pdf:{filt}",
                        "--outdir",
                        "/sandbox/out",
                        str(sandbox_input),
                    ]

                    req = SandboxRequest(
                        argv=argv,
                        ro_mounts=[
                            Mount(stage, Path("/sandbox/in"), read_only=True),
                        ],
                        rw_mounts=[
                            Mount(output_dir, Path("/sandbox/out"), read_only=False),
                            Mount(
                                profile_root, Path("/sandbox/profile"), read_only=False
                            ),
                        ],
                        limits=limits,
                        env={
                            "HOME": "/sandbox/profile",
                            "TMPDIR": "/sandbox/profile/tmp",
                            "SAL_NO_DBUS": "1",
                        },
                    )
                    result = self._sandbox.run(req)

                    if result.killed:
                        last_error = f"soffice killed (timeout?): {result.stderr.decode(errors='replace')}"
                        break

                    if result.exit_code != 0:
                        stderr_text = result.stderr.decode(errors="replace")
                        last_error = f"soffice exited {result.exit_code}: {stderr_text}"
                        can_retry_original_name = (
                            rewrite_active
                            and name_idx == 0
                            and attempt_name != original_name
                            and "source file could not be loaded" in stderr_text.lower()
                        )
                        if can_retry_original_name:
                            continue
                        break

                    # Check for PDF output
                    expected_pdf = output_dir / (input_path.stem + ".pdf")
                    if not expected_pdf.exists():
                        pdfs = list(output_dir.glob("*.pdf"))
                        if pdfs:
                            expected_pdf = pdfs[0]
                        else:
                            last_error = "soffice produced no PDF"
                            break

                    # Capture sheet names from the staged xlsx (the final
                    # form LO just exported from). For xlsx/xlsm inputs
                    # this is the original file patched in place; for
                    # xls/xlsb/ods/csv it's the intermediate xlsx the
                    # two-pass produced. Either way it's what LO actually
                    # saw, so the visible-sheet order aligns with the PDF.
                    if staged_input.suffix.lower() in (".xlsx", ".xlsm"):
                        try:
                            from clippyshot.libreoffice.sheet_prep import (
                                read_sheet_list,
                            )

                            self.last_run_sheets = read_sheet_list(staged_input)
                        except Exception:
                            self.last_run_sheets = []

                    return expected_pdf

            # All attempts failed
            if last_error and "killed" in last_error:
                raise LibreOfficeError(last_error)
            if last_error and "no PDF" in last_error:
                raise LibreOfficeEmptyOutputError(
                    "all conversion strategies failed; the input may be "
                    "malformed or an exploit targeting a parser LO no longer ships"
                )
            raise LibreOfficeError(last_error or "conversion failed")
