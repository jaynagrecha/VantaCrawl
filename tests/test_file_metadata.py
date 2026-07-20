"""File metadata extraction — PDF / OOXML / images."""

import io
import struct
import zipfile

from file_metadata import (
    extract_file_metadata,
    looks_like_document,
    metadata_findings,
)


def _minimal_pdf_with_author(author: str = "Ada Lovelace") -> bytes:
    # Tiny valid-enough PDF with Info dict for pypdf / regex fallback
    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R >>endobj\n"
    )
    objects.append(b"4 0 obj<< /Length 0 >>stream\nendstream\nendobj\n")
    info = f"5 0 obj<< /Author ({author}) /Creator (UnitTest) /Producer (pytest) /Title (Lab) >>endobj\n".encode()
    objects.append(info)

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(
        f"trailer<< /Size {len(offsets)} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return bytes(out)


def _minimal_docx(author: str = "Grace Hopper") -> bytes:
    core = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
      xmlns:dc="http://purl.org/dc/elements/1.1/"
      xmlns:dcterms="http://purl.org/dc/terms/"
      xmlns:dcmitype="http://purl.org/dc/dcmitype/"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <dc:creator>{author}</dc:creator>
      <cp:lastModifiedBy>lab-admin</cp:lastModifiedBy>
      <dc:title>Secret Plan</dc:title>
    </cp:coreProperties>""".encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("docProps/core.xml", core)
    return buf.getvalue()


def _minimal_jpeg() -> bytes:
    # 1x1 JPEG (no EXIF) — still classified as image
    return bytes(
        [
            0xFF,
            0xD8,
            0xFF,
            0xE0,
            0x00,
            0x10,
            0x4A,
            0x46,
            0x49,
            0x46,
            0x00,
            0x01,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0xFF,
            0xDB,
            0x00,
            0x43,
            0x00,
            *([0x08] * 64),
            0xFF,
            0xC0,
            0x00,
            0x0B,
            0x08,
            0x00,
            0x01,
            0x00,
            0x01,
            0x01,
            0x01,
            0x11,
            0x00,
            0xFF,
            0xC4,
            0x00,
            0x14,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0xFF,
            0xDA,
            0x00,
            0x08,
            0x01,
            0x01,
            0x00,
            0x00,
            0x3F,
            0x00,
            0x7F,
            0xFF,
            0xD9,
        ]
    )


def test_looks_like_pdf_and_docx():
    assert looks_like_document("https://x.com/a.pdf", "application/pdf", b"%PDF-1.4") == "pdf"
    assert looks_like_document("https://x.com/a.docx", "", _minimal_docx()) == "ooxml"
    assert looks_like_document("https://x.com/a.jpg", "image/jpeg", _minimal_jpeg()) == "image"


def test_pdf_author_extracted():
    body = _minimal_pdf_with_author("Ada Lovelace")
    record = extract_file_metadata("https://lab.example/report.pdf", body, "application/pdf")
    assert record
    assert record["kind"] == "pdf"
    fields = {k.lower(): v for k, v in record["fields"].items()}
    assert any("ada" in v.lower() for v in fields.values())


def test_docx_author_extracted():
    body = _minimal_docx("Grace Hopper")
    record = extract_file_metadata("https://lab.example/plan.docx", body, "")
    assert record and record["kind"] == "ooxml"
    assert record["fields"].get("author") == "Grace Hopper"
    assert record["fields"].get("last_modified_by") == "lab-admin"


def test_metadata_findings_flag_author():
    record = {
        "url": "https://x.com/a.pdf",
        "fields": {"author": "jsmith@corp.local", "title": "Q1"},
        "interesting": {"author": "jsmith@corp.local"},
    }
    findings = metadata_findings(record)
    assert any(f[0] == "file_metadata" and f[1] == "medium" for f in findings)


def test_html_not_treated_as_document():
    assert looks_like_document("https://x.com/", "text/html", b"<html>hi</html>") == ""
    assert extract_file_metadata("https://x.com/", b"<html>hi</html>", "text/html") is None
