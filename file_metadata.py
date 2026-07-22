"""Rich file metadata extraction (PDF / Office / images / legacy OLE).

Uses pypdf, Pillow, and olefile when installed; stdlib fallbacks otherwise.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

# Optional power deps
try:
    from pypdf import PdfReader
except ImportError:  # pragma: no cover
    try:
        from PyPDF2 import PdfReader  # type: ignore
    except ImportError:
        PdfReader = None  # type: ignore

try:
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    TAGS = {}
    GPSTAGS = {}

try:
    import olefile
except ImportError:  # pragma: no cover
    olefile = None  # type: ignore

MAX_BYTES = 25 * 1024 * 1024
INTERESTING_META_KEYS = {
    "author",
    "creator",
    "producer",
    "company",
    "last_modified_by",
    "title",
    "subject",
    "keywords",
    "software",
    "make",
    "model",
    "datetime",
    "datetimeoriginal",
    "gps",
    "gps_latitude",
    "gps_longitude",
    "creator_tool",
    "application",
    "template",
}

PDF_AUTHOR_RE = re.compile(
    r"/(?:Author|Creator|Producer|Title|Subject|Keywords)\s*\((?:\\.|[^\\)]){1,200}\)",
    re.IGNORECASE,
)


def looks_like_document(url: str, content_type: str = "", body: bytes = b"") -> str:
    """Return kind: pdf|image|ooxml|ole|''."""
    path = (urlparse(url).path or "").lower()
    ct = (content_type or "").lower()
    head = body[:16] if body else b""

    if head.startswith(b"%PDF") or path.endswith(".pdf") or "application/pdf" in ct:
        return "pdf"
    if head.startswith(b"\xff\xd8\xff") or path.endswith((".jpg", ".jpeg")) or "image/jpeg" in ct:
        return "image"
    if head.startswith(b"\x89PNG") or path.endswith(".png") or "image/png" in ct:
        return "image"
    if head[:6] in (b"GIF87a", b"GIF89a") or path.endswith(".gif") or "image/gif" in ct:
        return "image"
    if head.startswith(b"II*\x00") or head.startswith(b"MM\x00*") or path.endswith((".tif", ".tiff", ".webp")):
        return "image"
    if head.startswith(b"PK\x03\x04") or path.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")):
        # Confirm OOXML/ODF vs random zip
        if path.endswith((".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp")):
            return "ooxml"
        sample = body[:8000]
        if body and (b"word/" in sample or b"xl/" in sample or b"ppt/" in sample):
            return "ooxml"
        if body and b"mimetype" in body[:2000] and b"opendocument" in body[:4000]:
            return "ooxml"
    if path.endswith((".doc", ".xls", ".ppt")) or (body[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if "image/" in ct:
        return "image"
    return ""


def extract_file_metadata(
    url: str,
    body: bytes,
    content_type: str = "",
) -> Optional[Dict[str, Any]]:
    """Return a metadata record or None if not applicable / empty."""
    if not body or len(body) > MAX_BYTES:
        return None
    kind = looks_like_document(url, content_type, body)
    if not kind:
        return None

    fields: Dict[str, str] = {}
    engine = "none"
    if kind == "pdf":
        fields, engine = _extract_pdf(body)
    elif kind == "image":
        fields, engine = _extract_image(body)
    elif kind == "ooxml":
        fields, engine = _extract_ooxml(body, url)
    elif kind == "ole":
        fields, engine = _extract_ole(body)

    if not fields:
        return None

    interesting = {k: v for k, v in fields.items() if k.lower() in INTERESTING_META_KEYS or k.lower().startswith("gps")}
    return {
        "url": url,
        "kind": kind,
        "engine": engine,
        "fields": fields,
        "interesting": interesting,
        "size": len(body),
    }


def metadata_findings(record: Dict[str, Any]) -> List[Tuple[str, str, str, Optional[str]]]:
    """Return (category, severity, detail, evidence) tuples for notable metadata."""
    if not record:
        return []
    out: List[Tuple[str, str, str, Optional[str]]] = []
    fields = record.get("fields") or {}
    url = record.get("url") or ""

    gps_lat = fields.get("gps_latitude") or fields.get("GPSLatitude")
    gps_lon = fields.get("gps_longitude") or fields.get("GPSLongitude")
    if gps_lat and gps_lon:
        evidence = f"{gps_lat}, {gps_lon}"
        out.append(
            (
                "file_metadata",
                "medium",
                f"Image GPS coordinates embedded in file metadata at {url}",
                evidence,
            )
        )

    # Plain Author/Creator names stay in inventory fields — only emit PII / internal hints
    for key in ("author", "creator", "last_modified_by", "company"):
        value = fields.get(key) or fields.get(key.title()) or fields.get(key.upper())
        if not value:
            for fk, fv in fields.items():
                if fk.lower() == key and fv:
                    value = fv
                    break
        if not value:
            continue
        if not re.search(r"(?i)@|\.local\b|\binternal\b|corp\\|\\\\", str(value)):
            continue
        out.append(
            (
                "file_metadata",
                "medium",
                f"Document {key.replace('_', ' ')} in metadata may leak PII/internal identity: {str(value)[:120]}",
                str(value)[:160],
            )
        )
    return out[:12]


def _extract_pdf(body: bytes) -> Tuple[Dict[str, str], str]:
    fields: Dict[str, str] = {}
    if PdfReader is not None:
        try:
            reader = PdfReader(io.BytesIO(body))
            meta = reader.metadata
            if meta is not None:
                attr_map = {
                    "author": "author",
                    "creator": "creator",
                    "producer": "producer",
                    "title": "title",
                    "subject": "subject",
                    "keywords": "keywords",
                    "creation_date": "creation_date",
                    "modification_date": "mod_date",
                }
                for attr, dest in attr_map.items():
                    value = getattr(meta, attr, None)
                    if value:
                        fields[dest] = str(value).strip()
                # Dict-style keys as backup
                for src, dest in (
                    ("/Author", "author"),
                    ("/Creator", "creator"),
                    ("/Producer", "producer"),
                    ("/Title", "title"),
                    ("/Subject", "subject"),
                    ("/Keywords", "keywords"),
                ):
                    if dest in fields:
                        continue
                    try:
                        value = meta.get(src) if hasattr(meta, "get") else meta[src]  # type: ignore[index]
                    except Exception:
                        value = None
                    if value:
                        fields[dest] = str(value).strip()
            if fields:
                return fields, "pypdf"
        except Exception:
            pass

    # Regex fallback on raw PDF trailer-ish text
    try:
        text = body[:500_000].decode("latin-1", errors="ignore")
    except Exception:
        return {}, "none"
    for match in PDF_AUTHOR_RE.finditer(text):
        token = match.group(0)
        key_m = re.match(r"/(\w+)", token)
        val_m = re.search(r"\((?:\\.|[^\\)])*\)", token)
        if not key_m or not val_m:
            continue
        key = key_m.group(1).lower()
        raw = val_m.group(0)[1:-1]
        raw = raw.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
        if raw.strip():
            fields[key] = raw.strip()[:300]
    return fields, "regex" if fields else "none"


def _extract_image(body: bytes) -> Tuple[Dict[str, str], str]:
    fields: Dict[str, str] = {}
    if Image is None:
        return _extract_jpeg_exif_minimal(body)

    try:
        img = Image.open(io.BytesIO(body))
        fields["format"] = str(img.format or "")
        fields["image_size"] = f"{img.width}x{img.height}"
        exif = img.getexif() if hasattr(img, "getexif") else None
        if not exif:
            # Older API
            raw = getattr(img, "_getexif", lambda: None)()
            if raw:
                for tag_id, value in raw.items():
                    name = TAGS.get(tag_id, str(tag_id))
                    fields[_norm_key(name)] = _stringify(value)[:300]
            return fields, "pillow" if fields else "none"

        for tag_id, value in exif.items():
            name = TAGS.get(tag_id, str(tag_id))
            if name == "GPSInfo" and isinstance(value, dict):
                gps = _parse_gps(value)
                fields.update(gps)
            else:
                fields[_norm_key(name)] = _stringify(value)[:300]

        # Pillow 10+ GPS via get_ifd
        try:
            gps_ifd = exif.get_ifd(0x8825)
            if gps_ifd:
                fields.update(_parse_gps(gps_ifd))
        except Exception:
            pass
        return fields, "pillow"
    except Exception:
        return _extract_jpeg_exif_minimal(body)


def _extract_jpeg_exif_minimal(body: bytes) -> Tuple[Dict[str, str], str]:
    """Bare EXIF ASCII strings from JPEG APP1 — last-resort fallback."""
    if not body.startswith(b"\xff\xd8"):
        return {}, "none"
    idx = body.find(b"Exif\x00\x00")
    if idx < 0:
        return {}, "none"
    chunk = body[idx : idx + 64_000]
    fields: Dict[str, str] = {}
    for pattern, key in (
        (rb"ASCII\x00\x00\x00([ -~]{4,80})", "exif_ascii"),
        (rb"([A-Za-z0-9_ ./:\-]{8,60})", "exif_string"),
    ):
        for match in re.finditer(pattern, chunk):
            value = match.group(1).decode("ascii", errors="ignore").strip()
            if value and key not in fields:
                fields[key] = value
                break
    return fields, "jpeg-scan" if fields else "none"


def _extract_ooxml(body: bytes, url: str = "") -> Tuple[Dict[str, str], str]:
    fields: Dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = set(zf.namelist())
            # OOXML core/app props
            for candidate in (
                "docProps/core.xml",
                "docProps/app.xml",
                "meta.xml",  # ODF
            ):
                if candidate not in names:
                    continue
                try:
                    xml = zf.read(candidate)
                except Exception:
                    continue
                fields.update(_parse_office_xml(xml))
            if not fields and url.lower().endswith((".odt", ".ods", ".odp")):
                pass
    except zipfile.BadZipFile:
        return {}, "none"
    except Exception:
        return fields, "ooxml" if fields else "none"
    return fields, "ooxml" if fields else "none"


def _parse_office_xml(xml: bytes) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return fields
    # Strip namespaces for easier matching
    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower() if isinstance(elem.tag, str) else ""
        text = (elem.text or "").strip()
        if not text or len(text) > 500:
            continue
        mapping = {
            "creator": "author",
            "lastmodifiedby": "last_modified_by",
            "title": "title",
            "subject": "subject",
            "description": "description",
            "keywords": "keywords",
            "created": "creation_date",
            "modified": "mod_date",
            "application": "application",
            "appversion": "app_version",
            "company": "company",
            "template": "template",
            "generator": "creator_tool",
            "initial-creator": "author",
            "editing-cycles": "editing_cycles",
        }
        key = mapping.get(tag)
        if key and key not in fields:
            fields[key] = text
    return fields


def _extract_ole(body: bytes) -> Tuple[Dict[str, str], str]:
    fields: Dict[str, str] = {}
    if olefile is None:
        return fields, "none"
    try:
        if not olefile.isOleFile(io.BytesIO(body)):
            return {}, "none"
        with olefile.OleFileIO(io.BytesIO(body)) as ole:
            meta = ole.get_metadata()
            for attr in (
                "author",
                "title",
                "subject",
                "keywords",
                "comments",
                "last_saved_by",
                "creating_application",
                "create_time",
                "last_saved_time",
                "company",
            ):
                value = getattr(meta, attr, None)
                if value:
                    key = "last_modified_by" if attr == "last_saved_by" else attr
                    if attr == "creating_application":
                        key = "application"
                    fields[key] = _stringify(value)[:300]
    except Exception:
        return fields, "olefile" if fields else "none"
    return fields, "olefile" if fields else "none"


def _parse_gps(gps_info: dict) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not gps_info:
        return out
    decoded = {}
    for key, value in gps_info.items():
        name = GPSTAGS.get(key, key) if GPSTAGS else key
        decoded[str(name)] = value

    def _to_deg(values, ref) -> Optional[float]:
        try:
            d, m, s = values
            deg = float(d) + float(m) / 60.0 + float(s) / 3600.0
            if ref in ("S", "W"):
                deg = -deg
            return deg
        except Exception:
            return None

    lat = _to_deg(decoded.get("GPSLatitude"), decoded.get("GPSLatitudeRef", "N"))
    lon = _to_deg(decoded.get("GPSLongitude"), decoded.get("GPSLongitudeRef", "E"))
    if lat is not None and lon is not None:
        out["gps_latitude"] = f"{lat:.6f}"
        out["gps_longitude"] = f"{lon:.6f}"
        out["gps"] = f"{lat:.6f},{lon:.6f}"
    return out


def _norm_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00")
    if isinstance(value, (list, tuple)):
        return ", ".join(_stringify(v) for v in value)
    return str(value)
