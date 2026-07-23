"""Path-shape wildcard calibration, response fingerprints, and enum hit classification.

Proves an accepted enum hit is a distinct resource — not a wildcard/soft-404 fallback —
before security analysis or crawl enqueue.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

# Path-shape classes used for wildcard controls (required audit set).
SHAPE_RANDOM = "random"  # /random-<nonce> or /crawler-wildcard-<nonce>
SHAPE_DOT_PREFIX = "dot_prefix"  # /.<nonce>
SHAPE_INDEX_EXT = "index_ext"  # /index.<nonce>
SHAPE_EXT_PHP = "ext_php"  # /<nonce>.php
SHAPE_EXT_BAK = "ext_bak"  # /<nonce>.bak
SHAPE_NESTED = "nested"  # /<nonce>/<nonce>
SHAPE_CASE = "case"  # /RANDOMCASE-<nonce>
SHAPE_PLAIN = "plain"  # ordinary /word or /path/seg

ALL_SHAPES = (
    SHAPE_RANDOM,
    SHAPE_DOT_PREFIX,
    SHAPE_INDEX_EXT,
    SHAPE_EXT_PHP,
    SHAPE_EXT_BAK,
    SHAPE_NESTED,
    SHAPE_CASE,
)

# Classifications for accepted / rejected candidates
CLASS_CONFIRMED = "confirmed_unique_resource"
CLASS_WILDCARD = "wildcard_response"
CLASS_SOFT_404 = "soft_404"
CLASS_CASE_VARIANT = "case_variant"
CLASS_CONTENT_DUP = "content_equivalent_fallback"
CLASS_ALREADY_KNOWN = "already_known"
CLASS_REDIRECT_EXISTING = "redirected_existing_route"
CLASS_INCONCLUSIVE_429 = "inconclusive_rate_limited"
CLASS_REJECTED_STATUS = "rejected_status"
CLASS_UNVERIFIED = "unverified_candidate"


@dataclass
class ResponseFingerprint:
    """Full response fingerprint for every enum HTTP attempt."""

    url: str = ""
    status: int = 0
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    length: int = 0
    content_type: str = ""
    title: str = ""
    raw_hash: str = ""
    normalized_hash: str = ""
    similarity: float = 0.0  # 0..1 similarity to matched baseline (1 = identical)
    duration_ms: float = 0.0
    baseline_shape: str = ""
    acceptance_reason: str = ""

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "status": self.status,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "length": self.length,
            "content_type": self.content_type,
            "title": self.title,
            "raw_hash": self.raw_hash,
            "normalized_hash": self.normalized_hash,
            "similarity": round(self.similarity, 4),
            "duration_ms": round(self.duration_ms, 2),
            "baseline_shape": self.baseline_shape,
            "acceptance_reason": self.acceptance_reason,
        }


@dataclass
class ShapeBaseline:
    """Wildcard / soft-404 fingerprint for one path shape class."""

    shape: str
    active: bool = False
    status: int = 0
    length: int = 0
    raw_hash: str = ""
    normalized_hash: str = ""
    content_type: str = ""
    title: str = ""
    samples: int = 0
    control_url: str = ""

    def signature(self) -> Tuple[int, int, str]:
        return (self.status, self.length, self.raw_hash)

    def matches(
        self,
        *,
        status: int,
        length: int,
        raw_hash: str,
        normalized_hash: str = "",
        similarity_threshold: int = 64,
    ) -> Tuple[bool, float]:
        if not self.active or not status:
            return False, 0.0
        if status != self.status:
            return False, 0.0
        if raw_hash and self.raw_hash and raw_hash == self.raw_hash:
            return True, 1.0
        if normalized_hash and self.normalized_hash and normalized_hash == self.normalized_hash:
            return True, 0.98
        if self.length and length and abs(length - self.length) < max(8, similarity_threshold):
            # Same status + near-identical length ⇒ soft-404 / wildcard candidate
            if not raw_hash or not self.raw_hash or raw_hash == self.raw_hash:
                return True, 0.85
            # Different hash but near length — still suspicious for catch-all stores
            if abs(length - self.length) <= max(16, similarity_threshold // 2):
                return True, 0.7
        return False, 0.0


@dataclass
class WildcardProfile:
    """Multi-shape wildcard calibration for a directory prefix."""

    active: bool = False
    # Legacy triple signatures (status, length, hash) — kept for older call sites
    signatures: Set[Tuple[int, int, str]] = field(default_factory=set)
    shapes: Dict[str, ShapeBaseline] = field(default_factory=dict)
    calibration_ok: bool = False
    calibration_notes: List[str] = field(default_factory=list)
    catch_all_200: bool = False
    # Optional raw bodies for DOM/text similarity (shape -> body bytes, capped)
    shape_bodies: Dict[str, bytes] = field(default_factory=dict)

    def baseline_for(self, shape: str) -> Optional[ShapeBaseline]:
        return self.shapes.get(shape)

    def any_active_shape(self) -> bool:
        return any(b.active for b in self.shapes.values())


def nonce(n: int = 12) -> str:
    return uuid.uuid4().hex[: max(8, n)]


def raw_body_hash(body: bytes, *, max_bytes: int = 65536) -> str:
    if not body:
        return "empty"
    return hashlib.sha256(body[:max_bytes]).hexdigest()[:32]


def normalize_body_for_hash(body: bytes, *, max_bytes: int = 65536) -> str:
    """Normalize HTML/text so soft-404 variants with nonce crumbs still collide."""
    if not body:
        return "empty"
    text = body[:max_bytes].decode("utf-8", errors="replace")
    text = text.lower()
    # Strip scripts/styles noise
    text = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    # Drop long hex/uuid-like tokens (control nonces, cache busters)
    text = re.sub(r"\b[a-f0-9]{8,}\b", "#", text)
    text = re.sub(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", "#", text)
    # Drop numeric ids
    text = re.sub(r"\b\d{4,}\b", "#", text)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:32]
    return digest


def extract_title(body: bytes, *, max_scan: int = 8192) -> str:
    if not body:
        return ""
    head = body[:max_scan].decode("utf-8", errors="replace")
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", head)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def classify_path_shape(path_or_word: str) -> str:
    """Map a candidate path/word onto a wildcard control class."""
    raw = (path_or_word or "").strip()
    path = urlparse(raw).path if "://" in raw else raw
    path = path.replace("\\", "/")
    segs = [s for s in path.strip("/").split("/") if s]
    if not segs:
        return SHAPE_PLAIN
    leaf = segs[-1]
    # Nested multi-segment random-ish
    if len(segs) >= 2 and all(re.fullmatch(r"[A-Za-z0-9_-]{6,}", s or "") for s in segs[-2:]):
        # Only treat as nested shape when both look nonce-like; otherwise plain
        if all(re.search(r"[0-9a-f]{6,}", s, re.I) for s in segs[-2:]):
            return SHAPE_NESTED
    if leaf.startswith(".") and len(leaf) > 1:
        return SHAPE_DOT_PREFIX
    low = leaf.lower()
    if low.startswith("index.") and "." in leaf[6:]:
        return SHAPE_INDEX_EXT
    if re.fullmatch(r"(?i)index\.[A-Za-z0-9_-]+", leaf):
        return SHAPE_INDEX_EXT
    if re.fullmatch(r"(?i).+\.php$", leaf):
        return SHAPE_EXT_PHP
    if re.fullmatch(r"(?i).+\.bak$", leaf):
        return SHAPE_EXT_BAK
    if re.fullmatch(r"(?i)randomcase-[A-Za-z0-9_-]+", leaf) or (
        leaf != leaf.lower() and leaf != leaf.upper() and re.search(r"[A-Z].*[a-z]|[a-z].*[A-Z]", leaf)
    ):
        # Mixed / upper control words map to case shape when probing; candidates with
        # unusual casing still use case baseline when present.
        if re.fullmatch(r"(?i)randomcase-[A-Za-z0-9_-]+", leaf) or leaf.isupper():
            return SHAPE_CASE
    if re.fullmatch(r"(?i)(?:random|crawler-wildcard)-[A-Za-z0-9_-]+", leaf):
        return SHAPE_RANDOM
    if leaf.startswith(".") or leaf.startswith("/."):
        return SHAPE_DOT_PREFIX
    return SHAPE_PLAIN


def relevant_shapes_for_candidate(path_or_word: str) -> List[str]:
    """Which baseline classes apply when validating this candidate."""
    shape = classify_path_shape(path_or_word)
    # Always compare against plain/random catch-all; add shape-specific class.
    out: List[str] = [SHAPE_RANDOM]
    if shape != SHAPE_PLAIN and shape != SHAPE_RANDOM:
        out.append(shape)
    elif shape == SHAPE_PLAIN:
        # Plain routes: also check case baseline if leaf is mixed-case
        leaf = (path_or_word or "").strip("/").rsplit("/", 1)[-1]
        if leaf and leaf != leaf.lower() and leaf != leaf.upper():
            out.append(SHAPE_CASE)
    # Dot-prefixed always include dot baseline
    leaf = (urlparse(path_or_word).path if "://" in (path_or_word or "") else path_or_word or "")
    leaf = leaf.strip("/").rsplit("/", 1)[-1]
    if leaf.startswith("."):
        if SHAPE_DOT_PREFIX not in out:
            out.append(SHAPE_DOT_PREFIX)
    if re.fullmatch(r"(?i)index\..+", leaf or ""):
        if SHAPE_INDEX_EXT not in out:
            out.append(SHAPE_INDEX_EXT)
    if re.fullmatch(r"(?i).+\.php$", leaf or ""):
        if SHAPE_EXT_PHP not in out:
            out.append(SHAPE_EXT_PHP)
    if re.fullmatch(r"(?i).+\.bak$", leaf or ""):
        if SHAPE_EXT_BAK not in out:
            out.append(SHAPE_EXT_BAK)
    return out


def control_paths_for_base(base_url: str) -> Dict[str, str]:
    """Build absolute control URLs for every required path shape."""
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    base_path = parsed.path or "/"
    if not base_path.endswith("/"):
        # Treat file-like leaf as directory parent
        leaf = base_path.rsplit("/", 1)[-1]
        if leaf and "." in leaf:
            base_path = base_path[: base_path.rfind("/") + 1] or "/"
        else:
            base_path = base_path.rstrip("/") + "/"
    n = nonce(16)
    n2 = nonce(12)
    n_case = f"RANDOMCASE-{n[:10]}"
    relative = {
        SHAPE_RANDOM: f"random-{n}",
        SHAPE_DOT_PREFIX: f".{n}",
        SHAPE_INDEX_EXT: f"index.{n[:10]}",
        SHAPE_EXT_PHP: f"{n2}.php",
        SHAPE_EXT_BAK: f"{n2}.bak",
        SHAPE_NESTED: f"{n[:8]}/{n2[:8]}",
        SHAPE_CASE: n_case,
    }
    out: Dict[str, str] = {}
    for shape, rel in relative.items():
        out[shape] = urljoin(root + base_path, rel)
    return out


def fingerprint_from_response(
    *,
    url: str,
    status: int,
    body: bytes,
    final_url: str = "",
    redirect_chain: Optional[List[str]] = None,
    content_type: str = "",
    duration_ms: float = 0.0,
    length: Optional[int] = None,
) -> ResponseFingerprint:
    raw = raw_body_hash(body)
    norm = normalize_body_for_hash(body)
    title = extract_title(body)
    return ResponseFingerprint(
        url=url,
        status=int(status or 0),
        final_url=final_url or url,
        redirect_chain=list(redirect_chain or []),
        length=int(length if length is not None else len(body or b"")),
        content_type=(content_type or "")[:120],
        title=title,
        raw_hash=raw,
        normalized_hash=norm,
        duration_ms=float(duration_ms or 0.0),
    )


def casefold_path_key(url: str) -> str:
    parsed = urlparse(url)
    path = (parsed.path or "/").casefold()
    # Drop trailing slash except root
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return f"{(parsed.netloc or '').casefold()}{path}"


def is_dot_prefixed_path(url_or_path: str) -> bool:
    path = urlparse(url_or_path).path if "://" in (url_or_path or "") else (url_or_path or "")
    leaf = path.strip("/").rsplit("/", 1)[-1] if path.strip("/") else ""
    return bool(leaf.startswith(".") and len(leaf) > 1)


@dataclass
class EnumHitRecord:
    """Rich enumeration result persisted to SQLite / reports."""

    url: str
    source: str = "directory_enum"
    base_word: str = ""
    variant: str = ""
    already_known: bool = False
    requested_status: int = 0
    final_status: int = 0
    final_url: str = ""
    classification: str = CLASS_UNVERIFIED
    path_shape: str = SHAPE_PLAIN
    fingerprint: Optional[ResponseFingerprint] = None
    wildcard_similarity: float = 0.0
    acceptance_reason: str = ""
    baseline_used: str = ""
    case_group: str = ""
    content_group: str = ""
    validated: bool = False

    def to_evidence_json(self) -> str:
        import json

        payload = {
            "url": self.url,
            "source": self.source,
            "base_word": self.base_word,
            "variant": self.variant,
            "already_known": self.already_known,
            "requested_status": self.requested_status,
            "final_status": self.final_status,
            "final_url": self.final_url,
            "classification": self.classification,
            "path_shape": self.path_shape,
            "wildcard_similarity": self.wildcard_similarity,
            "acceptance_reason": self.acceptance_reason,
            "baseline_used": self.baseline_used,
            "case_group": self.case_group,
            "content_group": self.content_group,
            "validated": self.validated,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else {},
        }
        return json.dumps(payload, ensure_ascii=False)

    def to_dict(self) -> Dict:
        import json

        return json.loads(self.to_evidence_json())


class HitProvenanceTracker:
    """Tracks already-known URLs, case groups, and content-equivalent fallbacks."""

    def __init__(self, known_urls: Optional[Iterable[str]] = None):
        self.known_casefold: Set[str] = set()
        self.known_exact: Set[str] = set()
        self.accepted_casefold: Dict[str, str] = {}  # casefold -> first url
        self.content_groups: Dict[str, str] = {}  # norm hash -> first url
        self.records: List[EnumHitRecord] = []
        for u in known_urls or []:
            if not u:
                continue
            self.known_exact.add(u)
            self.known_casefold.add(casefold_path_key(u))

    def note_known(self, urls: Iterable[str]) -> None:
        for u in urls or []:
            if not u:
                continue
            self.known_exact.add(u)
            self.known_casefold.add(casefold_path_key(u))

    def classify_and_record(
        self,
        *,
        url: str,
        base_word: str,
        variant: str,
        requested_status: int,
        final_status: int,
        final_url: str,
        fingerprint: ResponseFingerprint,
        wildcard_rejected: bool,
        wildcard_similarity: float,
        baseline_used: str,
        soft_404: bool,
        path_shape: str,
    ) -> EnumHitRecord:
        ck = casefold_path_key(url)
        already = url in self.known_exact or ck in self.known_casefold
        content_key = fingerprint.normalized_hash or fingerprint.raw_hash or ""
        case_group = ""
        content_group = ""
        classification = CLASS_CONFIRMED
        validated = True
        reason = "distinct_from_wildcard_baselines"

        if wildcard_rejected:
            classification = CLASS_WILDCARD
            validated = False
            reason = f"matched_wildcard_shape:{baseline_used or path_shape}"
        elif soft_404:
            classification = CLASS_SOFT_404
            validated = False
            reason = "soft_404_baseline"
        elif already:
            classification = CLASS_ALREADY_KNOWN
            validated = True
            reason = "path_known_before_enum"
        elif ck in self.accepted_casefold:
            classification = CLASS_CASE_VARIANT
            validated = False
            case_group = self.accepted_casefold[ck]
            reason = f"case_variant_of:{case_group}"
        elif content_key and content_key not in ("empty", "head-only") and content_key in self.content_groups:
            classification = CLASS_CONTENT_DUP
            validated = False
            content_group = self.content_groups[content_key]
            reason = f"content_equivalent_to:{content_group}"
        elif final_url and casefold_path_key(final_url) != ck and (
            final_url in self.known_exact or casefold_path_key(final_url) in self.known_casefold
        ):
            classification = CLASS_REDIRECT_EXISTING
            validated = True
            reason = "redirects_to_known_route"

        if classification == CLASS_CONFIRMED:
            self.accepted_casefold.setdefault(ck, url)
            if content_key and content_key not in ("empty", "head-only"):
                self.content_groups.setdefault(content_key, url)

        fingerprint.acceptance_reason = reason
        fingerprint.baseline_shape = baseline_used
        fingerprint.similarity = wildcard_similarity

        rec = EnumHitRecord(
            url=url,
            base_word=base_word,
            variant=variant,
            already_known=already,
            requested_status=requested_status,
            final_status=final_status,
            final_url=final_url or url,
            classification=classification,
            path_shape=path_shape,
            fingerprint=fingerprint,
            wildcard_similarity=wildcard_similarity,
            acceptance_reason=reason,
            baseline_used=baseline_used,
            case_group=case_group,
            content_group=content_group,
            validated=validated and classification in (
                CLASS_CONFIRMED,
                CLASS_ALREADY_KNOWN,
                CLASS_REDIRECT_EXISTING,
            ),
        )
        self.records.append(rec)
        return rec


def matches_any_shape_baseline(
    profile: WildcardProfile,
    *,
    path_or_word: str,
    status: int,
    length: int,
    raw_hash: str,
    normalized_hash: str,
    similarity_threshold: int = 64,
) -> Tuple[bool, float, str]:
    """Return (matched, similarity, shape_used)."""
    if not profile or not profile.shapes:
        # Legacy signature fallback
        if profile and profile.active and (status, length, raw_hash[:16] if raw_hash else "") in {
            (s, l, h) for s, l, h in profile.signatures
        }:
            return True, 1.0, SHAPE_RANDOM
        # Try short-hash legacy compare
        if profile and profile.active:
            for s, l, h in profile.signatures:
                if s == status and (raw_hash.startswith(h) or h.startswith(raw_hash[:16]) or (
                    abs(l - length) < similarity_threshold and (not h or h == raw_hash[:16])
                )):
                    return True, 0.9, SHAPE_RANDOM
        return False, 0.0, ""

    best_sim = 0.0
    best_shape = ""
    matched = False
    for shape in relevant_shapes_for_candidate(path_or_word):
        base = profile.shapes.get(shape)
        if not base:
            continue
        ok, sim = base.matches(
            status=status,
            length=length,
            raw_hash=raw_hash,
            normalized_hash=normalized_hash,
            similarity_threshold=similarity_threshold,
        )
        if ok and sim >= best_sim:
            matched = True
            best_sim = sim
            best_shape = shape
    return matched, best_sim, best_shape


def text_similarity(a: bytes, b: bytes, *, max_bytes: int = 8192) -> float:
    """DOM/text similarity 0..1 using normalized body text (SequenceMatcher)."""
    from difflib import SequenceMatcher

    def _norm(raw: bytes) -> str:
        text = (raw or b"")[:max_bytes].decode("utf-8", errors="replace").lower()
        text = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", text)
        text = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        text = re.sub(r"\b[a-f0-9]{8,}\b", "#", text)
        return text[:4000]

    sa, sb = _norm(a), _norm(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return float(SequenceMatcher(None, sa, sb).ratio())


def enum_validation_conclusion(
    *,
    http_attempts: int,
    accepted_hits: int,
    rejected_wildcard: int,
    rate_limited: int,
    calibration_ok: bool,
    wildcard_active: bool,
    catch_all_200: bool = False,
) -> str:
    """Defensible overall conclusion for reports when enum ran."""
    # Validation unsuccessful: catch-all 200 detected but filter never rejected anything
    # while hits were still accepted — or calibration failed to capture fingerprints.
    validation_failed = (not calibration_ok and wildcard_active) or (
        catch_all_200 and rejected_wildcard == 0 and accepted_hits > 0
    )
    if validation_failed:
        return (
            f"Directory enumeration executed {http_attempts:,} HTTP candidate requests and completed "
            f"its scheduling phase. However, wildcard-response validation was unsuccessful. The target "
            f"returned HTTP 200 for at least one random control path, and many accepted results may share "
            f"the same fallback-page security evidence. Consequently, the {accepted_hits:,} reported hits "
            f"are unverified candidates and should not be treated as confirmed hidden resources. "
            f"Additionally, {rate_limited:,} requests were rate-limited and remain inconclusive."
        )
    if rejected_wildcard > 0:
        return (
            f"Directory enumeration executed {http_attempts:,} HTTP candidate requests. "
            f"Wildcard calibration filtered {rejected_wildcard:,} false-positive response(s). "
            f"{accepted_hits:,} hit(s) remained after path-shape validation"
            + (
                f"; {rate_limited:,} request(s) were rate-limited and remain inconclusive."
                if rate_limited
                else "."
            )
        )
    return (
        f"Directory enumeration executed {http_attempts:,} HTTP candidate requests and completed. "
        f"{accepted_hits:,} validated hit(s) recorded"
        + (
            f"; {rate_limited:,} request(s) were rate-limited and remain inconclusive."
            if rate_limited
            else "."
        )
    )


def is_public_client_key_value(value: str) -> bool:
    """Unstable provider inference should not rename these — keep a stable label."""
    v = (value or "").strip()
    if not v:
        return False
    if v.lower().startswith("pubkey-"):
        return True
    if re.fullmatch(r"(?i)pk_(?:live|test)_[A-Za-z0-9]+", v):
        return True
    if re.fullmatch(r"(?i)pub[_-]?[A-Za-z0-9_-]{16,}", v) and "secret" not in v.lower():
        return True
    return False
