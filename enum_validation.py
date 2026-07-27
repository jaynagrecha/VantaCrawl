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
CLASS_PROVISIONAL = "provisional_cluster_representative"
CLASS_QUARANTINED = "quarantined_probable_fallback"
CLASS_REVOKED = "revoked_fallback_cluster_anchor"
CLASS_VALIDATION_INTERRUPTED = "validation_interrupted"
CLASS_WILDCARD = "wildcard_response"
CLASS_SOFT_404 = "soft_404"
CLASS_CASE_VARIANT = "case_variant"
CLASS_CONTENT_DUP = "content_equivalent_fallback"
CLASS_EXTENSION_VARIANT = "implausible_extension_variant"
CLASS_ALREADY_KNOWN = "already_known"
CLASS_REDIRECT_EXISTING = "redirected_existing_route"
CLASS_INCONCLUSIVE_429 = "inconclusive_rate_limited"
CLASS_BLOCKED_INCONCLUSIVE = "blocked_inconclusive"
CLASS_EDGE_CHECKPOINT = "edge_checkpoint"
CLASS_REJECTED_STATUS = "rejected_status"
CLASS_UNVERIFIED = "unverified_candidate"

# Cluster-anchor revocation: ≥3 unrelated paths + ≥2 extensions ⇒ fallback/interstitial
CLUSTER_REVOKE_MIN_MEMBERS = 3
CLUSTER_REVOKE_MIN_EXTENSIONS = 2
CLUSTER_QUARANTINE_MIN_MEMBERS = 3

# Stems that commonly explode into false multi-extension "hits"
_MULTI_EXT_STEMS = frozenset(
    {
        "index",
        "default",
        "home",
        "main",
        "backup",
        "config",
        "admin",
        "test",
        "temp",
        "tmp",
        "old",
        "new",
        "copy",
        "data",
        "db",
        "dump",
        "robots",
        "sitemap",
    }
)


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
    # Uniform edge checkpoint across control paths (Vercel etc.) — abort enum
    edge_blocked: bool = False
    edge_checkpoint_signal: str = ""
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


def path_leaf_name(url_or_path: str) -> str:
    path = urlparse(url_or_path).path if "://" in (url_or_path or "") else (url_or_path or "")
    path = path.replace("\\", "/")
    segs = [s for s in path.strip("/").split("/") if s]
    return segs[-1] if segs else ""


def path_stem_and_ext(url_or_path: str) -> Tuple[str, str]:
    leaf = path_leaf_name(url_or_path)
    if not leaf:
        return "", ""
    if leaf.startswith(".") and "." not in leaf[1:]:
        return leaf.casefold(), ""
    if "." not in leaf or leaf.startswith("."):
        # .env / .git — treat whole leaf as stem, no extension family
        if leaf.startswith("."):
            return leaf.casefold(), "dotfile"
        return leaf.casefold(), ""
    stem, ext = leaf.rsplit(".", 1)
    return stem.casefold(), ext.casefold()


@dataclass
class ContentCluster:
    """Fingerprint cluster for content-equivalent enum responses."""

    key: str
    anchor_url: str
    members: List[str] = field(default_factory=list)
    stems: Set[str] = field(default_factory=set)
    extensions: Set[str] = field(default_factory=set)
    classification: str = CLASS_PROVISIONAL
    revoked: bool = False
    edge_signal: str = ""

    def add(self, url: str) -> None:
        if url not in self.members:
            self.members.append(url)
        stem, ext = path_stem_and_ext(url)
        if stem:
            self.stems.add(stem)
        if ext:
            self.extensions.add(ext)

    @property
    def unrelated_path_count(self) -> int:
        return len(self.stems)

    def should_revoke(self) -> bool:
        if self.revoked:
            return False
        return (
            len(self.members) >= CLUSTER_REVOKE_MIN_MEMBERS
            and self.unrelated_path_count >= CLUSTER_REVOKE_MIN_MEMBERS
            and len(self.extensions) >= CLUSTER_REVOKE_MIN_EXTENSIONS
        )

    def should_quarantine(self) -> bool:
        if self.revoked:
            return False
        return (
            len(self.members) >= CLUSTER_QUARANTINE_MIN_MEMBERS
            and self.unrelated_path_count >= CLUSTER_QUARANTINE_MIN_MEMBERS
        )


@dataclass
class RevokeEvent:
    """Retroactive invalidation of a provisional cluster anchor."""

    url: str
    reason: str
    cluster_key: str
    cluster_size: int
    classification: str = CLASS_REVOKED
    members: List[str] = field(default_factory=list)


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
    state: str = ""  # provisional | quarantined | confirmed | revoked | blocked
    revoke_events: List[RevokeEvent] = field(default_factory=list)

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
            "state": self.state or (
                "confirmed"
                if self.validated
                else ("provisional" if self.classification == CLASS_PROVISIONAL else "rejected")
            ),
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else {},
        }
        return json.dumps(payload, ensure_ascii=False)

    def to_dict(self) -> Dict:
        import json

        return json.loads(self.to_evidence_json())


def extension_family_key(url_or_path: str) -> str:
    """Group implausible multi-extension siblings (index.sql / index.bak / …)."""
    path = urlparse(url_or_path).path if "://" in (url_or_path or "") else (url_or_path or "")
    path = path.replace("\\", "/")
    segs = [s for s in path.strip("/").split("/") if s]
    if not segs:
        return ""
    leaf = segs[-1]
    if "." not in leaf or leaf.startswith("."):
        # Dotfiles like .robots — family by casefold leaf name without leading dots' case
        if leaf.startswith(".") and len(leaf) > 1:
            parent = "/".join(segs[:-1]).casefold()
            stem = leaf.lstrip(".").casefold()
            return f"dotfam:{parent}/{stem}"
        return ""
    stem, ext = leaf.rsplit(".", 1)
    if not stem or not ext:
        return ""
    stem_l = stem.casefold()
    if stem_l not in _MULTI_EXT_STEMS and not re.fullmatch(r"(?i)index", stem):
        return ""
    parent = "/".join(segs[:-1]).casefold()
    return f"extfam:{parent}/{stem_l}"


class HitProvenanceTracker:
    """Tracks already-known URLs, case groups, content-equivalent and extension-family dups.

    First sight of a content fingerprint is *provisional* — never auto-confirmed.
    When a cluster gathers ≥3 unrelated paths with multiple extensions, the anchor
    is retroactively revoked (first-response poisoning / cluster-anchor fix).

    Thread-safe: classify_and_record / note_* are safe under concurrent enum workers.
    """

    def __init__(self, known_urls: Optional[Iterable[str]] = None):
        import threading

        self._lock = threading.RLock()
        self.known_casefold: Set[str] = set()
        self.known_exact: Set[str] = set()
        self.accepted_casefold: Dict[str, str] = {}  # casefold -> first url
        self.content_groups: Dict[str, str] = {}  # norm hash -> first url
        self.extension_families: Dict[str, str] = {}  # family key -> first url
        self.clusters: Dict[str, ContentCluster] = {}
        self.provisional_urls: Set[str] = set()
        self.revoked_urls: Set[str] = set()
        self.pending_revokes: List[RevokeEvent] = []
        self.records: List[EnumHitRecord] = []
        for u in known_urls or []:
            if not u:
                continue
            self.known_exact.add(u)
            self.known_casefold.add(casefold_path_key(u))

    def note_known(self, urls: Iterable[str]) -> None:
        with self._lock:
            for u in urls or []:
                if not u:
                    continue
                self.known_exact.add(u)
                self.known_casefold.add(casefold_path_key(u))

    def note_content(self, url: str, normalized_hash: str) -> None:
        """Seed content groups from crawl page bodies so enum fallbacks collide early."""
        key = (normalized_hash or "").strip()
        if not key or key in ("empty", "head-only") or not url:
            return
        with self._lock:
            self.content_groups.setdefault(key, url)
            cluster = self.clusters.get(key)
            if cluster is None:
                cluster = ContentCluster(key=key, anchor_url=url)
                self.clusters[key] = cluster
            cluster.add(url)

    def drain_revokes(self) -> List[RevokeEvent]:
        with self._lock:
            out = list(self.pending_revokes)
            self.pending_revokes.clear()
            return out

    def blocked_cluster_keys_for_edge_abort(self) -> Set[str]:
        """Content keys whose provisional anchors must revoke on edge abort."""
        blocked: Set[str] = set()
        with self._lock:
            for key, cluster in self.clusters.items():
                title_l = ""
                for mem in cluster.members[:3]:
                    for rec in self.records:
                        if rec.url == mem and rec.fingerprint:
                            title_l = (rec.fingerprint.title or "").lower()
                            break
                    if title_l:
                        break
                if (
                    cluster.revoked
                    or cluster.edge_signal
                    or cluster.should_revoke()
                    or "checkpoint" in title_l
                ):
                    blocked.add(key)
        return blocked

    def disposition_on_edge_abort(self, url: str) -> Tuple[str, str, str]:
        """Classify a provisional hit when enum aborts on edge checkpoint.

        Returns (classification, state, acceptance_reason).
        Distinct fingerprints (e.g. /login) → validation_interrupted.
        Checkpoint / fallback cluster members → revoked.
        """
        content_key = ""
        with self._lock:
            for rec in self.records:
                if rec.url != url:
                    continue
                if rec.fingerprint:
                    content_key = (
                        rec.fingerprint.normalized_hash or rec.fingerprint.raw_hash or ""
                    )
                break
        blocked_keys = self.blocked_cluster_keys_for_edge_abort()
        in_blocked = bool(content_key and content_key in blocked_keys)
        with self._lock:
            cluster = self.clusters.get(content_key) if content_key else None
            if cluster and (cluster.revoked or cluster.edge_signal):
                in_blocked = True
        if in_blocked:
            return (
                CLASS_REVOKED,
                "revoked",
                "anchor_of_content_equivalent_fallback_cluster",
            )
        return (
            CLASS_VALIDATION_INTERRUPTED,
            "validation_interrupted",
            "edge_blocked_before_final_validation",
        )

    def promote_survivors(self) -> List[EnumHitRecord]:
        """End-of-enum: provisional anchors whose clusters stayed unique → confirmed."""
        promoted: List[EnumHitRecord] = []
        with self._lock:
            for rec in self.records:
                if rec.classification != CLASS_PROVISIONAL or rec.validated:
                    continue
                if rec.url in self.revoked_urls:
                    continue
                content_key = ""
                title_l = ""
                if rec.fingerprint:
                    content_key = rec.fingerprint.normalized_hash or rec.fingerprint.raw_hash or ""
                    title_l = (rec.fingerprint.title or "").lower()
                cluster = self.clusters.get(content_key) if content_key else None
                # Never confirm checkpoint / interstitial pages
                if "checkpoint" in title_l or "just a moment" in title_l or "attention required" in title_l:
                    if cluster is None and content_key:
                        cluster = ContentCluster(key=content_key, anchor_url=rec.url)
                        cluster.add(rec.url)
                        self.clusters[content_key] = cluster
                    if cluster:
                        self._revoke_cluster_locked(
                            cluster,
                            reason="anchor_of_content_equivalent_fallback_cluster",
                        )
                    else:
                        rec.classification = CLASS_REVOKED
                        rec.state = "revoked"
                        rec.validated = False
                        rec.acceptance_reason = "anchor_of_content_equivalent_fallback_cluster"
                        self.provisional_urls.discard(rec.url)
                        self.revoked_urls.add(rec.url)
                    continue
                if cluster and (cluster.revoked or cluster.should_revoke() or cluster.should_quarantine()):
                    if cluster.should_revoke() and not cluster.revoked:
                        self._revoke_cluster_locked(
                            cluster,
                            reason="anchor_of_content_equivalent_fallback_cluster",
                        )
                    continue
                # Unique resource — cluster never attracted unrelated paths
                if cluster and len(cluster.members) > 1 and cluster.unrelated_path_count >= 2:
                    # Small multi-path cluster without enough extensions → quarantine
                    rec.classification = CLASS_QUARANTINED
                    rec.state = "quarantined"
                    rec.validated = False
                    rec.acceptance_reason = "probable_fallback_cluster"
                    self.provisional_urls.discard(rec.url)
                    continue
                rec.classification = CLASS_CONFIRMED
                rec.state = "confirmed"
                rec.validated = True
                rec.acceptance_reason = "confirmed_unique_after_cluster_review"
                if rec.fingerprint:
                    rec.fingerprint.acceptance_reason = rec.acceptance_reason
                self.provisional_urls.discard(rec.url)
                ck = casefold_path_key(rec.url)
                self.accepted_casefold.setdefault(ck, rec.url)
                promoted.append(rec)
        return promoted

    def _revoke_cluster_locked(self, cluster: ContentCluster, *, reason: str) -> Optional[RevokeEvent]:
        if cluster.revoked:
            return None
        cluster.revoked = True
        cluster.classification = CLASS_REVOKED
        anchor = cluster.anchor_url
        self.revoked_urls.add(anchor)
        self.provisional_urls.discard(anchor)
        # Downgrade any provisional/confirmed record for the anchor
        for rec in self.records:
            if rec.url == anchor or rec.url in cluster.members:
                if rec.classification in (CLASS_PROVISIONAL, CLASS_CONFIRMED, CLASS_QUARANTINED):
                    if rec.url == anchor:
                        rec.classification = CLASS_REVOKED
                        rec.state = "revoked"
                        rec.acceptance_reason = reason
                        rec.validated = False
                        if rec.fingerprint:
                            rec.fingerprint.acceptance_reason = reason
                    elif rec.classification == CLASS_PROVISIONAL:
                        rec.classification = CLASS_CONTENT_DUP
                        rec.state = "rejected"
                        rec.validated = False
                        rec.content_group = anchor
                        rec.acceptance_reason = f"content_equivalent_to:{anchor}"
        event = RevokeEvent(
            url=anchor,
            reason=reason,
            cluster_key=cluster.key,
            cluster_size=len(cluster.members),
            members=list(cluster.members),
        )
        self.pending_revokes.append(event)
        return event

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
        edge_checkpoint: str = "",
        rate_limited: bool = False,
        access_denied: bool = False,
    ) -> EnumHitRecord:
        with self._lock:
            return self._classify_locked(
                url=url,
                base_word=base_word,
                variant=variant,
                requested_status=requested_status,
                final_status=final_status,
                final_url=final_url,
                fingerprint=fingerprint,
                wildcard_rejected=wildcard_rejected,
                wildcard_similarity=wildcard_similarity,
                baseline_used=baseline_used,
                soft_404=soft_404,
                path_shape=path_shape,
                edge_checkpoint=edge_checkpoint,
                rate_limited=rate_limited,
                access_denied=access_denied,
            )

    def _classify_locked(
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
        edge_checkpoint: str = "",
        rate_limited: bool = False,
        access_denied: bool = False,
    ) -> EnumHitRecord:
        ck = casefold_path_key(url)
        already_exact = url in self.known_exact
        already_case = ck in self.known_casefold
        already = already_exact or already_case
        content_key = fingerprint.normalized_hash or fingerprint.raw_hash or ""
        fam_key = extension_family_key(url) or extension_family_key(variant)
        case_group = ""
        content_group = ""
        classification = CLASS_PROVISIONAL
        validated = False
        state = "provisional"
        reason = "provisional_awaiting_cluster_review"
        revoke_events: List[RevokeEvent] = []

        # Classification order (audit): edge → rate-limit → auth → wildcard/soft-404
        # → duplicate content → genuine (provisional) candidate.
        if edge_checkpoint:
            classification = CLASS_EDGE_CHECKPOINT
            state = "blocked"
            validated = False
            reason = f"edge_checkpoint:{edge_checkpoint}"
        elif rate_limited or final_status == 429:
            classification = CLASS_INCONCLUSIVE_429
            state = "blocked"
            validated = False
            reason = "rate_limited"
        elif access_denied:
            classification = CLASS_BLOCKED_INCONCLUSIVE
            state = "blocked"
            validated = False
            reason = "access_denied"
        elif wildcard_rejected:
            classification = CLASS_WILDCARD
            state = "rejected"
            validated = False
            reason = f"matched_wildcard_shape:{baseline_used or path_shape}"
        elif soft_404:
            classification = CLASS_SOFT_404
            state = "rejected"
            validated = False
            reason = "soft_404_baseline"
        elif already_exact or already_case:
            if already_exact:
                classification = CLASS_ALREADY_KNOWN
                reason = "path_known_before_enum"
            else:
                classification = CLASS_CASE_VARIANT
                case_group = next(
                    (u for u in self.known_exact if casefold_path_key(u) == ck),
                    ck,
                )
                reason = f"case_variant_of_known:{case_group}"
            state = "rejected"
            validated = False
        elif ck in self.accepted_casefold or ck in {casefold_path_key(u) for u in self.provisional_urls}:
            classification = CLASS_CASE_VARIANT
            state = "rejected"
            validated = False
            case_group = self.accepted_casefold.get(ck) or next(
                (u for u in self.provisional_urls if casefold_path_key(u) == ck),
                ck,
            )
            reason = f"case_variant_of:{case_group}"
        elif content_key and content_key not in ("empty", "head-only") and content_key in self.content_groups:
            classification = CLASS_CONTENT_DUP
            state = "rejected"
            validated = False
            content_group = self.content_groups[content_key]
            reason = f"content_equivalent_to:{content_group}"
            cluster = self.clusters.get(content_key)
            if cluster is None:
                cluster = ContentCluster(key=content_key, anchor_url=content_group)
                cluster.add(content_group)
                self.clusters[content_key] = cluster
            cluster.add(url)
            if edge_checkpoint or (fingerprint.title or "").lower().find("checkpoint") >= 0:
                cluster.edge_signal = edge_checkpoint or "edge_security_checkpoint"
                event = self._revoke_cluster_locked(
                    cluster,
                    reason="anchor_of_content_equivalent_fallback_cluster",
                )
                if event:
                    revoke_events.append(event)
            elif cluster.should_revoke():
                event = self._revoke_cluster_locked(
                    cluster,
                    reason="anchor_of_content_equivalent_fallback_cluster",
                )
                if event:
                    revoke_events.append(event)
            elif cluster.should_quarantine():
                cluster.classification = CLASS_QUARANTINED
                for prec in self.records:
                    if prec.url == cluster.anchor_url and prec.classification == CLASS_PROVISIONAL:
                        prec.classification = CLASS_QUARANTINED
                        prec.state = "quarantined"
                        prec.validated = False
                        prec.acceptance_reason = "probable_fallback_cluster"
        elif fam_key and fam_key in self.extension_families:
            classification = CLASS_EXTENSION_VARIANT
            state = "rejected"
            validated = False
            case_group = self.extension_families[fam_key]
            reason = f"extension_variant_of:{case_group}"
        elif final_url and casefold_path_key(final_url) != ck and (
            final_url in self.known_exact or casefold_path_key(final_url) in self.known_casefold
        ):
            classification = CLASS_REDIRECT_EXISTING
            state = "rejected"
            validated = False
            reason = "redirects_to_known_route"

        # Brand-new distinct content → provisional only (never auto-confirmed)
        if classification == CLASS_PROVISIONAL:
            self.accepted_casefold.setdefault(ck, url)
            self.provisional_urls.add(url)
            if content_key and content_key not in ("empty", "head-only"):
                self.content_groups.setdefault(content_key, url)
                cluster = self.clusters.get(content_key)
                if cluster is None:
                    cluster = ContentCluster(key=content_key, anchor_url=url)
                    self.clusters[content_key] = cluster
                cluster.add(url)
            if fam_key:
                self.extension_families.setdefault(fam_key, url)
            validated = False
            state = "provisional"
            reason = "provisional_awaiting_cluster_review"

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
            validated=validated,
            state=state,
            revoke_events=revoke_events,
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
    edge_blocked: bool = False,
    edge_checkpoint_signal: str = "",
    blocked_count: int = 0,
) -> str:
    """Defensible overall conclusion for reports when enum ran."""
    if edge_blocked:
        from edge_checkpoint import enum_blocked_conclusion

        return enum_blocked_conclusion(
            signal=edge_checkpoint_signal or "edge_security_checkpoint",
            blocked_count=blocked_count or http_attempts,
            http_attempts=http_attempts,
        )
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
