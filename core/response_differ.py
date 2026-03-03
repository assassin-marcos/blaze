"""
# Blaze - Response Differ

Smart soft-404 detection using response body diffing. Compares HTTP responses
against calibrated baselines using `difflib.SequenceMatcher` similarity ratios.
Strips dynamic content (timestamps, CSRF tokens, nonces, session IDs) before
comparison so that trivially varying 404 pages are correctly identified.

The calibration phase requests multiple random non-existent paths to build a
pool of baseline response bodies. During scanning, each response is compared
against every baseline; if *any* comparison exceeds the similarity threshold
the response is flagged as a soft-404.

An adaptive tracking mechanism monitors response body hashes seen during the
scan. When a particular hash appears frequently it is automatically promoted
into the baseline pool, catching soft-404 templates that only appear after
calibration.
"""

import hashlib
import random
import re
import string
from collections import defaultdict
from difflib import SequenceMatcher
from typing import List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_path(length: int = 12) -> str:
    """Generate a random alphanumeric path segment."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


# Pre-compiled regexes for stripping dynamic content.
_DYNAMIC_PATTERNS: List[re.Pattern] = [
    # Hex tokens (CSRF, nonces, session IDs) - 16+ hex chars
    re.compile(r"[0-9a-fA-F]{16,}"),
    # UUIDs (8-4-4-4-12 hex with dashes)
    re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ),
    # ISO-8601 timestamps  2024-01-15T12:30:00Z / 2024-01-15 12:30:00
    re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    ),
    # Common date formats: DD/MM/YYYY, MM/DD/YYYY, YYYY/MM/DD
    re.compile(r"\d{1,4}[/\-]\d{1,2}[/\-]\d{1,4}"),
    # Unix timestamps (10-13 digits standing alone)
    re.compile(r"\b\d{10,13}\b"),
    # Standalone numbers of 4+ digits (counters, IDs, sizes)
    re.compile(r"\b\d{4,}\b"),
    # Base64-ish blobs (20+ mixed alphanumeric with +/=)
    re.compile(r"[A-Za-z0-9+/=]{20,}"),
]


class ResponseDiffer:
    """
    Detect soft-404 pages by diffing response bodies against calibrated
    baselines.

    Usage::

        differ = ResponseDiffer(threshold=0.85)
        await differ.calibrate(session, "https://example.com")
        if differ.is_soft_404(some_response_body):
            print("Soft-404 detected")

    Parameters
    ----------
    threshold : float
        Similarity ratio (0.0 -- 1.0) above which a response is considered a
        soft-404.  Default ``0.85``.
    auto_add_threshold : int
        Number of times the same response hash must be seen before it is
        automatically added to the baseline pool.  Default ``15``.
    """

    def __init__(
        self,
        threshold: float = 0.85,
        auto_add_threshold: int = 15,
    ):
        self.threshold = threshold
        self.auto_add_threshold = auto_add_threshold

        # Baseline bodies (already stripped of dynamic content).
        self._baselines: List[str] = []
        # Fast-reject set: hashes of known baselines.
        self._baseline_hashes: set = set()
        # Track response hashes seen during the scan for adaptive detection.
        self._seen_hashes: defaultdict = defaultdict(int)
        # Map hash -> raw stripped body (kept until promoted or evicted).
        self._hash_to_body: dict = {}
        # Whether calibration has been performed.
        self.calibrated: bool = False

    # ------------------------------------------------------------------
    # Dynamic content stripping
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_dynamic(body: str) -> str:
        """Remove dynamic tokens, timestamps, and large numbers from *body*.

        This normalises two responses that differ only in session-specific or
        time-specific fragments so that ``SequenceMatcher`` can reliably
        compare the static page structure.
        """
        stripped = body
        for pattern in _DYNAMIC_PATTERNS:
            stripped = pattern.sub("", stripped)
        # Collapse resulting whitespace runs.
        stripped = re.sub(r"\s+", " ", stripped).strip()
        return stripped

    # ------------------------------------------------------------------
    # Calibration
    # ------------------------------------------------------------------

    async def calibrate(
        self,
        session,
        target: str,
        proxy: Optional[str] = None,
    ) -> int:
        """Request five random non-existent paths and store their bodies as
        baselines.

        Parameters
        ----------
        session : aiohttp.ClientSession
            An open HTTP session.
        target : str
            The base URL of the target (e.g. ``https://example.com``).
        proxy : str, optional
            HTTP proxy URL.

        Returns
        -------
        int
            Number of baselines successfully collected.
        """
        target = target.rstrip("/")
        probes = [
            f"{_random_path(10)}_{_random_path(6)}",
            f"{_random_path(8)}/{_random_path(8)}.html",
            f"{_random_path(14)}.php",
            f"nonexist_{_random_path(12)}",
            f"{_random_path(6)}/{_random_path(6)}/{_random_path(6)}",
        ]

        collected = 0
        for probe in probes:
            try:
                url = f"{target}/{probe}"
                async with session.get(
                    url, allow_redirects=True, proxy=proxy,
                ) as resp:
                    body = await resp.text(errors="replace")
                    self.add_baseline(body)
                    collected += 1
            except Exception:
                # Network errors during calibration are non-fatal; we just
                # proceed with fewer baselines.
                continue

        self.calibrated = collected > 0
        return collected

    # ------------------------------------------------------------------
    # Baseline management
    # ------------------------------------------------------------------

    def add_baseline(self, body: str) -> bool:
        """Add a response body to the baseline pool.

        The body is stripped of dynamic content and deduplicated by hash.

        Returns
        -------
        bool
            ``True`` if the body was new and added, ``False`` if it was a
            duplicate of an existing baseline.
        """
        stripped = self._strip_dynamic(body)
        h = hashlib.md5(stripped.encode("utf-8", errors="replace")).hexdigest()
        if h in self._baseline_hashes:
            return False
        self._baseline_hashes.add(h)
        self._baselines.append(stripped)
        return True

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def is_soft_404(self, body: str) -> bool:
        """Return ``True`` if *body* is a soft-404 according to the baselines.

        The method:
        1. Strips dynamic content from *body*.
        2. Checks for an exact hash match (fast path).
        3. Falls back to ``SequenceMatcher.ratio()`` against each baseline.
        4. Tracks the stripped hash for adaptive baseline promotion.
        """
        if not self._baselines:
            return False

        stripped = self._strip_dynamic(body)
        h = hashlib.md5(stripped.encode("utf-8", errors="replace")).hexdigest()

        # Fast path: exact match with a known baseline hash.
        if h in self._baseline_hashes:
            return True

        # Sequence-matching against each baseline.
        for baseline in self._baselines:
            ratio = SequenceMatcher(None, stripped, baseline).ratio()
            if ratio >= self.threshold:
                # Promote this body into baselines so future checks are faster.
                self._baseline_hashes.add(h)
                return True

        # Adaptive tracking: record the hash and promote if seen frequently.
        self._track_and_adapt(h, stripped)

        return False

    # ------------------------------------------------------------------
    # Adaptive tracking
    # ------------------------------------------------------------------

    def _track_and_adapt(self, body_hash: str, stripped_body: str) -> None:
        """Track how often a particular response hash is encountered.

        If a hash is seen more than ``auto_add_threshold`` times it is very
        likely a custom error page template that was not caught during
        calibration.  Promote it into the baseline pool automatically.
        """
        self._seen_hashes[body_hash] += 1
        # Keep a copy of the body until we decide whether to promote.
        if body_hash not in self._hash_to_body:
            self._hash_to_body[body_hash] = stripped_body

        if self._seen_hashes[body_hash] >= self.auto_add_threshold:
            if body_hash not in self._baseline_hashes:
                self._baseline_hashes.add(body_hash)
                self._baselines.append(self._hash_to_body[body_hash])
            # Clean up the tracking entry to save memory.
            self._hash_to_body.pop(body_hash, None)

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @property
    def baseline_count(self) -> int:
        """Number of distinct baselines currently stored."""
        return len(self._baselines)

    def reset(self) -> None:
        """Clear all baselines and tracking state."""
        self._baselines.clear()
        self._baseline_hashes.clear()
        self._seen_hashes.clear()
        self._hash_to_body.clear()
        self.calibrated = False
