"""
Blaze Response Filters - Wildcard detection, soft-404 detection,
response deduplication, and configurable filtering by status/size/words/lines.
"""

import asyncio
import hashlib
import random
import string
from dataclasses import dataclass
from typing import Optional, Set, Dict
from .reporter import ScanResult


def _random_string(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


@dataclass
class WildcardProfile:
    """Stores baseline wildcard response characteristics."""
    status_code: int = 0
    content_length: int = 0
    content_hash: str = ""
    word_count: int = 0
    line_count: int = 0
    # Tolerance for size comparison (percentage)
    size_tolerance: float = 0.05


class WildcardDetector:
    """
    Detects wildcard responses by probing random non-existent paths
    and fingerprinting the responses. Uses multiple probes for accuracy.
    """

    def __init__(self):
        self.has_wildcard = False
        self.wildcard_status: int = 0
        self.wildcard_size: int = 0
        self.wildcard_redirect: str = ""  # Where wildcard 301/302 redirects to
        self.profiles: list = []
        self._response_hashes: Set[str] = set()
        self._seen_hashes: Dict[str, int] = {}

    async def calibrate(self, session, target: str, proxy: str = None):
        """Send random requests to detect wildcard behavior."""
        probes = [
            f"{_random_string(10)}",
            f"{_random_string(8)}/{_random_string(6)}",
            f"{_random_string(15)}.html",
            f"{_random_string(12)}.php",
            f"{_random_string(8)}/{_random_string(8)}/{_random_string(8)}",
        ]

        profiles = []
        redirect_locations = []
        for probe in probes:
            try:
                url = f"{target}/{probe}"
                async with session.get(
                    url, allow_redirects=False, proxy=proxy
                ) as resp:
                    body = await resp.text(errors="replace")
                    profile = WildcardProfile(
                        status_code=resp.status,
                        content_length=len(body.encode()),
                        content_hash=hashlib.md5(body.encode()).hexdigest(),
                        word_count=len(body.split()),
                        line_count=body.count("\n") + 1,
                    )
                    profiles.append(profile)
                    # Track redirect Location for 301/302
                    if resp.status in (301, 302, 303, 307, 308):
                        redirect_locations.append(
                            str(resp.headers.get("Location", ""))
                        )
            except Exception:
                continue

        if len(profiles) < 2:
            return

        # Check if responses are consistent (wildcard behavior)
        statuses = {p.status_code for p in profiles}
        hashes = {p.content_hash for p in profiles}

        # Wildcard = server returns HTTP 200 with same/similar content for
        # any random path. Only 200 matters here — 301/302/403/404 are handled
        # by status filtering and don't need wildcard detection.
        if len(statuses) == 1:
            status = profiles[0].status_code
            if status == 200:
                if len(hashes) == 1:
                    # Exact same content for all random paths = definite wildcard
                    self.has_wildcard = True
                    self.wildcard_status = status
                    self.wildcard_size = profiles[0].content_length
                    self.profiles = profiles
                    self._response_hashes = hashes
                else:
                    # Same status but different content - check size similarity
                    sizes = [p.content_length for p in profiles]
                    avg_size = sum(sizes) / len(sizes)
                    max_diff = max(abs(s - avg_size) for s in sizes)
                    if avg_size > 0 and (max_diff / avg_size) < 0.1:
                        self.has_wildcard = True
                        self.wildcard_status = status
                        self.wildcard_size = int(avg_size)
                        self.profiles = profiles

    def is_wildcard(self, result: "ScanResult") -> bool:
        """Check if a scan result matches the wildcard 200 profile.
        Only applies to HTTP 200 — other statuses are not wildcard-checked."""
        if not self.has_wildcard:
            return False

        # Only filter 200 responses (wildcard is only detected on 200)
        if result.status_code != 200:
            return False

        # Check content hash (exact match)
        if result.content_hash in self._response_hashes:
            return True

        # Check content size similarity
        if self.wildcard_size > 0:
            size_diff = abs(result.content_length - self.wildcard_size)
            tolerance = self.wildcard_size * 0.05  # 5% tolerance
            if size_diff <= tolerance:
                return True

        # Check word count similarity across profiles
        if self.profiles:
            avg_words = sum(p.word_count for p in self.profiles) / len(
                self.profiles
            )
            if avg_words > 0:
                word_diff = abs(result.word_count - avg_words)
                if word_diff / avg_words < 0.05:
                    return True

        return False

    def track_response(self, result: "ScanResult") -> bool:
        """
        Track response hashes for deduplication.
        Returns True if this is a duplicate response.
        """
        h = result.content_hash
        self._seen_hashes[h] = self._seen_hashes.get(h, 0) + 1
        # If we've seen the same hash more than 10 times, it's likely junk
        return self._seen_hashes[h] > 10


class ResponseFilter:
    """
    Configurable response filter based on status codes, content length,
    word count, line count, and regex patterns.
    """

    def __init__(self, config: dict):
        # Status code filters
        self.include_status = set(config.get("include_status", []))
        self.exclude_status = set(
            config.get("exclude_status", [404])
        )

        # Size filters
        self.min_size = config.get("min_size", None)
        self.max_size = config.get("max_size", None)

        # Word count filters
        self.min_words = config.get("min_words", None)
        self.max_words = config.get("max_words", None)

        # Line count filters
        self.min_lines = config.get("min_lines", None)
        self.max_lines = config.get("max_lines", None)

        # Regex filter for response body (exclude if matches)
        self.exclude_regex = config.get("exclude_regex", None)

        # Exclude specific content lengths (for auto-calibrated filtering)
        self.exclude_sizes: Set[int] = set()

    def should_show(self, result: "ScanResult") -> bool:
        """Determine if a result should be displayed based on filters."""

        # Include status filter (whitelist - if set, only these pass)
        if self.include_status:
            if result.status_code not in self.include_status:
                return False
        else:
            # Exclude status filter (blacklist)
            if result.status_code in self.exclude_status:
                return False

        # Size filters
        if self.min_size is not None and result.content_length < self.min_size:
            return False
        if self.max_size is not None and result.content_length > self.max_size:
            return False

        # Word count filters
        if self.min_words is not None and result.word_count < self.min_words:
            return False
        if self.max_words is not None and result.word_count > self.max_words:
            return False

        # Line count filters
        if self.min_lines is not None and result.line_count < self.min_lines:
            return False
        if self.max_lines is not None and result.line_count > self.max_lines:
            return False

        # Exclude specific sizes
        if result.content_length in self.exclude_sizes:
            return False

        return True

    def add_exclude_size(self, size: int):
        """Dynamically add a size to exclude (for runtime calibration)."""
        self.exclude_sizes.add(size)
