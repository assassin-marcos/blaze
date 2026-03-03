"""
Blaze Core Engine v2.2 - Full-featured async directory scanner.

Integrates: smart status filtering, response diffing, WAF detection,
tech fingerprinting, smart recursion with context-aware multi-wordlist,
smart extension probing, JS endpoint extraction, resume support,
real-time adaptation, headless browser challenge bypass,
header leak detection, rate limit fingerprinting, subdomain-aware
wordlist selection, and custom signature packs.
"""

import asyncio
import aiohttp
import hashlib
import time
import ssl
import random
import re
import os
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Callable
from urllib.parse import urljoin, urlparse

from .waf_detector import WAFDetector, WAFResult
from .tech_detector import TechDetector, TechResult
from .wordlist_manager import WordlistManager
from .filters import ResponseFilter, WildcardDetector
from .reporter import Reporter, ScanResult, ScanStats
from .response_differ import ResponseDiffer
from .smart_recursion import SmartRecursion
from .smart_extensions import SmartExtensions
from .js_extractor import JSExtractor
from .resume_manager import ResumeManager, ScanState
from .header_analyzer import HeaderAnalyzer
from .signature_loader import SignatureLoader


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# Status codes that indicate real results (not errors/not-found)
IMPORTANT_STATUS_CODES = {200, 201, 204, 301, 302, 307, 308}
# Conditionally shown (only if not wildcard)
CONDITIONAL_STATUS_CODES = {401, 405, 500}
# Always hidden
HIDDEN_STATUS_CODES = {404}
# Shown only with --show-forbidden
FORBIDDEN_STATUS_CODES = {403}

# How many identical (status, size) combos before auto-filtering kicks in
ADAPTIVE_FILTER_THRESHOLD = 8
# How many identical (status, line_count) combos before auto-filtering
ADAPTIVE_LINE_THRESHOLD = 10


class DynamicSemaphore:
    """Asyncio semaphore with dynamically adjustable concurrency limit.

    Allows the engine to increase or decrease the number of concurrent
    requests at runtime based on server response characteristics.
    """

    def __init__(self, value: int):
        self._limit = value
        self._active = 0
        self._cond = asyncio.Condition()

    @property
    def limit(self):
        return self._limit

    @property
    def active(self):
        return self._active

    async def set_limit(self, new_value: int):
        async with self._cond:
            self._limit = max(1, new_value)
            self._cond.notify_all()

    async def __aenter__(self):
        async with self._cond:
            while self._active >= self._limit:
                await self._cond.wait()
            self._active += 1
        return self

    async def __aexit__(self, *args):
        async with self._cond:
            self._active -= 1
            self._cond.notify()


class AdaptiveThreadManager:
    """Automatically adjusts concurrency based on server response times,
    error rates, CPU cores, and estimated bandwidth.

    - Fast responses (<30ms avg)  → increase threads aggressively
    - Normal responses (30-200ms) → hold steady
    - Slow responses (>500ms)     → decrease threads
    - High error rate (>15%)      → decrease threads
    - Uses CPU core count for sensible bounds
    """

    def __init__(self, initial_threads: int, semaphore: "DynamicSemaphore"):
        self.semaphore = semaphore
        self.cpu_cores = os.cpu_count() or 4

        self.min_threads = max(10, self.cpu_cores * 2)
        self.max_threads = max(initial_threads * 4, self.cpu_cores * 125)
        self.current_threads = initial_threads

        self._response_times: List[float] = []
        self._error_count = 0
        self._success_count = 0
        self._request_count = 0
        self._check_interval = 200
        self.thread_changes: List[str] = []

    def record(self, response_time: float, is_error: bool = False):
        self._response_times.append(response_time)
        if len(self._response_times) > 500:
            self._response_times = self._response_times[-500:]
        if is_error:
            self._error_count += 1
        else:
            self._success_count += 1
        self._request_count += 1

    def should_adjust(self) -> bool:
        return (
            self._request_count > 0
            and self._request_count % self._check_interval == 0
        )

    async def adjust(self) -> Optional[str]:
        """Calculate and apply optimal thread count. Returns message or None."""
        if len(self._response_times) < 50:
            return None

        recent = self._response_times[-200:]
        avg_rt = sum(recent) / len(recent)
        total = self._success_count + self._error_count
        error_rate = self._error_count / total if total > 0 else 0

        new_threads = self.current_threads
        reason = ""

        if error_rate > 0.15:
            new_threads = int(self.current_threads * 0.7)
            reason = f"high error rate ({error_rate:.0%})"
        elif avg_rt < 0.03:
            new_threads = int(self.current_threads * 1.4)
            reason = f"very fast responses ({avg_rt * 1000:.0f}ms avg)"
        elif avg_rt < 0.08:
            new_threads = int(self.current_threads * 1.2)
            reason = f"fast responses ({avg_rt * 1000:.0f}ms avg)"
        elif avg_rt > 1.0:
            new_threads = int(self.current_threads * 0.6)
            reason = f"slow responses ({avg_rt * 1000:.0f}ms avg)"
        elif avg_rt > 0.5:
            new_threads = int(self.current_threads * 0.8)
            reason = f"sluggish responses ({avg_rt * 1000:.0f}ms avg)"
        else:
            return None

        new_threads = max(self.min_threads, min(self.max_threads, new_threads))

        if new_threads != self.current_threads:
            old = self.current_threads
            self.current_threads = new_threads
            await self.semaphore.set_limit(new_threads)
            msg = f"Threads {old} → {new_threads} ({reason})"
            self.thread_changes.append(msg)
            self._error_count = 0
            self._success_count = 0
            return msg

        return None

    @property
    def avg_response_time(self) -> float:
        if not self._response_times:
            return 0
        window = self._response_times[-100:]
        return sum(window) / len(window)


class RealtimeAdaptiveFilter:
    """
    Learns wildcard patterns IN REAL-TIME during scanning.

    Tracks (status_code, content_length) and (status_code, line_count) pairs.
    When a specific combo is seen more than THRESHOLD times, it's flagged as
    a wildcard pattern and all future matches are auto-filtered.

    This catches:
    - Wildcard 403 from internal firewalls (all same size)
    - Wildcard 401 from auth gateways
    - Wildcard 200 custom error pages missed by initial calibration
    - Any repetitive response pattern
    """

    def __init__(self, size_threshold: int = ADAPTIVE_FILTER_THRESHOLD,
                 line_threshold: int = ADAPTIVE_LINE_THRESHOLD):
        self.size_threshold = size_threshold
        self.line_threshold = line_threshold

        # (status_code, content_length) → hit count
        self._size_counter: Dict[Tuple[int, int], int] = {}
        # (status_code, line_count) → hit count
        self._line_counter: Dict[Tuple[int, int], int] = {}
        # (status_code, content_hash) → hit count
        self._hash_counter: Dict[Tuple[int, str], int] = {}

        # Confirmed wildcard patterns (auto-filter these)
        self._blocked_size_patterns: Set[Tuple[int, int]] = set()
        self._blocked_line_patterns: Set[Tuple[int, int]] = set()
        self._blocked_hash_patterns: Set[Tuple[int, str]] = set()

        # Track what we've already notified about
        self._notified: Set[str] = set()

        # Total filtered by this module
        self.total_filtered = 0

    def track_and_check(self, status: int, content_length: int,
                        line_count: int, content_hash: str) -> bool:
        """
        Track a response and check if it matches a known wildcard pattern.
        Returns True if this response should be FILTERED (is wildcard junk).
        """
        # Fast path: already blocked?
        size_key = (status, content_length)
        line_key = (status, line_count)
        hash_key = (status, content_hash)

        if size_key in self._blocked_size_patterns:
            self.total_filtered += 1
            return True
        if hash_key in self._blocked_hash_patterns:
            self.total_filtered += 1
            return True
        if line_key in self._blocked_line_patterns:
            self.total_filtered += 1
            return True

        # Track this response
        self._size_counter[size_key] = self._size_counter.get(size_key, 0) + 1
        self._line_counter[line_key] = self._line_counter.get(line_key, 0) + 1
        self._hash_counter[hash_key] = self._hash_counter.get(hash_key, 0) + 1

        # Check if any pattern just crossed the threshold
        newly_blocked = False

        # Content hash is the strongest signal (exact same body)
        if self._hash_counter[hash_key] >= self.size_threshold // 2:
            if hash_key not in self._blocked_hash_patterns:
                self._blocked_hash_patterns.add(hash_key)
                # Also block the size pattern for this status
                self._blocked_size_patterns.add(size_key)
                newly_blocked = True

        # Size-based detection
        if self._size_counter[size_key] >= self.size_threshold:
            if size_key not in self._blocked_size_patterns:
                self._blocked_size_patterns.add(size_key)
                newly_blocked = True

        # Line-count-based detection
        if self._line_counter[line_key] >= self.line_threshold:
            if line_key not in self._blocked_line_patterns:
                self._blocked_line_patterns.add(line_key)
                newly_blocked = True

        return newly_blocked  # filter this one too since it triggered the block

    def get_notification(self, status: int, content_length: int,
                         line_count: int) -> Optional[str]:
        """Get a notification message if a new pattern was just blocked."""
        size_key = (status, content_length)
        key_str = f"{status}:{content_length}"
        if size_key in self._blocked_size_patterns and key_str not in self._notified:
            self._notified.add(key_str)
            count = self._size_counter.get(size_key, 0)
            return (
                f"Auto-filtering: HTTP {status} with {content_length}B "
                f"(seen {count}x — wildcard pattern detected)"
            )
        line_key = (status, line_count)
        lkey_str = f"{status}:L{line_count}"
        if line_key in self._blocked_line_patterns and lkey_str not in self._notified:
            self._notified.add(lkey_str)
            return (
                f"Auto-filtering: HTTP {status} with {line_count} lines "
                f"(repetitive pattern detected)"
            )
        return None

    def is_filtered(self, status: int, content_length: int,
                    line_count: int, content_hash: str) -> bool:
        """Quick check if a response matches known wildcard patterns."""
        return (
            (status, content_length) in self._blocked_size_patterns
            or (status, content_hash) in self._blocked_hash_patterns
            or (status, line_count) in self._blocked_line_patterns
        )

    @property
    def blocked_patterns_summary(self) -> List[str]:
        """Summary of all blocked patterns for reporting."""
        patterns = []
        for status, size in sorted(self._blocked_size_patterns):
            patterns.append(f"HTTP {status} / {size}B")
        return patterns


class AdaptiveRateLimiter:
    """Dynamically adjusts request rate based on server responses.

    Includes rate limit fingerprinting: reads Retry-After,
    X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
    headers to intelligently pace requests.
    """

    def __init__(self, initial_delay: float = 0):
        self.delay = initial_delay
        self.last_request = 0.0
        self.consecutive_errors = 0
        self.consecutive_429s = 0
        self.backoff_factor = 1.0
        self._lock = asyncio.Lock()

        # Rate limit fingerprinting state
        self.rate_limit_max: Optional[int] = None
        self.rate_limit_remaining: Optional[int] = None
        self.rate_limit_reset: Optional[float] = None
        self.retry_after: Optional[float] = None
        self._rate_limit_detected = False

    async def wait(self):
        if self.delay <= 0 and self.backoff_factor <= 1.0 and not self._rate_limit_detected:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_request

            # If rate limit headers give us a remaining count near zero, pace ourselves
            if self._rate_limit_detected and self.rate_limit_remaining is not None:
                if self.rate_limit_remaining <= 1 and self.rate_limit_reset:
                    wait_secs = max(0, self.rate_limit_reset - time.time())
                    if wait_secs > 0 and wait_secs < 120:
                        await asyncio.sleep(min(wait_secs, 30))
                        self.last_request = time.monotonic()
                        return

            effective_delay = self.delay * self.backoff_factor
            if elapsed < effective_delay:
                await asyncio.sleep(effective_delay - elapsed)
            self.last_request = time.monotonic()

    def fingerprint_rate_limit(self, headers: dict) -> Optional[str]:
        """Extract rate limiting info from response headers.
        Returns a description string if rate limit was detected, else None."""
        info_parts = []

        # Retry-After (from 429 or 503)
        retry_after = headers.get("Retry-After") or headers.get("retry-after")
        if retry_after:
            try:
                self.retry_after = float(retry_after)
                info_parts.append(f"Retry-After: {self.retry_after}s")
            except ValueError:
                pass

        # Standard rate limit headers (various casings)
        for prefix in ("X-RateLimit", "X-Rate-Limit", "RateLimit", "X-Ratelimit"):
            limit_val = headers.get(f"{prefix}-Limit") or headers.get(f"{prefix}-limit")
            remaining_val = headers.get(f"{prefix}-Remaining") or headers.get(f"{prefix}-remaining")
            reset_val = headers.get(f"{prefix}-Reset") or headers.get(f"{prefix}-reset")

            if limit_val:
                try:
                    self.rate_limit_max = int(limit_val)
                    info_parts.append(f"Limit: {self.rate_limit_max}")
                except ValueError:
                    pass

            if remaining_val:
                try:
                    self.rate_limit_remaining = int(remaining_val)
                    info_parts.append(f"Remaining: {self.rate_limit_remaining}")
                except ValueError:
                    pass

            if reset_val:
                try:
                    reset_num = float(reset_val)
                    # Could be epoch timestamp or seconds-from-now
                    if reset_num > 1e9:
                        self.rate_limit_reset = reset_num
                    else:
                        self.rate_limit_reset = time.time() + reset_num
                    info_parts.append(f"Reset: {reset_num}")
                except ValueError:
                    pass

        if info_parts:
            self._rate_limit_detected = True
            # Auto-pace if we know the limit
            if self.rate_limit_max and self.rate_limit_max > 0 and self.delay == 0:
                self.delay = max(0.01, 1.0 / self.rate_limit_max)
            return " | ".join(info_parts)

        return None

    def on_success(self):
        self.consecutive_errors = 0
        self.consecutive_429s = 0
        self.backoff_factor = max(self.backoff_factor * 0.95, 1.0)

    def on_rate_limit(self, headers: dict = None):
        self.consecutive_429s += 1
        if headers:
            self.fingerprint_rate_limit(headers)
        if self.retry_after and self.retry_after < 120:
            self.backoff_factor = max(self.backoff_factor, self.retry_after / max(self.delay, 0.1))
        else:
            self.backoff_factor = min(self.backoff_factor * 2.0, 30.0)
        if self.delay == 0:
            self.delay = 0.1

    def on_error(self):
        self.consecutive_errors += 1
        if self.consecutive_errors > 5:
            self.backoff_factor = min(self.backoff_factor * 1.5, 10.0)

    @property
    def is_heavily_throttled(self) -> bool:
        return self.consecutive_429s > 10 or self.backoff_factor > 15.0

    @property
    def rate_limit_info(self) -> Optional[str]:
        """Summary of detected rate limiting for reporting."""
        if not self._rate_limit_detected:
            return None
        parts = []
        if self.rate_limit_max:
            parts.append(f"max={self.rate_limit_max}/window")
        if self.consecutive_429s > 0:
            parts.append(f"429s_seen={self.consecutive_429s}")
        return ", ".join(parts) if parts else "detected"


class BlazeEngine:
    """Core scanning engine with all smart features."""

    def __init__(self, config: dict):
        self.config = config
        self.target = config["url"].rstrip("/")

        # Auto-detect optimal threads from CPU cores if not specified
        cpu_cores = os.cpu_count() or 4
        user_threads = config.get("threads", 0)
        if user_threads <= 0:
            self.threads = max(50, cpu_cores * 25)
            config["threads"] = self.threads
        else:
            self.threads = user_threads

        self.timeout = config.get("timeout", 10)
        self.follow_redirects = config.get("follow_redirects", False)
        self.recursive = config.get("recursive", False)
        self.max_depth = config.get("max_depth", 3)
        self.smart_mode = config.get("smart", True)
        self.force = config.get("force", False)
        self.random_agent = config.get("random_agent", False)
        self.proxy = config.get("proxy", None)
        self.custom_headers = config.get("headers", {})
        self.custom_cookies = config.get("cookies", {})
        self.extensions = config.get("extensions", [])
        self.delay = config.get("delay", 0)
        self.show_forbidden = config.get("show_forbidden", False)
        self.extract_js = config.get("extract_js", True)

        # Core modules — DynamicSemaphore allows runtime thread adjustment
        self.semaphore = DynamicSemaphore(self.threads)
        self.rate_limiter = AdaptiveRateLimiter(self.delay)
        self.waf_detector = WAFDetector()
        self.tech_detector = TechDetector()
        self.wordlist_manager = WordlistManager(config)
        self.response_filter = ResponseFilter(config)
        self.wildcard_detector = WildcardDetector()
        self.reporter = Reporter(config)

        # v2 smart modules
        self.response_differ = ResponseDiffer(
            threshold=config.get("diff_threshold", 0.85)
        )
        self.smart_recursion = SmartRecursion(config)
        self.smart_extensions = SmartExtensions(config)
        self.js_extractor = JSExtractor()
        self.resume_manager = ResumeManager(self.target)

        # v2.1 modules — header leak detection, custom signatures
        self.header_analyzer = HeaderAnalyzer()
        self.signature_loader = SignatureLoader()

        # State
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[ScanResult] = []
        self.found_dirs: List[str] = []
        self.scanned_paths: Set[str] = set()
        self.stats = ScanStats()
        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()

        # Crawled paths from HTML responses
        self._crawled_paths: Set[str] = set()
        # Discovered subdomains (scope-aware crawling)
        self._discovered_subdomains: Set[str] = set()

        # Real-time adaptive filter (the killer feature)
        self.adaptive_filter = RealtimeAdaptiveFilter(
            size_threshold=config.get("adaptive_threshold", ADAPTIVE_FILTER_THRESHOLD),
        )

        # Adaptive thread manager — adjusts concurrency based on server/network
        self.thread_manager = AdaptiveThreadManager(self.threads, self.semaphore)

        # Real-time adaptation state
        self._detected_tech: Set[str] = set()
        self._js_urls: Set[str] = set()
        self._js_extracted_paths: Set[str] = set()
        self._wildcard_statuses: Dict[int, int] = {}  # status → count from calibration
        self._save_counter = 0

        # Callback for user interaction
        self.user_prompt_callback: Optional[Callable] = None

    def _get_headers(self) -> dict:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }
        if self.random_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = self.config.get(
                "user_agent", USER_AGENTS[0]
            )
        headers.update(self.custom_headers)
        return headers

    def _get_ssl_context(self):
        ctx = ssl.create_default_context()
        if self.config.get("ignore_ssl", True):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _create_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(
            limit=0,  # No connector limit; DynamicSemaphore handles concurrency
            limit_per_host=0,
            ttl_dns_cache=300,
            ssl=self._get_ssl_context(),
            enable_cleanup_closed=True,
            force_close=False,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.timeout, connect=max(self.timeout // 2, 5)
        )
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=cookie_jar,
            headers=self._get_headers(),
        )
        if self.custom_cookies:
            for name, value in self.custom_cookies.items():
                session.cookie_jar.update_cookies({name: value})
        return session

    # ════════════════════════ PHASE: Initial Probe ════════════════════════

    async def initial_probe(self) -> Optional[dict]:
        self.reporter.info(f"Probing target: {self.target}")
        try:
            async with self.session.get(
                self.target, allow_redirects=True, proxy=self.proxy
            ) as resp:
                body = await resp.text(errors="replace")
                headers = dict(resp.headers)
                cookies = {k: v.value for k, v in resp.cookies.items()}
                self.reporter.info(
                    f"Target responded: HTTP {resp.status} "
                    f"[{resp.headers.get('Content-Type', 'unknown')}]"
                )
                return {
                    "status": resp.status, "headers": headers,
                    "cookies": cookies, "body": body, "url": str(resp.url),
                }
        except Exception as e:
            self.reporter.error(f"Failed to connect to target: {e}")
            return None

    # ════════════════════════ PHASE: WAF Detection ════════════════════════

    async def detect_waf(self, probe_data: dict) -> WAFResult:
        self.reporter.phase("WAF Detection")
        result = self.waf_detector.detect(
            headers=probe_data["headers"],
            body=probe_data["body"],
            cookies=probe_data["cookies"],
        )
        trigger_paths = [
            "/../../../etc/passwd",
            "/<script>alert(1)</script>",
            "/admin' OR '1'='1",
        ]
        for path in trigger_paths:
            try:
                async with self.session.get(
                    self.target + path, allow_redirects=False, proxy=self.proxy
                ) as resp:
                    body = await resp.text(errors="replace")
                    headers = dict(resp.headers)
                    cookies = {k: v.value for k, v in resp.cookies.items()}
                    tr = self.waf_detector.detect(
                        headers=headers, body=body, cookies=cookies
                    )
                    if tr.detected:
                        result.merge(tr)
                        break
            except Exception:
                continue

        if result.detected:
            self.reporter.waf_detected(result)
        else:
            self.reporter.info("No WAF detected")
        return result

    # ════════════════════════ PHASE: Tech Detection ════════════════════════

    async def detect_technology(self, probe_data: dict) -> TechResult:
        self.reporter.phase("Technology Detection")
        result = self.tech_detector.detect_from_response(
            headers=probe_data["headers"],
            body=probe_data["body"],
            cookies=probe_data["cookies"],
        )
        tech_probes = self.tech_detector.get_probe_paths()
        tasks = [self._probe_tech_path(p, t) for p, t in tech_probes]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Count how many probes returned each status to detect blanket responses
        status_counts = {}
        valid_probes = []
        for pr in probe_results:
            if isinstance(pr, tuple) and len(pr) >= 4:
                if pr[0]:  # detected
                    status = pr[3]
                    status_counts[status] = status_counts.get(status, 0) + 1
                    valid_probes.append(pr)

        # Detect blanket responses: if any single status code accounts for >60%
        # of all probe hits, the server is returning the same thing for everything
        # (WAF blocking with 403, catch-all redirect with 301, etc.)
        total_hits = len(valid_probes)
        blanket_status = None
        if total_hits > 5:
            for status, count in status_counts.items():
                if count / total_hits > 0.6 and status != 200:
                    blanket_status = status
                    break

        for pr in valid_probes:
            status = pr[3]
            if blanket_status and status == blanket_status:
                continue  # Skip blanket false positives
            result.add_technology(pr[1], pr[2])

        if blanket_status:
            self.reporter.warning(
                f"Most probe paths returned {blanket_status} (blanket response). "
                f"Probe-based tech detection skipped — using header/body signatures only."
            )

        if result.technologies:
            self.reporter.tech_detected(result)
            self._detected_tech.update(result.technologies.keys())
        else:
            self.reporter.info("No specific technology detected")
        return result

    async def _probe_tech_path(self, path: str, tech_name: str) -> Tuple[bool, str, float, int]:
        try:
            url = f"{self.target}/{path.lstrip('/')}"
            async with self.session.get(
                url, allow_redirects=False, proxy=self.proxy
            ) as resp:
                if resp.status == 200:
                    return (True, tech_name, 0.9, resp.status)
                elif resp.status in (301, 302):
                    return (True, tech_name, 0.7, resp.status)
                elif resp.status == 403:
                    # 403 could be a WAF blanket block — return low confidence,
                    # will be filtered out later if most probes return 403
                    return (True, tech_name, 0.5, resp.status)
        except Exception:
            pass
        return (False, tech_name, 0.0, 0)

    # ════════════════════ PHASE: Wildcard + Soft-404 Calibration ════════════════════

    async def calibrate_detection(self):
        """Calibrate wildcard detection AND response diffing for soft-404."""
        self.reporter.phase("Response Calibration")

        # Standard wildcard calibration
        await self.wildcard_detector.calibrate(self.session, self.target, self.proxy)
        if self.wildcard_detector.has_wildcard:
            ws = self.wildcard_detector.wildcard_status
            self._wildcard_statuses[ws] = self._wildcard_statuses.get(ws, 0) + 1
            self.reporter.warning(
                f"Wildcard response detected "
                f"(Status: {ws}, Size: ~{self.wildcard_detector.wildcard_size}B). "
                f"Auto-filtering enabled."
            )
        else:
            self.reporter.info("No wildcard responses detected")

        # Response diffing calibration for smart soft-404
        await self.response_differ.calibrate(self.session, self.target, self.proxy)
        if self.response_differ.baseline_count:
            self.reporter.info(
                f"Soft-404 detection calibrated ({self.response_differ.baseline_count} baselines)"
            )

        # Detect wildcard 401/403 (if random paths all return same status)
        await self._detect_wildcard_auth()

    async def _detect_wildcard_auth(self):
        """Detect if target returns 401 or 403 for ALL random paths (wildcard auth)."""
        import string
        statuses = []
        for _ in range(4):
            rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
            try:
                async with self.session.get(
                    f"{self.target}/{rnd}", allow_redirects=False, proxy=self.proxy
                ) as resp:
                    statuses.append(resp.status)
            except Exception:
                continue

        if len(statuses) >= 3:
            for status in (401, 403):
                count = statuses.count(status)
                if count >= 3:
                    self._wildcard_statuses[status] = count
                    self.reporter.warning(
                        f"Wildcard {status} detected (all random paths return {status}). "
                        f"Auto-filtering {status} responses."
                    )

    def _is_wildcard_status(self, status_code: int) -> bool:
        """Check if a status code is a wildcard (returned for random non-existent paths)."""
        return self._wildcard_statuses.get(status_code, 0) >= 3

    # ════════════════════════ Interactive Wordlist Selection ════════════════════════

    async def _prompt_wordlist_selection(self) -> List[str]:
        """When no technology is detected, show available wordlists and let user pick."""
        available = self.wordlist_manager.get_available_wordlists()
        if not available:
            return []

        c = Colors
        print(f"\n  {c.BOLD}No technology detected.{c.RESET} Select wordlists to scan with:")
        print(f"  {c.DIM}(common.txt, backup.txt, sensitive.txt are always included){c.RESET}\n")

        # Show numbered list with entry counts
        wl_dir = self.wordlist_manager.wordlist_dir
        for i, wl in enumerate(available, 1):
            path = os.path.join(wl_dir, wl)
            try:
                with open(path) as f:
                    count = sum(1 for line in f if line.strip() and not line.startswith("#"))
            except IOError:
                count = 0
            print(f"    {c.CYAN}{i:2d}.{c.RESET} {wl:<28s} {c.DIM}({count:,} entries){c.RESET}")

        print(f"\n  {c.DIM}Enter numbers separated by commas (e.g. 1,5,12) or 'all' or press Enter to skip:{c.RESET}")

        try:
            choice = input(f"  {c.CYAN}>{c.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []

        if not choice:
            return []

        selected = []
        if choice.lower() == "all":
            selected = list(available)
        else:
            for part in choice.split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(available):
                        selected.append(available[idx])

        if selected:
            print(f"\n  {c.GREEN}[ok]{c.RESET} Selected: {', '.join(selected)}")
            # Add extensions from selected wordlists (map wordlist name to tech)
            self._add_extensions_from_wordlists(selected)
        else:
            print(f"  {c.DIM}No wordlists selected, using defaults.{c.RESET}")

        return selected

    def _add_extensions_from_wordlists(self, wordlist_names: List[str]):
        """Infer and add relevant extensions based on selected wordlist names."""
        c = Colors
        wl_ext_map = {
            "php.txt": [".php", ".phtml"],
            "asp.txt": [".aspx", ".asp", ".ashx"],
            "jsp.txt": [".jsp", ".jsf", ".do", ".action"],
            "spring.txt": [".jsp", ".do", ".action", ".html"],
            "wordpress.txt": [".php"],
            "joomla.txt": [".php"],
            "drupal.txt": [".php", ".module", ".inc"],
            "laravel.txt": [".php", ".blade.php"],
            "python_web.txt": [".py", ".html"],
            "rails.txt": [".html", ".erb", ".rb"],
            "nodejs.txt": [".js", ".json", ".html"],
            "iis.txt": [".aspx", ".asp", ".ashx", ".asmx"],
            "tomcat.txt": [".jsp", ".jsf", ".do"],
            "magento.txt": [".php", ".phtml"],
            "typo3.txt": [".php", ".html"],
            "umbraco.txt": [".aspx", ".ashx", ".cshtml"],
            "moodle.txt": [".php"],
            "sharepoint.txt": [".aspx", ".ashx", ".asmx"],
            "aem.txt": [".html", ".json", ".xml"],
            "confluence.txt": [".action", ".do"],
            "jenkins.txt": [".html", ".xml"],
            "gitlab.txt": [".html", ".json"],
            "swagger.txt": [".json", ".yaml", ".html"],
            "graphql.txt": [".json"],
            "elasticsearch.txt": [".json"],
        }
        added = set()
        for wl_name in wordlist_names:
            for ext in wl_ext_map.get(wl_name, []):
                if ext not in self.extensions:
                    self.extensions.append(ext)
                    added.add(ext)
        # Always add sensitive extensions
        for ext in [".bak", ".old", ".txt", ".conf", ".log", ".sql", ".xml", ".json"]:
            if ext not in self.extensions:
                self.extensions.append(ext)
                added.add(ext)
        if added:
            print(f"  {c.GREEN}[ok]{c.RESET} Auto-added extensions: {', '.join(sorted(added))}")

    # ════════════════════════ PHASE: Smart Status Filtering ════════════════════════

    def _should_show_result(self, result: ScanResult, body: str) -> bool:
        """
        Smart status-based filtering:
        - 200, 201, 204, 301, 302, 307, 308 → SHOW (if not wildcard/soft-404)
        - 401 → SHOW only if NOT wildcard 401
        - 403 → SHOW only if --show-forbidden and NOT wildcard 403
        - 404 → NEVER show
        - 500 → SHOW only if not wildcard (may reveal stack traces)
        """
        status = result.status_code

        # Never show 404
        if status in HIDDEN_STATUS_CODES:
            return False

        # Wildcard status check (applies to all)
        if self._is_wildcard_status(status):
            return False

        # Standard wildcard content check
        if self.wildcard_detector.is_wildcard(result):
            return False

        # Soft-404 check via response diffing
        if status == 200 and self.response_differ.is_soft_404(body):
            return False

        # Important statuses - always show
        if status in IMPORTANT_STATUS_CODES:
            return True

        # Conditional statuses
        if status == 401:
            return True  # already filtered wildcard 401 above

        if status == 403:
            return self.show_forbidden

        if status == 405:
            return True  # method not allowed = endpoint exists

        if status == 500:
            return True  # internal error = might reveal info

        # User-configured include/exclude overrides
        if self.response_filter.include_status:
            return status in self.response_filter.include_status

        if status in self.response_filter.exclude_status:
            return False

        return True

    # ════════════════════════ PHASE: Main Scan ════════════════════════

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes}B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f}KB"
        return f"{size_bytes / (1024 * 1024):.1f}MB"

    async def scan_wordlist(self, words: List[str], base_path: str = ""):
        tasks = []
        for word in words:
            if self._stop_event.is_set():
                break
            word = word.strip()
            if not word or word.startswith("#"):
                continue

            paths_to_scan = [word]
            # Only append extensions to bare names (no extension, not a directory path)
            # e.g. "admin" -> "admin.php", but NOT "config.php" or "admin/"
            basename = word.rstrip("/").split("/")[-1]
            is_bare = "." not in basename and not word.endswith("/")
            if self.extensions and is_bare:
                for ext in self.extensions:
                    ext = ext.lstrip(".")
                    paths_to_scan.append(f"{word}.{ext}")

            for path in paths_to_scan:
                full_path = f"{base_path}/{path}".lstrip("/")
                if full_path in self.scanned_paths:
                    continue
                self.scanned_paths.add(full_path)
                tasks.append(self._scan_path(full_path))

        total_tasks = len(tasks)
        self.reporter.start_progress(total_tasks)
        chunk_size = max(self.threads * 10, 200)
        completed = 0

        for i in range(0, total_tasks, chunk_size):
            if self._stop_event.is_set():
                break
            chunk = tasks[i : i + chunk_size]
            await asyncio.gather(*chunk, return_exceptions=True)
            completed += len(chunk)

            # Calculate live metrics
            elapsed = time.monotonic() - self.stats.start_time
            rps = self.stats.total_requests / elapsed if elapsed > 0.5 else 0

            self.reporter.update_progress(
                completed,
                rps=rps,
                threads=self.thread_manager.current_threads,
                adaptive_filtered=self.adaptive_filter.total_filtered,
            )

            # Adaptive thread adjustment
            if self.thread_manager.should_adjust():
                msg = await self.thread_manager.adjust()
                if msg:
                    self.reporter.adaptive(msg)

            # Auto-save progress
            self._save_counter += len(chunk)
            if self.config.get("resume", False) and self._save_counter >= 1000:
                self._save_counter = 0
                self._auto_save_state(words)

    async def _scan_path(self, path: str):
        await self._pause_event.wait()
        if self._stop_event.is_set():
            return

        async with self.semaphore:
            await self.rate_limiter.wait()
            self.stats.total_requests += 1

            url = f"{self.target}/{path}"
            try:
                start_time = time.monotonic()
                async with self.session.get(
                    url, allow_redirects=self.follow_redirects, proxy=self.proxy,
                ) as resp:
                    elapsed = time.monotonic() - start_time
                    body = await resp.text(errors="replace")
                    content_length = len(body.encode())
                    headers = dict(resp.headers)
                    line_count = body.count("\n") + 1
                    content_hash = hashlib.md5(body.encode()).hexdigest()

                    result = ScanResult(
                        url=url, path=path,
                        status_code=resp.status,
                        content_length=content_length,
                        content_type=resp.headers.get("Content-Type", ""),
                        redirect_url=(
                            str(resp.headers.get("Location", ""))
                            if resp.status in (301, 302, 303, 307, 308) else None
                        ),
                        response_time=elapsed,
                        word_count=len(body.split()),
                        line_count=line_count,
                        content_hash=content_hash,
                    )

                    # Directory detection
                    if resp.status in (200, 301, 302, 403) and (
                        path.endswith("/")
                        or resp.headers.get("Content-Type", "").startswith("text/html")
                    ):
                        result.is_directory = True

                    # ═══ REAL-TIME ADAPTIVE FILTER (catches wildcard 403, etc.) ═══
                    # This runs BEFORE everything else — it learns patterns live
                    is_junk = self.adaptive_filter.track_and_check(
                        resp.status, content_length, line_count, content_hash
                    )
                    if is_junk:
                        self.stats.filtered += 1
                        note = self.adaptive_filter.get_notification(
                            resp.status, content_length, line_count
                        )
                        if note:
                            self.reporter.adaptive(
                                f"Auto-filter: HTTP {resp.status} × "
                                f"{self._fmt_size(content_length)} "
                                f"(wildcard pattern detected)"
                            )
                        self.rate_limiter.on_success()
                        self.thread_manager.record(elapsed)
                        return

                    if self.adaptive_filter.is_filtered(
                        resp.status, content_length, line_count, content_hash
                    ):
                        self.stats.filtered += 1
                        self.rate_limiter.on_success()
                        self.thread_manager.record(elapsed)
                        return

                    if not self._should_show_result(result, body):
                        self.stats.filtered += 1
                        self.response_differ.track_response(body)
                        self.rate_limiter.on_success()
                        self.thread_manager.record(elapsed)
                        return

                    # Additional response filter (size/words/lines)
                    if not self.response_filter.should_show(result):
                        self.stats.filtered += 1
                        return

                    # Live WAF block check
                    if self.waf_detector.is_waf_block(resp.status, headers, body):
                        self.stats.waf_blocks += 1
                        if self.stats.waf_blocks > 10:
                            self.reporter.warning(
                                "Multiple WAF blocks detected! Consider reducing threads."
                            )
                        if self.stats.waf_blocks > 50:
                            self._stop_event.set()
                            self.reporter.error("Too many WAF blocks. Stopping scan.")
                        return

                    # ═══ Rate limit fingerprinting (runs on every response) ═══
                    rl_info = self.rate_limiter.fingerprint_rate_limit(headers)
                    if rl_info and not hasattr(self, '_rl_notified'):
                        self._rl_notified = True
                        self.reporter.info(f"Rate limit detected: {rl_info}")

                    # Handle 429 Too Many Requests
                    if resp.status == 429:
                        self.rate_limiter.on_rate_limit(headers)
                        self.thread_manager.record(elapsed, is_error=True)
                        return

                    # ═══ VALID RESULT ═══
                    self.stats.successful += 1
                    self.results.append(result)
                    self.reporter.found(result)

                    # ── Header leak analysis ──
                    if self.smart_mode:
                        new_leaks = self.header_analyzer.analyze(headers)
                        for leak in new_leaks:
                            if leak.severity == "high":
                                self.reporter.warning(
                                    f"Header leak [{leak.severity}]: "
                                    f"{leak.header}: {leak.value} — {leak.description}"
                                )

                    # ── Crawl links from HTML responses ──
                    if (resp.status == 200
                        and "text/html" in resp.headers.get("Content-Type", "")
                        and self.smart_mode):
                        self._crawl_links(body, path)

                    # ── Real-time adaptation ──
                    await self._on_result_found(result, body, headers)

                    self.rate_limiter.on_success()
                    self.thread_manager.record(elapsed)

            except asyncio.TimeoutError:
                self.stats.errors += 1
                self.rate_limiter.on_error()
                self.thread_manager.record(self.timeout, is_error=True)
            except aiohttp.ClientError:
                self.stats.errors += 1
                self.rate_limiter.on_error()
                self.thread_manager.record(self.timeout * 0.5, is_error=True)
            except Exception:
                self.stats.errors += 1
                self.rate_limiter.on_error()
                self.thread_manager.record(self.timeout * 0.5, is_error=True)

    def _crawl_links(self, body: str, source_path: str):
        """Extract links from HTML responses and queue them for scanning.

        Scope-aware: stays within the target's base domain (e.g., if target is
        app.example.com, also accepts links to api.example.com paths but only
        scans paths on the original target host).
        """
        target_parsed = urlparse(self.target)
        target_host = target_parsed.hostname or ""
        # Extract base domain for scope checking (e.g., "example.com" from "app.example.com")
        host_parts = target_host.split(".")
        base_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else target_host

        link_patterns = [
            r'href=["\']([^"\'#?]+)',
            r'src=["\']([^"\'#?]+)',
            r'action=["\']([^"\'#?]+)',
        ]
        for pattern in link_patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                link = match.group(1).strip()
                # Skip non-HTTP schemes
                if any(link.startswith(p) for p in (
                    "mailto:", "javascript:", "data:", "tel:", "ftp:", "#",
                )):
                    continue

                # Handle absolute URLs
                if link.startswith(("http://", "https://", "//")):
                    if link.startswith("//"):
                        link = f"{target_parsed.scheme}:{link}"
                    parsed = urlparse(link)
                    link_host = parsed.hostname or ""
                    # Same host → use the path directly
                    if link_host == target_host:
                        link = parsed.path
                    # Same base domain (scope-aware) → log the subdomain but only scan paths on target
                    elif link_host.endswith(base_domain):
                        if link_host not in self._discovered_subdomains:
                            self._discovered_subdomains.add(link_host)
                            self.reporter.info(
                                f"Related subdomain discovered: {link_host} (from /{source_path})"
                            )
                        continue  # don't scan other subdomains' paths on our target
                    else:
                        continue  # external domain, skip

                # Normalize
                link = link.lstrip("/")
                if link and link not in self.scanned_paths and len(link) < 256:
                    self.scanned_paths.add(link)
                    self._crawled_paths.add(link)

    # ════════════════════ Real-Time Adaptation ════════════════════

    async def _on_result_found(self, result: ScanResult, body: str, headers: dict):
        """Called after every valid result. Triggers smart reactions."""

        # 1. Collect directories for smart recursion
        if result.is_directory and self.recursive:
            self.found_dirs.append(result.path.rstrip("/") + "/")

        # 2. Real-time tech detection from response content
        self._realtime_tech_detect(result, body, headers)

        # 3. Queue smart extension probes for suspicious files
        if self.smart_mode and self.smart_extensions.should_probe_extensions(
            result.path, result.status_code
        ):
            await self._probe_smart_extensions(result)

        # 4. Queue directory archive probes (backup.zip, backup.tar.gz, etc.)
        if result.is_directory and self.smart_mode:
            await self._probe_dir_archives(result)

        # 5. Extract JS endpoints if response is JavaScript
        if self.extract_js and result.status_code == 200:
            content_type = result.content_type.lower()
            if "javascript" in content_type or result.path.endswith((".js", ".mjs")):
                self._js_urls.add(result.url)

    def _realtime_tech_detect(self, result: ScanResult, body: str, headers: dict):
        """Detect technology from individual scan results in real-time."""
        path_lower = result.path.lower()

        tech_indicators = {
            "WordPress": ["wp-content", "wp-admin", "wp-includes", "wp-login"],
            "Joomla": ["administrator", "com_content", "joomla"],
            "Drupal": ["sites/default", "core/misc", "drupal"],
            "PHP": [".php"],
            "ASP.NET": [".aspx", ".ashx", ".asmx", "web.config"],
            "Java/JSP": [".jsp", ".do", ".action", "WEB-INF"],
            "Node.js": ["node_modules", "package.json"],
            "Python": ["__pycache__", ".py", "django", "flask"],
            "Ruby on Rails": ["rails", ".rb", "Gemfile"],
            "Spring": ["actuator", "swagger", "spring"],
        }

        for tech, indicators in tech_indicators.items():
            if tech not in self._detected_tech:
                for indicator in indicators:
                    if indicator in path_lower:
                        self._detected_tech.add(tech)
                        self.reporter.info(
                            f"Real-time tech detected: {tech} (from /{result.path})"
                        )
                        break

    async def _probe_smart_extensions(self, result: ScanResult):
        """Probe backup/archive extensions for a discovered file."""
        probes = self.smart_extensions.get_file_probes(result.path, result.status_code)
        for probe in probes[:10]:  # Limit to top 10 priority probes per file
            if probe.probe_path not in self.scanned_paths:
                self.scanned_paths.add(probe.probe_path)
                # Fire and forget - these are bonus probes
                asyncio.create_task(self._scan_path(probe.probe_path))

    async def _probe_dir_archives(self, result: ScanResult):
        """Probe archive variants for a discovered directory."""
        probes = self.smart_extensions.get_dir_probes(result.path)
        for probe in probes:
            if probe.probe_path not in self.scanned_paths:
                self.scanned_paths.add(probe.probe_path)
                asyncio.create_task(self._scan_path(probe.probe_path))

    # ════════════════════ PHASE: Smart Recursive Scan ════════════════════

    async def smart_recursive_scan(self, current_depth: int = 1):
        """Context-aware recursive scanning with multi-wordlist per directory."""
        if current_depth > self.max_depth or not self.found_dirs:
            return

        dirs_to_scan = list(self.found_dirs)
        self.found_dirs.clear()

        for dir_path in dirs_to_scan:
            if self._stop_event.is_set():
                break

            # Get context-aware wordlist for this directory
            context = self.smart_recursion.get_context_info(dir_path)
            wordlist = self.smart_recursion.build_recursive_wordlist(dir_path)

            wl_names = ", ".join(context["matched_wordlists"])
            suspicious = " [SUSPICIOUS]" if context["is_suspicious"] else ""
            self.reporter.info(
                f"Recursing: /{dir_path} → [{wl_names}] "
                f"({len(wordlist)} words, depth {current_depth}/{self.max_depth})"
                f"{suspicious}"
            )

            await self.scan_wordlist(wordlist, base_path=dir_path)

        # Continue recursion if new dirs found
        if self.found_dirs:
            await self.smart_recursive_scan(current_depth + 1)

    # ════════════════════ PHASE: JS Endpoint Extraction ════════════════════

    async def extract_js_endpoints(self):
        """Extract endpoints from discovered JavaScript files."""
        if not self._js_urls:
            return

        self.reporter.phase(f"JS Endpoint Extraction ({len(self._js_urls)} files)")

        all_paths = set()
        for js_url in self._js_urls:
            try:
                async with self.session.get(
                    js_url, proxy=self.proxy
                ) as resp:
                    if resp.status == 200:
                        js_body = await resp.text(errors="replace")
                        paths = self.js_extractor.extract_paths(js_body)
                        all_paths.update(paths)
            except Exception:
                continue

        # Filter already-scanned paths
        new_paths = [p for p in all_paths if p not in self.scanned_paths]
        self._js_extracted_paths.update(new_paths)

        if new_paths:
            self.reporter.info(f"Extracted {len(new_paths)} new endpoints from JS files")
            await self.scan_wordlist(new_paths)
        else:
            self.reporter.info("No new endpoints found in JS files")

    # ════════════════════ PHASE: Resume Support ════════════════════

    def _auto_save_state(self, current_wordlist: List[str]):
        """Auto-save scan state for resume capability."""
        state = ScanState(
            target=self.target,
            scanned_paths=self.scanned_paths,
            results=[
                {"url": r.url, "path": r.path, "status": r.status_code,
                 "size": r.content_length}
                for r in self.results
            ],
            config=self.config,
            wordlist_index=len(self.scanned_paths),
            total_words=len(current_wordlist),
            timestamp="",
            found_dirs=self.found_dirs,
        )
        self.resume_manager.save_state(state)

    def _load_resume_state(self) -> bool:
        """Try to load previous scan state. Returns True if resumed."""
        if not self.resume_manager.has_saved_state():
            return False

        info = self.resume_manager.resume_info()
        if info:
            self.reporter.info(
                f"Found saved state: {info['scanned']:,} paths scanned, "
                f"{info['results_found']} results, "
                f"{info['progress_pct']:.1f}% complete"
            )

        state = self.resume_manager.load_state()
        if state:
            self.scanned_paths = state.scanned_paths
            self.found_dirs = list(state.found_dirs)
            self.reporter.success(
                f"Resumed scan. Skipping {len(self.scanned_paths):,} already-scanned paths."
            )
            return True
        return False

    # ════════════════════ MAIN EXECUTION FLOW ════════════════════

    async def run(self):
        self.stats.start_time = time.monotonic()
        self.reporter.banner()
        self.reporter.scan_config(self.config)

        self.session = await self._create_session()

        try:
            # Load custom signature packs
            sig_count = self.signature_loader.load_all()
            if sig_count > 0:
                self.reporter.info(
                    f"Loaded {sig_count} custom signature pack(s): "
                    f"{', '.join(self.signature_loader.get_pack_names())}"
                )

            # Resume check
            if self.config.get("resume", False):
                self._load_resume_state()

            # Phase 1: Initial probe
            probe_data = await self.initial_probe()
            if not probe_data:
                self.reporter.error("Cannot reach target. Aborting.")
                return

            # Phase 2: WAF Detection
            if not self.config.get("no_waf_check", False):
                waf_result = await self.detect_waf(probe_data)
                if waf_result.detected:
                    self.reporter.warning(
                        f"WAF Detected: {', '.join(waf_result.waf_names)} — "
                        f"continuing scan automatically"
                    )

            # Phase 3: Technology Detection
            tech_result = TechResult()
            if self.smart_mode:
                tech_result = await self.detect_technology(probe_data)
                auto_extensions = self.tech_detector.get_extensions(tech_result)
                if auto_extensions:
                    for ext in auto_extensions:
                        if ext not in self.extensions:
                            self.extensions.append(ext)
                    self.reporter.info(
                        f"Auto-added extensions: {', '.join(auto_extensions)}"
                    )

            # Phase 4: Response calibration (wildcard + soft-404 + wildcard auth)
            await self.calibrate_detection()

            # Phase 4b: Subdomain-aware wordlist hints
            subdomain_lists = HeaderAnalyzer.get_subdomain_wordlists(self.target)
            if subdomain_lists:
                self.reporter.info(
                    f"Subdomain intelligence: adding {', '.join(subdomain_lists)}"
                )

            # Phase 4c: If no tech detected, ask user to pick wordlists
            user_extra_lists = []
            if not tech_result.technologies and self.user_prompt_callback:
                user_extra_lists = await self._prompt_wordlist_selection()

            # Phase 5: Wordlist assembly
            self.reporter.phase("Wordlist Assembly")
            all_extra = (subdomain_lists or []) + user_extra_lists
            wordlist = self.wordlist_manager.build_wordlist(
                tech_result, extra_wordlists=all_extra if all_extra else None
            )
            self.reporter.info(f"Total words to scan: {len(wordlist):,}")

            # Phase 6: Main scan
            self.reporter.phase("Directory Scan")
            await self.scan_wordlist(wordlist)

            # Phase 6b: Scan crawled links from HTML responses
            if self._crawled_paths:
                crawled = [p for p in self._crawled_paths if p not in self.scanned_paths]
                if crawled:
                    self.reporter.phase(f"Crawled Links ({len(crawled)} new paths)")
                    await self.scan_wordlist(crawled)

            # Phase 7: JS endpoint extraction
            if self.extract_js and self._js_urls:
                await self.extract_js_endpoints()

            # Phase 8: Smart recursive scan
            if self.recursive and self.found_dirs:
                self.reporter.phase("Smart Recursive Scan")
                await self.smart_recursive_scan()

            # Phase 9: Results
            self.stats.end_time = time.monotonic()
            self.stats.elapsed = self.stats.end_time - self.stats.start_time
            self.stats.rps = (
                self.stats.total_requests / self.stats.elapsed
                if self.stats.elapsed > 0 else 0
            )

            adaptive_info = {
                "patterns_blocked": self.adaptive_filter.blocked_patterns_summary,
                "total_filtered": self.adaptive_filter.total_filtered,
                "thread_changes": self.thread_manager.thread_changes,
            }

            # Header leak summary
            leak_summary = self.header_analyzer.get_summary()
            if any(leak_summary.values()):
                adaptive_info["header_leaks"] = leak_summary
                self.reporter.info(
                    f"Header leaks found: {leak_summary['high']} high, "
                    f"{leak_summary['medium']} medium, {leak_summary['low']} low"
                )

            # Rate limit info
            rl_info = self.rate_limiter.rate_limit_info
            if rl_info:
                adaptive_info["rate_limit"] = rl_info

            self.reporter.summary(self.stats, self.results, adaptive_info)

            # Export results
            if self.config.get("output"):
                self.reporter.export(
                    self.results,
                    self.config["output"],
                    self.config.get("output_format", "txt"),
                )

            # Clear resume state on successful completion
            if self.config.get("resume", False):
                self.resume_manager.clear_state()
                self.reporter.info("Scan complete. Resume state cleared.")

        except KeyboardInterrupt:
            self.reporter.warning("\nScan interrupted by user.")
            if self.config.get("resume", False):
                self._auto_save_state(wordlist if 'wordlist' in dir() else [])
                self.reporter.info("State saved. Use --resume to continue.")
            self.stats.end_time = time.monotonic()
            self.stats.elapsed = self.stats.end_time - self.stats.start_time
            self.reporter.summary(self.stats, self.results)
        finally:
            await self.session.close()

    def stop(self):
        self._stop_event.set()

    def pause(self):
        self._pause_event.clear()

    def resume_scan(self):
        self._pause_event.set()
