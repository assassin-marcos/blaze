"""
Blaze Content Discovery - Parameter and content discovery mode.

Fuzzes common query parameters on discovered endpoints to find hidden
functionality, reflected values, debug output, stack traces, and
security-sensitive responses. Designed to run alongside or after
directory bruteforce scanning.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger("blaze.content_discovery")


# ──────────────────── Built-in Parameter Wordlist ────────────────────

COMMON_PARAMS: List[str] = [
    "id", "page", "file", "path", "dir", "search", "q", "url",
    "redirect", "next", "callback", "debug", "test", "admin",
    "action", "cmd", "exec", "command", "type", "category",
    "name", "user", "username", "email", "password", "token",
    "key", "api_key", "secret", "config", "view", "template",
    "include", "require", "source", "src", "lang", "language",
    "format", "output", "download", "upload", "filter", "sort",
    "order", "limit", "offset", "start", "end", "from", "to",
    "return", "continue", "ref", "referrer", "target", "dest",
    "destination", "uri", "site", "domain", "host", "port",
    "data", "input", "payload", "body", "content", "text",
    "message", "msg", "error", "status", "code", "module",
    "plugin", "theme", "style", "method", "mode", "role",
    "access", "level", "group", "scope", "state", "session",
    "hash", "signature", "nonce", "timestamp", "version",
    "v", "p", "s", "r", "t", "u", "c", "f", "w",
]

TEST_VALUES: List[str] = [
    "1",
    "true",
    "admin",
    "test",
    "{{7*7}}",
    "${7*7}",
    "../../../etc/passwd",
    "<script>alert(1)</script>",
    "' OR '1'='1",
]

# ────────────────── Interesting Response Patterns ──────────────────

# Patterns that indicate debug/error output worth investigating
_INTERESTING_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Stack traces and error messages
    (re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
     "Python stack trace"),
    (re.compile(r"at\s+[\w.$]+\s*\([\w/.]+:\d+:\d+\)"),
     "JavaScript/Node.js stack trace"),
    (re.compile(r"(?:Fatal|Parse|Syntax)\s+error.*?(?:in|on line)\s+\S+", re.IGNORECASE),
     "PHP fatal/parse error"),
    (re.compile(r"java\.\w+\.[\w.]+Exception", re.IGNORECASE),
     "Java exception"),
    (re.compile(r"System\.(?:Web|IO|Data|Net)\.\w+Exception", re.IGNORECASE),
     "ASP.NET exception"),
    (re.compile(r"#\d+\s+\S+\(.*?\)\s+called at\s+\[", re.IGNORECASE),
     "PHP backtrace"),
    (re.compile(r"(?:RuntimeError|ValueError|TypeError|KeyError|ImportError|AttributeError):", re.IGNORECASE),
     "Python exception"),

    # File path disclosure
    (re.compile(r"(?:/var/www|/home/\w+|/opt/|/srv/|/usr/share|C:\\\\inetpub|C:\\\\Users)", re.IGNORECASE),
     "Server file path disclosure"),
    (re.compile(r"(?:DocumentRoot|DOCUMENT_ROOT|SCRIPT_FILENAME)\s*[=:]\s*\S+", re.IGNORECASE),
     "Document root disclosure"),

    # Database errors
    (re.compile(r"(?:SQL syntax|mysql_|mysqli_|pg_query|sqlite3?_|ORA-\d{5})", re.IGNORECASE),
     "SQL error / database disclosure"),
    (re.compile(r"(?:SQLSTATE\[|PDOException|Unclosed quotation mark)", re.IGNORECASE),
     "Database exception"),
    (re.compile(r"(?:You have an error in your SQL syntax|Query failed|mysql_fetch)", re.IGNORECASE),
     "MySQL error"),

    # Debug / configuration leakage
    (re.compile(r"(?:DEBUG\s*=\s*True|DJANGO_SETTINGS_MODULE|APP_DEBUG\s*=\s*true)", re.IGNORECASE),
     "Debug mode enabled"),
    (re.compile(r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET)\s*[=:]", re.IGNORECASE),
     "Credential/secret disclosure"),
    (re.compile(r"(?:phpinfo\(\)|<title>phpinfo\(\)</title>)", re.IGNORECASE),
     "phpinfo() output"),
    (re.compile(r"(?:xdebug|Xdebug|XDEBUG)", re.IGNORECASE),
     "Xdebug enabled"),

    # Directory listings
    (re.compile(r"(?:Index of /|Directory listing for|Parent Directory)", re.IGNORECASE),
     "Directory listing"),

    # Template engine errors (SSTI indicators)
    (re.compile(r"(?:TemplateSyntaxError|Jinja2|UndefinedError|TemplateNotFound)", re.IGNORECASE),
     "Template engine error (potential SSTI)"),
    (re.compile(r"49(?:\s|$)"),  # Result of {{7*7}} or ${7*7}
     "Template expression evaluated (SSTI)"),

    # Source code disclosure
    (re.compile(r"<\?php\s", re.IGNORECASE),
     "PHP source code disclosure"),
    (re.compile(r"<%@?\s*(?:page|import|include)", re.IGNORECASE),
     "JSP/ASP source code disclosure"),

    # Authentication / authorization flaws
    (re.compile(r"(?:admin.*panel|admin.*dashboard|admin.*console)", re.IGNORECASE),
     "Admin interface exposed"),
    (re.compile(r"(?:root:|admin:|password\s*:)", re.IGNORECASE),
     "Credential pattern in response"),

    # Sensitive file content (LFI indicators)
    (re.compile(r"root:x:0:0:", re.IGNORECASE),
     "/etc/passwd content (LFI)"),
    (re.compile(r"\[boot loader\]|\\Windows\\System32", re.IGNORECASE),
     "Windows system file content (LFI)"),
]

# Marker value used for reflection detection (unique enough to avoid false positives)
_REFLECTION_CANARY = "blzr3fl3ct"


@dataclass
class ParamResult:
    """Result of testing a single parameter/value combination."""
    url: str
    param: str
    value: str
    status_code: int
    reflected: bool
    interesting: bool
    detail: str
    content_length: int = 0
    response_time: float = 0.0


@dataclass
class DiscoveryStats:
    """Aggregate statistics for a content discovery run."""
    total_requests: int = 0
    params_tested: int = 0
    reflections_found: int = 0
    interesting_found: int = 0
    errors: int = 0
    start_time: float = 0.0
    elapsed: float = 0.0


class ContentDiscovery:
    """
    Parameter and content discovery engine.

    Fuzzes query parameters on discovered endpoints, detecting:
    - Parameter reflection (value appears in response body)
    - Interesting responses (debug output, stack traces, file paths, errors)
    - Hidden GET parameters on pages that return 200 OK

    Usage:
        discovery = ContentDiscovery(threads=20)
        results = await discovery.discover_params(session, "https://target.com/endpoint")
        for r in results:
            if r.interesting:
                print(f"  [{r.status_code}] ?{r.param}={r.value} -- {r.detail}")
    """

    def __init__(
        self,
        threads: int = 20,
        params: Optional[List[str]] = None,
        values: Optional[List[str]] = None,
        timeout: int = 10,
    ):
        """
        Args:
            threads: Maximum concurrent requests.
            params:  Custom parameter list (defaults to COMMON_PARAMS).
            values:  Custom test values (defaults to TEST_VALUES).
            timeout: Per-request timeout in seconds.
        """
        self.threads = threads
        self.params = params or COMMON_PARAMS
        self.values = values or TEST_VALUES
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(threads)
        self.stats = DiscoveryStats()

    async def discover_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        proxy: Optional[str] = None,
        baseline_body: Optional[str] = None,
    ) -> List[ParamResult]:
        """
        Fuzz all configured parameters on a single URL.

        First fetches a baseline response (no extra params), then tests
        every param/value combination in parallel, reporting reflections
        and interesting findings.

        Args:
            session:       Active aiohttp.ClientSession.
            url:           Target URL to fuzz parameters on.
            proxy:         Optional proxy URL.
            baseline_body: Pre-fetched baseline body (skips baseline request if provided).

        Returns:
            List of ParamResult for every finding (reflected or interesting).
        """
        self.stats = DiscoveryStats()
        self.stats.start_time = time.monotonic()

        # Fetch baseline if not provided
        if baseline_body is None:
            baseline_body = await self._fetch_baseline(session, url, proxy)

        baseline_length = len(baseline_body) if baseline_body else 0

        # Build task list: every (param, value) pair
        tasks = []
        for param in self.params:
            for value in self.values:
                tasks.append(
                    self._test_param(session, url, param, value, proxy, baseline_length)
                )

            # Also test with the reflection canary for clean reflection detection
            tasks.append(
                self._test_param(
                    session, url, param, _REFLECTION_CANARY, proxy, baseline_length
                )
            )

        # Execute all tasks with bounded concurrency
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter to only meaningful results (reflected or interesting)
        results: List[ParamResult] = []
        for r in raw_results:
            if isinstance(r, Exception):
                self.stats.errors += 1
                logger.debug("Parameter test error: %s", r)
                continue
            if r is not None:
                results.append(r)

        self.stats.elapsed = time.monotonic() - self.stats.start_time

        # Deduplicate: if the same param is interesting for multiple values,
        # keep the most informative one
        results = self._deduplicate_results(results)

        return results

    async def discover_hidden_params(
        self,
        session: aiohttp.ClientSession,
        url: str,
        proxy: Optional[str] = None,
    ) -> List[ParamResult]:
        """
        Detect hidden GET parameters on a 200 OK page.

        Tests each parameter with a benign value and checks whether the
        response differs meaningfully from the baseline (status change,
        significant size change, or interesting content appears).

        Args:
            session: Active aiohttp.ClientSession.
            url:     Target URL (should already return 200 OK).
            proxy:   Optional proxy URL.

        Returns:
            List of ParamResult for parameters that changed the response.
        """
        baseline_body = await self._fetch_baseline(session, url, proxy)
        if baseline_body is None:
            return []

        baseline_length = len(baseline_body)
        results: List[ParamResult] = []

        tasks = []
        for param in self.params:
            tasks.append(
                self._test_hidden_param(
                    session, url, param, proxy, baseline_length, baseline_body
                )
            )

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in raw_results:
            if isinstance(r, Exception):
                continue
            if r is not None:
                results.append(r)

        return results

    async def _fetch_baseline(
        self,
        session: aiohttp.ClientSession,
        url: str,
        proxy: Optional[str],
    ) -> Optional[str]:
        """Fetch the baseline response body for a URL with no extra params."""
        try:
            req_timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with session.get(
                url, proxy=proxy, timeout=req_timeout, allow_redirects=True
            ) as resp:
                return await resp.text(errors="replace")
        except Exception as exc:
            logger.debug("Baseline fetch failed for %s: %s", url, exc)
            return None

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param: str,
        value: str,
        proxy: Optional[str],
        baseline_length: int,
    ) -> Optional[ParamResult]:
        """
        Test a single parameter/value combination against the target URL.

        Returns a ParamResult if the response is reflected or interesting,
        otherwise returns None to reduce noise.
        """
        async with self._semaphore:
            self.stats.total_requests += 1
            self.stats.params_tested += 1

            # Build the test URL
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param}={value}"

            try:
                req_timeout = aiohttp.ClientTimeout(total=self.timeout)
                start = time.monotonic()

                async with session.get(
                    test_url,
                    proxy=proxy,
                    timeout=req_timeout,
                    allow_redirects=True,
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text(errors="replace")
                    status = resp.status
                    content_length = len(body)

            except asyncio.TimeoutError:
                self.stats.errors += 1
                return None
            except aiohttp.ClientError:
                self.stats.errors += 1
                return None
            except Exception:
                self.stats.errors += 1
                return None

            reflected = self._is_reflected(body, value)
            interesting, detail = self._is_interesting(body)

            # Also flag significant size changes as interesting
            if not interesting and baseline_length > 0:
                size_diff = abs(content_length - baseline_length)
                # More than 20% change in response size is notable
                if size_diff > baseline_length * 0.2 and size_diff > 100:
                    interesting = True
                    detail = (
                        f"Response size changed significantly "
                        f"({baseline_length} -> {content_length} bytes)"
                    )

            # Only return if there is something to report
            if not reflected and not interesting:
                return None

            if reflected:
                self.stats.reflections_found += 1
            if interesting:
                self.stats.interesting_found += 1

            return ParamResult(
                url=test_url,
                param=param,
                value=value,
                status_code=status,
                reflected=reflected,
                interesting=interesting,
                detail=detail,
                content_length=content_length,
                response_time=elapsed,
            )

    async def _test_hidden_param(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param: str,
        proxy: Optional[str],
        baseline_length: int,
        baseline_body: str,
    ) -> Optional[ParamResult]:
        """
        Test if a parameter changes the response when added to a 200 OK page.
        Uses benign values to detect hidden functionality.
        """
        async with self._semaphore:
            self.stats.total_requests += 1

            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param}=1"

            try:
                req_timeout = aiohttp.ClientTimeout(total=self.timeout)
                start = time.monotonic()

                async with session.get(
                    test_url,
                    proxy=proxy,
                    timeout=req_timeout,
                    allow_redirects=True,
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text(errors="replace")
                    status = resp.status
                    content_length = len(body)

            except Exception:
                self.stats.errors += 1
                return None

            # Detect meaningful differences from baseline
            detail_parts: List[str] = []

            # Status code changed
            if status != 200:
                detail_parts.append(f"Status changed to {status}")

            # Significant size difference
            size_diff = abs(content_length - baseline_length)
            if baseline_length > 0 and size_diff > baseline_length * 0.1 and size_diff > 50:
                detail_parts.append(
                    f"Size delta: {content_length - baseline_length:+d} bytes"
                )

            # Check for interesting content in the changed response
            is_int, int_detail = self._is_interesting(body)
            if is_int:
                detail_parts.append(int_detail)

            if not detail_parts:
                return None

            return ParamResult(
                url=test_url,
                param=param,
                value="1",
                status_code=status,
                reflected=False,
                interesting=True,
                detail="; ".join(detail_parts),
                content_length=content_length,
                response_time=elapsed,
            )

    def _is_interesting(self, body: str) -> Tuple[bool, str]:
        """
        Check if a response body contains interesting / security-relevant content.

        Returns:
            (True, description) if interesting content is found.
            (False, "") otherwise.
        """
        if not body:
            return False, ""

        findings: List[str] = []

        for pattern, description in _INTERESTING_PATTERNS:
            if pattern.search(body):
                findings.append(description)
                # Stop after first 3 findings to avoid noise
                if len(findings) >= 3:
                    break

        if findings:
            return True, "; ".join(findings)

        return False, ""

    def _is_reflected(self, body: str, value: str) -> bool:
        """
        Check if a test value is reflected in the response body.

        Uses case-sensitive matching for exact values and is conservative
        to avoid false positives on very short or common values.
        """
        if not body or not value:
            return False

        # Skip reflection check for very short generic values that would
        # produce false positives (e.g., "1" appears in most HTML pages)
        if len(value) < 4 and value in ("1", "0", "a", "true", "false"):
            return False

        return value in body

    def _deduplicate_results(self, results: List[ParamResult]) -> List[ParamResult]:
        """
        Deduplicate results, keeping the most informative finding per parameter.

        Priority: interesting + reflected > interesting > reflected
        """
        best: Dict[str, ParamResult] = {}

        for r in results:
            key = r.param
            if key not in best:
                best[key] = r
                continue

            existing = best[key]
            new_score = (2 if r.interesting else 0) + (1 if r.reflected else 0)
            old_score = (2 if existing.interesting else 0) + (1 if existing.reflected else 0)

            if new_score > old_score:
                best[key] = r
            elif new_score == old_score and len(r.detail) > len(existing.detail):
                best[key] = r

        # Sort by: interesting first, then reflected, then alphabetically
        return sorted(
            best.values(),
            key=lambda r: (
                -(2 if r.interesting else 0) - (1 if r.reflected else 0),
                r.param,
            ),
        )

    def get_stats_summary(self) -> str:
        """Return a human-readable summary of discovery statistics."""
        return (
            f"Requests: {self.stats.total_requests} | "
            f"Params tested: {self.stats.params_tested} | "
            f"Reflections: {self.stats.reflections_found} | "
            f"Interesting: {self.stats.interesting_found} | "
            f"Errors: {self.stats.errors} | "
            f"Time: {self.stats.elapsed:.1f}s"
        )
