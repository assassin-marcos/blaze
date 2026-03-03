"""
Blaze JS Extractor - Extract endpoints, paths, and API routes from JavaScript files.
Parses JS content for URL patterns, API endpoints, relative paths, and route
definitions using regex-based analysis. Deduplicates, normalizes, and scores
extracted paths by likelihood of being real endpoints.
"""

import re
import logging
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, unquote

import aiohttp

logger = logging.getLogger("blaze.js_extractor")


# ────────────────────── Exclusion Lists ──────────────────────

# File extensions that are almost never useful directory endpoints
STATIC_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp", ".avif",
    ".css", ".less", ".sass", ".scss",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".map", ".ts.map", ".js.map", ".css.map",
})

# URI schemes that are not HTTP paths
EXCLUDED_SCHEMES = frozenset({
    "data:", "mailto:", "tel:", "javascript:", "blob:", "ws:", "wss:",
    "ftp:", "ftps:", "chrome:", "chrome-extension:", "moz-extension:",
    "about:", "file:", "magnet:",
})

# Common CDN / external hostnames to skip
CDN_HOSTS = frozenset({
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "code.jquery.com", "cdn.bootcss.com", "cdn.bootcdn.net",
    "use.fontawesome.com", "kit.fontawesome.com",
    "www.google-analytics.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.segment.com", "js.stripe.com",
})

# Strings that look like paths but are JS framework internals or noise
NOISE_PATTERNS = frozenset({
    "use strict", "undefined", "null", "true", "false",
    "object", "function", "prototype", "constructor",
    "hasOwnProperty", "toString", "valueOf",
    "application/json", "application/x-www-form-urlencoded",
    "text/html", "text/plain", "multipart/form-data",
    "content-type", "authorization", "accept",
})

# Minimum and maximum path lengths to consider
MIN_PATH_LENGTH = 2
MAX_PATH_LENGTH = 256


# ──────────────────── Extraction Regex Patterns ────────────────────

# String literals containing path-like values (single and double quotes, backticks)
_QUOTED_PATH = re.compile(
    r"""(?:["'`])"""
    r"""(\/(?:[a-zA-Z0-9_\-\.~:@!$&'()*+,;=%]|\/)+)"""
    r"""(?:["'`])""",
    re.MULTILINE,
)

# fetch(), axios, $.ajax, XMLHttpRequest open() patterns
_FETCH_CALL = re.compile(
    r"""fetch\s*\(\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.MULTILINE,
)

_AXIOS_CALL = re.compile(
    r"""axios\s*\.\s*(?:get|post|put|patch|delete|head|options|request)\s*\(\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

_JQUERY_AJAX = re.compile(
    r"""\$\s*\.\s*(?:ajax|get|post|getJSON|put|delete)\s*\(\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.MULTILINE,
)

_XHR_OPEN = re.compile(
    r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]\s*,\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# Route / path definition patterns (common in SPA routers, Express, etc.)
_ROUTE_DEFINITION = re.compile(
    r"""(?:path|route|url|endpoint|uri|href|action|src)\s*[:=]\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# window.location / document.location assignments
_LOCATION_ASSIGN = re.compile(
    r"""(?:window|document)\s*\.\s*location\s*(?:\.\s*(?:href|pathname|assign|replace)\s*(?:=|\())\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# API base URL concatenations: baseURL + "/endpoint" or apiUrl + "/path"
_API_CONCAT = re.compile(
    r"""(?:base[_]?url|api[_]?url|api[_]?base|api[_]?endpoint|api[_]?prefix|base[_]?path|api[_]?host)\s*\+?\s*["'`](\/[^"'`\s]{2,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# API path pattern: "/api/v1/...", "/v1/...", "/rest/..."
_API_PATH = re.compile(
    r"""["'`](\/(?:api|rest|graphql|v\d+|internal|private|public|service|services|gateway)\/[^"'`\s]{1,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# Absolute URL strings (http/https)
_ABSOLUTE_URL = re.compile(
    r"""["'`](https?:\/\/[^"'`\s]{5,})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# Template literal expressions with paths: `${baseUrl}/api/users`
_TEMPLATE_LITERAL = re.compile(
    r"""`[^`]*\$\{[^}]+\}(\/[a-zA-Z0-9_\-/]+)[^`]*`""",
    re.MULTILINE,
)

# Comment annotations: @url, @path, @endpoint, @api
_COMMENT_ANNOTATION = re.compile(
    r"""(?:@url|@path|@endpoint|@api|@route)\s+["']?(\/[^\s"']+)""",
    re.IGNORECASE | re.MULTILINE,
)

# All compiled patterns paired with priority weights (higher = more likely real endpoint)
_PATTERNS: List[Tuple[re.Pattern, float]] = [
    (_FETCH_CALL, 1.0),
    (_AXIOS_CALL, 1.0),
    (_JQUERY_AJAX, 1.0),
    (_XHR_OPEN, 1.0),
    (_API_PATH, 0.95),
    (_ROUTE_DEFINITION, 0.9),
    (_LOCATION_ASSIGN, 0.85),
    (_API_CONCAT, 0.85),
    (_COMMENT_ANNOTATION, 0.8),
    (_TEMPLATE_LITERAL, 0.7),
    (_ABSOLUTE_URL, 0.6),
    (_QUOTED_PATH, 0.5),
]


class JSExtractor:
    """
    Extract endpoints, paths, and API routes from JavaScript content.

    Usage:
        extractor = JSExtractor()
        paths = extractor.extract_paths(js_source_code)
        # or async from a URL:
        paths = await extractor.extract_from_url(session, "https://example.com/app.js")
    """

    def __init__(self):
        self._seen: Set[str] = set()
        self._scores: dict = {}

    def extract_paths(self, js_content: str) -> List[str]:
        """
        Extract and deduplicate paths from JavaScript source code.

        Applies all regex patterns, normalizes results, filters out noise,
        and returns paths sorted by descending confidence score.

        Args:
            js_content: Raw JavaScript source code.

        Returns:
            Deduplicated list of paths sorted by likelihood of being real endpoints.
        """
        if not js_content or not isinstance(js_content, str):
            return []

        path_scores: dict = {}

        # Run every extraction pattern
        for pattern, weight in _PATTERNS:
            for match in pattern.finditer(js_content):
                raw = match.group(1)
                paths = self._expand_raw(raw)
                for path in paths:
                    normalized = self._normalize_path(path)
                    if normalized and self._is_valid_path(normalized):
                        current = path_scores.get(normalized, 0.0)
                        path_scores[normalized] = max(current, weight)

        # Apply heuristic score boosting
        scored = self._apply_heuristics(path_scores)

        # Sort by score descending, then alphabetically for stability
        sorted_paths = sorted(
            scored.keys(),
            key=lambda p: (-scored[p], p),
        )

        # Track globally seen paths
        self._seen.update(sorted_paths)
        self._scores.update(scored)

        return sorted_paths

    async def extract_from_url(
        self,
        session: aiohttp.ClientSession,
        js_url: str,
        timeout: int = 15,
    ) -> List[str]:
        """
        Fetch a JavaScript file and extract paths from its content.

        Args:
            session: An active aiohttp.ClientSession.
            js_url:  Full URL to the JavaScript file.
            timeout: Request timeout in seconds.

        Returns:
            Extracted paths, or an empty list on failure.
        """
        try:
            req_timeout = aiohttp.ClientTimeout(total=timeout)
            async with session.get(
                js_url,
                timeout=req_timeout,
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    logger.debug(
                        "Non-200 response (%d) fetching JS: %s",
                        resp.status,
                        js_url,
                    )
                    return []

                content_type = resp.headers.get("Content-Type", "")
                # Tolerate common MIME types for JS files
                if not any(
                    ct in content_type.lower()
                    for ct in (
                        "javascript", "ecmascript", "text/plain",
                        "application/json", "text/html", "octet-stream",
                    )
                ):
                    logger.debug(
                        "Unexpected Content-Type '%s' for JS URL: %s",
                        content_type,
                        js_url,
                    )
                    return []

                body = await resp.text(errors="replace")
                # Sanity check: skip tiny or enormous responses
                if len(body) < 20 or len(body) > 10_000_000:
                    return []

                return self.extract_paths(body)

        except asyncio.TimeoutError:
            logger.debug("Timeout fetching JS: %s", js_url)
            return []
        except aiohttp.ClientError as exc:
            logger.debug("Client error fetching JS %s: %s", js_url, exc)
            return []
        except Exception as exc:
            logger.debug("Unexpected error fetching JS %s: %s", js_url, exc)
            return []

    def _expand_raw(self, raw: str) -> List[str]:
        """
        Expand a raw extracted string into one or more candidate paths.

        Handles absolute URLs by extracting the path component, and
        splits concatenated paths if present.
        """
        results = []

        raw = raw.strip()
        if not raw:
            return results

        # Handle absolute URLs: extract just the path
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            # Skip external CDN / analytics hosts
            if parsed.hostname and parsed.hostname.lower() in CDN_HOSTS:
                return results
            if parsed.path and parsed.path != "/":
                results.append(parsed.path)
            return results

        results.append(raw)
        return results

    def _normalize_path(self, path: str) -> Optional[str]:
        """
        Normalize a path string for consistent deduplication.

        - URL-decode
        - Strip trailing slashes (except root)
        - Collapse double slashes
        - Remove query strings and fragments
        - Ensure leading slash

        Returns None if the path is invalid after normalization.
        """
        if not path:
            return None

        try:
            path = unquote(path)
        except Exception:
            return None

        # Remove query string and fragment
        path = path.split("?")[0].split("#")[0]

        # Strip whitespace
        path = path.strip()

        # Ensure leading slash
        if not path.startswith("/"):
            path = "/" + path

        # Collapse consecutive slashes
        while "//" in path:
            path = path.replace("//", "/")

        # Strip trailing slash (keep root "/" intact)
        if len(path) > 1:
            path = path.rstrip("/")

        # Length check
        if len(path) < MIN_PATH_LENGTH or len(path) > MAX_PATH_LENGTH:
            return None

        # Must be at least "/" + one char
        if path == "/":
            return None

        return path

    def _is_valid_path(self, path: str) -> bool:
        """
        Determine whether a normalized path is likely a real web endpoint
        rather than noise, a static asset, or an excluded scheme.

        Returns True if the path should be kept.
        """
        lower = path.lower()

        # Reject excluded URI schemes
        for scheme in EXCLUDED_SCHEMES:
            if lower.startswith(scheme):
                return False

        # Reject pure static asset extensions
        for ext in STATIC_EXTENSIONS:
            if lower.endswith(ext):
                return False

        # Reject .js and .min.js files (we want endpoints, not source files)
        if lower.endswith(".js") or lower.endswith(".mjs") or lower.endswith(".cjs"):
            return False

        # Reject paths that are clearly framework noise
        stripped = path.lstrip("/").lower()
        if stripped in NOISE_PATTERNS:
            return False

        # Reject paths that are just a single dot-file extension
        if re.match(r"^/\.[a-z]+$", lower) and lower not in ("/. env", "/.git", "/.svn"):
            return False

        # Reject overly long path segments (likely base64, hashes, etc.)
        segments = path.split("/")
        for segment in segments:
            if len(segment) > 80:
                return False

        # Reject paths that look like version hashes or chunk identifiers
        # e.g., /static/js/2.abc123de.chunk
        if re.search(r"/[a-f0-9]{20,}", lower):
            return False

        # Reject if more than 50% of the path is digits/hex (likely hash or ID)
        alpha_chars = sum(1 for c in stripped if c.isalpha())
        total_chars = len(stripped.replace("/", ""))
        if total_chars > 5 and alpha_chars / max(total_chars, 1) < 0.3:
            return False

        return True

    def _apply_heuristics(self, path_scores: dict) -> dict:
        """
        Apply heuristic score adjustments based on path characteristics.

        Boosts API-like paths, admin paths, and paths with recognizable
        endpoint structure. Penalizes generic or noisy-looking paths.
        """
        scored = {}
        for path, base_score in path_scores.items():
            score = base_score
            lower = path.lower()

            # Boost: API / REST-style paths
            if re.match(r"^/(?:api|rest|v\d+)/", lower):
                score = min(score + 0.15, 1.0)

            # Boost: Admin / auth endpoints
            if any(
                kw in lower
                for kw in (
                    "/admin", "/login", "/auth", "/dashboard",
                    "/signup", "/register", "/logout", "/settings",
                    "/profile", "/account", "/user", "/config",
                )
            ):
                score = min(score + 0.1, 1.0)

            # Boost: CRUD-looking endpoints
            if any(
                kw in lower
                for kw in (
                    "/create", "/update", "/delete", "/edit",
                    "/list", "/detail", "/search", "/upload",
                    "/download", "/export", "/import",
                )
            ):
                score = min(score + 0.05, 1.0)

            # Boost: Paths with common file extensions for dynamic content
            if any(
                lower.endswith(ext)
                for ext in (".php", ".asp", ".aspx", ".jsp", ".do", ".action", ".json", ".xml")
            ):
                score = min(score + 0.1, 1.0)

            # Penalize: Very short single-segment paths (e.g., "/a", "/x")
            segments = [s for s in path.split("/") if s]
            if len(segments) == 1 and len(segments[0]) <= 2:
                score = max(score - 0.3, 0.05)

            # Penalize: Paths with too many segments (likely deep nested resource)
            if len(segments) > 7:
                score = max(score - 0.2, 0.05)

            scored[path] = score

        return scored

    @property
    def all_extracted(self) -> List[str]:
        """Return all paths extracted across all calls, sorted by score."""
        return sorted(
            self._seen,
            key=lambda p: (-self._scores.get(p, 0.0), p),
        )

    def reset(self):
        """Clear all accumulated extraction state."""
        self._seen.clear()
        self._scores.clear()


# Required for async usage in extract_from_url
import asyncio
