"""
Blaze Headless Browser - Playwright-based headless browser for bypassing
JavaScript challenges (Cloudflare Under Attack mode, Akamai Bot Manager, etc.).

This module is an optional dependency. If playwright is not installed, all
public methods degrade gracefully: is_available() returns False, and
solve_challenge() / get_cookies() return None with a warning.
"""

import asyncio
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("blaze.headless")

# ────────────────────── Lazy Import Guard ──────────────────────

_PLAYWRIGHT_AVAILABLE: Optional[bool] = None


def _check_playwright() -> bool:
    """Check whether playwright is importable (cached after first call)."""
    global _PLAYWRIGHT_AVAILABLE
    if _PLAYWRIGHT_AVAILABLE is None:
        try:
            import playwright.async_api  # noqa: F401
            _PLAYWRIGHT_AVAILABLE = True
        except ImportError:
            _PLAYWRIGHT_AVAILABLE = False
    return _PLAYWRIGHT_AVAILABLE


# Default user-agent matching a recent Chrome release
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# JavaScript challenge indicators in page content
_CHALLENGE_INDICATORS = [
    "Checking your browser",
    "DDoS protection by",
    "Enable JavaScript and cookies",
    "challenge-platform",
    "Just a moment",
    "Verifying you are human",
    "cf-browser-verification",
    "cf_chl_opt",
    "ray ID",
    "Attention Required!",
    "_cf_chl_tk",
    "managed_checking_msg",
]

# Maximum number of polling iterations to wait for challenge resolution
_MAX_POLL_ITERATIONS = 120


class HeadlessBrowser:
    """
    Playwright-based headless browser for solving JavaScript challenges.

    The browser operates in stealth mode, spoofing common browser fingerprints
    to avoid bot-detection heuristics. After navigating to a URL and waiting
    for any challenge to resolve, it extracts cookies and headers that can be
    injected into subsequent aiohttp requests.

    Usage:
        if HeadlessBrowser.is_available():
            browser = HeadlessBrowser(timeout=45)
            result = await browser.solve_challenge("https://target.com")
            if result:
                cookies = result["cookies"]
                headers = result["headers"]
                user_agent = result["user_agent"]
            await browser.close()
    """

    def __init__(self, timeout: int = 30):
        """
        Args:
            timeout: Maximum seconds to wait for a challenge to resolve.
        """
        self.timeout = timeout
        self._playwright = None
        self._browser = None
        self._context = None

    @staticmethod
    def is_available() -> bool:
        """Return True if playwright is installed and importable."""
        return _check_playwright()

    async def _ensure_browser(self, user_agent: Optional[str] = None):
        """
        Lazily initialize playwright, the browser instance, and a stealth
        browser context. Reuses existing instances across calls.
        """
        if self._browser is not None:
            return

        if not _check_playwright():
            raise RuntimeError(
                "playwright is not installed. "
                "Install it with: pip install playwright && python -m playwright install chromium"
            )

        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()

        # Launch Chromium in headless mode with stealth-friendly flags
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--disable-infobars",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-sandbox",
            ],
        )

        ua = user_agent or _DEFAULT_USER_AGENT
        self._context = await self._browser.new_context(
            user_agent=ua,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            java_script_enabled=True,
            ignore_https_errors=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
                ),
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            },
        )

        # Apply stealth patches to every new page in this context
        await self._context.add_init_script(_STEALTH_SCRIPT)

    async def solve_challenge(
        self,
        url: str,
        user_agent: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Navigate to a URL, wait for any JavaScript challenge to resolve,
        and return extracted session data.

        Args:
            url:        Target URL that may present a JS challenge.
            user_agent: Override the default User-Agent string.

        Returns:
            A dict with keys:
                - cookies:    dict of cookie name -> value
                - headers:    dict of recommended headers for follow-up requests
                - user_agent: the User-Agent string used
                - final_url:  the URL after all redirects
                - title:      page title after challenge resolution
            Returns None if playwright is unavailable or the challenge
            could not be solved within the timeout.
        """
        if not _check_playwright():
            logger.warning(
                "Playwright is not installed. Cannot solve JS challenges. "
                "Install with: pip install playwright && python -m playwright install chromium"
            )
            return None

        try:
            await self._ensure_browser(user_agent)
            page = await self._context.new_page()

            try:
                result = await self._navigate_and_solve(page, url, user_agent)
                return result
            finally:
                await page.close()

        except Exception as exc:
            logger.error("Headless challenge solving failed: %s", exc)
            return None

    async def _navigate_and_solve(
        self,
        page,
        url: str,
        user_agent: Optional[str],
    ) -> Optional[Dict]:
        """Internal: perform navigation, wait for challenge, extract data."""
        logger.info("Navigating headless browser to: %s", url)

        # Navigate with a generous timeout for slow challenges
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=self.timeout * 1000,
            )
        except Exception as exc:
            logger.warning("Navigation failed: %s", exc)
            return None

        if response is None:
            logger.warning("No response received for: %s", url)
            return None

        # Check if the page presents a challenge
        content = await page.content()
        is_challenge = self._detect_challenge(content)

        if is_challenge:
            logger.info("Challenge detected, waiting for resolution...")
            solved = await self._wait_for_resolution(page)
            if not solved:
                logger.warning(
                    "Challenge was not solved within %ds timeout", self.timeout
                )
                return None
            logger.info("Challenge resolved successfully")

        # Extract cookies
        cookies_list = await self._context.cookies(url)
        cookies = {c["name"]: c["value"] for c in cookies_list}

        # Build recommended headers for follow-up requests
        ua = user_agent or _DEFAULT_USER_AGENT
        headers = {
            "User-Agent": ua,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

        final_url = page.url
        title = await page.title()

        return {
            "cookies": cookies,
            "headers": headers,
            "user_agent": ua,
            "final_url": final_url,
            "title": title,
        }

    def _detect_challenge(self, html_content: str) -> bool:
        """Return True if the page content looks like a JS challenge page."""
        if not html_content:
            return False
        for indicator in _CHALLENGE_INDICATORS:
            if indicator.lower() in html_content.lower():
                return True
        return False

    async def _wait_for_resolution(self, page) -> bool:
        """
        Poll the page until the challenge disappears or timeout is reached.

        Checks every 500ms whether challenge indicators are still present.
        Also monitors for navigation events (challenge pages often redirect
        after solving).
        """
        poll_interval_ms = 500
        max_iterations = min(
            _MAX_POLL_ITERATIONS,
            int((self.timeout * 1000) / poll_interval_ms),
        )

        for _ in range(max_iterations):
            await asyncio.sleep(poll_interval_ms / 1000.0)

            try:
                content = await page.content()
            except Exception:
                # Page might be navigating; give it a moment
                continue

            if not self._detect_challenge(content):
                # Wait a bit more to let cookies settle
                await asyncio.sleep(1.0)
                return True

        return False

    async def get_cookies(self, url: str) -> Optional[Dict[str, str]]:
        """
        Convenience method: navigate to URL, solve any challenge, return
        just the cookies dict.

        Returns None if playwright is unavailable or challenge solving fails.
        """
        result = await self.solve_challenge(url)
        if result is None:
            return None
        return result.get("cookies", {})

    async def close(self):
        """Shut down the browser and playwright instance."""
        try:
            if self._context is not None:
                await self._context.close()
                self._context = None
        except Exception as exc:
            logger.debug("Error closing browser context: %s", exc)

        try:
            if self._browser is not None:
                await self._browser.close()
                self._browser = None
        except Exception as exc:
            logger.debug("Error closing browser: %s", exc)

        try:
            if self._playwright is not None:
                await self._playwright.stop()
                self._playwright = None
        except Exception as exc:
            logger.debug("Error stopping playwright: %s", exc)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False


# ──────────────────────── Stealth Script ────────────────────────
# Injected into every page to mask automation fingerprints.

_STEALTH_SCRIPT = """
() => {
    // Remove webdriver property
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
    });

    // Override navigator.plugins to look like a real browser
    Object.defineProperty(navigator, 'plugins', {
        get: () => [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', filename: 'internal-nacl-plugin' },
        ],
    });

    // Override navigator.languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
    });

    // Override navigator.platform
    Object.defineProperty(navigator, 'platform', {
        get: () => 'Win32',
    });

    // Override navigator.hardwareConcurrency
    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: () => 8,
    });

    // Override navigator.deviceMemory
    Object.defineProperty(navigator, 'deviceMemory', {
        get: () => 8,
    });

    // Hide chrome automation flags
    window.chrome = {
        runtime: {},
        loadTimes: function() {},
        csi: function() {},
        app: {},
    };

    // Override permissions query to avoid detection
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );

    // Spoof WebGL vendor and renderer
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) {
            return 'Intel Inc.';
        }
        if (parameter === 37446) {
            return 'Intel Iris OpenGL Engine';
        }
        return getParameter.call(this, parameter);
    };

    // Override connection rtt to avoid fingerprinting
    if (navigator.connection) {
        Object.defineProperty(navigator.connection, 'rtt', {
            get: () => 50,
        });
    }
}
"""
