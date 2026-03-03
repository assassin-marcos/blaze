"""
# Blaze - VHost Scanner

Virtual host discovery by fuzzing the HTTP ``Host`` header against a target IP
address. For each candidate hostname the scanner issues a request with the
corresponding ``Host`` header and compares the response body against a
pre-established baseline (the response for the server's default/fallback
virtual host). Responses that differ meaningfully from the baseline indicate a
distinct virtual host configuration.

Detection uses ``difflib.SequenceMatcher`` with dynamic-content stripping
(delegated to ``ResponseDiffer._strip_dynamic``) so that trivially varying
default pages do not produce false positives.

Concurrency is controlled via an ``asyncio.Semaphore`` so that the scanner
respects a configurable thread (coroutine) limit.
"""

import asyncio
import ssl
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import List, Optional

from .response_differ import ResponseDiffer


# ---------------------------------------------------------------------------
# Result data-class
# ---------------------------------------------------------------------------

@dataclass
class VHostResult:
    """Represents one virtual-host probe result."""

    hostname: str
    status_code: int
    content_length: int
    is_unique: bool


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class VHostScanner:
    """Discover virtual hosts by sending requests with fuzzed ``Host`` headers.

    Parameters
    ----------
    target_ip : str
        The IP address (or hostname) to connect to.
    port : int
        Destination port.  Default ``443``.
    threads : int
        Maximum concurrent probes.  Default ``50``.
    use_ssl : bool
        Whether to use HTTPS.  Default ``True``.
    threshold : float
        ``SequenceMatcher`` ratio below which a response is considered
        *unique* (i.e. different from the baseline).  Default ``0.85``.

    Example
    -------
    ::

        scanner = VHostScanner("93.184.216.34", port=443, threads=30)
        async with aiohttp.ClientSession(...) as session:
            baseline = await scanner.get_baseline(session)
            results = await scanner.scan(session, hostnames, baseline)
            for r in results:
                if r.is_unique:
                    print(f"Found vhost: {r.hostname}")
    """

    def __init__(
        self,
        target_ip: str,
        port: int = 443,
        threads: int = 50,
        use_ssl: bool = True,
        threshold: float = 0.85,
    ):
        self.target_ip = target_ip
        self.port = port
        self.threads = threads
        self.use_ssl = use_ssl
        self.threshold = threshold

        self._semaphore = asyncio.Semaphore(threads)
        self._differ = ResponseDiffer(threshold=threshold)

        # Build the base URL once.
        scheme = "https" if self.use_ssl else "http"
        default_port = 443 if self.use_ssl else 80
        if self.port == default_port:
            self._base_url = f"{scheme}://{self.target_ip}/"
        else:
            self._base_url = f"{scheme}://{self.target_ip}:{self.port}/"

    # ------------------------------------------------------------------
    # SSL helper
    # ------------------------------------------------------------------

    @staticmethod
    def _permissive_ssl_context() -> ssl.SSLContext:
        """Return an SSL context that ignores certificate errors.

        Virtual-host scanning almost always hits IPs directly, so the
        certificate will never match the hostname we are fuzzing.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ------------------------------------------------------------------
    # Baseline acquisition
    # ------------------------------------------------------------------

    async def get_baseline(
        self,
        session,
        proxy: Optional[str] = None,
    ) -> str:
        """Fetch the default virtual-host response body.

        Sends a request whose ``Host`` header is simply the target IP itself.
        The response body (stripped of dynamic content) serves as the baseline
        for comparison.

        Returns
        -------
        str
            Raw response body text of the default vhost.
        """
        headers = {"Host": self.target_ip}
        ssl_ctx = self._permissive_ssl_context() if self.use_ssl else None

        async with session.get(
            self._base_url,
            headers=headers,
            ssl=ssl_ctx,
            proxy=proxy,
            allow_redirects=True,
        ) as resp:
            return await resp.text(errors="replace")

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    async def scan(
        self,
        session,
        hostnames: List[str],
        baseline_body: str,
        proxy: Optional[str] = None,
    ) -> List[VHostResult]:
        """Probe every hostname and return results.

        Parameters
        ----------
        session : aiohttp.ClientSession
            An open HTTP session.  The caller is responsible for supplying an
            appropriate connector (e.g. with ``ssl=False`` or a permissive SSL
            context if needed).
        hostnames : list[str]
            Candidate hostnames / subdomains to test.
        baseline_body : str
            The default vhost response body (as returned by
            :meth:`get_baseline`).
        proxy : str, optional
            HTTP proxy URL.

        Returns
        -------
        list[VHostResult]
            One entry per hostname.  Check ``is_unique`` to find real vhosts.
        """
        stripped_baseline = ResponseDiffer._strip_dynamic(baseline_body)

        tasks = [
            self._check_vhost(session, hostname.strip(), stripped_baseline, proxy)
            for hostname in hostnames
            if hostname.strip()
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[VHostResult] = []
        for r in raw_results:
            if isinstance(r, VHostResult):
                results.append(r)
            # Exceptions are silently dropped; the caller can check the count
            # against len(hostnames) to infer failures.

        return results

    async def _check_vhost(
        self,
        session,
        hostname: str,
        stripped_baseline: str,
        proxy: Optional[str] = None,
    ) -> Optional[VHostResult]:
        """Probe a single hostname behind the semaphore.

        Parameters
        ----------
        session : aiohttp.ClientSession
        hostname : str
            The ``Host`` header value to send.
        stripped_baseline : str
            Pre-stripped baseline body for comparison.
        proxy : str, optional

        Returns
        -------
        VHostResult or None
        """
        async with self._semaphore:
            try:
                headers = {"Host": hostname}
                ssl_ctx = (
                    self._permissive_ssl_context() if self.use_ssl else None
                )

                async with session.get(
                    self._base_url,
                    headers=headers,
                    ssl=ssl_ctx,
                    proxy=proxy,
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="replace")
                    content_length = len(body.encode("utf-8", errors="replace"))
                    status_code = resp.status

                    # Compare against baseline.
                    stripped_body = ResponseDiffer._strip_dynamic(body)
                    ratio = SequenceMatcher(
                        None, stripped_body, stripped_baseline
                    ).ratio()
                    is_unique = ratio < self.threshold

                    return VHostResult(
                        hostname=hostname,
                        status_code=status_code,
                        content_length=content_length,
                        is_unique=is_unique,
                    )
            except Exception:
                # Connection failures, timeouts, etc. - return a non-unique
                # result so the caller knows the hostname was attempted.
                return VHostResult(
                    hostname=hostname,
                    status_code=0,
                    content_length=0,
                    is_unique=False,
                )
