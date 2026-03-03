"""
Blaze Header Analyzer - Detects leaked information in HTTP response headers
and provides subdomain-aware intelligence for wordlist selection.
"""

import re
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

@dataclass
class HeaderLeak:
    header: str
    value: str
    severity: str  # "high", "medium", "low"
    description: str

# Headers that leak sensitive info
INTERESTING_HEADERS = {
    # High severity - reveals internal infrastructure
    "X-Backend-Server": ("high", "Internal backend server revealed"),
    "X-Server-Name": ("high", "Internal server name revealed"),
    "X-Debug": ("high", "Debug mode enabled"),
    "X-Debug-Token": ("high", "Debug token leaked"),
    "X-Debug-Token-Link": ("high", "Debug profiler link leaked"),
    "X-Powered-By": ("medium", "Technology stack revealed"),
    "X-AspNet-Version": ("high", "ASP.NET version revealed"),
    "X-AspNetMvc-Version": ("high", "ASP.NET MVC version revealed"),
    "X-Runtime": ("medium", "Runtime information leaked"),
    "X-Version": ("medium", "Application version revealed"),
    "X-App-Version": ("medium", "Application version revealed"),
    "X-API-Version": ("medium", "API version revealed"),
    "Server": ("low", "Server software revealed"),

    # Internal IP leakage
    "X-Forwarded-For": ("high", "Internal IP addresses leaked"),
    "X-Real-IP": ("high", "Real IP address leaked"),
    "X-Original-URL": ("medium", "Original URL revealed"),
    "X-Rewrite-URL": ("medium", "Rewrite URL revealed"),
    "X-Forwarded-Host": ("medium", "Forwarded host revealed"),
    "X-Host": ("medium", "Internal host revealed"),
    "X-Original-Host": ("medium", "Original host revealed"),

    # Framework/CMS specific
    "X-Generator": ("medium", "CMS/Framework generator revealed"),
    "X-Drupal-Cache": ("low", "Drupal detected via cache header"),
    "X-Drupal-Dynamic-Cache": ("low", "Drupal dynamic cache detected"),
    "X-Varnish": ("low", "Varnish cache proxy detected"),
    "X-Cache": ("low", "Cache layer revealed"),
    "X-Cache-Hits": ("low", "Cache statistics revealed"),
    "X-Litespeed-Cache": ("low", "LiteSpeed cache detected"),
    "X-Turbo-Charged-By": ("low", "LiteSpeed detected"),

    # Security misconfig
    "X-Frame-Options": ("low", "Frame policy set (info only)"),
    "Access-Control-Allow-Origin": ("medium", "CORS policy revealed"),
    "X-Amz-Cf-Id": ("medium", "AWS CloudFront ID revealed"),
    "X-Amz-Request-Id": ("medium", "AWS request ID revealed"),
    "X-Azure-Ref": ("medium", "Azure reference revealed"),

    # Debug/Dev headers
    "X-Request-Id": ("low", "Request tracking ID"),
    "X-Trace-Id": ("low", "Trace ID revealed"),
    "X-Correlation-Id": ("low", "Correlation ID revealed"),
    "X-B3-TraceId": ("low", "Zipkin trace ID revealed"),
    "X-Envoy-Upstream-Service-Time": ("medium", "Envoy proxy timing revealed"),
}

# Patterns to detect internal IPs in header values
INTERNAL_IP_PATTERN = re.compile(
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'169\.254\.\d{1,3}\.\d{1,3})'
)

# Subdomain patterns → suggested wordlists
SUBDOMAIN_WORDLIST_MAP = [
    (r"(?i)^api[.-]", ["api.txt", "swagger.txt"]),
    (r"(?i)^rest[.-]", ["api.txt", "swagger.txt"]),
    (r"(?i)^graphql[.-]", ["graphql.txt", "api.txt"]),
    (r"(?i)^admin[.-]", ["common.txt", "backup.txt"]),
    (r"(?i)^portal[.-]", ["common.txt"]),
    (r"(?i)^dev[.-]|^staging[.-]|^test[.-]|^qa[.-]", ["common.txt", "backup.txt", "sensitive_files.txt"]),
    (r"(?i)^git[.-]|^gitlab[.-]", ["gitlab.txt"]),
    (r"(?i)^jenkins[.-]|^ci[.-]|^build[.-]", ["jenkins.txt", "devops.txt"]),
    (r"(?i)^jira[.-]|^confluence[.-]|^wiki[.-]", ["confluence.txt"]),
    (r"(?i)^elastic[.-]|^kibana[.-]|^es[.-]", ["elasticsearch.txt"]),
    (r"(?i)^docker[.-]|^registry[.-]|^k8s[.-]|^kube[.-]", ["docker_kubernetes.txt"]),
    (r"(?i)^sap[.-]", ["sap.txt"]),
    (r"(?i)^mail[.-]|^smtp[.-]|^imap[.-]|^webmail[.-]", ["common.txt"]),
    (r"(?i)^cdn[.-]|^static[.-]|^assets[.-]|^media[.-]", ["common.txt"]),
    (r"(?i)^blog[.-]|^wp[.-]|^wordpress[.-]", ["wordpress.txt"]),
    (r"(?i)^store[.-]|^shop[.-]", ["magento.txt", "common.txt"]),
    (r"(?i)^vault[.-]|^secret[.-]", ["devops.txt", "sensitive.txt"]),
    (r"(?i)^grafana[.-]|^prometheus[.-]|^monitor[.-]", ["devops.txt", "cloud_devops.txt"]),
    (r"(?i)^sso[.-]|^auth[.-]|^login[.-]|^oauth[.-]", ["common.txt", "api.txt"]),
    (r"(?i)^cms[.-]", ["common.txt", "wordpress.txt"]),
    (r"(?i)^sharepoint[.-]|^sp[.-]", ["sharepoint.txt"]),
    (r"(?i)^moodle[.-]|^lms[.-]", ["moodle.txt"]),
]

class HeaderAnalyzer:
    def __init__(self):
        self._seen_leaks: Set[str] = set()
        self.leaks: List[HeaderLeak] = []

    def analyze(self, headers: Dict[str, str]) -> List[HeaderLeak]:
        """Analyze response headers for sensitive information leaks."""
        new_leaks = []

        for header_name, header_value in headers.items():
            # Check known interesting headers (case-insensitive)
            for known_header, (severity, description) in INTERESTING_HEADERS.items():
                if header_name.lower() == known_header.lower():
                    key = f"{header_name}:{header_value}"
                    if key not in self._seen_leaks:
                        self._seen_leaks.add(key)
                        leak = HeaderLeak(
                            header=header_name,
                            value=header_value,
                            severity=severity,
                            description=description,
                        )
                        new_leaks.append(leak)
                        self.leaks.append(leak)

            # Check for internal IPs in any header value
            ip_match = INTERNAL_IP_PATTERN.search(str(header_value))
            if ip_match:
                key = f"internal_ip:{ip_match.group()}"
                if key not in self._seen_leaks:
                    self._seen_leaks.add(key)
                    leak = HeaderLeak(
                        header=header_name,
                        value=header_value,
                        severity="high",
                        description=f"Internal IP address leaked: {ip_match.group()}",
                    )
                    new_leaks.append(leak)
                    self.leaks.append(leak)

        return new_leaks

    def get_summary(self) -> Dict[str, int]:
        """Return counts of leaks by severity."""
        counts = {"high": 0, "medium": 0, "low": 0}
        for leak in self.leaks:
            counts[leak.severity] += 1
        return counts

    @staticmethod
    def get_subdomain_wordlists(url: str) -> List[str]:
        """Given a target URL, detect subdomain patterns and return suggested extra wordlists."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        suggested = []
        for pattern, wordlists in SUBDOMAIN_WORDLIST_MAP:
            if re.search(pattern, hostname):
                suggested.extend(wordlists)

        # Deduplicate while preserving order
        seen = set()
        result = []
        for wl in suggested:
            if wl not in seen:
                seen.add(wl)
                result.append(wl)

        return result
