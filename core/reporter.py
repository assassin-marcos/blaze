"""
Blaze Reporter v2.2 - Clean, visually appealing terminal output
with live adaptive progress bar and structured result display.
"""

import json
import csv
import time
import os
import sys
import shutil
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class ScanResult:
    url: str = ""
    path: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    redirect_url: Optional[str] = None
    response_time: float = 0.0
    word_count: int = 0
    line_count: int = 0
    content_hash: str = ""
    is_directory: bool = False


@dataclass
class ScanStats:
    total_requests: int = 0
    successful: int = 0
    errors: int = 0
    filtered: int = 0
    waf_blocks: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    elapsed: float = 0.0
    rps: float = 0.0


# ════════════════════════ ANSI Colors ════════════════════════

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;208m"
    GRAY = "\033[38;5;245m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    @staticmethod
    def disable():
        for attr in dir(Colors):
            if attr.isupper() and not attr.startswith("_"):
                setattr(Colors, attr, "")


if not sys.stdout.isatty():
    Colors.disable()


STATUS_COLORS = {
    200: Colors.GREEN,
    201: Colors.GREEN,
    204: Colors.GREEN,
    301: Colors.CYAN,
    302: Colors.CYAN,
    307: Colors.CYAN,
    308: Colors.CYAN,
    401: Colors.YELLOW,
    403: Colors.ORANGE,
    405: Colors.YELLOW,
    500: Colors.RED,
    502: Colors.RED,
    503: Colors.RED,
}

BANNER = r"""
{blue}{bold}    ██████╗ ██╗      █████╗ ███████╗███████╗
    ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝
    ██████╔╝██║     ███████║  ███╔╝ █████╗
    ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝
    ██████╔╝███████╗██║  ██║███████╗███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝{reset}
{dim}    Smart Directory Bruteforce Engine v2.2{reset}
"""


class Reporter:
    def __init__(self, config: dict):
        self.config = config
        self.quiet = config.get("quiet", False)
        self.verbose = config.get("verbose", False)
        self.no_color = config.get("no_color", False)

        # Progress bar state
        self._progress_total = 0
        self._progress_current = 0
        self._progress_start = 0.0
        self._last_progress_time = 0.0
        self._has_progress = False
        self._progress_len = 0

        # Terminal dimensions
        try:
            self._tw = shutil.get_terminal_size().columns
        except Exception:
            self._tw = 80

        if self.no_color:
            Colors.disable()

    # ════════════════════ Output Management ════════════════════

    def _clear_progress(self):
        """Clear the progress bar line before printing content above it."""
        if self._has_progress and sys.stdout.isatty():
            sys.stdout.write(f"\r{' ' * min(self._progress_len, self._tw)}\r")
            sys.stdout.flush()

    def _print(self, text: str):
        """Print a line, managing the progress bar."""
        self._clear_progress()
        print(text)

    # ════════════════════ Banner & Config ════════════════════

    def banner(self):
        if self.quiet:
            return
        print(BANNER.format(
            blue=Colors.BLUE, bold=Colors.BOLD,
            reset=Colors.RESET, dim=Colors.DIM,
        ))

    def scan_config(self, config: dict):
        if self.quiet:
            return
        c = Colors
        w = min(self._tw - 2, 60)
        bar = "─" * max(0, w - 23)

        print(f" {c.DIM}┌─{c.RESET}{c.BOLD} Scan Configuration {c.RESET}{c.DIM}{bar}┐{c.RESET}")

        cpu = os.cpu_count() or 4
        lines = [
            ("Target", config["url"]),
            ("Threads", f"{config.get('threads', 50)} (adaptive, {cpu} cores)"),
            ("Timeout", f"{config.get('timeout', 10)}s"),
        ]

        mode_parts = []
        if config.get("smart", True):
            mode_parts.append("Smart")
        if config.get("recursive"):
            mode_parts.append(f"Recursive (depth {config.get('max_depth', 3)})")
        lines.append(("Mode", " | ".join(mode_parts) or "Standard"))

        if config.get("extensions"):
            lines.append(("Extensions", ", ".join(f".{e}" for e in config["extensions"])))
        if config.get("proxy"):
            lines.append(("Proxy", config["proxy"]))

        for label, value in lines:
            # Pad the value area
            inner_vis = 1 + 11 + len(value)
            pad = max(1, w - inner_vis - 1)
            print(
                f" {c.DIM}│{c.RESET} {c.CYAN}{label:<11s}{c.RESET}{value}"
                f"{' ' * pad}{c.DIM}│{c.RESET}"
            )

        print(f" {c.DIM}└{'─' * w}┘{c.RESET}\n")

    # ════════════════════ Phase Headers ════════════════════

    def phase(self, name: str):
        if self.quiet:
            return
        c = Colors
        self._clear_progress()
        print(f"\n {c.BOLD}{c.BLUE}▶ {name}{c.RESET}")

    # ════════════════════ Messages ════════════════════

    def info(self, message: str):
        if self.quiet:
            return
        self._print(f"   {Colors.GRAY}✓{Colors.RESET} {message}")

    def warning(self, message: str):
        self._print(
            f"   {Colors.YELLOW}⚠{Colors.RESET} {Colors.YELLOW}{message}{Colors.RESET}"
        )

    def error(self, message: str):
        self._clear_progress()
        print(
            f"   {Colors.RED}✗{Colors.RESET} {Colors.RED}{message}{Colors.RESET}",
            file=sys.stderr,
        )

    def success(self, message: str):
        if self.quiet:
            return
        self._print(f"   {Colors.GREEN}✓{Colors.RESET} {message}")

    def debug(self, message: str):
        if not self.verbose:
            return
        self._print(f"   {Colors.DIM}[D] {message}{Colors.RESET}")

    def adaptive(self, message: str):
        """Show adaptive engine notification (thread changes, pattern filters)."""
        self._print(
            f"   {Colors.MAGENTA}⚡{Colors.RESET} {Colors.MAGENTA}{message}{Colors.RESET}"
        )

    # ════════════════════ WAF & Tech Display ════════════════════

    def waf_detected(self, waf_result):
        c = Colors
        self._print(f"\n   {c.BG_RED}{c.WHITE}{c.BOLD} WAF DETECTED {c.RESET}")
        for name in waf_result.waf_names:
            confidence = waf_result.confidence.get(name, 0)
            detail = waf_result.details.get(name, "")
            filled = int(confidence * 10)
            bar = f"{c.RED}{'━' * filled}{c.DIM}{'─' * (10 - filled)}{c.RESET}"
            self._print(
                f"   {c.RED}●{c.RESET} {c.BOLD}{name}{c.RESET}  {bar}  "
                f"{c.DIM}{confidence:.0%}{c.RESET}"
            )
            if detail:
                self._print(f"     {c.DIM}{detail}{c.RESET}")
        print()

    def tech_detected(self, tech_result):
        c = Colors
        print()
        for tech_name, confidence in sorted(
            tech_result.technologies.items(), key=lambda x: x[1], reverse=True
        ):
            filled = int(confidence * 10)
            bar = f"{c.GREEN}{'━' * filled}{c.DIM}{'─' * (10 - filled)}{c.RESET}"
            self._print(
                f"   {c.GREEN}●{c.RESET} {c.BOLD}{tech_name:<14s}{c.RESET} "
                f"{bar}  {c.DIM}{confidence:.0%}{c.RESET}"
            )

        meta = []
        if tech_result.server:
            meta.append(("Server", tech_result.server))
        if tech_result.language:
            meta.append(("Language", tech_result.language))
        if tech_result.framework:
            meta.append(("Framework", tech_result.framework))
        if tech_result.cms:
            meta.append(("CMS", tech_result.cms))
        if tech_result.os:
            meta.append(("OS", tech_result.os))
        if meta:
            print()
            for label, value in meta:
                self._print(f"   {c.DIM}{label}:{c.RESET}  {value}")
        print()

    # ════════════════════ Scan Results ════════════════════

    def found(self, result: ScanResult):
        """Display a found URL with status code, size, and response time."""
        c = Colors
        color = STATUS_COLORS.get(result.status_code, Colors.WHITE)
        size_str = self._format_size(result.content_length)
        ms = f"{result.response_time * 1000:.0f}ms"

        line = f" {color}{result.status_code}{c.RESET}  {c.BOLD}{result.url}{c.RESET}"

        if result.redirect_url:
            line += f"  {c.DIM}→{c.RESET} {c.CYAN}{result.redirect_url}{c.RESET}"

        line += f"  {c.DIM}{size_str}  {ms}{c.RESET}"

        if result.is_directory:
            line += f"  {c.BLUE}[DIR]{c.RESET}"

        self._print(line)

    # ════════════════════ Live Progress Bar ════════════════════

    def start_progress(self, total: int):
        self._progress_total = total
        self._progress_current = 0
        self._progress_start = time.monotonic()
        self._last_progress_time = 0
        self._has_progress = True

    def update_progress(
        self,
        current: int,
        rps: float = 0,
        threads: int = 0,
        adaptive_filtered: int = 0,
    ):
        """Redraw the live adaptive progress bar."""
        self._progress_current = current
        now = time.monotonic()

        if now - self._last_progress_time < 0.25:
            return
        self._last_progress_time = now

        if self.quiet or not sys.stdout.isatty():
            return

        c = Colors
        total = self._progress_total
        if total <= 0:
            return

        pct = min(current / total, 1.0)
        elapsed = now - self._progress_start

        # RPS
        if rps <= 0 and elapsed > 0.5:
            rps = current / elapsed

        # ETA
        if rps > 0:
            remaining = total - current
            eta = remaining / rps
            if eta < 60:
                eta_str = f"~{eta:.0f}s"
            elif eta < 3600:
                eta_str = f"~{eta / 60:.0f}m"
            else:
                eta_str = f"~{eta / 3600:.1f}h"
        else:
            eta_str = "..."

        # Bar
        bw = min(28, self._tw - 55)
        if bw < 5:
            bw = 5
        filled = int(bw * pct)
        bar = f"{c.GREEN}{'━' * filled}{c.DIM}{'─' * (bw - filled)}{c.RESET}"

        parts = [
            f" {bar} {pct:>4.0%}",
            f"{current:,}/{total:,}",
            f"{rps:.0f}/s",
        ]
        if threads > 0:
            parts.append(f"T:{threads}")
        parts.append(eta_str)

        line = " │ ".join(parts)
        self._progress_len = len(line) + 30  # account for ANSI codes
        sys.stdout.write(f"\r{line}")
        sys.stdout.flush()

    def finish_progress(self):
        """Clear the progress bar after scanning completes."""
        if self._has_progress and sys.stdout.isatty():
            sys.stdout.write(
                f"\r{' ' * min(self._progress_len, self._tw)}\r"
            )
            sys.stdout.flush()
        self._has_progress = False

    # ════════════════════ Summary ════════════════════

    def summary(
        self,
        stats: ScanStats,
        results: List[ScanResult],
        adaptive_info: dict = None,
    ):
        c = Colors
        self.finish_progress()
        w = min(self._tw - 2, 60)

        print(f"\n {c.BOLD}{'═' * w}{c.RESET}")
        print(f" {c.BOLD}{c.BLUE}  SCAN RESULTS{c.RESET}")
        print(f" {c.BOLD}{'═' * w}{c.RESET}")

        if results:
            by_status: Dict[int, List[ScanResult]] = {}
            for r in results:
                by_status.setdefault(r.status_code, []).append(r)

            for status in sorted(by_status.keys()):
                color = STATUS_COLORS.get(status, Colors.WHITE)
                count = len(by_status[status])
                print(
                    f"\n   {color}{c.BOLD}HTTP {status}{c.RESET}"
                    f" {c.DIM}({count} found){c.RESET}"
                )
                for r in by_status[status]:
                    size_str = self._format_size(r.content_length)
                    line = f"   {color}▸{c.RESET} {r.url}  {c.DIM}{size_str}{c.RESET}"
                    if r.redirect_url:
                        line += f" {c.DIM}→{c.RESET} {c.CYAN}{r.redirect_url}{c.RESET}"
                    print(line)
        else:
            print(f"\n   {c.DIM}No results found.{c.RESET}")

        # ── Statistics ──
        print(f"\n {c.BOLD}{'─' * w}{c.RESET}")
        print(f" {c.BOLD}  STATISTICS{c.RESET}")
        print(f" {c.BOLD}{'─' * w}{c.RESET}")

        print(
            f"   {c.CYAN}Requests{c.RESET} {stats.total_requests:>9,}   "
            f"{c.GREEN}Found{c.RESET}    {stats.successful:>8,}   "
            f"{c.CYAN}Time{c.RESET}  {stats.elapsed:>7.1f}s"
        )
        print(
            f"   {c.DIM}Filtered{c.RESET} {stats.filtered:>9,}   "
            f"{c.RED}Errors{c.RESET}   {stats.errors:>8,}   "
            f"{c.CYAN}Speed{c.RESET} {stats.rps:>6.0f}/s"
        )

        if stats.waf_blocks:
            print(f"   {c.YELLOW}WAF Blocks{c.RESET} {stats.waf_blocks:>7,}")

        # Adaptive info
        if adaptive_info:
            af = adaptive_info.get("total_filtered", 0)
            patterns = adaptive_info.get("patterns_blocked", [])
            changes = adaptive_info.get("thread_changes", [])

            if af > 0 or patterns:
                print(
                    f"\n   {c.MAGENTA}Adaptive Filter{c.RESET}  "
                    f"{af:,} auto-filtered"
                )
                for p in patterns[:5]:
                    print(f"     {c.DIM}▸ {p}{c.RESET}")
            if changes:
                print(
                    f"   {c.MAGENTA}Thread Adjustments{c.RESET}  "
                    f"{len(changes)} changes"
                )

        print(f"\n {c.BOLD}{'═' * w}{c.RESET}\n")

    # ════════════════════ Export ════════════════════

    def export(
        self, results: List[ScanResult], output_path: str, fmt: str = "txt"
    ):
        try:
            if fmt == "json":
                self._export_json(results, output_path)
            elif fmt == "csv":
                self._export_csv(results, output_path)
            else:
                self._export_txt(results, output_path)
            self.success(f"Results saved to: {output_path}")
        except IOError as e:
            self.error(f"Failed to save results: {e}")

    def _export_json(self, results: List[ScanResult], path: str):
        data = {
            "target": self.config.get("url", ""),
            "timestamp": datetime.now().isoformat(),
            "results": [
                {
                    "url": r.url, "path": r.path, "status": r.status_code,
                    "size": r.content_length, "content_type": r.content_type,
                    "redirect": r.redirect_url,
                    "response_time_ms": round(r.response_time * 1000, 1),
                    "is_directory": r.is_directory,
                }
                for r in results
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _export_csv(self, results: List[ScanResult], path: str):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "URL", "Path", "Status", "Size", "Content-Type",
                "Redirect", "Response Time (ms)", "Directory",
            ])
            for r in results:
                writer.writerow([
                    r.url, r.path, r.status_code, r.content_length,
                    r.content_type, r.redirect_url or "",
                    round(r.response_time * 1000, 1), r.is_directory,
                ])

    def _export_txt(self, results: List[ScanResult], path: str):
        with open(path, "w") as f:
            f.write(f"# Blaze v2.2 Scan Results\n")
            f.write(f"# Target: {self.config.get('url', '')}\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# {'─' * 50}\n\n")
            for r in results:
                line = f"[{r.status_code}] {r.url} [{r.content_length}B]"
                if r.redirect_url:
                    line += f" → {r.redirect_url}"
                f.write(line + "\n")

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes}B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f}KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f}MB"
