#!/usr/bin/env python3
"""
Blaze v2.2 - Smart Directory Bruteforce Engine

Features:
  - Async I/O engine (aiohttp) for maximum throughput
  - WAF detection (22+ providers) with auto-stop
  - Technology fingerprinting & smart wordlist selection
  - Wildcard/soft-404/wildcard-401 detection
  - Response diffing for intelligent false-positive elimination
  - Smart context-aware recursive scanning with multi-wordlist
  - Auto backup/archive extension probing on discovered files
  - JavaScript endpoint extraction
  - Resume interrupted scans
  - VHOST discovery, parameter fuzzing, pattern generation
  - Real-time adaptation based on scan results
  - Headless browser JS challenge bypass
  - Multiple output formats (JSON/CSV/TXT)

Usage:
  python blaze.py -u https://target.com
  python blaze.py -u https://target.com -t 100 -r --smart
  python blaze.py -u https://target.com --resume
  python blaze.py -u https://target.com --vhost --vhost-wordlist hosts.txt
  python blaze.py --merge-dicts
"""

import argparse
import asyncio
import sys
import os
import json
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import BlazeEngine
from core.reporter import Reporter, Colors
from core.wordlist_manager import WordlistManager


def parse_args():
    parser = argparse.ArgumentParser(
        prog="blaze",
        description="Blaze v2.2 - Smart Directory Bruteforce Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://target.com                          Basic smart scan
  %(prog)s -u https://target.com -t 100 -r --depth 5      Recursive, 100 threads
  %(prog)s -u https://target.com -w custom.txt             Custom wordlist
  %(prog)s -u https://target.com -e php,html,txt           With extensions
  %(prog)s -u https://target.com --show-forbidden          Also show 403s
  %(prog)s -u https://target.com --resume                  Resume interrupted scan
  %(prog)s -u https://target.com --no-js-extract           Skip JS extraction
  %(prog)s -u https://target.com --force --no-waf-check    Skip WAF check
  %(prog)s -u https://target.com -o out.json --format json Export JSON
  %(prog)s -u https://target.com --vhost --vhost-wordlist h.txt  VHOST discovery
  %(prog)s -u https://target.com --discover-params         Parameter fuzzing
  %(prog)s -u https://target.com -p "backup-{DATE}.{EXT}"  Pattern generation
  %(prog)s -u https://target.com --headless                Bypass JS challenges
  %(prog)s --setup-lists                                    Configure always-run lists
  %(prog)s --merge-dicts                                    Merge user dictionaries
  %(prog)s --merge-dicts --source-dir /path/to/dicts        Merge from custom dir
        """,
    )

    # ── Target ──
    target = parser.add_argument_group("Target")
    target.add_argument("-u", "--url", help="Target URL (e.g., https://example.com)")

    # ── Wordlists ──
    wordlists = parser.add_argument_group("Wordlists")
    wordlists.add_argument(
        "-w", "--wordlist", action="append", default=[],
        help="Wordlist file(s) (can specify multiple: -w a.txt -w b.txt)",
    )
    wordlists.add_argument("--always-lists", action="append", default=[],
                           help="Wordlists to always include (saved to config)")
    wordlists.add_argument("--setup-lists", action="store_true",
                           help="Interactive setup for always-run wordlists")
    wordlists.add_argument("--list-wordlists", action="store_true",
                           help="List all available built-in wordlists")
    wordlists.add_argument("--merge-dicts", action="store_true",
                           help="Merge user dictionaries into Blaze wordlists")
    wordlists.add_argument("--source-dir", type=str, default="",
                           help="Source directory for --merge-dicts (default: wordlists/dict/)")

    # ── Scan Options ──
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-t", "--threads", type=int, default=0,
                      help="Concurrent threads (0 = auto-detect from CPU cores)")
    scan.add_argument("--timeout", type=int, default=10,
                      help="Request timeout in seconds (default: 10)")
    scan.add_argument("-r", "--recursive", action="store_true",
                      help="Enable smart recursive scanning")
    scan.add_argument("--depth", type=int, default=3,
                      help="Max recursion depth (default: 3)")
    scan.add_argument("-e", "--extensions", type=str, default="",
                      help="File extensions (comma-separated: php,html,txt)")
    scan.add_argument("--delay", type=float, default=0,
                      help="Delay between requests in seconds")
    scan.add_argument("--smart", action="store_true", default=True,
                      help="Smart mode (default: on)")
    scan.add_argument("--no-smart", action="store_true",
                      help="Disable smart mode")

    # ── Smart Features ──
    smart = parser.add_argument_group("Smart Features")
    smart.add_argument("--show-forbidden", action="store_true",
                       help="Show 403 Forbidden responses (hidden by default)")
    smart.add_argument("--no-js-extract", action="store_true",
                       help="Skip JavaScript endpoint extraction")
    smart.add_argument("--no-ext-probe", action="store_true",
                       help="Skip smart backup extension probing")
    smart.add_argument("--diff-threshold", type=float, default=0.85,
                       help="Soft-404 similarity threshold (default: 0.85)")
    smart.add_argument("--resume", action="store_true",
                       help="Resume an interrupted scan")
    smart.add_argument("--clear-state", action="store_true",
                       help="Clear saved scan state for target")

    # ── Advanced Modes ──
    advanced = parser.add_argument_group("Advanced Modes")
    advanced.add_argument("--vhost", action="store_true",
                          help="Enable VHOST discovery mode")
    advanced.add_argument("--vhost-wordlist", type=str, default="",
                          help="Hostname wordlist for VHOST mode")
    advanced.add_argument("--discover-params", action="store_true",
                          help="Enable parameter discovery on found pages")
    advanced.add_argument("-p", "--pattern", type=str, default="",
                          help='Pattern generation (e.g., "backup-{DATE}.{EXT}")')
    advanced.add_argument("--headless", action="store_true",
                          help="Use headless browser to bypass JS challenges")

    # ── Request Options ──
    request = parser.add_argument_group("Request Options")
    request.add_argument("--user-agent", type=str, default="")
    request.add_argument("--random-agent", action="store_true",
                         help="Random User-Agent per request")
    request.add_argument("-H", "--header", action="append", default=[],
                         help='Custom header (-H "Auth: Bearer token")')
    request.add_argument("-c", "--cookie", type=str, default="",
                         help='Cookies ("key=val; key2=val2")')
    request.add_argument("--proxy", type=str, default="",
                         help="Proxy URL (http://127.0.0.1:8080)")
    request.add_argument("-L", "--follow-redirects", action="store_true")
    request.add_argument("--ignore-ssl", action="store_true", default=True)

    # ── Filters ──
    filters = parser.add_argument_group("Filters")
    filters.add_argument("-s", "--include-status", type=str, default="",
                         help="Only show these status codes (200,301)")
    filters.add_argument("-x", "--exclude-status", type=str, default="404",
                         help="Exclude status codes (default: 404)")
    filters.add_argument("--min-size", type=int, default=None)
    filters.add_argument("--max-size", type=int, default=None)
    filters.add_argument("--min-words", type=int, default=None)
    filters.add_argument("--max-words", type=int, default=None)

    # ── WAF ──
    waf = parser.add_argument_group("WAF Options")
    waf.add_argument("--no-waf-check", action="store_true")
    waf.add_argument("--force", action="store_true",
                     help="Continue even if WAF detected")

    # ── Output ──
    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", type=str, default="")
    output.add_argument("--format", type=str, choices=["txt", "json", "csv"],
                        default="txt")
    output.add_argument("-q", "--quiet", action="store_true")
    output.add_argument("-v", "--verbose", action="store_true")
    output.add_argument("--no-color", action="store_true")

    # ── Update ──
    updater = parser.add_argument_group("Update")
    updater.add_argument("--update", action="store_true",
                         help="Update Blaze to the latest version from git")

    return parser.parse_args()


def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_cookies(cookie_str):
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(";"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                cookies[key.strip()] = value.strip()
    return cookies


def parse_status_codes(status_str):
    if not status_str:
        return []
    return [int(s.strip()) for s in status_str.split(",") if s.strip().isdigit()]


def build_config(args):
    return {
        "url": args.url,
        "threads": args.threads,
        "timeout": args.timeout,
        "recursive": args.recursive,
        "max_depth": args.depth,
        "smart": args.smart and not args.no_smart,
        "force": args.force,
        "no_waf_check": args.no_waf_check,
        "follow_redirects": args.follow_redirects,
        "random_agent": args.random_agent,
        "ignore_ssl": args.ignore_ssl,
        "delay": args.delay,
        "proxy": args.proxy or None,
        "user_agent": args.user_agent,
        "headers": parse_headers(args.header),
        "cookies": parse_cookies(args.cookie),
        "extensions": [e.strip().lstrip(".") for e in args.extensions.split(",") if e.strip()] if args.extensions else [],
        "wordlists": args.wordlist,
        "always_lists": args.always_lists,
        "include_status": parse_status_codes(args.include_status),
        "exclude_status": parse_status_codes(args.exclude_status),
        "min_size": args.min_size,
        "max_size": args.max_size,
        "min_words": args.min_words,
        "max_words": args.max_words,
        "output": args.output or None,
        "output_format": args.format,
        "quiet": args.quiet,
        "verbose": args.verbose,
        "no_color": args.no_color,
        # v2 features
        "show_forbidden": args.show_forbidden,
        "extract_js": not args.no_js_extract,
        "smart_ext_probe": not args.no_ext_probe,
        "diff_threshold": args.diff_threshold,
        "resume": args.resume,
        "vhost": args.vhost,
        "vhost_wordlist": args.vhost_wordlist,
        "discover_params": args.discover_params,
        "pattern": args.pattern,
        "headless": args.headless,
    }


def setup_always_run_lists():
    c = Colors
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wl_dir = os.path.join(base_dir, "wordlists")
    config_path = os.path.join(base_dir, "config.json")

    print(f"\n {c.BOLD}{c.BLUE}Blaze - Always-Run Wordlist Configuration{c.RESET}")
    print(f" {c.DIM}{'─' * 50}{c.RESET}")

    available = sorted([
        f for f in os.listdir(wl_dir)
        if f.endswith(".txt") and os.path.isfile(os.path.join(wl_dir, f))
    ]) if os.path.exists(wl_dir) else []

    if not available:
        print(f" {c.YELLOW}No built-in wordlists found.{c.RESET}")
        return

    print(f"\n {c.BOLD}Available wordlists:{c.RESET}")
    for i, wl in enumerate(available, 1):
        path = os.path.join(wl_dir, wl)
        try:
            with open(path) as f:
                count = sum(1 for line in f if line.strip() and not line.startswith("#"))
        except IOError:
            count = 0
        print(f"  {c.CYAN}{i:2d}.{c.RESET} {wl:<25s} {c.DIM}({count:,} entries){c.RESET}")

    current_lists = []
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                current_lists = json.load(f).get("always_run_wordlists", [])
        except (json.JSONDecodeError, IOError):
            pass

    if current_lists:
        print(f"\n {c.BOLD}Currently configured:{c.RESET}")
        for wl in current_lists:
            print(f"  {c.GREEN}✓{c.RESET} {wl}")

    print(f"\n Enter numbers (comma-separated), paths, 'clear', or 'done':\n")
    selected = list(current_lists)

    while True:
        try:
            choice = input(f" {c.CYAN}>{c.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice.lower() in ("done", ""):
            break
        elif choice.lower() == "clear":
            selected.clear()
            print(f" {c.YELLOW}Cleared all.{c.RESET}")
            continue
        for part in choice.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(available):
                    wl = available[idx]
                    if wl in selected:
                        selected.remove(wl)
                        print(f" {c.YELLOW}- Removed: {wl}{c.RESET}")
                    else:
                        selected.append(wl)
                        print(f" {c.GREEN}+ Added: {wl}{c.RESET}")
            elif os.path.exists(part):
                if part not in selected:
                    selected.append(part)
                    print(f" {c.GREEN}+ Added: {part}{c.RESET}")

    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    config["always_run_wordlists"] = selected
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"\n {c.GREEN}[✓]{c.RESET} Saved. Always-run: {selected}\n")


def list_wordlists():
    c = Colors
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wl_dir = os.path.join(base_dir, "wordlists")
    print(f"\n {c.BOLD}{c.BLUE}Available Wordlists{c.RESET}")
    print(f" {c.DIM}{'─' * 50}{c.RESET}")
    if not os.path.exists(wl_dir):
        print(f" {c.YELLOW}Wordlist directory not found.{c.RESET}")
        return
    total = 0
    for wl in sorted(os.listdir(wl_dir)):
        if not wl.endswith(".txt") or not os.path.isfile(os.path.join(wl_dir, wl)):
            continue
        path = os.path.join(wl_dir, wl)
        try:
            with open(path) as f:
                count = sum(1 for l in f if l.strip() and not l.startswith("#"))
        except IOError:
            count = 0
        total += count
        print(f"  {c.CYAN}▸{c.RESET} {wl:<25s} {c.DIM}{count:>8,} entries{c.RESET}")
    print(f"  {c.DIM}{'─' * 40}{c.RESET}")
    print(f"  {c.BOLD}{'TOTAL':<25s} {total:>8,} entries{c.RESET}")
    print()


def run_merge_dicts(source_dir=""):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not source_dir:
        source_dir = os.path.join(base_dir, "wordlists", "dict")
    tools_dir = os.path.join(base_dir, "tools")
    sys.path.insert(0, tools_dir)
    from dict_merger import merge_wordlists
    merge_wordlists(source_dir)


def run_self_update():
    """Update Blaze from the git repository."""
    import subprocess
    c = Colors

    REPO_URL = "https://github.com/assassin-marcos/blaze.git"
    base_dir = os.path.dirname(os.path.abspath(__file__))

    print(f"\n {c.BOLD}{c.BLUE}Blaze Self-Update{c.RESET}")
    print(f" {c.DIM}{'─' * 50}{c.RESET}")

    # Check if we're in a git repo (installed from git clone)
    git_dir = os.path.join(base_dir, ".git")
    if os.path.isdir(git_dir):
        print(f" {c.CYAN}>{c.RESET} Updating via git pull...")
        try:
            result = subprocess.run(
                ["git", "pull", "--rebase"],
                cwd=base_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                print(f" {c.GREEN}[ok]{c.RESET} {result.stdout.strip()}")
            else:
                print(f" {c.RED}[ERR]{c.RESET} git pull failed: {result.stderr.strip()}")
                return False
        except FileNotFoundError:
            print(f" {c.RED}[ERR]{c.RESET} git not found. Install git first.")
            return False
        except subprocess.TimeoutExpired:
            print(f" {c.RED}[ERR]{c.RESET} git pull timed out.")
            return False

        # Re-install after pull
        print(f" {c.CYAN}>{c.RESET} Re-installing package...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", base_dir,
                 "--force-reinstall", "--quiet", "--break-system-packages"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print(f" {c.GREEN}[ok]{c.RESET} Package reinstalled successfully.")
            else:
                print(f" {c.YELLOW}[!!]{c.RESET} pip install warning: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f" {c.RED}[ERR]{c.RESET} pip install timed out.")
            return False
    else:
        # Not a git clone — install directly from repo URL via pip
        print(f" {c.CYAN}>{c.RESET} Installing latest from {REPO_URL}...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install",
                 f"git+{REPO_URL}", "--upgrade", "--force-reinstall",
                 "--quiet", "--break-system-packages"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print(f" {c.GREEN}[ok]{c.RESET} Updated from git successfully.")
            else:
                print(f" {c.RED}[ERR]{c.RESET} pip install failed: {result.stderr.strip()}")
                return False
        except subprocess.TimeoutExpired:
            print(f" {c.RED}[ERR]{c.RESET} Install timed out.")
            return False

    # Show new version
    try:
        from importlib import reload
        import core as _core
        reload(_core)
        print(f"\n {c.GREEN}{c.BOLD}Updated to Blaze v{_core.__version__}{c.RESET}\n")
    except Exception:
        print(f"\n {c.GREEN}{c.BOLD}Update complete!{c.RESET}\n")

    return True


async def run_vhost_mode(config):
    """Run VHOST discovery mode."""
    from core.vhost_scanner import VHostScanner
    from urllib.parse import urlparse

    parsed = urlparse(config["url"])
    target_ip = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    wl_path = config.get("vhost_wordlist", "")
    if not wl_path or not os.path.exists(wl_path):
        print(f" {Colors.RED}[✗] VHOST mode requires --vhost-wordlist path{Colors.RESET}")
        return

    with open(wl_path) as f:
        hostnames = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    print(f"\n {Colors.BOLD}{Colors.BLUE}VHOST Discovery Mode{Colors.RESET}")
    print(f" Target: {target_ip}:{port}")
    print(f" Hostnames: {len(hostnames):,}")

    import aiohttp, ssl as _ssl
    scanner = VHostScanner(target_ip, port=port, threads=config.get("threads", 50), use_ssl=use_ssl)
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        baseline = await scanner.get_baseline(session)
        if baseline:
            results = await scanner.scan(session, hostnames, baseline)
            unique = [r for r in results if r.is_unique]
            print(f"\n {Colors.GREEN}Found {len(unique)} unique VHOST(s):{Colors.RESET}")
            for r in unique:
                print(f"  {Colors.GREEN}▸{Colors.RESET} {r.hostname} [{r.status_code}] [{r.content_length}B]")
        else:
            print(f" {Colors.RED}[✗] Could not get baseline response{Colors.RESET}")


async def run_param_discovery(config, found_urls):
    """Run parameter discovery on found pages."""
    from core.content_discovery import ContentDiscovery
    import aiohttp, ssl as _ssl

    c = Colors
    discovery = ContentDiscovery(threads=min(config.get("threads", 20), 20))
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    connector = aiohttp.TCPConnector(ssl=ctx)

    print(f"\n {c.BOLD}{c.BLUE}Parameter Discovery{c.RESET}")
    print(f" Testing {min(len(found_urls), 20)} pages...")

    async with aiohttp.ClientSession(connector=connector) as session:
        for url in found_urls[:20]:
            results = await discovery.discover_params(session, url, config.get("proxy"))
            interesting = [r for r in results if r.interesting or r.reflected]
            if interesting:
                print(f"\n  {c.CYAN}{url}{c.RESET}")
                for r in interesting:
                    marker = ""
                    if r.reflected:
                        marker += f" {c.YELLOW}[REFLECTED]{c.RESET}"
                    if r.interesting:
                        marker += f" {c.RED}[INTERESTING]{c.RESET}"
                    print(f"    {c.GREEN}▸{c.RESET} ?{r.param}={r.value} → {r.status_code}{marker}")
                    if r.detail:
                        print(f"      {c.DIM}{r.detail}{c.RESET}")


async def user_prompt(message: str) -> bool:
    try:
        response = input(message).strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


async def main():
    args = parse_args()

    # Utility commands
    if args.update:
        run_self_update()
        return
    if args.setup_lists:
        setup_always_run_lists()
        return
    if args.list_wordlists:
        list_wordlists()
        return
    if args.merge_dicts:
        run_merge_dicts(args.source_dir)
        return

    # Validate URL
    if not args.url:
        print(f"\n {Colors.RED}[✗] Target URL required (-u URL){Colors.RESET}\n", file=sys.stderr)
        sys.exit(1)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        args.url = url

    config = build_config(args)

    # VHOST mode (standalone)
    if config.get("vhost"):
        await run_vhost_mode(config)
        return

    # Clear resume state
    if args.clear_state:
        from core.resume_manager import ResumeManager
        rm = ResumeManager(url)
        rm.clear_state()
        print(f" {Colors.GREEN}[✓]{Colors.RESET} State cleared for {url}")
        return

    # Headless browser challenge bypass (pre-scan)
    if config.get("headless"):
        try:
            from core.headless import HeadlessBrowser
            if HeadlessBrowser.is_available():
                reporter = Reporter(config)
                reporter.info("Solving JS challenge with headless browser...")
                async with HeadlessBrowser() as browser:
                    result = await browser.solve_challenge(url)
                    if result and result.get("cookies"):
                        config["cookies"].update(result["cookies"])
                        reporter.success(f"Challenge solved. Got {len(result['cookies'])} cookies.")
                    else:
                        reporter.warning("No challenge detected or solve failed.")
            else:
                print(f" {Colors.YELLOW}[!] playwright not installed. Run: pip install playwright && playwright install{Colors.RESET}")
        except Exception as e:
            print(f" {Colors.YELLOW}[!] Headless error: {e}{Colors.RESET}")

    # Pattern generation (add to wordlists)
    if config.get("pattern"):
        from core.pattern_generator import PatternGenerator
        gen = PatternGenerator()
        exts = config.get("extensions", []) or ["zip", "tar.gz", "bak", "sql", "gz"]
        words = []
        for wl in config.get("wordlists", []):
            if os.path.exists(wl):
                with open(wl) as f:
                    words.extend(l.strip() for l in f if l.strip())
        paths = gen.generate(config["pattern"], words=words or None, extensions=exts)
        print(f" {Colors.BLUE}[i]{Colors.RESET} Pattern '{config['pattern']}' generated {len(paths):,} paths")
        config["_pattern_paths"] = paths

    # Create engine and run
    engine = BlazeEngine(config)
    engine.user_prompt_callback = user_prompt

    def signal_handler(sig, frame):
        engine.stop()
        print(f"\n {Colors.YELLOW}[!] Stopping scan...{Colors.RESET}")

    signal.signal(signal.SIGINT, signal_handler)

    await engine.run()

    # Post-scan: parameter discovery
    if config.get("discover_params") and engine.results:
        found_200 = [r.url for r in engine.results if r.status_code == 200]
        if found_200:
            await run_param_discovery(config, found_200)


def cli_entry():
    """Entry point for pip-installed 'blaze' command."""
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass
    asyncio.run(main())


if __name__ == "__main__":
    cli_entry()
