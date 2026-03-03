#!/usr/bin/env python3
"""
Blaze Dictionary Merger - Analyzes user-provided wordlists and merges
unique entries into the appropriate technology-specific Blaze wordlists.

Usage:
    python tools/dict_merger.py [--source-dir dict/] [--dry-run]
"""

import os
import re
import sys
import argparse
from collections import defaultdict
from typing import Dict, List, Set, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# ──────── Classification Rules ────────
# Maps regex patterns to target wordlist filenames

CLASSIFICATION_RULES = [
    # WordPress
    (r"(?i)(wp-|wordpress|xmlrpc\.php|wp-content|wp-admin|wp-includes|wp-login|wp-json|woocommerce)", "wordpress.txt"),
    # Joomla
    (r"(?i)(joomla|com_content|com_users|administrator/components|option=com_)", "joomla.txt"),
    # Drupal
    (r"(?i)(drupal|sites/default|sites/all|node/\d|core/misc|modules/system|CHANGELOG\.txt)", "drupal.txt"),
    # Laravel
    (r"(?i)(laravel|artisan|storage/logs|telescope|horizon|livewire|\.blade\.php|sanctum)", "laravel.txt"),
    # Django / Python
    (r"(?i)(django|\.py$|__pycache__|wsgi|asgi|manage\.py|flask|fastapi|uvicorn|gunicorn|\.pyc)", "python_web.txt"),
    # Spring / Java
    (r"(?i)(actuator|spring|\.jsp$|\.do$|\.action$|swagger|h2-console|jolokia|WEB-INF|META-INF|\.class|struts)", "spring.txt"),
    # Tomcat
    (r"(?i)(tomcat|host-manager|catalina|jasper|\.war$)", "tomcat.txt"),
    # Ruby on Rails
    (r"(?i)(rails|\.rb$|Gemfile|sidekiq|devise|activeadmin|\.erb$|rack)", "rails.txt"),
    # Node.js
    (r"(?i)(node_modules|package\.json|\.mjs$|express|npm|yarn|bower|next|nuxt|\.jsx$|\.tsx$)", "nodejs.txt"),
    # ASP.NET / IIS / Umbraco
    (r"(?i)(\.aspx$|\.ashx$|\.asmx$|\.axd$|\.asax$|\.cshtml$|\.config$|web\.config|App_Data|App_Code|_vti_|umbraco|DotNetNuke|\.svc$|telerik|signalr|hangfire|elmah)", "asp.txt"),
    # IIS specific
    (r"(?i)(iis|_vti_bin|_vti_adm|aspnet_client|iisstart|_layouts|_mem_bin)", "iis.txt"),
    # PHP
    (r"(?i)(\.php$|\.php[3457]$|\.phtml$|phpinfo|phpmyadmin|PHPSESSID|\.inc\.php|composer)", "php.txt"),
    # Apache
    (r"(?i)(\.htaccess|\.htpasswd|server-status|server-info|cgi-bin/|\.cgi$|httpd|apache|mod_)", "apache.txt"),
    # Nginx
    (r"(?i)(nginx|stub_status|fastcgi|uwsgi|scgi_params)", "nginx.txt"),
    # API
    (r"(?i)(^api/|^rest/|graphql|swagger|openapi|/v[0-9]+/|oauth|\.json$|\.yaml$|endpoint|webhook)", "api.txt"),
    # Backup / Sensitive
    (r"(?i)(\.bak$|\.old$|\.orig$|\.save$|\.swp$|\.zip$|\.tar|\.gz$|\.rar$|\.7z$|\.sql$|backup|\.env|\.git/|\.svn|\.key$|\.pem$|\.crt$|id_rsa|password|credential|secret|sensitive|\.log$|debug|trace)", "backup.txt"),
    # JSP / Java EE
    (r"(?i)(\.jsp$|\.jsf$|\.faces$|web\.xml|struts\.xml|beans\.xml|persistence\.xml|MANIFEST\.MF)", "jsp.txt"),
]

# Source file → forced target mapping (known files)
KNOWN_SOURCE_MAP = {
    "apache2.txt": "apache.txt",
    "api-1.txt": "api.txt",
    "asp-ashmx-wordlist.txt": "asp.txt",
    "CGIs.txt": "apache.txt",
    "Django.txt": "python_web.txt",
    "iis.txt": "iis.txt",
    "iis-mine.txt": "iis.txt",
    "nginx.txt": "nginx.txt",
    "sensitive.txt": "backup.txt",
    "umbraco.txt": "asp.txt",
    "common.txt": "common.txt",
    "combined_directories.txt": "common.txt",
    "direct.txt": "common.txt",
}


def load_wordlist(path: str) -> Set[str]:
    """Load unique non-empty, non-comment lines from a wordlist."""
    words = set()
    if not os.path.exists(path):
        return words
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.add(line)
    except IOError:
        pass
    return words


def classify_path(path: str) -> str:
    """Classify a path into a target wordlist based on pattern matching."""
    for pattern, target in CLASSIFICATION_RULES:
        if re.search(pattern, path):
            return target
    return "common.txt"  # default fallback


def analyze_source_file(filepath: str, source_name: str) -> Dict[str, Set[str]]:
    """
    Analyze a source dictionary and classify its entries.
    For known source files, use forced mapping.
    For unknown files, classify each entry individually.
    """
    result = defaultdict(set)
    forced_target = KNOWN_SOURCE_MAP.get(source_name)

    words = load_wordlist(filepath)
    for word in words:
        if forced_target:
            # For known files, also sub-classify tech-specific paths
            # but put the bulk in the forced target
            specific = classify_path(word)
            if specific != "common.txt" and specific != forced_target:
                result[specific].add(word)
            result[forced_target].add(word)
        else:
            target = classify_path(word)
            result[target].add(word)

    return result


def merge_wordlists(source_dir: str, dry_run: bool = False) -> Dict[str, Tuple[int, int]]:
    """
    Main merge function.
    Returns dict of {target_file: (old_count, new_count)}
    """
    # Load current wordlists
    current_lists: Dict[str, Set[str]] = {}
    for f in os.listdir(WORDLIST_DIR):
        if f.endswith(".txt") and os.path.isfile(os.path.join(WORDLIST_DIR, f)):
            path = os.path.join(WORDLIST_DIR, f)
            current_lists[f] = load_wordlist(path)

    # Record old sizes
    old_sizes = {f: len(words) for f, words in current_lists.items()}

    # Find and process source files
    if not os.path.exists(source_dir):
        print(f"Source directory not found: {source_dir}")
        return {}

    source_files = []
    for f in os.listdir(source_dir):
        if f.endswith(".txt") and not f.startswith("."):
            full_path = os.path.join(source_dir, f)
            if os.path.isfile(full_path):
                source_files.append((f, full_path))

    if not source_files:
        print("No .txt source files found.")
        return {}

    print(f"\n\033[94m[*]\033[0m Found {len(source_files)} source dictionaries to process")
    print(f"\033[2m{'─' * 60}\033[0m")

    total_new = 0
    total_processed = 0

    for source_name, source_path in sorted(source_files):
        source_count = sum(1 for line in open(source_path, errors="replace")
                          if line.strip() and not line.strip().startswith("#"))
        total_processed += source_count
        print(f"\n  \033[96m▸\033[0m Analyzing: \033[1m{source_name}\033[0m ({source_count:,} entries)")

        classified = analyze_source_file(source_path, source_name)

        for target_file, new_words in sorted(classified.items()):
            if target_file not in current_lists:
                current_lists[target_file] = set()
                old_sizes[target_file] = 0

            before = len(current_lists[target_file])
            current_lists[target_file].update(new_words)
            added = len(current_lists[target_file]) - before
            total_new += added

            if added > 0:
                print(f"    → {target_file}: \033[92m+{added:,}\033[0m unique entries")

    # Write updated wordlists
    if not dry_run:
        for filename, words in current_lists.items():
            path = os.path.join(WORDLIST_DIR, filename)
            # Preserve header comment
            header = f"# Blaze - {filename.replace('.txt', '').replace('_', ' ').title()} Wordlist\n"
            sorted_words = sorted(words, key=str.lower)
            with open(path, "w") as f:
                f.write(header)
                for word in sorted_words:
                    f.write(word + "\n")

    # Build results
    new_sizes = {f: len(words) for f, words in current_lists.items()}
    results = {}
    all_files = set(list(old_sizes.keys()) + list(new_sizes.keys()))
    for f in sorted(all_files):
        old = old_sizes.get(f, 0)
        new = new_sizes.get(f, 0)
        if old != new or old > 0:
            results[f] = (old, new)

    # Print summary
    print(f"\n\033[2m{'─' * 60}\033[0m")
    print(f"\033[1m\033[94m  MERGE SUMMARY\033[0m")
    print(f"\033[2m{'─' * 60}\033[0m")
    print(f"  Source entries processed: {total_processed:,}")
    print(f"  New unique entries added: \033[92m{total_new:,}\033[0m")
    if dry_run:
        print(f"\n  \033[93m[!] DRY RUN - no files were modified\033[0m")
    print()

    print(f"  \033[1m{'Wordlist':<25s} {'Before':>10s} {'After':>10s} {'Change':>12s}\033[0m")
    print(f"  {'─' * 57}")
    total_before = 0
    total_after = 0
    for f in sorted(results.keys()):
        old, new = results[f]
        total_before += old
        total_after += new
        diff = new - old
        if diff > 0:
            change = f"\033[92m+{diff:,}\033[0m"
        elif diff < 0:
            change = f"\033[91m{diff:,}\033[0m"
        else:
            change = "\033[2m0\033[0m"
        print(f"  {f:<25s} {old:>10,} {new:>10,} {change:>20s}")

    print(f"  {'─' * 57}")
    total_diff = total_after - total_before
    total_change = f"\033[92m+{total_diff:,}\033[0m" if total_diff > 0 else f"\033[91m{total_diff:,}\033[0m"
    print(f"  \033[1m{'TOTAL':<25s} {total_before:>10,} {total_after:>10,}\033[0m {total_change:>20s}")
    print()

    return results


def main():
    parser = argparse.ArgumentParser(description="Blaze Dictionary Merger")
    parser.add_argument(
        "--source-dir",
        default=os.path.join(WORDLIST_DIR, "dict"),
        help="Directory containing source dictionaries (default: wordlists/dict/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files",
    )
    args = parser.parse_args()
    merge_wordlists(args.source_dir, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
