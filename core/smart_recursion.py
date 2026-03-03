"""
Blaze Smart Recursion - Context-aware recursive directory scanning.
When a directory is discovered, selects appropriate wordlists based on
the directory name/context. E.g., /backup → backup.txt, /api → api.txt.
Runs multiple wordlists per directory for thorough coverage.
"""

import os
import re
from typing import List, Set, Dict, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# ──────── Context Mapping ────────
# Maps directory name patterns to wordlists that should be used for recursion.
# Each entry: (regex_pattern, [list of wordlist filenames])

CONTEXT_MAP = [
    # Backup/Archive directories
    (r"(?i)(backup|bak|old|archive|dump|snapshot|export|restore)", ["backup.txt", "common.txt"]),
    # API directories
    (r"(?i)(api|rest|v[0-9]+|graphql|endpoint|service|gateway|webhook)", ["api.txt", "common.txt"]),
    # Admin panels
    (r"(?i)(admin|administrator|panel|dashboard|manage|management|backend|control|cpanel)", ["common.txt", "backup.txt"]),
    # WordPress
    (r"(?i)(wp-|wordpress|wp-content|wp-admin|wp-includes)", ["wordpress.txt"]),
    # Joomla
    (r"(?i)(joomla|administrator/components|com_)", ["joomla.txt"]),
    # Drupal
    (r"(?i)(drupal|sites/default|sites/all|core/modules)", ["drupal.txt"]),
    # Laravel
    (r"(?i)(laravel|storage|telescope|horizon|livewire)", ["laravel.txt", "php.txt"]),
    # Django/Python
    (r"(?i)(django|flask|python|static/admin|__pycache__)", ["python_web.txt"]),
    # Spring/Java
    (r"(?i)(spring|actuator|swagger|java|j2ee|jboss|wildfly)", ["spring.txt", "jsp.txt"]),
    # Tomcat
    (r"(?i)(tomcat|catalina|manager|host-manager|WEB-INF|META-INF)", ["tomcat.txt", "jsp.txt"]),
    # IIS/ASP.NET
    (r"(?i)(aspnet|asp|iis|_vti_|bin|App_Data|App_Code|umbraco)", ["asp.txt", "iis.txt"]),
    # PHP directories
    (r"(?i)(php|include|lib|class|module|vendor|composer)", ["php.txt"]),
    # Node.js
    (r"(?i)(node|npm|yarn|next|nuxt|express|bower)", ["nodejs.txt"]),
    # Ruby/Rails
    (r"(?i)(rails|ruby|gem|rack|sidekiq|config/routes)", ["rails.txt"]),
    # Upload directories
    (r"(?i)(upload|uploads|files|media|images|attachments|documents|assets)", ["backup.txt", "common.txt"]),
    # Config/sensitive directories
    (r"(?i)(config|conf|settings|setup|\.git|\.svn|private|secret|internal|hidden)", ["backup.txt", "common.txt"]),
    # Nginx specific
    (r"(?i)(nginx|proxy|upstream|fastcgi|uwsgi|server)", ["nginx.txt"]),
    # Apache specific
    (r"(?i)(apache|httpd|cgi-bin|cgi|htdocs)", ["apache.txt"]),
    # Auth/user directories
    (r"(?i)(auth|login|user|users|account|accounts|member|profile|session|sso|oauth)", ["common.txt", "api.txt"]),
    # Test/dev directories
    (r"(?i)(test|tests|testing|dev|development|staging|demo|debug|qa|sandbox)", ["common.txt", "backup.txt"]),
    # Log directories
    (r"(?i)(log|logs|logging|audit|trace|error|access)", ["backup.txt"]),
    # Database directories
    (r"(?i)(db|database|sql|mysql|postgres|mongo|redis|data)", ["backup.txt", "common.txt"]),
    # Static content
    (r"(?i)(static|assets|public|dist|build|resources|css|js|fonts|img|icons)", ["common.txt"]),
    # CMS content
    (r"(?i)(content|page|pages|post|posts|blog|article|news|cms|template|theme)", ["common.txt"]),
    # Documentation
    (r"(?i)(doc|docs|documentation|help|support|wiki|manual|readme|guide)", ["common.txt"]),
]

# Directories worth always scanning with common.txt in addition to context lists
ALWAYS_ADD_COMMON = True

# Suspicious directories that warrant aggressive recursion (more wordlists)
SUSPICIOUS_PATTERNS = [
    r"(?i)(backup|bak|old|archive|private|secret|hidden|internal|staging|dev|test|debug|admin|config|\.git)",
]


class SmartRecursion:
    def __init__(self, config: dict):
        self.config = config
        self.wordlist_dir = WORDLIST_DIR
        self.max_depth = config.get("max_depth", 3)
        self._wordlist_cache: Dict[str, List[str]] = {}

    def get_wordlists_for_dir(self, dir_path: str) -> List[str]:
        """
        Given a discovered directory path, determine which wordlists
        should be used for recursive scanning inside it.

        Returns list of wordlist file paths.
        """
        dir_name = dir_path.rstrip("/").split("/")[-1] if "/" in dir_path else dir_path.rstrip("/")
        full_path_lower = dir_path.lower()

        matched_lists: Set[str] = set()

        # Check context map
        for pattern, wordlists in CONTEXT_MAP:
            if re.search(pattern, dir_name) or re.search(pattern, full_path_lower):
                matched_lists.update(wordlists)

        # Always add common.txt for breadth
        if ALWAYS_ADD_COMMON:
            matched_lists.add("common.txt")

        # If suspicious, add backup.txt for sensitive file discovery
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, dir_name) or re.search(pattern, full_path_lower):
                matched_lists.add("backup.txt")
                matched_lists.add("common.txt")
                break

        # If no specific match, use common.txt
        if not matched_lists:
            matched_lists.add("common.txt")

        # Resolve to full paths
        resolved = []
        for wl_name in sorted(matched_lists):
            path = os.path.join(self.wordlist_dir, wl_name)
            if os.path.exists(path):
                resolved.append(path)

        return resolved

    def load_wordlist_cached(self, path: str) -> List[str]:
        """Load a wordlist with caching to avoid re-reading."""
        if path not in self._wordlist_cache:
            words = []
            try:
                with open(path, "r", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            words.append(line)
            except IOError:
                pass
            self._wordlist_cache[path] = words
        return self._wordlist_cache[path]

    def build_recursive_wordlist(self, dir_path: str) -> List[str]:
        """
        Build a merged, deduplicated wordlist for scanning a specific directory.
        """
        wordlist_paths = self.get_wordlists_for_dir(dir_path)
        seen: Set[str] = set()
        merged: List[str] = []

        for wl_path in wordlist_paths:
            words = self.load_wordlist_cached(wl_path)
            for word in words:
                word = word.strip().lstrip("/")
                if word and word not in seen:
                    seen.add(word)
                    merged.append(word)

        return merged

    def is_suspicious_dir(self, dir_path: str) -> bool:
        """Check if a directory name looks suspicious (worth extra scanning)."""
        dir_name = dir_path.rstrip("/").split("/")[-1] if "/" in dir_path else dir_path.rstrip("/")
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, dir_name):
                return True
        return False

    def get_context_info(self, dir_path: str) -> Dict[str, any]:
        """Get info about what context was matched for a directory."""
        dir_name = dir_path.rstrip("/").split("/")[-1] if "/" in dir_path else dir_path.rstrip("/")
        info = {
            "dir": dir_path,
            "dir_name": dir_name,
            "matched_wordlists": [],
            "is_suspicious": self.is_suspicious_dir(dir_path),
        }

        wordlist_paths = self.get_wordlists_for_dir(dir_path)
        info["matched_wordlists"] = [os.path.basename(p) for p in wordlist_paths]

        return info
