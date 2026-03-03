"""
Blaze Wordlist Manager - Smart wordlist selection, merging, and optimization.
Automatically selects wordlists based on detected technology, merges with
user-provided lists, deduplicates, and prioritizes high-value paths.
"""

import os
import json
from typing import List, Set, Dict, Optional
from .tech_detector import TechResult, TECH_WORDLIST_MAP


# High-priority paths scanned first (admin panels, login pages, etc.)
HIGH_PRIORITY_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "cpanel", "webmail", "phpmyadmin",
    "adminer", "manager", "console", "portal", "backend",
    "admin.php", "login.php", "user/login", "auth/login",
    ".env", ".git/config", "config.php", "wp-config.php",
    "web.config", "server-info", "server-status", ".htaccess",
    "backup", "backup.sql", "db.sql", "database.sql",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "api", "api/v1", "api/v2", "graphql",
    "swagger", "swagger-ui.html", "swagger.json", "openapi.json",
    ".git", ".svn", ".env.backup", ".env.local",
    "debug", "test", "staging", "dev",
    # New tech-specific high-value paths
    "umbraco/", "umbraco/login", "umbraco/backoffice/",
    "typo3/", "typo3conf/", "fileadmin/",
    "crx/de", "content/dam/", "system/console",
    "_layouts/", "_catalogs/", "_vti_pvt/",
    "confluence/", "rest/api/content", "login.action",
    "jenkins/", "job/", "script",
    "users/sign_in", "explore/projects",
    "_cluster/health", "_cat/indices",
    "sap/bc/", "irj/portal",
    "v2/_catalog",
    "graphql", "graphiql",
    "kibana/", "solr/", "prometheus/",
]


class WordlistManager:
    def __init__(self, config: dict):
        self.config = config
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # Primary: wordlists inside core package (works with pip install)
        core_dir = os.path.dirname(os.path.abspath(__file__))
        pkg_wordlists = os.path.join(core_dir, "wordlists")
        # Fallback: wordlists at repo root level (works from source)
        repo_wordlists = os.path.join(self.base_dir, "wordlists")
        self.wordlist_dir = pkg_wordlists if os.path.isdir(pkg_wordlists) else repo_wordlists
        self.user_wordlists = config.get("wordlists", [])
        self.always_run_lists = config.get("always_lists", [])
        self.smart_mode = config.get("smart", True)

        # Load user config for "always run" lists
        self._load_user_config()

    def _load_user_config(self):
        """Load persistent user config for always-run wordlists."""
        config_path = os.path.join(self.base_dir, "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    user_config = json.load(f)
                saved_lists = user_config.get("always_run_wordlists", [])
                for lst in saved_lists:
                    if lst not in self.always_run_lists:
                        self.always_run_lists.append(lst)
            except (json.JSONDecodeError, IOError):
                pass

    def save_always_run_config(self, wordlists: List[str]):
        """Save always-run wordlist config for future sessions."""
        config_path = os.path.join(self.base_dir, "config.json")
        config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    config = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        config["always_run_wordlists"] = wordlists
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

    def get_available_wordlists(self) -> List[str]:
        """List all available built-in wordlists."""
        if not os.path.exists(self.wordlist_dir):
            return []
        return sorted([
            f for f in os.listdir(self.wordlist_dir)
            if f.endswith(".txt")
        ])

    def _load_wordlist(self, path: str) -> List[str]:
        """Load words from a wordlist file."""
        words = []
        if not os.path.exists(path):
            return words
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
        except IOError:
            pass
        return words

    def _resolve_wordlist_path(self, name: str) -> Optional[str]:
        """Resolve a wordlist name to a full path."""
        # Already a full path
        if os.path.exists(name):
            return name
        # Check in wordlists directory
        path = os.path.join(self.wordlist_dir, name)
        if os.path.exists(path):
            return path
        # Try adding .txt extension
        path_txt = os.path.join(self.wordlist_dir, name + ".txt")
        if os.path.exists(path_txt):
            return path_txt
        return None

    def build_wordlist(self, tech_result: Optional[TechResult] = None,
                       extra_wordlists: Optional[List[str]] = None) -> List[str]:
        """
        Build the final wordlist by combining:
        1. High-priority paths (always first)
        2. User-provided custom wordlists
        3. Smart technology-based wordlists (if smart mode)
        3b. Extra wordlists (from subdomain intelligence, etc.)
        4. Always-run wordlists (from config)
        5. Common wordlist (baseline)
        """
        seen: Set[str] = set()
        final_words: List[str] = []

        def add_words(words: List[str]):
            for w in words:
                w = w.strip().lstrip("/")
                if w and w not in seen:
                    seen.add(w)
                    final_words.append(w)

        # 1. High-priority paths first
        add_words(HIGH_PRIORITY_PATHS)

        # 2. User-provided wordlists
        for wl in self.user_wordlists:
            path = self._resolve_wordlist_path(wl)
            if path:
                add_words(self._load_wordlist(path))

        # 3. Smart technology-based wordlists
        if self.smart_mode and tech_result and tech_result.technologies:
            tech_wordlists = set()
            for tech_name in tech_result.technologies:
                for key, wl_file in TECH_WORDLIST_MAP.items():
                    if (
                        key.lower() in tech_name.lower()
                        or tech_name.lower() in key.lower()
                    ):
                        tech_wordlists.add(wl_file)

            for wl_file in sorted(tech_wordlists):
                path = self._resolve_wordlist_path(wl_file)
                if path:
                    add_words(self._load_wordlist(path))

        # 3b. Extra wordlists (subdomain intelligence, custom)
        if extra_wordlists:
            for wl in extra_wordlists:
                path = self._resolve_wordlist_path(wl)
                if path:
                    add_words(self._load_wordlist(path))

        # 4. Always-run wordlists
        for wl in self.always_run_lists:
            path = self._resolve_wordlist_path(wl)
            if path:
                add_words(self._load_wordlist(path))

        # 5. Always-included wordlists (run regardless of tech detection)
        always_included = [
            "common.txt",
            "backup.txt",
            "sensitive.txt",
            "sensitive_files.txt",
            "api.txt",
            "swagger.txt",
            "graphql.txt",
            "devops.txt",
            "cloud_devops.txt",
            "spring.txt",
        ]
        for wl_name in always_included:
            wl_path = self._resolve_wordlist_path(wl_name)
            if wl_path:
                add_words(self._load_wordlist(wl_path))

        return final_words

    def get_smart_wordlist_info(
        self, tech_result: TechResult
    ) -> Dict[str, List[str]]:
        """Get info about which wordlists would be selected for detected tech."""
        info = {}
        for tech_name in tech_result.technologies:
            matched_lists = []
            for key, wl_file in TECH_WORDLIST_MAP.items():
                if (
                    key.lower() in tech_name.lower()
                    or tech_name.lower() in key.lower()
                ):
                    path = self._resolve_wordlist_path(wl_file)
                    if path:
                        count = len(self._load_wordlist(path))
                        matched_lists.append(f"{wl_file} ({count} words)")
            if matched_lists:
                info[tech_name] = matched_lists
        return info
