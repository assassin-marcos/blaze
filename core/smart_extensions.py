"""
Blaze Smart Extensions - Automatically probe backup/archive extensions
on discovered files, and detect suspicious directories that warrant
additional file-type fuzzing.

v2.1: Enhanced permutation patterns — for a file like "config.php", also
tries: .config.php.swp, config.php.1, config_backup.php, config.bak.php,
config.php.bak, Copy of config.php, etc.
"""

import re
from typing import List, Set, Tuple
from dataclasses import dataclass


# ──────── Backup Extensions ────────
# When a file is found (200/403), try these backup variants

BACKUP_EXTENSIONS = [
    # Direct backup extensions
    ".bak", ".old", ".orig", ".save", ".sav",
    ".backup", ".copy", ".tmp", ".temp",
    # Editor swap/temp files
    "~", ".swp", ".swo", ".swn",
    # Version control
    ".mine",
    # Config backups
    ".dist", ".default", ".sample", ".example",
    ".inc", ".conf",
]

ARCHIVE_EXTENSIONS = [
    ".zip", ".tar.gz", ".tgz", ".tar.bz2",
    ".gz", ".bz2", ".rar", ".7z",
    ".tar", ".xz",
]

SOURCE_EXTENSIONS = [
    ".txt", ".log", ".sql", ".xml",
    ".json", ".yml", ".yaml", ".csv",
    ".md", ".rst",
]

# When probing a file like "config.php", try "config.php.bak" etc.
FILE_BACKUP_SUFFIXES = BACKUP_EXTENSIONS + [".1", ".2", "._"]

# When probing a directory like "backup/", also try these as files
DIR_ARCHIVE_PROBES = [
    "{name}.zip", "{name}.tar.gz", "{name}.tgz",
    "{name}.tar.bz2", "{name}.gz", "{name}.rar",
    "{name}.7z", "{name}.tar", "{name}.sql",
    "{name}.sql.gz", "{name}.sql.bz2",
    "{name}.sql.zip", "{name}.dump",
]

# ──────── Advanced Permutation Templates ────────
# For file "dir/config.php":
#   base = "config", ext = ".php", full = "config.php"
# These patterns generate additional probes beyond simple suffix appending.
FILE_PERMUTATION_TEMPLATES = [
    # Hidden file variants (dot-prefix)
    ".{full}",           # .config.php
    ".{full}.swp",       # .config.php.swp (vim swap)
    ".{full}.swo",       # .config.php.swo
    # Numbered backups
    "{full}.1",          # config.php.1
    "{full}.2",          # config.php.2
    "{full}.0",          # config.php.0
    # Common rename patterns
    "{base}_backup{ext}",  # config_backup.php
    "{base}_old{ext}",     # config_old.php
    "{base}_bak{ext}",     # config_bak.php
    "{base}_orig{ext}",    # config_orig.php
    "{base}_copy{ext}",    # config_copy.php
    "{base}_dev{ext}",     # config_dev.php
    "{base}_test{ext}",    # config_test.php
    "{base}_new{ext}",     # config_new.php
    "{base}.bak{ext}",     # config.bak.php
    "{base}.old{ext}",     # config.old.php
    # Tilde/temp patterns
    "~{full}",             # ~config.php
    "{full}.save",         # config.php.save
    "#{full}#",            # #config.php# (emacs auto-save)
    # Copy of patterns
    "Copy of {full}",      # Copy of config.php
    "{full} (copy)",       # config.php (copy)
    # Date-stamped backups
    "{base}-backup{ext}",  # config-backup.php
    "{full}.bkp",          # config.php.bkp
]

# ──────── Suspicious Path Patterns ────────
# When these patterns are found, trigger aggressive extension probing

SUSPICIOUS_FILE_PATTERNS = [
    # Config files - high value
    (r"(?i)(config|settings|credentials|secrets|database|parameters|env)", "config"),
    # Backup indicators
    (r"(?i)(backup|dump|export|snapshot|archive|data)", "backup"),
    # Web configs
    (r"(?i)(web\.config|\.htaccess|\.htpasswd|nginx\.conf|httpd\.conf|apache)", "webconfig"),
    # Database files
    (r"(?i)(\.sql|\.db|\.sqlite|\.mdb|database|dump)", "database"),
    # Source code / sensitive
    (r"(?i)(\.php|\.asp|\.jsp|\.py|\.rb|\.js|\.ts)$", "source"),
    # Key/cert files
    (r"(?i)(\.key|\.pem|\.crt|\.cer|\.p12|\.pfx|id_rsa|id_dsa)", "crypto"),
]

# Extension sets for each file category
CATEGORY_EXTENSIONS = {
    "config": BACKUP_EXTENSIONS + SOURCE_EXTENSIONS,
    "backup": ARCHIVE_EXTENSIONS + [".sql", ".sql.gz", ".dump"],
    "webconfig": BACKUP_EXTENSIONS + [".txt", ".bak", ".old"],
    "database": ARCHIVE_EXTENSIONS + [".bak", ".old", ".dump", ".gz"],
    "source": BACKUP_EXTENSIONS + [".bak", ".old", "~", ".swp"],
    "crypto": [".bak", ".old", ".pub", ".txt"],
}


@dataclass
class ExtensionProbe:
    """A path + extension combination to probe."""
    original_path: str
    probe_path: str
    extension: str
    category: str
    priority: int  # 1=high, 2=medium, 3=low


class SmartExtensions:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self._probed: Set[str] = set()

    def get_file_probes(self, found_path: str, status_code: int) -> List[ExtensionProbe]:
        """
        Given a found file path, generate additional paths to probe
        with backup/archive extensions and filename permutations.

        Only probes for files that returned 200 or 403 (exists but maybe protected).
        """
        if status_code not in (200, 201, 204, 301, 302, 403):
            return []

        probes = []
        categories_matched = set()

        # Determine file category
        for pattern, category in SUSPICIOUS_FILE_PATTERNS:
            if re.search(pattern, found_path):
                categories_matched.add(category)

        # If no specific category, use basic backup probes
        if not categories_matched:
            categories_matched.add("source")

        # Generate suffix-based probes for each category
        for category in categories_matched:
            extensions = CATEGORY_EXTENSIONS.get(category, BACKUP_EXTENSIONS)
            for ext in extensions:
                probe_path = found_path + ext
                if probe_path not in self._probed:
                    self._probed.add(probe_path)
                    priority = 1 if category in ("config", "crypto", "database") else 2
                    probes.append(ExtensionProbe(
                        original_path=found_path,
                        probe_path=probe_path,
                        extension=ext,
                        category=category,
                        priority=priority,
                    ))

        # Generate permutation-based probes (for files with extensions)
        filename = found_path.split("/")[-1]
        dir_prefix = found_path[: len(found_path) - len(filename)]
        if "." in filename:
            base, ext = filename.rsplit(".", 1)
            ext = "." + ext
            for template in FILE_PERMUTATION_TEMPLATES:
                try:
                    permuted = template.format(full=filename, base=base, ext=ext)
                    probe_path = dir_prefix + permuted
                    if probe_path not in self._probed:
                        self._probed.add(probe_path)
                        probes.append(ExtensionProbe(
                            original_path=found_path,
                            probe_path=probe_path,
                            extension="(permutation)",
                            category="backup",
                            priority=2,
                        ))
                except (KeyError, IndexError):
                    continue

        # For files with extensions, also try without extension (source disclosure)
        if "." in found_path:
            base = found_path.rsplit(".", 1)[0]
            txt_probe = base + ".txt"
            if txt_probe not in self._probed:
                self._probed.add(txt_probe)
                probes.append(ExtensionProbe(
                    original_path=found_path,
                    probe_path=txt_probe,
                    extension=".txt",
                    category="source",
                    priority=3,
                ))

        return sorted(probes, key=lambda p: p.priority)

    def get_dir_probes(self, found_dir: str) -> List[ExtensionProbe]:
        """
        Given a found directory, generate archive probes.
        E.g., if /backup/ is found, try /backup.zip, /backup.tar.gz, etc.
        """
        probes = []
        dir_name = found_dir.rstrip("/")

        for template in DIR_ARCHIVE_PROBES:
            probe_path = template.format(name=dir_name)
            if probe_path not in self._probed:
                self._probed.add(probe_path)
                ext = "." + probe_path.split(".", 1)[1] if "." in probe_path else ""
                probes.append(ExtensionProbe(
                    original_path=found_dir,
                    probe_path=probe_path,
                    extension=ext,
                    category="backup",
                    priority=1,
                ))

        return probes

    def get_smart_extensions_for_tech(self, technologies: list) -> List[str]:
        """
        Based on detected technologies, return file extensions that should
        be appended to every wordlist entry during scanning.
        """
        extensions = set()
        tech_ext_map = {
            "php": [".php", ".php.bak", ".php~", ".php.old"],
            "asp": [".aspx", ".asp", ".ashx", ".config"],
            "jsp": [".jsp", ".jsf", ".do", ".action"],
            "python": [".py", ".pyc"],
            "ruby": [".rb", ".erb"],
            "node": [".js", ".json"],
            "java": [".java", ".class", ".jar", ".war"],
        }

        for tech in technologies:
            tech_lower = tech.lower()
            for key, exts in tech_ext_map.items():
                if key in tech_lower:
                    extensions.update(exts)

        return sorted(extensions)

    def should_probe_extensions(self, path: str, status_code: int) -> bool:
        """Check if a found path warrants extension probing."""
        if status_code not in (200, 201, 204, 301, 302, 403):
            return False
        for pattern, _ in SUSPICIOUS_FILE_PATTERNS:
            if re.search(pattern, path):
                return True
        # Also probe if it looks like a file (has extension)
        if "." in path.split("/")[-1]:
            return True
        return False
