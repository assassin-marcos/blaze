"""
Blaze Signature Loader - Load custom detection signatures from JSON packs.

Place .json files in the signatures/ directory to extend Blaze's detection:

Example format (signatures/custom_waf.json):
{
    "name": "Custom WAF Pack",
    "version": "1.0",
    "waf_signatures": {
        "header_patterns": {
            "X-Custom-WAF": ["CustomWAF", 0.9]
        },
        "body_patterns": {
            "Access Denied by CustomWAF": ["CustomWAF", 0.85]
        }
    },
    "tech_signatures": {
        "body_patterns": {
            "/custom-cms/": ["CustomCMS", 0.8]
        },
        "cookie_patterns": {
            "custom_session": ["CustomCMS", 0.9]
        },
        "probe_paths": [
            ["custom-admin/", "CustomCMS"]
        ]
    },
    "wordlist_map": {
        "CustomCMS": "common.txt"
    }
}
"""

import os
import json
from typing import Dict, List, Tuple, Any, Optional


class SignatureLoader:
    def __init__(self, signatures_dir: str = None):
        if signatures_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            signatures_dir = os.path.join(base_dir, "signatures")
        self.signatures_dir = signatures_dir
        self.loaded_packs: List[Dict[str, Any]] = []
        self._waf_header_sigs: Dict[str, Tuple[str, float]] = {}
        self._waf_body_sigs: Dict[str, Tuple[str, float]] = {}
        self._tech_body_sigs: Dict[str, Tuple[str, float]] = {}
        self._tech_cookie_sigs: Dict[str, Tuple[str, float]] = {}
        self._tech_probe_paths: List[Tuple[str, str]] = []
        self._wordlist_map: Dict[str, str] = {}

    def load_all(self) -> int:
        """Load all .json signature packs from the signatures directory.
        Returns the number of packs successfully loaded."""
        if not os.path.isdir(self.signatures_dir):
            return 0

        count = 0
        for fname in sorted(os.listdir(self.signatures_dir)):
            if fname.endswith(".json"):
                fpath = os.path.join(self.signatures_dir, fname)
                try:
                    pack = self._load_pack(fpath)
                    if pack:
                        self.loaded_packs.append(pack)
                        count += 1
                except (json.JSONDecodeError, IOError, KeyError) as e:
                    pass  # Skip invalid packs silently
        return count

    def _load_pack(self, path: str) -> Optional[Dict[str, Any]]:
        """Load and parse a single signature pack."""
        with open(path, "r") as f:
            data = json.load(f)

        pack_name = data.get("name", os.path.basename(path))

        # WAF signatures
        waf_sigs = data.get("waf_signatures", {})
        for pattern, (name, confidence) in waf_sigs.get("header_patterns", {}).items():
            self._waf_header_sigs[pattern] = (name, float(confidence))
        for pattern, (name, confidence) in waf_sigs.get("body_patterns", {}).items():
            self._waf_body_sigs[pattern] = (name, float(confidence))

        # Tech signatures
        tech_sigs = data.get("tech_signatures", {})
        for pattern, (name, confidence) in tech_sigs.get("body_patterns", {}).items():
            self._tech_body_sigs[pattern] = (name, float(confidence))
        for pattern, (name, confidence) in tech_sigs.get("cookie_patterns", {}).items():
            self._tech_cookie_sigs[pattern] = (name, float(confidence))
        for probe in tech_sigs.get("probe_paths", []):
            if len(probe) == 2:
                self._tech_probe_paths.append((probe[0], probe[1]))

        # Wordlist map
        for tech, wordlist in data.get("wordlist_map", {}).items():
            self._wordlist_map[tech] = wordlist

        return {"name": pack_name, "path": path, "data": data}

    @property
    def waf_header_signatures(self) -> Dict[str, Tuple[str, float]]:
        return self._waf_header_sigs

    @property
    def waf_body_signatures(self) -> Dict[str, Tuple[str, float]]:
        return self._waf_body_sigs

    @property
    def tech_body_signatures(self) -> Dict[str, Tuple[str, float]]:
        return self._tech_body_sigs

    @property
    def tech_cookie_signatures(self) -> Dict[str, Tuple[str, float]]:
        return self._tech_cookie_sigs

    @property
    def tech_probe_paths(self) -> List[Tuple[str, str]]:
        return self._tech_probe_paths

    @property
    def wordlist_map(self) -> Dict[str, str]:
        return self._wordlist_map

    def get_pack_names(self) -> List[str]:
        return [p["name"] for p in self.loaded_packs]
