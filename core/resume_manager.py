"""
# Blaze - Resume Manager

Persist and restore scan state to disk so that interrupted scans can be
resumed without re-scanning paths that have already been checked.

State is serialised as JSON inside a ``.blaze_state/`` directory (configurable).
Each target URL gets its own state file, named by a deterministic hash of the
URL, so multiple scans can coexist without collision.

The ``auto_save`` method should be called on every request; it writes to disk
only when the configured interval (default 1000 requests) has elapsed,
amortising I/O cost over many requests.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# State data-class
# ---------------------------------------------------------------------------

@dataclass
class ScanState:
    """Snapshot of a scan's progress at a given point in time.

    Attributes
    ----------
    target : str
        The base URL being scanned.
    scanned_paths : set[str]
        Paths that have already been requested.
    results : list[dict]
        Serialisable scan result dicts for paths that returned interesting
        responses.
    config : dict
        The engine configuration that was active when the scan started.
        Stored so that a resumed scan uses the same settings.
    wordlist_index : int
        Index into the wordlist indicating where to resume iteration.
    total_words : int
        Total number of words in the wordlist (for progress display).
    timestamp : str
        ISO-8601 timestamp of the last state save.
    found_dirs : list[str]
        Directories discovered so far (used for recursive scanning).
    """

    target: str = ""
    scanned_paths: Set[str] = field(default_factory=set)
    results: List[dict] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    wordlist_index: int = 0
    total_words: int = 0
    timestamp: str = ""
    found_dirs: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class ResumeManager:
    """Save, load, and manage scan state on disk.

    Parameters
    ----------
    target : str
        The target URL.  Used to derive the state-file name.
    state_dir : str
        Directory in which to store state files.  Created automatically if it
        does not exist.  Default ``".blaze_state"``.

    Example
    -------
    ::

        mgr = ResumeManager("https://example.com")
        if mgr.has_saved_state():
            state = mgr.load_state()
            print(f"Resuming: {state.wordlist_index}/{state.total_words}")
        else:
            state = ScanState(target="https://example.com", total_words=50000)

        # During scanning, call auto_save on every request:
        for i, word in enumerate(wordlist[state.wordlist_index:], state.wordlist_index):
            # ... do work ...
            state.wordlist_index = i + 1
            state.scanned_paths.add(word)
            mgr.auto_save(state, interval=1000)

        mgr.clear_state()
    """

    def __init__(self, target: str, state_dir: str = ".blaze_state"):
        self.target = target
        self.state_dir = state_dir
        self._state_file = self._build_state_path(target)
        self._request_counter: int = 0
        self._last_save_counter: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_state_path(self, target: str) -> str:
        """Derive a deterministic file path for *target*."""
        url_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
        return os.path.join(self.state_dir, f"blaze_{url_hash}.json")

    @staticmethod
    def _serialise_state(state: ScanState) -> dict:
        """Convert a ``ScanState`` to a JSON-friendly dict.

        ``set`` objects are not JSON-serialisable, so ``scanned_paths`` is
        converted to a sorted list.
        """
        data = asdict(state)
        data["scanned_paths"] = sorted(data["scanned_paths"])
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        return data

    @staticmethod
    def _deserialise_state(data: dict) -> ScanState:
        """Reconstruct a ``ScanState`` from a deserialised JSON dict."""
        data["scanned_paths"] = set(data.get("scanned_paths", []))
        data["results"] = data.get("results", [])
        data["config"] = data.get("config", {})
        data["found_dirs"] = data.get("found_dirs", [])
        return ScanState(**data)

    def _ensure_state_dir(self) -> None:
        """Create the state directory if it does not already exist."""
        os.makedirs(self.state_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_state(self, state: ScanState) -> None:
        """Persist *state* to disk immediately.

        Writes to a temporary file first, then atomically renames to avoid
        corruption if the process is killed mid-write.
        """
        self._ensure_state_dir()
        data = self._serialise_state(state)
        tmp_path = self._state_file + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp_path, self._state_file)

    def load_state(self) -> Optional[ScanState]:
        """Load a previously saved state from disk.

        Returns
        -------
        ScanState or None
            The restored state, or ``None`` if no state file exists or the
            file is corrupt.
        """
        if not self.has_saved_state():
            return None
        try:
            with open(self._state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            state = self._deserialise_state(data)
            return state
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def has_saved_state(self) -> bool:
        """Return ``True`` if a state file exists for this target."""
        return os.path.isfile(self._state_file)

    def clear_state(self) -> None:
        """Delete the state file for this target, if it exists."""
        try:
            os.remove(self._state_file)
        except FileNotFoundError:
            pass

    def auto_save(self, state: ScanState, interval: int = 1000) -> bool:
        """Increment the internal request counter and save if the interval has
        been reached.

        Call this method once per request.  It only performs actual I/O every
        *interval* calls, keeping disk overhead low.

        Parameters
        ----------
        state : ScanState
            Current scan state.
        interval : int
            Number of requests between automatic saves.  Default ``1000``.

        Returns
        -------
        bool
            ``True`` if a save was performed, ``False`` otherwise.
        """
        self._request_counter += 1
        if self._request_counter - self._last_save_counter >= interval:
            self.save_state(state)
            self._last_save_counter = self._request_counter
            return True
        return False

    # ------------------------------------------------------------------
    # Informational helpers
    # ------------------------------------------------------------------

    def resume_info(self, state: ScanState) -> Dict[str, object]:
        """Return a summary dict suitable for display to the user.

        Keys: ``target``, ``scanned``, ``remaining``, ``results_found``,
        ``found_dirs``, ``saved_at``.
        """
        scanned = len(state.scanned_paths)
        remaining = max(state.total_words - state.wordlist_index, 0)
        return {
            "target": state.target,
            "scanned": scanned,
            "remaining": remaining,
            "progress_pct": (
                round(state.wordlist_index / state.total_words * 100, 1)
                if state.total_words > 0
                else 0.0
            ),
            "results_found": len(state.results),
            "found_dirs": len(state.found_dirs),
            "saved_at": state.timestamp,
        }

    @property
    def state_file_path(self) -> str:
        """Absolute or relative path to the state file for this target."""
        return self._state_file
