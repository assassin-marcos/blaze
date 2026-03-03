"""
# Blaze - Pattern Generator

Generate URL path candidates from template patterns containing placeholder
tokens. This allows compact specification of large search spaces:

- ``{FUZZ}``        -- replaced by each word in the wordlist
- ``{EXT}``         -- replaced by each extension in the extension list
- ``{YEAR}``        -- replaced by years in a configurable range
- ``{MONTH}``       -- replaced by zero-padded months 01 -- 12
- ``{DAY}``         -- replaced by zero-padded days 01 -- 31
- ``{DATE}``        -- replaced by dates in both ``YYYY-MM-DD`` and
  ``YYYYMMDD`` formats over a configurable year range
- ``{NUM:start-end}`` -- replaced by zero-padded numbers in a range

Placeholders can be freely combined::

    backup-{DATE}.{EXT}
    admin-{FUZZ}/config.{EXT}
    release-v{NUM:1-20}/{FUZZ}.tar.gz

The generator performs a Cartesian product of all independent placeholder
expansions, yielding every combination.
"""

import itertools
import re
from datetime import date, timedelta
from typing import Dict, List, Optional


# Pre-compiled regex for the ``{NUM:start-end}`` token.
_NUM_PATTERN = re.compile(r"\{NUM:(\d+)-(\d+)\}")


class PatternGenerator:
    """Expand placeholder patterns into concrete path strings.

    Example
    -------
    ::

        gen = PatternGenerator()
        paths = gen.generate(
            "backup-{DATE}.{EXT}",
            extensions=["zip", "tar.gz", "sql.gz"],
        )
        # -> ['backup-2026-03-03.zip', 'backup-20260303.zip', ...]
    """

    def __init__(self) -> None:
        # Cached date strings so repeated calls don't regenerate them.
        self._date_cache: Dict[int, List[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        pattern: str,
        words: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
    ) -> List[str]:
        """Expand *pattern* into a list of concrete path strings.

        Parameters
        ----------
        pattern : str
            A path template containing zero or more placeholders.
        words : list[str], optional
            Values to substitute for ``{FUZZ}``.
        extensions : list[str], optional
            Values to substitute for ``{EXT}`` (leading dots are stripped
            automatically).

        Returns
        -------
        list[str]
            Every combination produced by expanding the placeholders.
        """
        words = words or []
        extensions = [ext.lstrip(".") for ext in (extensions or [])]

        # Build the replacement map for simple (non-NUM) tokens.
        replacements: Dict[str, List[str]] = {}

        if "{FUZZ}" in pattern:
            replacements["{FUZZ}"] = words if words else [""]

        if "{EXT}" in pattern:
            replacements["{EXT}"] = extensions if extensions else [""]

        if "{YEAR}" in pattern:
            replacements["{YEAR}"] = self._generate_years()

        if "{MONTH}" in pattern:
            replacements["{MONTH}"] = self._generate_months()

        if "{DAY}" in pattern:
            replacements["{DAY}"] = self._generate_days()

        if "{DATE}" in pattern:
            replacements["{DATE}"] = self.generate_dates()

        # Handle {NUM:start-end} -- there may be several in a single pattern.
        pattern, num_replacements = self._extract_num_tokens(pattern)
        replacements.update(num_replacements)

        return self.expand_pattern(pattern, replacements)

    def generate_dates(self, years_back: int = 5) -> List[str]:
        """Return date strings covering every first-of-month over the past
        *years_back* years, plus today, in both ``YYYY-MM-DD`` and
        ``YYYYMMDD`` formats.

        Results are cached by *years_back* so that repeated calls are free.
        """
        if years_back in self._date_cache:
            return self._date_cache[years_back]

        today = date.today()
        dates: List[str] = []
        seen: set = set()

        # Walk backwards month by month.
        current = today.replace(day=1)
        end_date = date(today.year - years_back, 1, 1)

        while current >= end_date:
            for fmt in (
                current.strftime("%Y-%m-%d"),
                current.strftime("%Y%m%d"),
            ):
                if fmt not in seen:
                    dates.append(fmt)
                    seen.add(fmt)
            # Step back one month.
            if current.month == 1:
                current = current.replace(year=current.year - 1, month=12)
            else:
                current = current.replace(month=current.month - 1)

        # Also include today's exact date.
        for fmt in (
            today.strftime("%Y-%m-%d"),
            today.strftime("%Y%m%d"),
        ):
            if fmt not in seen:
                dates.append(fmt)
                seen.add(fmt)

        self._date_cache[years_back] = dates
        return dates

    def generate_numbers(
        self, start: int, end: int, pad: int = 3,
    ) -> List[str]:
        """Return zero-padded number strings from *start* to *end* inclusive.

        Parameters
        ----------
        start : int
            First number in the range.
        end : int
            Last number in the range (inclusive).
        pad : int
            Minimum width; numbers are left-padded with zeros.  Default ``3``.
        """
        return [str(n).zfill(pad) for n in range(start, end + 1)]

    def expand_pattern(
        self,
        pattern: str,
        replacements: Dict[str, List[str]],
    ) -> List[str]:
        """Perform a Cartesian-product expansion of *pattern*.

        Every key in *replacements* that appears as a literal substring of
        *pattern* is replaced by each of the corresponding values.  When
        multiple placeholders are present the full Cartesian product is
        generated.

        Parameters
        ----------
        pattern : str
            Template string with placeholder substrings.
        replacements : dict[str, list[str]]
            Mapping of placeholder -> list of replacement values.

        Returns
        -------
        list[str]
            Expanded strings with all placeholder combinations applied.
        """
        if not replacements:
            return [pattern] if pattern else []

        # Filter to only the placeholders actually present in the pattern.
        active: Dict[str, List[str]] = {
            token: values
            for token, values in replacements.items()
            if token in pattern
        }

        if not active:
            return [pattern]

        tokens = list(active.keys())
        value_lists = [active[t] for t in tokens]

        results: List[str] = []
        for combo in itertools.product(*value_lists):
            expanded = pattern
            for token, value in zip(tokens, combo):
                expanded = expanded.replace(token, value, 1)
            results.append(expanded)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_years(years_back: int = 5) -> List[str]:
        """Years from (current - *years_back*) to current, as strings."""
        current_year = date.today().year
        return [str(y) for y in range(current_year - years_back, current_year + 1)]

    @staticmethod
    def _generate_months() -> List[str]:
        """Zero-padded months 01 -- 12."""
        return [str(m).zfill(2) for m in range(1, 13)]

    @staticmethod
    def _generate_days() -> List[str]:
        """Zero-padded days 01 -- 31."""
        return [str(d).zfill(2) for d in range(1, 32)]

    @staticmethod
    def _extract_num_tokens(
        pattern: str,
    ) -> tuple:
        """Find all ``{NUM:start-end}`` tokens, replace them with indexed
        placeholders, and return the modified pattern and replacement map.

        This allows multiple independent ``{NUM:...}`` tokens in a single
        pattern.

        Returns
        -------
        tuple[str, dict[str, list[str]]]
            (modified_pattern, replacements_dict)
        """
        replacements: Dict[str, List[str]] = {}
        counter = 0

        def _replacer(match: re.Match) -> str:
            nonlocal counter
            start = int(match.group(1))
            end = int(match.group(2))
            # Determine padding width from the longer of start/end literals.
            pad = max(len(match.group(1)), len(match.group(2)))
            placeholder = f"{{__NUM_{counter}__}}"
            replacements[placeholder] = [
                str(n).zfill(pad) for n in range(start, end + 1)
            ]
            counter += 1
            return placeholder

        modified = _NUM_PATTERN.sub(_replacer, pattern)
        return modified, replacements
