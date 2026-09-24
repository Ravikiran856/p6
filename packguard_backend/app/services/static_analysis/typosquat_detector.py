"""
typosquat_detector.py
======================
Scores how likely a package name is to be a typosquat of a well-known,
trusted PyPI package (e.g. "reqeusts" / "reqeusts1" vs "requests").

Two independent similarity signals are combined:

1. Levenshtein ratio — classic edit-distance similarity (insertions,
   deletions, substitutions all cost 1). Catches missing/extra/transposed
   characters and appended digits ("requests1").

2. Keyboard-adjacency-weighted edit distance — a *custom* edit distance
   where substituting a character for a QWERTY-adjacent key is cheaper
   (0.5) than a substitution for a non-adjacent key (1.0). This models the
   realistic typo distribution better than plain Levenshtein: "reqiests"
   (i is adjacent to u) is a much more *plausible* accidental typo of
   "requests" than a random 1-edit-distance string would be, and typosquatters
   deliberately exploit this same plausibility. Converted to a 0-1
   similarity the same way as the Levenshtein ratio.

Both use only the Python standard library plus (optionally) `rapidfuzz` /
`python-Levenshtein` for speed. A pure-Python fallback is included so this
module has zero hard dependencies and always runs, which matters for a
reproducible IEEE-paper artifact.

`typosquat_score` is the weighted average of the two signals, scaled to
0-100. A name is only reported as a typosquat match if the closest trusted
package's score clears `threshold` AND the two names are not identical
(scanning "requests" against the list containing "requests" must not flag
itself).
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Optional accelerated backend. Falls back to a pure-Python implementation
# below if neither is installed, so the module never hard-fails.
# --------------------------------------------------------------------------- #
try:
    from rapidfuzz.distance import Levenshtein as _rf_levenshtein

    def _levenshtein_distance(a: str, b: str) -> int:
        return _rf_levenshtein.distance(a, b)

except ImportError:  # pragma: no cover - exercised when rapidfuzz absent
    try:
        import Levenshtein as _pylev  # python-Levenshtein package

        def _levenshtein_distance(a: str, b: str) -> int:
            return _pylev.distance(a, b)

    except ImportError:  # pragma: no cover - pure python fallback

        def _levenshtein_distance(a: str, b: str) -> int:
            """Standard O(len(a) * len(b)) Wagner–Fischer edit distance."""
            if a == b:
                return 0
            if not a:
                return len(b)
            if not b:
                return len(a)
            prev_row = list(range(len(b) + 1))
            for i, ca in enumerate(a, start=1):
                curr_row = [i] + [0] * len(b)
                for j, cb in enumerate(b, start=1):
                    cost = 0 if ca == cb else 1
                    curr_row[j] = min(
                        curr_row[j - 1] + 1,      # insertion
                        prev_row[j] + 1,          # deletion
                        prev_row[j - 1] + cost,   # substitution
                    )
                prev_row = curr_row
            return prev_row[-1]


# --------------------------------------------------------------------------- #
# QWERTY keyboard adjacency map, used to weight substitution cost.
# --------------------------------------------------------------------------- #
_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _build_adjacency() -> dict:
    adjacency: dict = {}
    for row_idx, row in enumerate(_ROWS):
        for col_idx, char in enumerate(row):
            neighbours = set()
            # same-row neighbours
            if col_idx > 0:
                neighbours.add(row[col_idx - 1])
            if col_idx < len(row) - 1:
                neighbours.add(row[col_idx + 1])
            # adjacent-row neighbours (approximate horizontal offset)
            for other_row_idx in (row_idx - 1, row_idx + 1):
                if 0 <= other_row_idx < len(_ROWS):
                    other_row = _ROWS[other_row_idx]
                    if col_idx < len(other_row):
                        neighbours.add(other_row[col_idx])
                    if col_idx - 1 >= 0 and col_idx - 1 < len(other_row):
                        neighbours.add(other_row[col_idx - 1])
            adjacency[char] = neighbours
    return adjacency


_KEYBOARD_ADJACENCY = _build_adjacency()

_ADJACENT_SUB_COST = 0.5   # cheap: plausible fat-finger typo
_DEFAULT_SUB_COST = 1.0    # expensive: unrelated key, less "accidental"
_INDEL_COST = 1.0


def _is_keyboard_adjacent(a: str, b: str) -> bool:
    return b in _KEYBOARD_ADJACENCY.get(a.lower(), set())


def _keyboard_weighted_distance(a: str, b: str) -> float:
    """
    Weighted edit distance where character substitutions between
    QWERTY-adjacent keys are cheaper than arbitrary substitutions.
    Same Wagner-Fischer DP as Levenshtein, with a variable substitution cost.
    """
    if a == b:
        return 0.0
    if not a:
        return len(b) * _INDEL_COST
    if not b:
        return len(a) * _INDEL_COST

    prev_row = [j * _INDEL_COST for j in range(len(b) + 1)]
    for i, ca in enumerate(a, start=1):
        curr_row = [i * _INDEL_COST] + [0.0] * len(b)
        for j, cb in enumerate(b, start=1):
            if ca == cb:
                sub_cost = 0.0
            elif _is_keyboard_adjacent(ca, cb):
                sub_cost = _ADJACENT_SUB_COST
            else:
                sub_cost = _DEFAULT_SUB_COST
            curr_row[j] = min(
                curr_row[j - 1] + _INDEL_COST,       # insertion
                prev_row[j] + _INDEL_COST,           # deletion
                prev_row[j - 1] + sub_cost,          # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def _ratio_from_distance(distance: float, a: str, b: str) -> float:
    """
    Normalize a raw edit distance into a 0-1 similarity ratio using the same
    convention as difflib/rapidfuzz: 1 - distance / max_possible_distance.
    """
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return max(0.0, 1.0 - (distance / max_len))


def compute_similarity(name_a: str, name_b: str) -> Tuple[float, float]:
    """
    Returns (levenshtein_ratio, keyboard_adjacency_ratio), both in [0, 1],
    comparing the two (lowercased) package names.
    """
    a, b = name_a.lower(), name_b.lower()
    lev_distance = _levenshtein_distance(a, b)
    kb_distance = _keyboard_weighted_distance(a, b)
    return _ratio_from_distance(lev_distance, a, b), _ratio_from_distance(kb_distance, a, b)


def typosquat_score(name_a: str, name_b: str, lev_weight: float = 0.5) -> float:
    """
    Combined 0-100 typosquat similarity score between two package names.
    `lev_weight` controls the blend between plain Levenshtein similarity and
    keyboard-adjacency-weighted similarity (default: equal weight).
    """
    lev_ratio, kb_ratio = compute_similarity(name_a, name_b)
    combined = lev_weight * lev_ratio + (1 - lev_weight) * kb_ratio
    return round(combined * 100, 2)


def find_closest_match(
    candidate_name: str,
    trusted_package_names: Iterable[str],
    threshold: float = 70.0,
) -> Tuple[float, Optional[str]]:
    """
    Compare `candidate_name` against every name in `trusted_package_names`
    and return (best_score, best_match_name_or_None).

    - If `candidate_name` (case-insensitive) is itself in the trusted list,
      it's the real package, not an impostor: returns (100.0, candidate_name)
      but callers should treat an exact match as "not a typosquat" — see
      `is_typosquat` below for that decision logic.
    - If the best score across the whole trusted list is below `threshold`,
      returns (best_score, None): nothing suspiciously similar was found.
    """
    candidate_lower = candidate_name.lower()
    best_score = 0.0
    best_match: Optional[str] = None

    for trusted_name in trusted_package_names:
        if trusted_name.lower() == candidate_lower:
            return 100.0, trusted_name  # exact match short-circuit

        score = typosquat_score(candidate_name, trusted_name)
        if score > best_score:
            best_score = score
            best_match = trusted_name

    if best_score >= threshold:
        return best_score, best_match
    return best_score, None


def is_typosquat(
    candidate_name: str,
    trusted_package_names: Iterable[str],
    threshold: float = 70.0,
) -> Tuple[bool, float, Optional[str]]:
    """
    High-level decision helper used by the ML feature pipeline:
    returns (flagged_as_typosquat, score, nearest_trusted_name).

    A name that exactly matches a trusted name is NOT flagged (it likely
    *is* that legitimate package). Anything else scoring >= threshold
    against some trusted name IS flagged, since a near-miss to a popular
    name with a different identity is the textbook typosquat signature.
    """
    score, match = find_closest_match(candidate_name, trusted_package_names, threshold)
    if match is not None and match.lower() == candidate_name.lower():
        return False, score, match
    return (match is not None), score, match


if __name__ == "__main__":
    # Usage example / smoke test.
    #
    # NOTE on threshold choice: "reqeusts1" (transposed letters + an appended
    # digit) sits right at the edge of a 70-point cutoff because it carries
    # two edits, not one. In production, `feature_extractor.py` feeds
    # `suspicious_dependency_count` and this raw `typosquat_score` (not just
    # the boolean) into the Random Forest, so the model — not a single fixed
    # cutoff — learns the right operating point from labeled data. A
    # threshold of ~65 is a reasonable default for the standalone boolean
    # helper (`is_typosquat`) used outside the ML pipeline, e.g. for a fast
    # pre-filter or a UI warning badge.
    trusted_list: List[str] = ["requests", "numpy", "flask", "django", "pandas"]

    for test_name in ["requests", "reqeusts", "reqeusts1", "reqiests", "xyzabc123"]:
        flagged, sc, match = is_typosquat(test_name, trusted_list, threshold=65.0)
        print(f"{test_name!r:15} -> score={sc:6.2f}  match={match!r:10} flagged={flagged}")
