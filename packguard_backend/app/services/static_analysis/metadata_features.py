"""
metadata_features.py
====================
Extracts package supply-chain metadata features directly from the PyPI
JSON API (https://pypi.org/pypi/{package}/json) — no code download or execution.

Features extracted:
- maintainer_count: Count of distinct maintainers/authors listed in PyPI metadata.
- maintainer_account_age: Maintainer account age in days if exposed; safe default -1.0.
- days_since_first_publish: Days elapsed since earliest release version upload.
- days_since_last_release: Days elapsed since most recent release version upload.
- release_frequency: Average releases published per month over package lifetime.
- has_irregular_release_burst: 1.0 if >=3 versions released within a 24-hour window, else 0.0.
- declared_dependency_count: Number of unique declared dependencies in requires_dist.
- file_count: Number of archive files (wheels, sdist) in the latest release.

Additional context fields returned in dict:
- package_name: Canonical package name from PyPI.
- dependency_name_list: List of parsed distribution names.

All functions handle timeouts, 404s, network errors, and missing fields gracefully
by falling back to safe defaults without crashing the caller.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import httpx
import numpy as np

from app.services.static_analysis.typosquat_detector import is_typosquat

logger = logging.getLogger(__name__)

# Fixed feature ordering for numeric metadata features — matches downstream vector format
METADATA_FEATURE_ORDER: List[str] = [
    "maintainer_count",
    "maintainer_account_age",
    "days_since_first_publish",
    "days_since_last_release",
    "release_frequency",
    "has_irregular_release_burst",
    "declared_dependency_count",
    "file_count",
]

# None-safe default fallback dict when PyPI request times out or package is missing
METADATA_DEFAULTS: Dict[str, Any] = {
    "maintainer_count": 1.0,
    "maintainer_account_age": -1.0,  # -1.0 denotes unavailable / not reported by PyPI API
    "days_since_first_publish": 0.0,
    "days_since_last_release": 0.0,
    "release_frequency": 0.0,
    "has_irregular_release_burst": 0.0,
    "declared_dependency_count": 0.0,
    "file_count": 0.0,
    "package_name": "",
    "dependency_name_list": [],
}

from email.utils import getaddresses

DEP_NAME_PATTERN = re.compile(r"^([A-Za-z0-9_.\-]+)")


def _parse_maintainer_count(info: Dict[str, Any]) -> float:
    """
    Parses unique maintainers/authors from author, author_email, maintainer,
    and maintainer_email fields using email.utils.getaddresses for RFC-compliant
    email list parsing.
    """
    maintainers: Set[str] = set()

    for field in ("author", "maintainer"):
        raw = info.get(field)
        if raw and isinstance(raw, str) and raw.strip().lower() not in ("none", "null", ""):
            # Split comma/semicolon separated multiple maintainers
            for part in re.split(r"[,;]+", raw):
                cleaned = part.strip()
                if cleaned and len(cleaned) > 1:
                    maintainers.add(cleaned.lower())

    for email_field in ("author_email", "maintainer_email"):
        raw_email = info.get(email_field)
        if raw_email and isinstance(raw_email, str) and raw_email.strip().lower() not in ("none", "null", ""):
            for name, addr in getaddresses([raw_email]):
                if addr and addr.lower() not in ("none", "null", ""):
                    maintainers.add(addr.lower())
                elif name and name.lower() not in ("none", "null", ""):
                    maintainers.add(name.lower())

    if maintainers:
        return float(len(maintainers))

    # If package exists on PyPI but author fields are blank, at least 1 account uploaded it
    return 1.0


def _parse_iso_date(date_str: str) -> Optional[datetime]:
    """Parse ISO-8601 upload timestamp into UTC datetime."""
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        # Normalize trailing Z to +00:00 for python fromisoformat
        normalized = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _parse_dependencies(info: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Extract declared dependencies from requires_dist."""
    requires_dist = info.get("requires_dist")
    if not requires_dist or not isinstance(requires_dist, list):
        return 0.0, []

    names: List[str] = []
    seen: Set[str] = set()

    for item in requires_dist:
        if not isinstance(item, str):
            continue
        match = DEP_NAME_PATTERN.match(item.strip())
        if match:
            dep_name = match.group(1).lower().replace("_", "-")
            if dep_name not in seen:
                seen.add(dep_name)
                names.append(dep_name)

    return float(len(names)), names


def _detect_irregular_bursts(upload_timestamps: List[datetime]) -> float:
    """
    Flags whether >= 3 distinct versions were published within a 24-hour window.
    This pattern is common in malware test deployments, typo spamming, and compromised accounts.
    """
    if len(upload_timestamps) < 3:
        return 0.0

    sorted_ts = sorted(upload_timestamps)
    for i in range(len(sorted_ts)):
        count_in_24h = sum(
            1 for ts in sorted_ts[i:] if 0 <= (ts - sorted_ts[i]).total_seconds() <= 86400
        )
        if count_in_24h >= 3:
            return 1.0

    return 0.0


def extract_metadata_from_json(
    data: Dict[str, Any],
    fallback_package_name: str = "",
) -> Dict[str, Any]:
    """
    Extracts structured supply-chain features from a raw PyPI JSON response dictionary.
    Guarantees all keys in METADATA_FEATURE_ORDER are present as floats.
    """
    if not isinstance(data, dict):
        result = dict(METADATA_DEFAULTS)
        result["package_name"] = fallback_package_name
        return result

    info = data.get("info") or {}
    releases = data.get("releases") or {}

    package_name = info.get("name") or fallback_package_name or ""
    latest_version = str(info.get("version") or "")

    # 1. Maintainers
    maintainer_count = _parse_maintainer_count(info)
    # PyPI JSON API does not expose account registration timestamps; default to -1.0 safely
    maintainer_account_age = float(info.get("maintainer_account_age", -1.0))

    # 2. Release timelines & burst detection
    now = datetime.now(timezone.utc)
    version_first_upload: Dict[str, datetime] = {}

    for version, file_list in releases.items():
        if not isinstance(file_list, list):
            continue
        earliest_for_ver: Optional[datetime] = None
        for file_entry in file_list:
            if not isinstance(file_entry, dict):
                continue
            upload_str = file_entry.get("upload_time_iso_8601") or file_entry.get("upload_time")
            dt = _parse_iso_date(upload_str) if upload_str else None
            if dt is not None:
                if earliest_for_ver is None or dt < earliest_for_ver:
                    earliest_for_ver = dt
        if earliest_for_ver is not None:
            version_first_upload[version] = earliest_for_ver

    all_upload_dates = sorted(version_first_upload.values())

    if all_upload_dates:
        earliest_upload = all_upload_dates[0]
        latest_upload = all_upload_dates[-1]

        days_since_first = max(0.0, (now - earliest_upload).total_seconds() / 86400.0)
        days_since_last = max(0.0, (now - latest_upload).total_seconds() / 86400.0)

        lifetime_days = max(0.0, (latest_upload - earliest_upload).total_seconds() / 86400.0)
        lifetime_months = lifetime_days / 30.4375

        total_versions = len(all_upload_dates)
        if lifetime_months < 1.0:
            release_freq = float(total_versions)
        else:
            release_freq = round(total_versions / lifetime_months, 2)

        has_burst = _detect_irregular_bursts(all_upload_dates)
    else:
        days_since_first = 0.0
        days_since_last = 0.0
        release_freq = 0.0
        has_burst = 0.0

    # 3. Dependencies
    dep_count, dep_names = _parse_dependencies(info)

    # 4. File count in latest release
    latest_files = releases.get(latest_version, []) if latest_version else []
    file_count = float(len(latest_files)) if isinstance(latest_files, list) else 0.0

    result: Dict[str, Any] = {
        "maintainer_count": float(maintainer_count),
        "maintainer_account_age": float(maintainer_account_age),
        "days_since_first_publish": round(days_since_first, 1),
        "days_since_last_release": round(days_since_last, 1),
        "release_frequency": float(release_freq),
        "has_irregular_release_burst": float(has_burst),
        "declared_dependency_count": float(dep_count),
        "file_count": float(file_count),
        "package_name": package_name,
        "dependency_name_list": dep_names,
    }
    return result


def fetch_metadata_features(
    package_name: str,
    base_url: str = "https://pypi.org/pypi",
    timeout_seconds: float = 10.0,
) -> Dict[str, Any]:
    """
    Synchronous fetch of package metadata from PyPI JSON API.
    Catches timeouts, 404s, and connection errors gracefully.
    """
    normalized_name = package_name.strip().lower().replace("_", "-")
    url = f"{base_url.rstrip('/')}/{normalized_name}/json"

    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 404:
                logger.info("PyPI metadata not found for package %s (404)", package_name)
                fallback = dict(METADATA_DEFAULTS)
                fallback["package_name"] = package_name
                return fallback
            resp.raise_for_status()
            data = resp.json()
            return extract_metadata_from_json(data, fallback_package_name=package_name)
    except (httpx.TimeoutException, httpx.RequestError, Exception) as exc:
        logger.warning(
            "Failed or timed out fetching PyPI metadata for %s: %s; using safe defaults",
            package_name,
            exc,
        )
        fallback = dict(METADATA_DEFAULTS)
        fallback["package_name"] = package_name
        return fallback


async def fetch_metadata_features_async(
    package_name: str,
    base_url: str = "https://pypi.org/pypi",
    timeout_seconds: float = 10.0,
) -> Dict[str, Any]:
    """
    Asynchronous fetch of package metadata from PyPI JSON API.
    Catches timeouts, 404s, and connection errors gracefully.
    """
    normalized_name = package_name.strip().lower().replace("_", "-")
    url = f"{base_url.rstrip('/')}/{normalized_name}/json"

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                logger.info("PyPI metadata not found for package %s (404)", package_name)
                fallback = dict(METADATA_DEFAULTS)
                fallback["package_name"] = package_name
                return fallback
            resp.raise_for_status()
            data = resp.json()
            return extract_metadata_from_json(data, fallback_package_name=package_name)
    except (httpx.TimeoutException, httpx.RequestError, Exception) as exc:
        logger.warning(
            "Async failed or timed out fetching PyPI metadata for %s: %s; using safe defaults",
            package_name,
            exc,
        )
        fallback = dict(METADATA_DEFAULTS)
        fallback["package_name"] = package_name
        return fallback


def check_typosquat_from_metadata(
    metadata_features: Dict[str, Any],
    trusted_packages: Iterable[str],
    threshold: float = 70.0,
) -> Tuple[bool, float, Optional[str]]:
    """
    Convenience bridge feeding package_name from metadata_features into
    the existing typosquat_detector.
    """
    pkg_name = metadata_features.get("package_name") or ""
    return is_typosquat(pkg_name, trusted_packages, threshold=threshold)


def to_metadata_vector(feature_dict: Dict[str, Any]) -> np.ndarray:
    """Convert metadata feature dict into a fixed-order numpy vector."""
    return np.array([float(feature_dict.get(name, 0.0)) for name in METADATA_FEATURE_ORDER], dtype=float)
