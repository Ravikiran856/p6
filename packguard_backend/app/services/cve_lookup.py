"""
cve_lookup.py
=============
Queries OSV.dev's batch API for known disclosed vulnerabilities (CVEs / GHSAs)
affecting PyPI packages.

Endpoint: POST https://api.osv.dev/v1/querybatch
Request shape:
  {
    "queries": [
      {
        "package": {"name": "<pkg>", "ecosystem": "PyPI"},
        "version": "<version>"
      }
    ]
  }

Threat Classification Note:
  Known CVEs are distinct from malicious-intent findings (e.g. typosquatting,
  reverse shells, or backdoors). CVEs represent publicly disclosed software
  vulnerabilities in legitimate codebases, whereas static AST analysis detects
  suspected malicious supply-chain behavior.

Resilience:
  Async error handling ensures that OSV.dev timeouts or downtime do not fail or
  block the overall scan. If unavailable, an empty list is returned with
  `cve_lookup_status: "unavailable"`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

DEFAULT_OSV_BASE_URL = "https://api.osv.dev/v1"
DEFAULT_TIMEOUT_SECONDS = 8.0
MAX_BATCH_SIZE = 1000

# In-memory cache for vulnerability details to minimize repeat network requests
_VULN_CACHE: Dict[str, Dict[str, Any]] = {}
_MAX_CACHE_ENTRIES = 2000


def _cache_put(vuln_id: str, data: Dict[str, Any]) -> None:
    if len(_VULN_CACHE) >= _MAX_CACHE_ENTRIES:
        # Evict oldest entry (dict preserves insertion order in Python 3.7+)
        first_key = next(iter(_VULN_CACHE))
        _VULN_CACHE.pop(first_key, None)
    _VULN_CACHE[vuln_id] = data


def parse_vuln_entry(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse an OSV vulnerability record into the standardized PackGuard shape:
    { "cve_id": str, "severity": str, "summary": str, "fixed_version": Optional[str] }
    """
    vuln_id = vuln_data.get("id", "UNKNOWN")
    aliases = vuln_data.get("aliases", [])

    # Prefer CVE-* identifier if present in aliases or id
    cve_id = vuln_id
    if not cve_id.startswith("CVE-"):
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

    # Determine severity level
    severity = "UNKNOWN"
    db_specific = vuln_data.get("database_specific")
    if isinstance(db_specific, dict) and "severity" in db_specific:
        severity = str(db_specific["severity"]).upper()
    elif "severity" in vuln_data and isinstance(vuln_data["severity"], list):
        for s in vuln_data["severity"]:
            if isinstance(s, dict) and "score" in s:
                severity = str(s["score"])
                break

    # Extract human-readable summary
    summary = vuln_data.get("summary")
    if not summary:
        details = vuln_data.get("details", "")
        summary = details.split("\n")[0].strip() if details else "Known vulnerability in package."
    if len(summary) > 200:
        summary = summary[:197] + "..."

    # Determine the minimum fixed version
    fixed_version: Optional[str] = None
    affected = vuln_data.get("affected", [])
    if isinstance(affected, list):
        for aff in affected:
            if isinstance(aff, dict):
                for r in aff.get("ranges", []):
                    if isinstance(r, dict):
                        for event in r.get("events", []):
                            if isinstance(event, dict) and "fixed" in event:
                                fixed_version = str(event["fixed"])
                                break
                    if fixed_version:
                        break
            if fixed_version:
                break

    return {
        "cve_id": cve_id,
        "severity": severity,
        "summary": summary,
        "fixed_version": fixed_version,
    }


async def _fetch_vuln_detail(
    client: httpx.AsyncClient,
    base_url: str,
    vuln_id: str,
) -> Dict[str, Any]:
    """Fetch full vulnerability details by ID with in-memory caching."""
    if vuln_id in _VULN_CACHE:
        return _VULN_CACHE[vuln_id]

    url = f"{base_url.rstrip('/')}/vulns/{vuln_id}"
    try:
        resp = await client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            _cache_put(vuln_id, data)
            return data
    except Exception as exc:
        logger.debug("Failed to fetch detail for vuln %s: %s", vuln_id, exc)

    return {"id": vuln_id, "summary": f"Vulnerability {vuln_id}"}


async def _resolve_vulns_for_results(
    client: httpx.AsyncClient,
    base_url: str,
    raw_results: List[Dict[str, Any]],
) -> List[List[Dict[str, Any]]]:
    """
    Given OSV batch query results, collect all unique vulnerability IDs,
    fetch their details concurrently, and parse them into standardized lists.
    """
    # Collect unique IDs needing detail lookup
    needed_ids: Set[str] = set()
    for item in raw_results:
        for v in item.get("vulns", []):
            vid = v.get("id")
            if vid and vid not in _VULN_CACHE:
                needed_ids.add(vid)

    if needed_ids:
        tasks = [_fetch_vuln_detail(client, base_url, vid) for vid in needed_ids]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Map details to parsed CVE findings per package
    resolved_per_package: List[List[Dict[str, Any]]] = []
    for item in raw_results:
        pkg_vulns: List[Dict[str, Any]] = []
        for v in item.get("vulns", []):
            vid = v.get("id")
            detail = _VULN_CACHE.get(vid, v) if vid else v
            parsed = parse_vuln_entry(detail)
            pkg_vulns.append(parsed)
        resolved_per_package.append(pkg_vulns)

    return resolved_per_package


async def lookup_package_cves(
    package_name: str,
    version: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
    base_url: str = DEFAULT_OSV_BASE_URL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Query OSV.dev batch API for known vulnerabilities for a single package.

    Returns
    -------
    (vulnerabilities_list, status_string)
    status_string is "ok" on success or "unavailable" if OSV is down/times out.
    """
    query: Dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": "PyPI"}
    }
    if version:
        query["version"] = version

    request_payload = {"queries": [query]}
    endpoint = f"{base_url.rstrip('/')}/querybatch"

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds)
        close_client = True

    try:
        resp = await client.post(endpoint, json=request_payload)
        if resp.status_code != 200:
            logger.warning(
                "OSV.dev returned non-200 status code %s for %s",
                resp.status_code,
                package_name,
            )
            return [], "unavailable"

        data = resp.json()
        results = data.get("results", [])
        if not results:
            return [], "ok"

        resolved = await _resolve_vulns_for_results(client, base_url, results)
        return (resolved[0] if resolved else []), "ok"

    except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
        logger.warning("OSV.dev querybatch failed for package %s: %s", package_name, exc)
        return [], "unavailable"
    except Exception as exc:
        logger.warning("Unexpected error during OSV CVE lookup for %s: %s", package_name, exc)
        return [], "unavailable"
    finally:
        if close_client:
            await client.aclose()


async def lookup_batch_cves(
    packages: List[Tuple[str, Optional[str]]],
    client: Optional[httpx.AsyncClient] = None,
    base_url: str = DEFAULT_OSV_BASE_URL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS * 1.5,
) -> Tuple[Dict[str, List[Dict[str, Any]]], str]:
    """
    Batch query OSV.dev for multiple packages in a single request (up to 1000 per call).

    Parameters
    ----------
    packages: List of (package_name, version) tuples.

    Returns
    -------
    (dict_mapping_package_name_to_vulnerabilities, status_string)
    """
    if not packages:
        return {}, "ok"

    endpoint = f"{base_url.rstrip('/')}/querybatch"
    queries = []
    for pkg_name, ver in packages[:MAX_BATCH_SIZE]:
        q: Dict[str, Any] = {"package": {"name": pkg_name, "ecosystem": "PyPI"}}
        if ver:
            q["version"] = ver
        queries.append(q)

    request_payload = {"queries": queries}

    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=timeout_seconds)
        close_client = True

    fallback = {pkg_name: [] for pkg_name, _ in packages}

    try:
        resp = await client.post(endpoint, json=request_payload)
        if resp.status_code != 200:
            logger.warning("OSV.dev batch query returned status %s", resp.status_code)
            return fallback, "unavailable"

        data = resp.json()
        results = data.get("results", [])
        resolved = await _resolve_vulns_for_results(client, base_url, results)

        mapped_results: Dict[str, List[Dict[str, Any]]] = {}
        for (pkg_name, _), vulns in zip(packages, resolved):
            mapped_results[pkg_name] = vulns

        return mapped_results, "ok"

    except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as exc:
        logger.warning("OSV.dev batch CVE lookup timed out or failed: %s", exc)
        return fallback, "unavailable"
    except Exception as exc:
        logger.warning("Unexpected error during OSV batch CVE lookup: %s", exc)
        return fallback, "unavailable"
    finally:
        if close_client:
            await client.aclose()


# Backward-compatible convenience aliases
lookup_single_package = lookup_package_cves
lookup_batch_packages = lookup_batch_cves


if __name__ == "__main__":
    async def _test():
        print("Testing single-package OSV lookup for requests==2.20.0...")
        vulns, status = await lookup_package_cves("requests", "2.20.0")
        print(f"Status: {status}, Total CVEs found: {len(vulns)}")
        for v in vulns[:3]:
            print(f" - {v['cve_id']} [{v['severity']}]: {v['summary']} (fixed: {v['fixed_version']})")

        print("\nTesting batch OSV lookup for ['flask', 'urllib3==1.26.4']...")
        batch_res, b_status = await lookup_batch_cves([("flask", "0.12"), ("urllib3", "1.26.4")])
        print(f"Batch Status: {b_status}")
        for pkg, vlist in batch_res.items():
            print(f" - {pkg}: {len(vlist)} known CVEs")

    asyncio.run(_test())
