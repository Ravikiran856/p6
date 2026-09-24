"""Unit and integration tests for OSV.dev CVE lookup service."""

from __future__ import annotations

import httpx
import pytest
from unittest.mock import AsyncMock, patch

from app.services.cve_lookup import (
    lookup_batch_cves,
    lookup_package_cves,
    parse_vuln_entry,
)


def test_parse_vuln_entry_with_cve_alias():
    raw = {
        "id": "GHSA-9hjg-9r4m-mvj7",
        "aliases": ["CVE-2024-47081", "PYSEC-2026-1872"],
        "summary": "Requests vulnerable to .netrc credentials leak via malicious URLs",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.32.4"}],
                    }
                ],
            }
        ],
    }
    parsed = parse_vuln_entry(raw)
    assert parsed["cve_id"] == "CVE-2024-47081"
    assert parsed["severity"] == "MODERATE"
    assert "credentials leak" in parsed["summary"]
    assert parsed["fixed_version"] == "2.32.4"


def test_parse_vuln_entry_fallback():
    raw = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "details": "First line of long description\nSecond line with details",
    }
    parsed = parse_vuln_entry(raw)
    assert parsed["cve_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert parsed["severity"] == "UNKNOWN"
    assert parsed["summary"] == "First line of long description"
    assert parsed["fixed_version"] is None


@pytest.mark.asyncio
async def test_lookup_package_cves_timeout_handling():
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("OSV timeout")):
        vulns, status = await lookup_package_cves("test-pkg", "1.0.0", timeout_seconds=0.1)
        assert status == "unavailable"
        assert vulns == []


@pytest.mark.asyncio
async def test_lookup_package_cves_http_error_handling():
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        vulns, status = await lookup_package_cves("test-pkg", "1.0.0", timeout_seconds=0.1)
        assert status == "unavailable"
        assert vulns == []


@pytest.mark.asyncio
async def test_lookup_batch_cves_success_mock():
    mock_batch_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-1234",
                        "aliases": ["CVE-2023-9999"],
                        "summary": "Mock vulnerability 1",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "ranges": [
                                    {"events": [{"fixed": "1.5.0"}]}
                                ]
                            }
                        ],
                    }
                ]
            },
            {"vulns": []},
        ]
    }

    mock_resp = httpx.Response(200, json=mock_batch_response)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res, status = await lookup_batch_cves([("pkgA", "1.0.0"), ("pkgB", "2.0.0")])
        assert status == "ok"
        assert "pkgA" in res
        assert "pkgB" in res
        assert len(res["pkgA"]) == 1
        assert res["pkgA"][0]["cve_id"] == "CVE-2023-9999"
        assert res["pkgA"][0]["fixed_version"] == "1.5.0"
        assert res["pkgB"] == []


@pytest.mark.asyncio
async def test_lookup_batch_cves_timeout_fallback():
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Batch timeout")):
        res, status = await lookup_batch_cves([("pkgA", "1.0.0"), ("pkgB", "2.0.0")])
        assert status == "unavailable"
        assert res == {"pkgA": [], "pkgB": []}


def test_scan_package_endpoint_includes_cves(client, auth_headers):
    scan = client.post(
        "/api/v1/scan/package",
        json={"packageName": "six"},
        headers=auth_headers,
    )
    assert scan.status_code == 200
    body = scan.json()
    assert "knownVulnerabilities" in body or "known_vulnerabilities" in body
    vulns = body.get("knownVulnerabilities", body.get("known_vulnerabilities", []))
    assert isinstance(vulns, list)
    status = body.get("cveLookupStatus", body.get("cve_lookup_status", ""))
    assert status in ("ok", "unavailable")
