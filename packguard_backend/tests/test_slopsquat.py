"""Tests for AI-hallucination slopsquatting heuristic detection."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
import pytest

from app.services.slopsquat_detector import (
    DETECTION_METHOD,
    check_curated_list,
    detect_slopsquat,
    extract_slopsquat_pattern,
    load_known_hallucinated_packages,
)


def test_extract_slopsquat_pattern():
    """Verify common AI naming convention prefix and suffix extraction."""
    # Suffixes
    base, affix, kind = extract_slopsquat_pattern("requests-utils")
    assert base == "requests"
    assert affix == "-utils"
    assert kind == "suffix"

    base, affix, kind = extract_slopsquat_pattern("flask-helper")
    assert base == "flask"
    assert affix == "-helper"
    assert kind == "suffix"

    base, affix, kind = extract_slopsquat_pattern("boto3-tools")
    assert base == "boto3"
    assert affix == "-tools"
    assert kind == "suffix"

    # Prefixes
    base, affix, kind = extract_slopsquat_pattern("pyrequests")
    assert base == "requests"
    assert affix == "py"
    assert kind == "prefix"

    base, affix, kind = extract_slopsquat_pattern("py-jwt-decoder")
    assert base == "jwt-decoder"
    assert affix == "py-"
    assert kind == "prefix"

    # Unrelated regular package name
    base, affix, kind = extract_slopsquat_pattern("my-custom-app")
    assert base is None


def test_curated_list_exact_match():
    """Verify exact match against documented slopsquatting research incidents."""
    res = detect_slopsquat("huggingface-cli")
    assert res["is_possible_slopsquat"] is True
    assert res["confidence"] >= 90
    assert "huggingface-cli" in res["reason"]
    assert "Vulcan Cyber" in res["reason"]
    assert res["detection_method"] == "heuristic_proxy"
    assert res["detectionMethod"] == "heuristic_proxy"


def test_curated_list_near_match():
    """Verify near-match (edit distance 1) against documented incidents."""
    res = detect_slopsquat("huggingface-clii")
    assert res["is_possible_slopsquat"] is True
    assert res["confidence"] >= 75
    assert "Levenshtein distance 1" in res["reason"]
    assert "huggingface-cli" in res["reason"]
    assert res["detection_method"] == "heuristic_proxy"


def test_heuristic_proxy_high_confidence():
    """Package with AI convention + popular target library + recent publish + low downloads."""
    res = detect_slopsquat(
        "requests-utils",
        days_since_first_publish=14,
        download_count=85,
        maintainer_count=1.0,
    )
    assert res["is_possible_slopsquat"] is True
    assert res["confidence"] >= 80
    assert "requests" in res["reason"]
    assert "AI naming pattern" in res["reason"]
    assert res["detection_method"] == "heuristic_proxy"


def test_heuristic_proxy_mature_package_not_flagged():
    """Old mature package (> 2 years) with high adoption must not be falsely flagged."""
    res = detect_slopsquat(
        "requests-utils",
        days_since_first_publish=1200,
        download_count=250000,
        maintainer_count=5.0,
    )
    assert res["is_possible_slopsquat"] is False
    assert res["confidence"] < 50
    assert res["detection_method"] == "heuristic_proxy"


def test_trusted_package_never_flagged():
    """Established top packages like 'requests' or 'pytest' must never be flagged."""
    for pkg in ("requests", "pytest", "numpy", "flask"):
        res = detect_slopsquat(pkg)
        assert res["is_possible_slopsquat"] is False
        assert res["confidence"] == 0
        assert "verified established top" in res["reason"]


def test_scan_package_endpoint_includes_slopsquat(client, auth_headers):
    """Integration test verifying /scan/package includes slopsquat_analysis."""
    response = client.post(
        "/api/v1/scan/package",
        json={"packageName": "six"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert "slopsquatAnalysis" in body
    analysis = body["slopsquatAnalysis"]
    assert "isPossibleSlopsquat" in analysis
    assert "confidence" in analysis
    assert "reason" in analysis
    assert analysis["detectionMethod"] == "heuristic_proxy"
