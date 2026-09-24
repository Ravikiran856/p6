"""Unit tests for metadata_features module."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from app.services.static_analysis.metadata_features import (
    METADATA_DEFAULTS,
    METADATA_FEATURE_ORDER,
    _detect_irregular_bursts,
    _parse_dependencies,
    _parse_maintainer_count,
    check_typosquat_from_metadata,
    extract_metadata_from_json,
    fetch_metadata_features,
    to_metadata_vector,
)
from app.services.static_analysis.predict import RiskModel


def test_metadata_feature_order_length():
    assert len(METADATA_FEATURE_ORDER) == 8
    expected = [
        "maintainer_count",
        "maintainer_account_age",
        "days_since_first_publish",
        "days_since_last_release",
        "release_frequency",
        "has_irregular_release_burst",
        "declared_dependency_count",
        "file_count",
    ]
    assert METADATA_FEATURE_ORDER == expected


def test_parse_maintainer_count():
    info_single = {"author": "Alice"}
    assert _parse_maintainer_count(info_single) == 1.0

    info_multiple = {
        "author": "Alice, Bob",
        "maintainer_email": "Charlie <charlie@example.com>, dave@example.com",
    }
    assert _parse_maintainer_count(info_multiple) == 4.0

    # Blank author should fall back to 1.0 uploaded account
    assert _parse_maintainer_count({}) == 1.0


def test_parse_dependencies():
    info = {
        "requires_dist": [
            "urllib3<3,>=1.26",
            "certifi>=2023.5.7",
            "PySocks!=1.5.7,>=1.5.6; extra == 'socks'",
        ]
    }
    count, names = _parse_dependencies(info)
    assert count == 3.0
    assert "urllib3" in names
    assert "certifi" in names
    assert "pysocks" in names

    empty_count, empty_names = _parse_dependencies({})
    assert empty_count == 0.0
    assert empty_names == []


def test_detect_irregular_bursts():
    # 3 versions released within 2 hours -> burst
    now = datetime.now(timezone.utc)
    t1 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert _detect_irregular_bursts([t1, t2, t3]) == 1.0

    # Spaced out over months -> no burst
    t_spaced1 = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_spaced2 = datetime(2023, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_spaced3 = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    assert _detect_irregular_bursts([t_spaced1, t_spaced2, t_spaced3]) == 0.0


def test_extract_metadata_from_json_full():
    payload = {
        "info": {
            "name": "sample-pkg",
            "version": "1.2.0",
            "author": "SecTeam",
            "maintainer_email": "ops@example.com",
            "requires_dist": ["requests>=2.0", "click"],
        },
        "releases": {
            "1.0.0": [
                {
                    "upload_time_iso_8601": "2023-01-01T12:00:00Z",
                    "filename": "sample-pkg-1.0.0.tar.gz",
                }
            ],
            "1.1.0": [
                {
                    "upload_time_iso_8601": "2023-06-01T12:00:00Z",
                    "filename": "sample-pkg-1.1.0.whl",
                }
            ],
            "1.2.0": [
                {
                    "upload_time_iso_8601": "2024-01-01T12:00:00Z",
                    "filename": "sample-pkg-1.2.0.whl",
                },
                {
                    "upload_time_iso_8601": "2024-01-01T12:00:00Z",
                    "filename": "sample-pkg-1.2.0.tar.gz",
                },
            ],
        },
    }

    result = extract_metadata_from_json(payload)
    assert result["package_name"] == "sample-pkg"
    assert result["maintainer_count"] == 2.0
    assert result["maintainer_account_age"] == -1.0
    assert result["days_since_first_publish"] > 300.0
    assert result["days_since_last_release"] >= 0.0
    assert result["release_frequency"] > 0.0
    assert result["declared_dependency_count"] == 2.0
    assert result["file_count"] == 2.0
    assert result["dependency_name_list"] == ["requests", "click"]

    vec = to_metadata_vector(result)
    assert vec.shape == (8,)


def test_extract_metadata_none_safe():
    empty_result = extract_metadata_from_json({}, fallback_package_name="test-fallback")
    assert empty_result["package_name"] == "test-fallback"
    assert empty_result["maintainer_count"] == 1.0
    assert empty_result["days_since_first_publish"] == 0.0
    assert empty_result["declared_dependency_count"] == 0.0
    assert empty_result["dependency_name_list"] == []

    none_result = extract_metadata_from_json(None, fallback_package_name="test-none")
    assert none_result["package_name"] == "test-none"
    assert none_result["maintainer_count"] == 1.0


def test_check_typosquat_from_metadata():
    trusted = ["requests", "flask", "numpy"]
    meta = {"package_name": "reqeusts"}
    flagged, score, match = check_typosquat_from_metadata(meta, trusted)
    assert flagged is True
    assert match == "requests"
    assert score >= 65.0


def test_predict_with_metadata_features():
    model = RiskModel()
    sample = {
        "has_network_call": 1.0,
        "has_file_system_access": 1.0,
        "has_command_execution": 1.0,
        "has_credential_access": 1.0,
        "has_code_obfuscation": 1.0,
        "has_dynamic_imports": 0.0,
        "external_url_count": 3.0,
        "suspicious_dependency_count": 2.0,
        "maintainer_count": 1.0,
        "maintainer_account_age": -1.0,
        "days_since_first_publish": 2.0,
        "days_since_last_release": 1.0,
        "release_frequency": 18.0,
        "has_irregular_release_burst": 1.0,
        "declared_dependency_count": 2.0,
        "file_count": 1.0,
    }
    pred = model.predict(sample, typosquat_info={"score": 90.0, "match": "requests"})
    assert 0.0 <= pred.risk_score <= 100.0
    assert pred.risk_label in ("safe", "suspicious", "high_risk")
    assert len(pred.explanation) > 0
    # Burst and new publish should be captured in explanation
    assert any("burst" in exp.lower() or "recent" in exp.lower() or "requests" in exp.lower() for exp in pred.explanation)
