"""Firestore scan document serializers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


def scan_to_firestore(
    scan_id: str,
    uid: str,
    scan_type: str,
    *,
    input_package_name: Optional[str] = None,
    input_file_name: Optional[str] = None,
    package_count: int = 1,
    status: str = "queued",
) -> Dict[str, Any]:
    return {
        "scanId": scan_id,
        "uid": uid,
        "type": scan_type,
        "status": status,
        "inputPackageName": input_package_name,
        "inputFileName": input_file_name,
        "createdAt": datetime.utcnow(),
        "completedAt": None,
        "packageCount": package_count,
        "overallRiskLevel": None,
        "resultRefs": [],
    }


def scan_result_to_firestore(
    result_id: str,
    package_name: str,
    package_version: str,
    risk_score: float,
    risk_level: str,
    *,
    typosquat_score: float = 0.0,
    typosquat_nearest_match: Optional[str] = None,
    static_features: Optional[Dict[str, Any]] = None,
    flagged_reasons: Optional[List[Dict[str, Any]]] = None,
    model_version: str = "rf_v1.0",
    explanation: Optional[List[str]] = None,
    dependency_tree: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "resultId": result_id,
        "packageName": package_name,
        "packageVersion": package_version,
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "typosquatScore": typosquat_score,
        "typosquatNearestMatch": typosquat_nearest_match,
        "staticAnalysisFeatures": static_features or {},
        "flaggedReasons": flagged_reasons or [],
        "dependencyGraphRef": None,
        "modelVersion": model_version,
        "scannedAt": datetime.utcnow(),
        "explanation": explanation or [],
        "dependencyTree": dependency_tree or [],
    }
