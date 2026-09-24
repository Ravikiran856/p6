"""Scan endpoint request/response schemas."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


RiskLabel = Literal["safe", "suspicious", "high_risk"]


class PackageScanRequest(BaseModel):
    package_name: str = Field(..., alias="packageName", min_length=1, max_length=214)
    version: Optional[str] = Field(None, max_length=64)

    model_config = {"populate_by_name": True}


class ScanFinding(BaseModel):
    indicator_id: str = Field(..., alias="indicatorId")
    category: str
    line_number: int = Field(..., alias="lineNumber")
    code_snippet: str = Field(..., alias="codeSnippet")
    file_path: str = Field(..., alias="filePath")
    title: Optional[str] = None
    severity: Optional[str] = "medium"

    model_config = {"populate_by_name": True}


class KnownVulnerability(BaseModel):
    cve_id: str = Field(..., alias="cveId")
    severity: str = "UNKNOWN"
    summary: str = ""
    fixed_version: Optional[str] = Field(None, alias="fixedVersion")

    model_config = {"populate_by_name": True}


class SlopsquatAnalysis(BaseModel):
    is_possible_slopsquat: bool = Field(..., alias="isPossibleSlopsquat")
    confidence: int = Field(0, ge=0, le=100)
    reason: str = ""
    detection_method: str = Field("heuristic_proxy", alias="detectionMethod")

    model_config = {"populate_by_name": True}


class ScanResultResponse(BaseModel):
    package_name: str = Field(..., alias="packageName")
    package_version: Optional[str] = Field(None, alias="packageVersion")
    risk_score: float = Field(..., alias="riskScore", ge=0, le=100)
    risk_label: RiskLabel = Field(..., alias="riskLabel")
    explanation: List[str]
    findings: List[ScanFinding] = Field(default_factory=list)
    known_vulnerabilities: List[KnownVulnerability] = Field(
        default_factory=list, alias="knownVulnerabilities"
    )
    cve_lookup_status: str = Field("ok", alias="cveLookupStatus")
    slopsquat_analysis: Optional[SlopsquatAnalysis] = Field(
        None, alias="slopsquatAnalysis"
    )
    dependency_tree: List[str] = Field(default_factory=list, alias="dependencyTree")
    timestamp: str
    scan_id: Optional[str] = Field(None, alias="scanId")

    model_config = {"populate_by_name": True}


class RequirementsScanResponse(BaseModel):
    scan_id: str = Field(..., alias="scanId")
    results: List[ScanResultResponse]
    package_count: int = Field(..., alias="packageCount")

    model_config = {"populate_by_name": True}


class HistoryItem(BaseModel):
    scan_id: str = Field(..., alias="scanId")
    type: str
    input_package_name: Optional[str] = Field(None, alias="inputPackageName")
    input_file_name: Optional[str] = Field(None, alias="inputFileName")
    overall_risk_level: Optional[RiskLabel] = Field(None, alias="overallRiskLevel")
    created_at: str = Field(..., alias="createdAt")
    package_count: int = Field(1, alias="packageCount")

    model_config = {"populate_by_name": True}


class HistoryResponse(BaseModel):
    items: List[HistoryItem]
    next_cursor: Optional[str] = Field(None, alias="nextCursor")

    model_config = {"populate_by_name": True}


class RescanCheckResponse(BaseModel):
    checked: int
    changed: int
    alerts: List[dict]
    timestamp: str
    job_status: str = Field("completed", alias="jobStatus")

    model_config = {"populate_by_name": True}
