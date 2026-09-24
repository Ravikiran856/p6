"""Orchestrates PyPI download, static analysis, ML inference, and persistence."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import Settings
from app.services.cve_lookup import lookup_batch_cves, lookup_package_cves
from app.services.firebase_service import FirebaseService
from app.services.pypi_client import (
    PackageNotFoundError,
    PyPIClient,
    PyPIError,
    PyPITimeoutError,
    parse_dependency_name,
)
from app.services.slopsquat_detector import detect_slopsquat
from app.services.static_analysis.feature_extractor import extract_features
from app.services.static_analysis.metadata_features import fetch_metadata_features_async
from app.services.static_analysis.predict import PredictionResult, RiskModel
from app.services.static_analysis.typosquat_detector import is_typosquat
from app.services.typosquat.top_packages import get_trusted_packages

logger = logging.getLogger(__name__)

REQUIREMENTS_LINE_RE = re.compile(
    r"^\s*(?:-r|--requirement|-c|--constraint|-e|--editable)\s+", re.IGNORECASE
)
COMMENT_RE = re.compile(r"\s+#.*$")


def parse_requirements_txt(content: str) -> List[str]:
    """Parse requirements.txt lines into normalized package names."""
    packages: List[str] = []
    seen: set[str] = set()

    for raw_line in content.splitlines():
        line = COMMENT_RE.sub("", raw_line).strip()
        if not line or line.startswith("#"):
            continue
        if REQUIREMENTS_LINE_RE.match(line):
            raise ValueError(
                f"Nested requirement files are not supported: {line}"
            )
        # Strip version specifiers and extras: pkg[extra]>=1.0
        name_part = re.split(r"[>=<~!;\[]", line, maxsplit=1)[0].strip()
        if not name_part or name_part.startswith("-"):
            continue
        normalized = name_part.lower().replace("_", "-")
        if normalized not in seen:
            seen.add(normalized)
            packages.append(normalized)

    if not packages:
        raise ValueError("requirements.txt contains no valid package names")

    return packages


def _severity_for_label(label: str) -> str:
    return {"safe": "low", "suspicious": "medium", "high_risk": "high"}.get(
        label, "medium"
    )


def _features_to_static_analysis(feature_dict: Dict[str, float]) -> Dict[str, Any]:
    return {
        "usesNetworkCalls": bool(feature_dict.get("has_network_call")),
        "usesFileSystemAccess": bool(feature_dict.get("has_file_system_access")),
        "usesCommandExecution": bool(feature_dict.get("has_command_execution")),
        "accessesCredentials": bool(feature_dict.get("has_credential_access")),
        "isObfuscated": bool(feature_dict.get("has_code_obfuscation")),
        "usesDynamicImports": bool(feature_dict.get("has_dynamic_imports")),
        "suspiciousUrls": [],
    }


def _explanation_to_flagged_reasons(explanation: List[str]) -> List[Dict[str, Any]]:
    reasons = []
    for idx, message in enumerate(explanation):
        severity = "high" if any(
            kw in message.lower()
            for kw in ("exec", "command", "credential", "obfuscat", "similar")
        ) else "medium"
        reasons.append(
            {
                "code": f"REASON_{idx + 1}",
                "message": message,
                "severity": severity,
                "sourceLocation": None,
            }
        )
    return reasons


class ScanService:
    def __init__(
        self,
        settings: Settings,
        pypi: PyPIClient,
        firebase: FirebaseService,
        risk_model: RiskModel,
    ) -> None:
        self._settings = settings
        self._pypi = pypi
        self._firebase = firebase
        self._risk_model = risk_model
        self._trusted = get_trusted_packages()

    async def analyze_package(
        self,
        package_name: str,
        version: Optional[str] = None,
        cves: Optional[List[Dict[str, Any]]] = None,
        cve_status: Optional[str] = None,
    ) -> Tuple[PackageAnalysisResult, Optional[Any]]:
        """Download, analyze, and score a single package."""
        downloaded = await self._pypi.download_and_extract(package_name, version)
        try:
            static_features = extract_features(downloaded.extract_dir, set(self._trusted))

            # Query PyPI metadata and OSV.dev CVEs concurrently for optimal performance
            if cves is None:
                metadata_task = fetch_metadata_features_async(
                    package_name,
                    base_url=self._settings.pypi_base_url,
                    timeout_seconds=self._settings.pypi_timeout_seconds,
                )
                cve_task = lookup_package_cves(
                    package_name,
                    version=downloaded.metadata.version,
                    base_url=self._settings.osv_base_url,
                    timeout_seconds=self._settings.osv_timeout_seconds,
                )
                metadata_features, (resolved_cves, resolved_cve_status) = await asyncio.gather(
                    metadata_task, cve_task
                )
            else:
                metadata_features = await fetch_metadata_features_async(
                    package_name,
                    base_url=self._settings.pypi_base_url,
                    timeout_seconds=self._settings.pypi_timeout_seconds,
                )
                resolved_cves = cves
                resolved_cve_status = cve_status or "ok"

            canonical_pkg = metadata_features.get("package_name") or downloaded.metadata.name
            flagged, typo_score, typo_match = is_typosquat(
                canonical_pkg, self._trusted
            )
            typo_info = (
                {"score": typo_score, "match": typo_match}
                if flagged and typo_match
                else None
            )
            # Combine static AST features and metadata features for Random Forest inference
            combined_features = {**static_features, **metadata_features}
            findings = list(getattr(static_features, "findings", []))
            if metadata_features.get("has_irregular_release_burst"):
                findings.append({
                    "indicator_id": "META_RELEASE_BURST",
                    "category": "Metadata Manipulation",
                    "line_number": 1,
                    "code_snippet": f"burst: {metadata_features.get('release_frequency')}/month",
                    "file_path": "pypi_metadata",
                    "title": "Irregular Rapid Release Burst",
                    "severity": "medium",
                })
            prediction = self._risk_model.predict(combined_features, typo_info, findings=findings)
            deps = metadata_features.get("dependency_name_list") or [
                parse_dependency_name(d)
                for d in downloaded.metadata.requires_dist
            ]
            deps = [d for d in deps if d]

            slopsquat_res = detect_slopsquat(
                canonical_pkg,
                days_since_first_publish=metadata_features.get("days_since_first_publish"),
                maintainer_count=metadata_features.get("maintainer_count"),
                trusted_packages=set(self._trusted),
            )

            return PackageAnalysisResult(
                package_name=downloaded.metadata.name,
                package_version=downloaded.metadata.version,
                features=combined_features,
                prediction=prediction,
                typosquat_score=typo_score / 100.0,
                typosquat_nearest_match=typo_match,
                dependencies=deps,
                known_vulnerabilities=resolved_cves,
                cve_lookup_status=resolved_cve_status,
                slopsquat_analysis=slopsquat_res,
            ), downloaded
        except Exception:
            self._pypi.cleanup(downloaded)
            raise

    async def scan_single_package(
        self,
        uid: str,
        package_name: str,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        scan_id = await self._firebase.create_scan(
            uid,
            scan_type="single_package",
            input_package_name=package_name,
            package_count=1,
        )
        try:
            result, downloaded = await self.analyze_package(package_name, version)
            self._pypi.cleanup(downloaded)

            result_doc = self._build_result_doc(result)
            result_id = await self._firebase.save_scan_result(uid, scan_id, result_doc)
            await self._firebase.complete_scan(
                uid, scan_id, [result_id], result.prediction.risk_label
            )
            await self._firebase.upsert_package_cache(
                result.package_name,
                result.package_version,
                result.prediction.risk_score,
                result.prediction.risk_label,
                uid,
            )

            return self._to_scan_response(scan_id, result)
        except PackageNotFoundError as exc:
            await self._firebase.fail_scan(uid, scan_id, str(exc))
            raise
        except (PyPITimeoutError, PyPIError) as exc:
            await self._firebase.fail_scan(uid, scan_id, str(exc))
            raise
        except Exception as exc:
            await self._firebase.fail_scan(uid, scan_id, str(exc))
            logger.exception("Scan failed for %s", package_name)
            raise

    async def scan_requirements_file(
        self,
        uid: str,
        content: str,
        filename: str = "requirements.txt",
    ) -> List[Dict[str, Any]]:
        packages = parse_requirements_txt(content)
        if len(packages) > self._settings.max_requirements_packages:
            raise ValueError(
                f"Too many packages ({len(packages)}). "
                f"Maximum is {self._settings.max_requirements_packages}."
            )

        scan_id = await self._firebase.create_scan(
            uid,
            scan_type="requirements_file",
            input_file_name=filename,
            package_count=len(packages),
        )

        # Batch query all packages in one OSV.dev request (up to 1000 per call)
        batch_cves, batch_cve_status = await lookup_batch_cves(
            [(pkg, None) for pkg in packages],
            base_url=self._settings.osv_base_url,
            timeout_seconds=self._settings.osv_timeout_seconds,
        )

        results: List[Dict[str, Any]] = []
        result_refs: List[str] = []
        worst_label = "safe"
        label_rank = {"safe": 0, "suspicious": 1, "high_risk": 2}

        for pkg in packages:
            try:
                pkg_cves = batch_cves.get(pkg, [])
                analysis, downloaded = await self.analyze_package(
                    pkg,
                    cves=pkg_cves,
                    cve_status=batch_cve_status,
                )
                self._pypi.cleanup(downloaded)
                result_doc = self._build_result_doc(analysis)
                result_id = await self._firebase.save_scan_result(
                    uid, scan_id, result_doc
                )
                result_refs.append(result_id)
                if label_rank[analysis.prediction.risk_label] > label_rank[worst_label]:
                    worst_label = analysis.prediction.risk_label
                results.append(self._to_scan_response(scan_id, analysis))
                await self._firebase.upsert_package_cache(
                    analysis.package_name,
                    analysis.package_version,
                    analysis.prediction.risk_score,
                    analysis.prediction.risk_label,
                    uid,
                )
            except PackageNotFoundError:
                logger.warning("Package not found during requirements scan: %s", pkg)
                continue
            except Exception:
                logger.exception("Failed to scan package %s in requirements file", pkg)
                continue

        if not results:
            await self._firebase.fail_scan(
                uid, scan_id, "No packages could be analyzed from requirements file"
            )
            raise ValueError("No packages could be analyzed from requirements file")

        await self._firebase.complete_scan(uid, scan_id, result_refs, worst_label)
        return results

    def _build_result_doc(self, result: "PackageAnalysisResult") -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "resultId": str(uuid.uuid4()),
            "packageName": result.package_name,
            "packageVersion": result.package_version,
            "riskScore": result.prediction.risk_score,
            "riskLevel": result.prediction.risk_label,
            "typosquatScore": result.typosquat_score,
            "typosquatNearestMatch": result.typosquat_nearest_match,
            "staticAnalysisFeatures": _features_to_static_analysis(result.features),
            "metadataFeatures": {
                "maintainerCount": result.features.get("maintainer_count"),
                "daysSinceFirstPublish": result.features.get("days_since_first_publish"),
                "daysSinceLastRelease": result.features.get("days_since_last_release"),
                "releaseFrequency": result.features.get("release_frequency"),
                "hasIrregularReleaseBurst": bool(result.features.get("has_irregular_release_burst")),
                "declaredDependencyCount": result.features.get("declared_dependency_count"),
                "fileCount": result.features.get("file_count"),
            },
            "flaggedReasons": _explanation_to_flagged_reasons(
                result.prediction.explanation
            ),
            "findings": result.prediction.findings,
            "knownVulnerabilities": result.known_vulnerabilities,
            "cveLookupStatus": result.cve_lookup_status,
            "slopsquatAnalysis": result.slopsquat_analysis,
            "dependencyGraphRef": None,
            "modelVersion": self._settings.model_version,
            "scannedAt": now,
            "explanation": result.prediction.explanation,
            "dependencyTree": result.dependencies,
        }

    def _to_scan_response(
        self, scan_id: str, result: "PackageAnalysisResult"
    ) -> Dict[str, Any]:
        return {
            "scan_id": scan_id,
            "package_name": result.package_name,
            "package_version": result.package_version,
            "risk_score": result.prediction.risk_score,
            "risk_label": result.prediction.risk_label,
            "explanation": result.prediction.explanation,
            "findings": result.prediction.findings,
            "known_vulnerabilities": result.known_vulnerabilities,
            "cve_lookup_status": result.cve_lookup_status,
            "slopsquat_analysis": result.slopsquat_analysis,
            "dependency_tree": result.dependencies,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class PackageAnalysisResult:
    def __init__(
        self,
        package_name: str,
        package_version: str,
        features: Dict[str, float],
        prediction: PredictionResult,
        typosquat_score: float,
        typosquat_nearest_match: Optional[str],
        dependencies: List[str],
        known_vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        cve_lookup_status: str = "ok",
        slopsquat_analysis: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.package_name = package_name
        self.package_version = package_version
        self.features = features
        self.prediction = prediction
        self.typosquat_score = typosquat_score
        self.typosquat_nearest_match = typosquat_nearest_match
        self.dependencies = dependencies
        self.known_vulnerabilities = known_vulnerabilities or []
        self.cve_lookup_status = cve_lookup_status
        self.slopsquat_analysis = slopsquat_analysis
