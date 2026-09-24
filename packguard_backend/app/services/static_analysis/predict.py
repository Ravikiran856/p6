"""
predict.py
===========
Loads the trained Random Forest artifact and turns a single package's
feature vector into the three things the mobile app's Results screen
needs: `risk_score` (0-100), `risk_label`, and a dynamically-generated,
human-readable `explanation`, along with structured `findings`.

Explainability design (relevant to the IEEE paper's Methodology section):
    We do NOT hardcode "if has_command_execution: say X". Instead:
      1. `clf.feature_importances_` gives the model's *global* ranking of
         which features matter most overall (Gini importance).
      2. For a specific prediction, we only surface features that are both
         (a) globally important AND (b) actually "active" in this sample
         (a boolean feature is 1, or a count feature is above zero).
      3. Each active+important feature is mapped to a natural-language
         template via `FEATURE_EXPLANATIONS`, and populated with the
         concrete value observed (e.g. count of URLs, matched package name)
         where available.
      4. Structured AST findings are directly converted to actionable
         context (e.g. "Line 47 in setup.py — Reverse Shell pattern").
      5. Findings inside install scripts (setup.py, __init__.py) receive
         configurable higher weighting via INSTALL_SCRIPT_WEIGHT = 1.5.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from app.services.static_analysis.feature_extractor import (
    FEATURE_ORDER as STATIC_FEATURE_ORDER,
    INSTALL_SCRIPT_WEIGHT,
    is_install_script_finding,
)
from app.services.static_analysis.metadata_features import (
    METADATA_DEFAULTS,
    METADATA_FEATURE_ORDER,
)

FEATURE_ORDER: List[str] = STATIC_FEATURE_ORDER + METADATA_FEATURE_ORDER

ARTIFACT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "ml", "artifacts", "risk_random_forest.pkl"
)

# Risk-score cutoffs must match the labels the model was trained on
# (`safe` / `suspicious` / `high_risk`) so the UI's three-color scheme
# (electric green / amber / red) lines up with what the model predicts.
SCORE_CUTOFFS = {"safe": (0, 30), "suspicious": (30, 60), "high_risk": (60, 100)}

# Human-readable explanation templates. `{value}` is filled in with the
# feature's concrete value when that adds information (a count, a matched
# name); purely boolean features use a static, still-specific sentence.
FEATURE_EXPLANATIONS: Dict[str, str] = {
    "has_network_call": "Package makes outbound network calls (socket/requests/urllib usage).",
    "has_file_system_access": "Package reads, writes, or deletes files on the local filesystem.",
    "has_command_execution": "Package executes shell commands or dynamic code (os.system/subprocess/eval/exec).",
    "has_credential_access": "Package accesses environment variables or credential file paths (.aws, .ssh, .env).",
    "has_code_obfuscation": "Package contains obfuscated code (base64-decoded payload passed to exec, or long string-concatenation chains).",
    "has_dynamic_imports": "Package uses dynamic imports (importlib/__import__), which can hide what modules actually run.",
    "external_url_count": "Package references {value} external URL(s) in its source or comments.",
    "suspicious_dependency_count": "Package declares {value} dependency name(s) not found in the trusted top-5000 PyPI list.",
    "has_irregular_release_burst": "Package exhibits irregular release bursts (multiple releases published in rapid succession).",
    "release_frequency": "Package has an elevated release velocity ({value} releases per month).",
    "days_since_first_publish": "Package was first published very recently (only {value} days ago).",
    "days_since_last_release": "Package has been dormant/unmaintained for {value} days.",
    "maintainer_count": "Package has few or unverified maintainers ({value} listed maintainer(s)).",
    "maintainer_account_age": "Maintainer account was registered very recently ({value} days ago).",
    "declared_dependency_count": "Package declares an unusually high dependency count ({value} dependencies).",
    "file_count": "Latest release contains an unexpected file count ({value} files).",
}

# Extra, non-model-feature context the caller may attach (e.g. from
# typosquat_detector.py) so the explanation can mention the name-similarity
# finding even though it isn't literally one of the 8 RF input features.
TYPOSQUAT_TEMPLATE = "Package name is {score:.0f}% similar to the trusted package '{match}'."


def _is_active_risk(feature_name: str, value: float) -> bool:
    """
    Determines if a feature's concrete value indicates an active security risk factor.
    Avoids erroneously flagging benign mature packages for high publish age.
    """
    if feature_name in (
        "has_network_call",
        "has_file_system_access",
        "has_command_execution",
        "has_credential_access",
        "has_code_obfuscation",
        "has_dynamic_imports",
        "has_irregular_release_burst",
    ):
        return value >= 1.0

    if feature_name in ("external_url_count", "suspicious_dependency_count"):
        return value >= 1.0

    if feature_name == "days_since_first_publish":
        # Fresh package (< 30 days old) represents higher supply-chain risk
        return 0.0 <= value <= 30.0

    if feature_name == "days_since_last_release":
        # Dormant package (> 2 years) can be abandoned or hijack risk
        return value >= 730.0

    if feature_name == "release_frequency":
        return value >= 15.0

    if feature_name == "maintainer_count":
        return value <= 1.0

    if feature_name == "maintainer_account_age":
        return 0.0 <= value <= 30.0

    if feature_name == "declared_dependency_count":
        return value >= 25.0

    return False


@dataclass
class PredictionResult:
    risk_score: float
    risk_label: str
    explanation: List[str]
    findings: List[Dict[str, Any]] = field(default_factory=list)


class RiskModel:
    """Thin wrapper around the persisted joblib artifact."""

    def __init__(self, artifact_path: str = ARTIFACT_PATH):
        artifact = joblib.load(artifact_path)
        self.model = artifact["model"]
        self.feature_order = artifact["feature_order"]
        self.labels = artifact["labels"]

        if self.feature_order != FEATURE_ORDER:
            # Defensive check: the model must have been trained on exactly
            # the columns FEATURE_ORDER currently produces, in the
            # same order, or predictions would silently be scored on the
            # wrong columns.
            raise ValueError(
                "Loaded model's feature_order does not match the current "
                "FEATURE_ORDER in predict.py. Retrain the model."
            )

    def _vector_from_dict(self, feature_dict: Dict[str, Any]) -> pd.DataFrame:
        clean_dict = dict(feature_dict)
        missing = set(self.feature_order) - set(clean_dict)
        if missing:
            # Gracefully populate missing metadata features with None-safe defaults
            for key in missing:
                if key in METADATA_DEFAULTS:
                    clean_dict[key] = METADATA_DEFAULTS[key]
            missing = set(self.feature_order) - set(clean_dict)
            if missing:
                raise ValueError(f"feature_vector is missing required keys: {missing}")

        return pd.DataFrame(
            [[float(clean_dict[name]) for name in self.feature_order]],
            columns=self.feature_order,
        )

    def _risk_score_from_proba(self, proba: np.ndarray) -> float:
        """
        Converts class probabilities into a single 0-100 continuous score by
        taking a weighted sum over ordered severity midpoints (15/45/80),
        rather than just returning `max(proba) if high_risk else ...`. This
        keeps the score continuous/smooth (e.g. a package that's 60%
        high_risk and 40% suspicious scores higher than one that's 100%
        suspicious), which is what the circular gauge in the Results screen
        is designed to display.
        """
        severity_midpoints = {"safe": 15, "suspicious": 45, "high_risk": 82}
        class_index = {label: i for i, label in enumerate(self.model.classes_)}
        score = 0.0
        for label, midpoint in severity_midpoints.items():
            idx = class_index.get(label)
            if idx is not None:
                score += proba[idx] * midpoint
        return round(float(np.clip(score, 0, 100)), 1)

    def _label_from_score(self, score: float) -> str:
        for label, (low, high) in SCORE_CUTOFFS.items():
            if low <= score < high or (label == "high_risk" and score == 100):
                return label
        return "high_risk"  # fallback, should be unreachable given cutoffs above

    def _build_explanation(
        self,
        feature_dict: Dict[str, Any],
        typosquat_info: Optional[Dict[str, float]],
        top_n: int,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[str]:
        reasons: List[str] = []

        # Optional typosquat reason first, since name-similarity is often
        # the single most decisive signal for a human reviewer
        if typosquat_info and typosquat_info.get("match"):
            reasons.append(
                TYPOSQUAT_TEMPLATE.format(
                    score=typosquat_info["score"], match=typosquat_info["match"]
                )
            )

        # Surface specific code findings (prioritizing install-script and high-severity findings)
        if findings:
            sev_rank = {"high": 3, "medium": 2, "low": 1}
            sorted_findings = sorted(
                findings,
                key=lambda f: (
                    1 if is_install_script_finding(f) else 0,
                    sev_rank.get(f.get("severity", "medium"), 0),
                ),
                reverse=True,
            )
            for f in sorted_findings:
                if len(reasons) >= top_n:
                    break
                lineno = f.get("line_number", 1)
                file_path = f.get("file_path", "source")
                title = f.get("title") or f.get("indicator_id", "Finding").replace("_", " ").title()
                snippet = f.get("code_snippet", "").strip()
                if snippet:
                    reason_str = f"Line {lineno} in {file_path} — {title}: {snippet}"
                else:
                    reason_str = f"Line {lineno} in {file_path} — {title}"
                if reason_str not in reasons:
                    reasons.append(reason_str)

        # Backfill remaining slots from global feature importances if needed
        if len(reasons) < top_n:
            importances = self.model.feature_importances_  # aligned with self.feature_order
            ranked = sorted(
                zip(self.feature_order, importances), key=lambda pair: pair[1], reverse=True
            )

            for feature_name, _importance in ranked:
                if len(reasons) >= top_n:
                    break
                if feature_name not in FEATURE_EXPLANATIONS:
                    continue
                val = float(feature_dict.get(feature_name, 0.0))
                if not _is_active_risk(feature_name, val):
                    continue
                template = FEATURE_EXPLANATIONS[feature_name]
                val_display = int(val) if val.is_integer() else f"{val:.1f}"
                reason_str = template.format(value=val_display)
                if reason_str not in reasons:
                    reasons.append(reason_str)

        if not reasons:
            reasons.append("No significant risk indicators were found in static analysis or package metadata.")

        return reasons

    def predict(
        self,
        feature_dict: Dict[str, float],
        typosquat_info: Optional[Dict[str, float]] = None,
        max_reasons: int = 5,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> PredictionResult:
        """
        Parameters
        ----------
        feature_dict:
            Output of `feature_extractor.extract_features(...)` — must
            contain exactly the keys in FEATURE_ORDER.
        typosquat_info:
            Optional dict `{"score": float, "match": str}` from
            `typosquat_detector.find_closest_match(...)`.
        max_reasons:
            Cap on how many explanation strings to return.
        findings:
            Optional list of structured AST findings. If None, checks
            `getattr(feature_dict, "findings", None)`.
        """
        if findings is None:
            findings = list(getattr(feature_dict, "findings", []))
        else:
            findings = list(findings)

        # If typosquat info is present, ensure a corresponding structured finding exists
        if typosquat_info and typosquat_info.get("match"):
            if not any(f.get("indicator_id") == "META_TYPOSQUAT" for f in findings):
                findings.append({
                    "indicator_id": "META_TYPOSQUAT",
                    "category": "Metadata Manipulation",
                    "line_number": 1,
                    "code_snippet": f"name_similarity: {typosquat_info.get('score', 0):.0f}% to '{typosquat_info.get('match')}'",
                    "file_path": "package_metadata",
                    "title": f"Typosquatting Hazard ({typosquat_info.get('match')})",
                    "severity": "high",
                })

        vector = self._vector_from_dict(feature_dict)
        proba = self.model.predict_proba(vector)[0]

        base_score = self._risk_score_from_proba(proba)

        # Install-script weighting: findings inside setup.py or __init__.py install hooks
        # receive a configurable higher weight in the final risk score calculation
        if findings and any(is_install_script_finding(f) for f in findings):
            risk_score = round(float(np.clip(base_score * INSTALL_SCRIPT_WEIGHT, 0.0, 100.0)), 1)
        else:
            risk_score = base_score

        risk_label = self._label_from_score(risk_score)
        explanation = self._build_explanation(feature_dict, typosquat_info, max_reasons, findings=findings)

        return PredictionResult(
            risk_score=risk_score,
            risk_label=risk_label,
            explanation=explanation,
            findings=findings,
        )


# --------------------------------------------------------------------------- #
# Convenience module-level function mirroring the class API
# --------------------------------------------------------------------------- #
_default_model: Optional[RiskModel] = None


def predict_risk(
    feature_dict: Dict[str, float],
    typosquat_info: Optional[Dict[str, float]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> PredictionResult:
    global _default_model
    if _default_model is None:
        _default_model = RiskModel()
    return _default_model.predict(feature_dict, typosquat_info, findings=findings)


if __name__ == "__main__":
    sample = {
        "has_network_call": 1,
        "has_file_system_access": 1,
        "has_command_execution": 1,
        "has_credential_access": 1,
        "has_code_obfuscation": 1,
        "has_dynamic_imports": 0,
        "external_url_count": 2,
        "suspicious_dependency_count": 1,
    }
    dummy_findings = [
        {
            "indicator_id": "EXEC_SUBPROCESS",
            "category": "Execution",
            "line_number": 47,
            "code_snippet": "subprocess.Popen(['/bin/sh', '-i'])",
            "file_path": "setup.py",
            "title": "Reverse Shell / Subprocess Execution",
            "severity": "high",
        }
    ]
    result = predict_risk(sample, typosquat_info={"score": 92.0, "match": "requests"}, findings=dummy_findings)
    print(f"risk_score = {result.risk_score}")
    print(f"risk_label = {result.risk_label}")
    print(f"findings count = {len(result.findings)}")
    print("explanation:")
    for reason in result.explanation:
        print(" -", reason)
