"""
train_model.py
================
Trains the PackGuard risk classifier.

Pipeline:
    1. Load a labeled dataset (features + label column).
    2. Train a RandomForestClassifier (the production model).
    3. Train a simple weighted-sum rule-based baseline for comparison
       (needed for the "ML vs. baseline" ablation in the IEEE paper's
       Results section).
    4. Report precision/recall/F1/confusion-matrix for both.
    5. Persist the trained RandomForest to `ml/artifacts/risk_random_forest.pkl`.

--------------------------------------------------------------------------
PLUGGING IN A REAL DATASET
--------------------------------------------------------------------------
This script currently GENERATES a small synthetic dataset (~50 rows) so the
pipeline is runnable end-to-end without any external data. For the actual
paper, replace `generate_synthetic_dataset()` with a real, labeled CSV that
has exactly these columns (see FEATURE_ORDER in feature_extractor.py):

    has_network_call, has_file_system_access, has_command_execution,
    has_credential_access, has_code_obfuscation, has_dynamic_imports,
    external_url_count, suspicious_dependency_count, label

Good sources to build that real dataset from:
  - Backstabber's Knife Collection (DataDog Security Research) — a curated
    corpus of confirmed-malicious PyPI/npm packages with source code you can
    run `feature_extractor.extract_features()` over to get real positive
    (suspicious/high_risk) examples:
    https://github.com/DataDog/malicious-software-packages-dataset
  - Backstabber's Knife Collection paper (Ohm et al., 2020), which
    originated the "malicious PyPI/npm/RubyGems package" dataset concept.
  - For "safe" negative examples: sample the top-5000 trusted PyPI package
    list already used by `typosquat_detector.py` and run the same feature
    extractor over their source to get labeled `safe` rows.

Once you have a real CSV, just point `--csv-path` at it:
    python train_model.py --csv-path data/real_labeled_packages.csv
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Make the sibling `app/` package importable when this script is run directly
# (i.e. `python ml/train_model.py` from the repo root).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.services.static_analysis.feature_extractor import FEATURE_ORDER as STATIC_FEATURE_ORDER  # noqa: E402
from app.services.static_analysis.metadata_features import METADATA_FEATURE_ORDER  # noqa: E402

FEATURE_ORDER: list[str] = STATIC_FEATURE_ORDER + METADATA_FEATURE_ORDER

LABEL_COLUMN = "label"
LABELS = ["safe", "suspicious", "high_risk"]
ARTIFACT_PATH = os.path.join(os.path.dirname(__file__), "artifacts", "risk_random_forest.pkl")
RANDOM_SEED = 42


# --------------------------------------------------------------------------- #
# 1. Synthetic dataset generator (stand-in until real labeled data exists)
# --------------------------------------------------------------------------- #
def generate_synthetic_dataset(n_rows: int = 50, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """
    Produces a small, deliberately-separable synthetic dataset so the full
    train/evaluate/save pipeline can be exercised end-to-end before real
    labeled data is available. Each label class gets its own generating
    distribution so the RandomForest has genuine signal to learn from
    (this is a placeholder for methodology validation, NOT a claim of
    real-world accuracy — the paper's real results must come from the
    Backstabber's Knife Collection-derived dataset described above).
    """
    rng = np.random.default_rng(seed)
    rows = []

    n_per_class = n_rows // 3
    remainder = n_rows - n_per_class * 3
    class_counts = {
        "safe": n_per_class + (1 if remainder > 0 else 0),
        "suspicious": n_per_class + (1 if remainder > 1 else 0),
        "high_risk": n_per_class,
    }

    for label, count in class_counts.items():
        for _ in range(count):
            if label == "safe":
                row = {
                    "has_network_call": rng.choice([0, 1], p=[0.6, 0.4]),
                    "has_file_system_access": rng.choice([0, 1], p=[0.8, 0.2]),
                    "has_command_execution": rng.choice([0, 1], p=[0.95, 0.05]),
                    "has_credential_access": rng.choice([0, 1], p=[0.97, 0.03]),
                    "has_code_obfuscation": rng.choice([0, 1], p=[0.98, 0.02]),
                    "has_dynamic_imports": rng.choice([0, 1], p=[0.85, 0.15]),
                    "external_url_count": rng.poisson(0.3),
                    "suspicious_dependency_count": rng.poisson(0.2),
                    # Metadata supply-chain features (safe: established package, multi-maintainer)
                    "maintainer_count": float(rng.integers(2, 8)),
                    "maintainer_account_age": -1.0,
                    "days_since_first_publish": float(rng.integers(500, 4500)),
                    "days_since_last_release": float(rng.integers(10, 365)),
                    "release_frequency": round(float(rng.uniform(0.5, 3.0)), 2),
                    "has_irregular_release_burst": float(rng.choice([0, 1], p=[0.95, 0.05])),
                    "declared_dependency_count": float(rng.poisson(3.0)),
                    "file_count": float(rng.integers(2, 10)),
                }
            elif label == "suspicious":
                row = {
                    "has_network_call": rng.choice([0, 1], p=[0.3, 0.7]),
                    "has_file_system_access": rng.choice([0, 1], p=[0.5, 0.5]),
                    "has_command_execution": rng.choice([0, 1], p=[0.6, 0.4]),
                    "has_credential_access": rng.choice([0, 1], p=[0.7, 0.3]),
                    "has_code_obfuscation": rng.choice([0, 1], p=[0.75, 0.25]),
                    "has_dynamic_imports": rng.choice([0, 1], p=[0.6, 0.4]),
                    "external_url_count": rng.poisson(1.5),
                    "suspicious_dependency_count": rng.poisson(1.2),
                    # Metadata supply-chain features (suspicious: newer, few maintainers)
                    "maintainer_count": float(rng.integers(1, 3)),
                    "maintainer_account_age": -1.0,
                    "days_since_first_publish": float(rng.integers(15, 180)),
                    "days_since_last_release": float(rng.integers(1, 30)),
                    "release_frequency": round(float(rng.uniform(2.0, 10.0)), 2),
                    "has_irregular_release_burst": float(rng.choice([0, 1], p=[0.6, 0.4])),
                    "declared_dependency_count": float(rng.poisson(2.0)),
                    "file_count": float(rng.integers(1, 3)),
                }
            else:  # high_risk
                row = {
                    "has_network_call": rng.choice([0, 1], p=[0.1, 0.9]),
                    "has_file_system_access": rng.choice([0, 1], p=[0.2, 0.8]),
                    "has_command_execution": rng.choice([0, 1], p=[0.15, 0.85]),
                    "has_credential_access": rng.choice([0, 1], p=[0.2, 0.8]),
                    "has_code_obfuscation": rng.choice([0, 1], p=[0.25, 0.75]),
                    "has_dynamic_imports": rng.choice([0, 1], p=[0.3, 0.7]),
                    "external_url_count": rng.poisson(3.5),
                    "suspicious_dependency_count": rng.poisson(2.8),
                    # Metadata supply-chain features (high-risk: brand new package, single maintainer, bursts)
                    "maintainer_count": float(rng.choice([0, 1], p=[0.3, 0.7])),
                    "maintainer_account_age": -1.0,
                    "days_since_first_publish": float(rng.integers(0, 10)),
                    "days_since_last_release": float(rng.integers(0, 5)),
                    "release_frequency": round(float(rng.uniform(5.0, 30.0)), 2),
                    "has_irregular_release_burst": float(rng.choice([0, 1], p=[0.15, 0.85])),
                    "declared_dependency_count": float(rng.poisson(1.0)),
                    "file_count": 1.0,
                }
            row[LABEL_COLUMN] = label
            rows.append(row)

    df = pd.DataFrame(rows)[FEATURE_ORDER + [LABEL_COLUMN]]
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # shuffle


# --------------------------------------------------------------------------- #
# 2. Rule-based weighted-sum baseline (for the ML-vs-baseline comparison)
# --------------------------------------------------------------------------- #
# Fixed, hand-picked weights reflecting a security analyst's intuitive
# severity ranking — this is intentionally simple/interpretable so it is a
# fair, transparent "no-ML" comparison point, not a competing black box.
BASELINE_WEIGHTS = {
    "has_network_call": 8,
    "has_file_system_access": 8,
    "has_command_execution": 20,
    "has_credential_access": 20,
    "has_code_obfuscation": 25,
    "has_dynamic_imports": 10,
    "external_url_count": 4,          # per URL found, capped implicitly by data
    "suspicious_dependency_count": 6,  # per suspicious dependency
    "has_irregular_release_burst": 15, # rapid burst penalty
}


def baseline_predict(df: pd.DataFrame) -> np.ndarray:
    """
    Computes a 0-100 weighted-sum risk score per row and buckets it into
    safe / suspicious / high_risk using fixed cutoffs. This is the
    "rule-based" system the Random Forest is compared against.
    """
    scores = np.zeros(len(df))
    for feature, weight in BASELINE_WEIGHTS.items():
        if feature in df.columns:
            scores += df[feature].to_numpy() * weight

    # Add penalty for brand-new packages published < 14 days ago
    if "days_since_first_publish" in df.columns:
        recent_mask = df["days_since_first_publish"] < 14
        scores += np.where(recent_mask, 15, 0)
    scores = np.clip(scores, 0, 100)

    labels = np.where(scores >= 60, "high_risk", np.where(scores >= 30, "suspicious", "safe"))
    return labels


# --------------------------------------------------------------------------- #
# 3. Train / evaluate / persist
# --------------------------------------------------------------------------- #
def train_and_evaluate(df: pd.DataFrame) -> Tuple[RandomForestClassifier, dict]:
    X = df[FEATURE_ORDER]
    y = df[LABEL_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=RANDOM_SEED, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=6,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_SEED,
    )
    clf.fit(X_train, y_train)

    y_pred_rf = clf.predict(X_test)
    y_pred_baseline = baseline_predict(X_test)

    metrics = {
        "random_forest": _summarize(y_test, y_pred_rf, "Random Forest"),
        "baseline": _summarize(y_test, y_pred_baseline, "Rule-Based Baseline"),
    }
    return clf, metrics


def _summarize(y_true: pd.Series, y_pred: np.ndarray, model_name: str) -> dict:
    print(f"\n=== {model_name} ===")
    report = classification_report(y_true, y_pred, labels=LABELS, zero_division=0)
    print(report)

    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    print("Confusion matrix (rows=true, cols=predicted), label order:", LABELS)
    print(cm)

    return {
        "precision_macro": precision_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0),
        "confusion_matrix": cm.tolist(),
    }


def save_model(clf: RandomForestClassifier, path: str = ARTIFACT_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump({"model": clf, "feature_order": FEATURE_ORDER, "labels": LABELS}, path)
    print(f"\nSaved trained Random Forest to: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the PackGuard risk classifier.")
    parser.add_argument(
        "--csv-path",
        type=str,
        default=None,
        help="Path to a real labeled CSV (see module docstring for required "
        "columns). If omitted, a synthetic dataset is generated instead.",
    )
    parser.add_argument("--n-rows", type=int, default=50, help="Synthetic dataset size.")
    args = parser.parse_args()

    if args.csv_path:
        print(f"Loading labeled dataset from {args.csv_path} ...")
        df = pd.read_csv(args.csv_path)
        missing = set(FEATURE_ORDER + [LABEL_COLUMN]) - set(df.columns)
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}")
    else:
        print(
            f"No --csv-path given: generating a synthetic {args.n_rows}-row "
            "placeholder dataset. See this file's module docstring for how "
            "to plug in Backstabber's Knife Collection or another real, "
            "labeled dataset."
        )
        df = generate_synthetic_dataset(n_rows=args.n_rows)

    print(f"\nDataset shape: {df.shape}")
    print("Label distribution:\n", df[LABEL_COLUMN].value_counts())

    clf, metrics = train_and_evaluate(df)
    save_model(clf)

    print("\n=== Summary (macro-averaged) ===")
    for model_name, m in metrics.items():
        print(
            f"{model_name:15s} precision={m['precision_macro']:.3f}  "
            f"recall={m['recall_macro']:.3f}  f1={m['f1_macro']:.3f}"
        )


if __name__ == "__main__":
    main()
