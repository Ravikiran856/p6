"""Re-export of metadata_features from app.services.static_analysis.metadata_features."""

from app.services.static_analysis.metadata_features import (
    METADATA_FEATURE_ORDER,
    METADATA_DEFAULTS,
    extract_metadata_from_json,
    fetch_metadata_features,
    fetch_metadata_features_async,
    check_typosquat_from_metadata,
    to_metadata_vector,
)

__all__ = [
    "METADATA_FEATURE_ORDER",
    "METADATA_DEFAULTS",
    "extract_metadata_from_json",
    "fetch_metadata_features",
    "fetch_metadata_features_async",
    "check_typosquat_from_metadata",
    "to_metadata_vector",
]
