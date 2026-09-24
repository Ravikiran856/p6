"""Package search schemas."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class PackageSearchItem(BaseModel):
    name: str
    latest_version: Optional[str] = Field(None, alias="latestVersion")
    is_known_top_5000: bool = Field(True, alias="isKnownTop5000")

    model_config = {"populate_by_name": True}


class PackageSearchResponse(BaseModel):
    results: List[PackageSearchItem]
