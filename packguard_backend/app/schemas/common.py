"""Shared schema types."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class HealthResponse(BaseModel):
    status: str = "ok"
    model_version: str = Field(..., alias="modelVersion")
    timestamp: str

    model_config = {"populate_by_name": True}
