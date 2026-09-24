"""Shared FastAPI dependencies."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.core.security import AuthenticatedUser, get_current_user
from app.services.dependency_graph_builder import DependencyGraphBuilder
from app.services.firebase_service import FirebaseService
from app.services.pypi_client import PyPIClient
from app.services.rescan_watcher import RescanWatcher
from app.services.scan_service import ScanService
from app.services.static_analysis.predict import RiskModel


@lru_cache
def get_risk_model() -> RiskModel:
    settings = get_settings()
    return RiskModel(artifact_path=settings.model_path)


@lru_cache
def get_firebase_service() -> FirebaseService:
    return FirebaseService(get_settings())


def get_pypi_client(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PyPIClient:
    return PyPIClient(settings)


def get_scan_service(
    settings: Annotated[Settings, Depends(get_settings)],
    pypi: Annotated[PyPIClient, Depends(get_pypi_client)],
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
    risk_model: Annotated[RiskModel, Depends(get_risk_model)],
) -> ScanService:
    return ScanService(settings, pypi, firebase, risk_model)


def get_graph_builder(
    settings: Annotated[Settings, Depends(get_settings)],
    pypi: Annotated[PyPIClient, Depends(get_pypi_client)],
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
) -> DependencyGraphBuilder:
    return DependencyGraphBuilder(settings, pypi, scan_service, firebase)


def get_rescan_watcher(
    settings: Annotated[Settings, Depends(get_settings)],
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
    pypi: Annotated[PyPIClient, Depends(get_pypi_client)],
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
) -> RescanWatcher:
    return RescanWatcher(settings, firebase, pypi, scan_service)


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]
