"""Aggregate v1 API routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import auth, graph, health, packages, scans

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(packages.router)
api_router.include_router(scans.router)
api_router.include_router(graph.router)
