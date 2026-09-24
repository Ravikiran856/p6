"""Pytest fixtures for PackGuard backend tests."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Enable dev auth bypass before app import
os.environ.setdefault("ALLOW_DEV_AUTH_BYPASS", "true")

from main import create_app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    from app.services import firebase_service as fb_mod

    # Reset in-memory Firestore between tests
    for key in fb_mod._MEMORY:
        fb_mod._MEMORY[key].clear()
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer dev:pytest-user:pytest@example.com"}
