"""Authentication endpoints — Firebase token verification."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import Settings, get_settings
from app.core.security import verify_firebase_token
from app.deps import get_firebase_service
from app.schemas.auth import AuthTokenRequest, AuthUserResponse
from app.services.firebase_service import FirebaseService

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=AuthUserResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    body: AuthTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
) -> AuthUserResponse:
    """
    Verify Firebase ID token from client-side signup and create user profile.

    The mobile app handles account creation via Firebase Auth SDK; the backend
    only verifies the resulting ID token and persists the user document.
    """
    user = await verify_firebase_token(body.id_token, settings)
    existing = await firebase.get_user(user.uid)
    is_new = existing is None

    profile = await firebase.upsert_user(user.uid, user.email, user.display_name)

    if not is_new:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists. Use /auth/login instead.",
        )

    return AuthUserResponse(
        uid=profile["uid"],
        email=profile.get("email"),
        displayName=profile.get("displayName"),
        isNewUser=True,
    )


@router.post("/login", response_model=AuthUserResponse)
async def login(
    body: AuthTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
) -> AuthUserResponse:
    """Verify Firebase ID token from client-side login and return user profile."""
    user = await verify_firebase_token(body.id_token, settings)
    profile = await firebase.upsert_user(user.uid, user.email, user.display_name)

    return AuthUserResponse(
        uid=profile["uid"],
        email=profile.get("email"),
        displayName=profile.get("displayName"),
        isNewUser=False,
    )
