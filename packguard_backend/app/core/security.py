"""Firebase ID-token verification and auth dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings

_bearer = HTTPBearer(auto_error=False)
_firebase_initialized = False


@dataclass
class AuthenticatedUser:
    uid: str
    email: Optional[str] = None
    display_name: Optional[str] = None


def _init_firebase(settings: Settings) -> None:
    global _firebase_initialized
    if _firebase_initialized:
        return
    if not settings.firebase_credentials_path:
        return
    import firebase_admin
    from firebase_admin import credentials

    if not firebase_admin._apps:
        cred = credentials.Certificate(settings.firebase_credentials_path)
        firebase_admin.initialize_app(cred, {"projectId": settings.firebase_project_id})
    _firebase_initialized = True


async def verify_firebase_token(
    token: str,
    settings: Settings,
) -> AuthenticatedUser:
    """Verify a Firebase ID token and return the authenticated user."""
    if settings.allow_dev_auth_bypass and token.startswith("dev:"):
        parts = token.split(":", 2)
        uid = parts[1] if len(parts) > 1 else "dev-user"
        email = parts[2] if len(parts) > 2 else f"{uid}@dev.local"
        return AuthenticatedUser(uid=uid, email=email, display_name="Dev User")

    _init_firebase(settings)
    if not settings.firebase_credentials_path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Firebase credentials not configured on server",
        )

    from firebase_admin import auth

    try:
        decoded = auth.verify_id_token(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired Firebase token: {exc}",
        ) from exc

    return AuthenticatedUser(
        uid=decoded["uid"],
        email=decoded.get("email"),
        display_name=decoded.get("name"),
    )


async def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthenticatedUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )
    return await verify_firebase_token(credentials.credentials, settings)
