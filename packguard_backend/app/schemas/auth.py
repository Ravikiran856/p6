"""Auth request/response schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AuthTokenRequest(BaseModel):
    """Mobile app sends Firebase ID token after client-side signup/login."""

    id_token: str = Field(..., alias="idToken", min_length=10)

    model_config = {"populate_by_name": True}


class AuthUserResponse(BaseModel):
    uid: str
    email: Optional[str] = None
    display_name: Optional[str] = Field(None, alias="displayName")
    is_new_user: bool = Field(False, alias="isNewUser")

    model_config = {"populate_by_name": True}
