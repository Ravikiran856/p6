"""Package autocomplete — used by Dashboard and Scan input as the user types."""

from __future__ import annotations

from typing import Annotated, List

from fastapi import APIRouter, Depends, Query, Request

from app.core.rate_limit import limiter
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.package import PackageSearchItem, PackageSearchResponse
from app.services.typosquat.top_packages import get_trusted_packages

router = APIRouter(prefix="/packages", tags=["packages"])


@router.get("/search", response_model=PackageSearchResponse)
@limiter.limit("60/minute")
async def search_packages(
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    q: str = Query(..., min_length=2, max_length=80),
    limit: int = Query(10, ge=1, le=25),
) -> PackageSearchResponse:
    """Prefix/substring match against the trusted top-package list."""
    _ = user, request
    needle = q.strip().lower().replace("_", "-")
    trusted = sorted(get_trusted_packages())
    hits: List[str] = [name for name in trusted if needle in name][:limit]

    # Always surface the raw query so a brand-new / typosquat name is still scannable.
    if needle not in hits and len(hits) < limit:
        hits.append(needle)

    return PackageSearchResponse(
        results=[
            PackageSearchItem(
                name=name,
                latestVersion=None,
                isKnownTop5000=name in get_trusted_packages(),
            )
            for name in hits
        ]
    )
