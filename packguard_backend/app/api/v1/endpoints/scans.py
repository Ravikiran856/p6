"""Scan, history, report, and rescan endpoints."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Optional, Union

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import Response

from app.core.rate_limit import limiter
from app.deps import (
    CurrentUser,
    get_firebase_service,
    get_rescan_watcher,
    get_scan_service,
)
from app.schemas.scan import (
    HistoryItem,
    HistoryResponse,
    PackageScanRequest,
    RequirementsScanResponse,
    RescanCheckResponse,
    ScanResultResponse,
)
from app.services.firebase_service import FirebaseService
from app.services.pdf_report_service import generate_scan_report_pdf
from app.services.pypi_client import PackageNotFoundError, PyPIError, PyPITimeoutError
from app.services.rescan_watcher import RescanWatcher
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


def _format_timestamp(value) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else ""


async def _scan_single(
    scan_service: ScanService, uid: str, name: str, version: Optional[str]
) -> ScanResultResponse:
    try:
        result = await scan_service.scan_single_package(uid, name, version)
    except PackageNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PyPITimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(exc)) from exc
    except PyPIError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return ScanResultResponse.model_validate(result)


@router.post(
    "/package",
    response_model=Union[ScanResultResponse, RequirementsScanResponse],
    status_code=status.HTTP_200_OK,
)
@limiter.limit("10/minute")
async def scan_package(
    request: Request,
    user: CurrentUser,
    scan_service: Annotated[ScanService, Depends(get_scan_service)],
    package_name: Annotated[Optional[str], Form()] = None,
    version: Annotated[Optional[str], Form()] = None,
    requirements_file: Annotated[Optional[UploadFile], File()] = None,
) -> Union[ScanResultResponse, RequirementsScanResponse]:
    """
    Scan a single PyPI package or a requirements.txt upload.

    Accepts either:
      - JSON: `{ "packageName": "requests", "version": null }`
      - multipart: `package_name` field and/or `requirements_file` upload
    """
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        body = PackageScanRequest.model_validate(await request.json())
        return await _scan_single(
            scan_service, user.uid, body.package_name, body.version
        )

    if requirements_file is not None:
        if not requirements_file.filename or not requirements_file.filename.endswith(".txt"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="requirements_file must be a .txt file",
            )
        content_bytes = await requirements_file.read()
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="requirements.txt must be UTF-8 encoded",
            ) from exc

        try:
            results_raw = await scan_service.scan_requirements_file(
                user.uid, content, requirements_file.filename
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        scan_id = results_raw[0]["scan_id"] if results_raw else ""
        return RequirementsScanResponse(
            scanId=scan_id,
            results=[ScanResultResponse.model_validate(r) for r in results_raw],
            packageCount=len(results_raw),
        )

    if package_name:
        return await _scan_single(scan_service, user.uid, package_name, version)

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail='Provide JSON {"packageName": "..."} or form fields package_name / requirements_file',
    )


@router.get("/history", response_model=HistoryResponse)
async def scan_history(
    user: CurrentUser,
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None, alias="riskLevel"),
) -> HistoryResponse:
    """Paginated scan history for the authenticated user."""
    if risk_level and risk_level not in ("safe", "suspicious", "high_risk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="riskLevel must be safe, suspicious, or high_risk",
        )

    items_raw, next_cursor = await firebase.list_scans(
        user.uid, limit=limit, cursor=cursor, risk_level=risk_level
    )

    items = [
        HistoryItem(
            scanId=item["scanId"],
            type=item["type"],
            inputPackageName=item.get("inputPackageName"),
            inputFileName=item.get("inputFileName"),
            overallRiskLevel=item.get("overallRiskLevel"),
            createdAt=_format_timestamp(item.get("createdAt")),
            packageCount=item.get("packageCount", 1),
        )
        for item in items_raw
    ]

    return HistoryResponse(items=items, nextCursor=next_cursor)


@router.get("/report/{scan_id}/pdf")
@limiter.limit("5/minute")
async def download_scan_report_pdf(
    request: Request,
    scan_id: str,
    user: CurrentUser,
    firebase: Annotated[FirebaseService, Depends(get_firebase_service)],
) -> Response:
    """Generate and return a PDF report for a completed scan."""
    scan = await firebase.get_scan(user.uid, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if scan.get("status") != "completed":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report available only for completed scans",
        )

    results = await firebase.get_scan_results(user.uid, scan_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No scan results found",
        )

    pdf_bytes = generate_scan_report_pdf(scan, results)
    filename = f"packguard_report_{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _run_rescan_background(watcher: RescanWatcher, uid: str) -> None:
    try:
        await watcher.run_rescan_check(uid=uid)
    except Exception:
        logger.exception("Background rescan check failed for uid=%s", uid)


@router.post("/rescan-check", response_model=RescanCheckResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_rescan_check(
    request: Request,
    user: CurrentUser,
    background_tasks: BackgroundTasks,
    watcher: Annotated[RescanWatcher, Depends(get_rescan_watcher)],
    run_sync: bool = Query(False, description="Run synchronously for testing"),
) -> RescanCheckResponse:
    """
    Trigger a background re-scan of previously watched packages.

    Checks PyPI for new versions and flags packages whose risk level changed.
    Powers the FCM push notification feature.
    """
    if run_sync:
        result = await watcher.run_rescan_check(uid=user.uid)
        return RescanCheckResponse(**result, jobStatus="completed")

    background_tasks.add_task(_run_rescan_background, watcher, user.uid)
    return RescanCheckResponse(
        checked=0,
        changed=0,
        alerts=[],
        timestamp=datetime.now(timezone.utc).isoformat(),
        jobStatus="queued",
    )
