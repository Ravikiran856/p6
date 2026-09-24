"""Re-check previously scanned packages for version/risk drift."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import Settings
from app.services.firebase_service import FirebaseService
from app.services.pypi_client import PackageNotFoundError, PyPIClient
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)


class RescanWatcher:
    """
    Background job handler for POST /scan/rescan-check.

    In production, wire this to Celery beat:
        @celery.task
        def periodic_rescan(): asyncio.run(watcher.run_rescan_check())
    """

    def __init__(
        self,
        settings: Settings,
        firebase: FirebaseService,
        pypi: PyPIClient,
        scan_service: ScanService,
    ) -> None:
        self._settings = settings
        self._firebase = firebase
        self._pypi = pypi
        self._scan_service = scan_service

    async def run_rescan_check(self, uid: Optional[str] = None) -> Dict[str, Any]:
        """
        Re-fetch latest versions for cached packages and flag risk changes.

        If uid is provided, only re-check packages watched by that user.
        """
        watched = await self._firebase.list_watched_packages()
        if uid:
            watched = [p for p in watched if uid in p.get("watchedByUids", [])]

        alerts: List[Dict[str, Any]] = []
        checked = 0
        changed = 0

        for entry in watched:
            pkg_name = entry.get("packageName", "")
            old_version = entry.get("version", "")
            old_risk = entry.get("riskLevel", "safe")
            old_score = entry.get("riskScore", 0.0)

            try:
                meta = await self._pypi.fetch_metadata(pkg_name)
                checked += 1

                version_changed = meta.version != old_version
                needs_rescan = version_changed

                if not needs_rescan:
                    continue

                analysis, downloaded = await self._scan_service.analyze_package(
                    pkg_name, meta.version
                )
                self._pypi.cleanup(downloaded)

                new_risk = analysis.prediction.risk_label
                new_score = analysis.prediction.risk_score
                risk_rank = {"safe": 0, "suspicious": 1, "high_risk": 2}
                risk_increased = risk_rank.get(new_risk, 0) > risk_rank.get(old_risk, 0)

                for watcher_uid in entry.get("watchedByUids", []):
                    await self._firebase.upsert_package_cache(
                        pkg_name,
                        meta.version,
                        new_score,
                        new_risk,
                        watcher_uid,
                    )

                if risk_increased or (version_changed and new_risk != old_risk):
                    changed += 1
                    alert = {
                        "packageName": pkg_name,
                        "previousVersion": old_version,
                        "newVersion": meta.version,
                        "previousRiskLevel": old_risk,
                        "previousRiskScore": old_score,
                        "newRiskLevel": new_risk,
                        "newRiskScore": new_score,
                        "versionChanged": version_changed,
                        "riskIncreased": risk_increased,
                        "knownVulnerabilities": analysis.known_vulnerabilities,
                    }
                    alerts.append(alert)

                    for watcher_uid in entry.get("watchedByUids", []):
                        await self._firebase.log_notification_event(
                            watcher_uid,
                            {
                                "eventId": str(uuid.uuid4()),
                                "packageName": pkg_name,
                                "previousRiskLevel": old_risk,
                                "newRiskLevel": new_risk,
                                "sentAt": datetime.now(timezone.utc),
                                "read": False,
                            },
                        )
                        # FCM push would be dispatched here via firebase_admin.messaging
                        logger.info(
                            "Rescan alert for uid=%s pkg=%s: %s -> %s",
                            watcher_uid,
                            pkg_name,
                            old_risk,
                            new_risk,
                        )

            except PackageNotFoundError:
                logger.warning("Package removed from PyPI during rescan: %s", pkg_name)
            except Exception:
                logger.exception("Rescan failed for %s", pkg_name)

        return {
            "checked": checked,
            "changed": changed,
            "alerts": alerts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
