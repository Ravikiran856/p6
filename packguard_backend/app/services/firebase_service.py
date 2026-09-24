"""Firestore persistence with in-memory fallback for local development."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import Settings
from app.core.security import _init_firebase

logger = logging.getLogger(__name__)

# Shared in-memory store for local dev (survives across requests when Firebase
# credentials are not configured). Module-level so all FirebaseService instances
# read/write the same data.
_MEMORY: Dict[str, Any] = {
    "users": {},
    "scans": {},
    "scan_results": {},
    "dependency_graphs": {},
    "package_scan_cache": {},
    "notifications_log": {},
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FirebaseService:
    """Read/write scan data to Firestore (or in-memory store in dev mode)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._db = None
        self._memory = _MEMORY
        if settings.firebase_credentials_path:
            _init_firebase(settings)
            from firebase_admin import firestore

            self._db = firestore.client()

    @property
    def using_firestore(self) -> bool:
        return self._db is not None

    # ------------------------------------------------------------------ users
    async def upsert_user(
        self,
        uid: str,
        email: Optional[str],
        display_name: Optional[str],
    ) -> Dict[str, Any]:
        now = _utcnow()
        doc = {
            "uid": uid,
            "email": email or "",
            "displayName": display_name,
            "createdAt": now,
            "fcmTokens": [],
            "settings": {"notifyOnRescan": True, "theme": "dark"},
        }
        if self._db:
            ref = self._db.collection("users").document(uid)
            existing = ref.get()
            if existing.exists:
                ref.update({"email": doc["email"], "displayName": doc["displayName"]})
                data = existing.to_dict() or {}
                data.update({"email": doc["email"], "displayName": doc["displayName"]})
                return data
            ref.set(doc)
            return doc

        if uid not in self._memory["users"]:
            self._memory["users"][uid] = doc
        else:
            self._memory["users"][uid].update(
                {"email": doc["email"], "displayName": doc["displayName"]}
            )
        return self._memory["users"][uid]

    async def get_user(self, uid: str) -> Optional[Dict[str, Any]]:
        if self._db:
            snap = self._db.collection("users").document(uid).get()
            return snap.to_dict() if snap.exists else None
        return self._memory["users"].get(uid)

    # ------------------------------------------------------------------ scans
    async def create_scan(
        self,
        uid: str,
        scan_type: str,
        input_package_name: Optional[str] = None,
        input_file_name: Optional[str] = None,
        package_count: int = 1,
    ) -> str:
        scan_id = str(uuid.uuid4())
        now = _utcnow()
        doc = {
            "scanId": scan_id,
            "uid": uid,
            "type": scan_type,
            "status": "analyzing",
            "inputPackageName": input_package_name,
            "inputFileName": input_file_name,
            "createdAt": now,
            "completedAt": None,
            "packageCount": package_count,
            "overallRiskLevel": None,
            "resultRefs": [],
        }
        if self._db:
            self._db.collection("users").document(uid).collection("scans").document(
                scan_id
            ).set(doc)
        else:
            self._memory["scans"][(uid, scan_id)] = doc
        return scan_id

    async def complete_scan(
        self,
        uid: str,
        scan_id: str,
        result_refs: List[str],
        overall_risk_level: str,
    ) -> None:
        now = _utcnow()
        updates = {
            "status": "completed",
            "completedAt": now,
            "resultRefs": result_refs,
            "overallRiskLevel": overall_risk_level,
        }
        if self._db:
            self._db.collection("users").document(uid).collection("scans").document(
                scan_id
            ).update(updates)
        else:
            key = (uid, scan_id)
            if key in self._memory["scans"]:
                self._memory["scans"][key].update(updates)

    async def fail_scan(self, uid: str, scan_id: str, reason: str) -> None:
        updates = {"status": "failed", "failureReason": reason, "completedAt": _utcnow()}
        if self._db:
            self._db.collection("users").document(uid).collection("scans").document(
                scan_id
            ).update(updates)
        else:
            key = (uid, scan_id)
            if key in self._memory["scans"]:
                self._memory["scans"][key].update(updates)

    async def get_scan(self, uid: str, scan_id: str) -> Optional[Dict[str, Any]]:
        if self._db:
            snap = (
                self._db.collection("users")
                .document(uid)
                .collection("scans")
                .document(scan_id)
                .get()
            )
            return snap.to_dict() if snap.exists else None
        return self._memory["scans"].get((uid, scan_id))

    async def list_scans(
        self,
        uid: str,
        limit: int = 20,
        cursor: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if self._db:
            query = (
                self._db.collection("users")
                .document(uid)
                .collection("scans")
                .order_by("createdAt", direction="DESCENDING")
            )
            if risk_level:
                query = query.where("overallRiskLevel", "==", risk_level)
            if cursor:
                cursor_doc = (
                    self._db.collection("users")
                    .document(uid)
                    .collection("scans")
                    .document(cursor)
                    .get()
                )
                if cursor_doc.exists:
                    query = query.start_after(cursor_doc)
            docs = query.limit(limit + 1).stream()
            items = [d.to_dict() for d in docs]
        else:
            items = [
                v for k, v in self._memory["scans"].items() if k[0] == uid
            ]
            items.sort(key=lambda x: x.get("createdAt", _utcnow()), reverse=True)
            if risk_level:
                items = [i for i in items if i.get("overallRiskLevel") == risk_level]
            if cursor:
                idx = next(
                    (i for i, it in enumerate(items) if it["scanId"] == cursor), -1
                )
                items = items[idx + 1 :] if idx >= 0 else items
            items = items[: limit + 1]

        next_cursor = None
        if len(items) > limit:
            next_cursor = items[limit - 1]["scanId"]
            items = items[:limit]
        return items, next_cursor

    # ----------------------------------------------------------- scan results
    async def save_scan_result(
        self,
        uid: str,
        scan_id: str,
        result_doc: Dict[str, Any],
    ) -> str:
        result_id = result_doc.get("resultId") or str(uuid.uuid4())
        result_doc["resultId"] = result_id
        if self._db:
            self._db.collection("users").document(uid).collection("scans").document(
                scan_id
            ).collection("scan_results").document(result_id).set(result_doc)
        else:
            self._memory["scan_results"][(uid, scan_id, result_id)] = result_doc
        return result_id

    async def get_scan_results(
        self, uid: str, scan_id: str
    ) -> List[Dict[str, Any]]:
        if self._db:
            docs = (
                self._db.collection("users")
                .document(uid)
                .collection("scans")
                .document(scan_id)
                .collection("scan_results")
                .stream()
            )
            return [d.to_dict() for d in docs]
        return [
            v
            for k, v in self._memory["scan_results"].items()
            if k[0] == uid and k[1] == scan_id
        ]

    async def get_scan_result_by_id(
        self, uid: str, scan_id: str, result_id: str
    ) -> Optional[Dict[str, Any]]:
        if self._db:
            snap = (
                self._db.collection("users")
                .document(uid)
                .collection("scans")
                .document(scan_id)
                .collection("scan_results")
                .document(result_id)
                .get()
            )
            return snap.to_dict() if snap.exists else None
        return self._memory["scan_results"].get((uid, scan_id, result_id))

    # ------------------------------------------------------ dependency graphs
    async def save_dependency_graph(self, graph_doc: Dict[str, Any]) -> str:
        graph_id = graph_doc.get("graphId") or str(uuid.uuid4())
        graph_doc["graphId"] = graph_id
        if self._db:
            self._db.collection("dependency_graphs").document(graph_id).set(graph_doc)
        else:
            self._memory["dependency_graphs"][graph_id] = graph_doc
        return graph_id

    async def get_dependency_graph(self, graph_id: str) -> Optional[Dict[str, Any]]:
        if self._db:
            snap = self._db.collection("dependency_graphs").document(graph_id).get()
            return snap.to_dict() if snap.exists else None
        return self._memory["dependency_graphs"].get(graph_id)

    # -------------------------------------------------------- package cache
    async def get_package_cache(
        self, package_name: str, version: str
    ) -> Optional[Dict[str, Any]]:
        key = f"{package_name}_{version}"
        if self._db:
            snap = self._db.collection("package_scan_cache").document(key).get()
            return snap.to_dict() if snap.exists else None
        return self._memory["package_scan_cache"].get(key)

    async def upsert_package_cache(
        self,
        package_name: str,
        version: str,
        risk_score: float,
        risk_level: str,
        uid: str,
    ) -> None:
        key = f"{package_name}_{version}"
        now = _utcnow()
        if self._db:
            ref = self._db.collection("package_scan_cache").document(key)
            snap = ref.get()
            if snap.exists:
                data = snap.to_dict() or {}
                watched = set(data.get("watchedByUids", []))
                watched.add(uid)
                ref.update(
                    {
                        "lastScannedAt": now,
                        "riskScore": risk_score,
                        "riskLevel": risk_level,
                        "watchedByUids": list(watched),
                    }
                )
            else:
                ref.set(
                    {
                        "packageName": package_name,
                        "version": version,
                        "lastScannedAt": now,
                        "riskScore": risk_score,
                        "riskLevel": risk_level,
                        "watchedByUids": [uid],
                    }
                )
        else:
            existing = self._memory["package_scan_cache"].get(key, {})
            watched = set(existing.get("watchedByUids", []))
            watched.add(uid)
            self._memory["package_scan_cache"][key] = {
                "packageName": package_name,
                "version": version,
                "lastScannedAt": now,
                "riskScore": risk_score,
                "riskLevel": risk_level,
                "watchedByUids": list(watched),
            }

    async def list_watched_packages(self) -> List[Dict[str, Any]]:
        if self._db:
            return [d.to_dict() for d in self._db.collection("package_scan_cache").stream()]
        return list(self._memory["package_scan_cache"].values())

    async def log_notification_event(
        self, uid: str, event: Dict[str, Any]
    ) -> None:
        event_id = event.get("eventId") or str(uuid.uuid4())
        event["eventId"] = event_id
        if self._db:
            self._db.collection("notifications_log").document(uid).collection(
                "events"
            ).document(event_id).set(event)
        else:
            self._memory["notifications_log"].setdefault(uid, {})[event_id] = event
