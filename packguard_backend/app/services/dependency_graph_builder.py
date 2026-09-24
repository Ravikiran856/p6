"""Build dependency graphs with per-node risk scores for visualization."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from app.core.config import Settings
from app.services.centrality import BLAST_RADIUS_SCOPE, compute_graph_centrality
from app.services.firebase_service import FirebaseService
from app.services.pypi_client import PackageNotFoundError, PyPIClient
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

RISK_COLORS = {
    "safe": "#00FF9C",
    "suspicious": "#FFB020",
    "high_risk": "#FF4757",
    "unknown": "#6B7280",
}


class DependencyGraphBuilder:
    def __init__(
        self,
        settings: Settings,
        pypi: PyPIClient,
        scan_service: ScanService,
        firebase: FirebaseService,
    ) -> None:
        self._settings = settings
        self._pypi = pypi
        self._scan_service = scan_service
        self._firebase = firebase

    async def build_graph(
        self,
        package_name: str,
        version: Optional[str] = None,
        max_depth: Optional[int] = None,
    ) -> Dict[str, Any]:
        depth_limit = max_depth or self._settings.dependency_graph_max_depth
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        visited: Set[str] = set()
        node_index: Dict[str, str] = {}

        async def _add_node(
            name: str,
            ver: str,
            risk_label: str,
            risk_score: float,
        ) -> str:
            node_key = f"{name}@{ver}"
            if node_key in node_index:
                return node_index[node_key]
            node_id = f"n{len(nodes) + 1}"
            node_index[node_key] = node_id
            nodes.append(
                {
                    "id": node_id,
                    "label": name,
                    "packageName": name,
                    "version": ver,
                    "riskLevel": risk_label,
                    "riskScore": risk_score,
                    "risk_color": RISK_COLORS.get(risk_label, RISK_COLORS["unknown"]),
                }
            )
            return node_id

        async def _walk(
            name: str,
            ver: Optional[str],
            current_depth: int,
            parent_id: Optional[str],
        ) -> None:
            if current_depth > depth_limit:
                return

            visit_key = f"{name.lower()}@{ver or 'latest'}"
            if visit_key in visited:
                if parent_id:
                    child_id = node_index.get(visit_key)
                    if child_id:
                        edges.append({"source": parent_id, "target": child_id})
                return
            visited.add(visit_key)

            try:
                analysis, downloaded = await self._scan_service.analyze_package(
                    name, ver
                )
                self._pypi.cleanup(downloaded)
            except PackageNotFoundError:
                node_id = await _add_node(name, ver or "unknown", "unknown", 0.0)
                if parent_id:
                    edges.append({"source": parent_id, "target": node_id})
                return
            except Exception:
                logger.exception("Graph walk failed for %s", name)
                node_id = await _add_node(name, ver or "unknown", "unknown", 0.0)
                if parent_id:
                    edges.append({"source": parent_id, "target": node_id})
                return

            node_id = await _add_node(
                analysis.package_name,
                analysis.package_version,
                analysis.prediction.risk_label,
                analysis.prediction.risk_score,
            )
            node_index[visit_key] = node_id

            if parent_id:
                edges.append({"source": parent_id, "target": node_id})

            if current_depth >= depth_limit:
                return

            for dep in analysis.dependencies[:20]:
                await _walk(dep, None, current_depth + 1, node_id)

        root_meta = await self._pypi.fetch_metadata(package_name, version)
        await _walk(root_meta.name, root_meta.version, 0, None)

        # Compute in-degree, NetworkX degree centrality, tree depth, and blast-radius criticality
        compute_graph_centrality(nodes, edges, root_package=root_meta.name)

        graph_id = hashlib.sha256(
            f"{root_meta.name}:{root_meta.version}:d{depth_limit}".encode()
        ).hexdigest()[:16]

        graph_doc = {
            "graphId": graph_id,
            "rootPackage": root_meta.name,
            "rootVersion": root_meta.version,
            "nodes": [
                {
                    "id": n["id"],
                    "packageName": n["packageName"],
                    "version": n["version"],
                    "riskLevel": n["riskLevel"],
                    "inDegree": n.get("inDegree", 0),
                    "degreeCentrality": n.get("degreeCentrality", 0.0),
                    "depthInTree": n.get("depthInTree", 0),
                    "criticalityLabel": n.get("criticalityLabel", "Low"),
                    "blastRadiusScope": n.get("blastRadiusScope", BLAST_RADIUS_SCOPE),
                }
                for n in nodes
            ],
            "edges": [{"from": e["source"], "to": e["target"]} for e in edges],
            "blastRadiusScope": BLAST_RADIUS_SCOPE,
            "generatedAt": datetime.now(timezone.utc),
        }
        await self._firebase.save_dependency_graph(graph_doc)

        return {
            "graph_id": graph_id,
            "root_package": root_meta.name,
            "root_version": root_meta.version,
            "nodes": nodes,
            "edges": edges,
            "blast_radius_scope": BLAST_RADIUS_SCOPE,
        }
