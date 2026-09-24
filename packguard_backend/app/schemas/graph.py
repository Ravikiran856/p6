"""Dependency graph visualization schemas."""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

RiskLabel = Literal["safe", "suspicious", "high_risk", "unknown"]


class GraphNode(BaseModel):
    id: str
    label: str
    package_name: str = Field(..., alias="packageName")
    version: str
    risk_level: RiskLabel = Field(..., alias="riskLevel")
    risk_score: float = Field(0.0, alias="riskScore")
    risk_color: str = Field(..., alias="risk_color")
    in_degree: int = Field(0, alias="inDegree")
    degree_centrality: float = Field(0.0, alias="degreeCentrality")
    depth_in_tree: int = Field(0, alias="depthInTree")
    criticality_label: str = Field("Low", alias="criticalityLabel")
    blast_radius_scope: str = Field(
        "local blast radius within 3 levels", alias="blastRadiusScope"
    )

    model_config = {"populate_by_name": True}


class GraphEdge(BaseModel):
    source: str
    target: str


class DependencyGraphResponse(BaseModel):
    graph_id: str = Field(..., alias="graphId")
    root_package: str = Field(..., alias="rootPackage")
    root_version: str = Field(..., alias="rootVersion")
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    max_depth: int = Field(3, alias="maxDepth")
    blast_radius_scope: str = Field(
        "local blast radius within 3 levels", alias="blastRadiusScope"
    )

    model_config = {"populate_by_name": True}

