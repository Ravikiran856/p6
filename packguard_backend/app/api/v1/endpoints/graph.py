"""Dependency graph visualization endpoint."""

from __future__ import annotations

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.rate_limit import limiter
from app.deps import CurrentUser, get_graph_builder
from app.schemas.graph import DependencyGraphResponse, GraphEdge, GraphNode
from app.services.dependency_graph_builder import DependencyGraphBuilder
from app.services.pypi_client import PackageNotFoundError, PyPIError, PyPITimeoutError

router = APIRouter(prefix="/scan", tags=["graph"])


@router.get(
    "/dependency-graph/{package_name}",
    response_model=DependencyGraphResponse,
)
@limiter.limit("10/minute")
async def get_dependency_graph(
    request: Request,
    package_name: str,
    user: CurrentUser,
    graph_builder: Annotated[DependencyGraphBuilder, Depends(get_graph_builder)],
    version: Optional[str] = Query(None),
    max_depth: Optional[int] = Query(None, alias="maxDepth", ge=1, le=5),
) -> DependencyGraphResponse:
    """
    Return a dependency graph ready for visualization.

    Recursively scans dependencies up to depth 3 (configurable via maxDepth).
    Computes in-degree, NetworkX degree centrality, depth in tree, and criticality labels.
    NOTE: All criticality metrics represent the local blast radius within 3 levels
    and do not imply full transitive PyPI ecosystem coverage.
    """
    _ = user  # auth required; graph is user-scoped via token

    try:
        graph = await graph_builder.build_graph(
            package_name, version=version, max_depth=max_depth
        )
    except PackageNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PyPITimeoutError as exc:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(exc)) from exc
    except PyPIError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    return DependencyGraphResponse(
        graphId=graph["graph_id"],
        rootPackage=graph["root_package"],
        rootVersion=graph["root_version"],
        nodes=[GraphNode(**n) for n in graph["nodes"]],
        edges=[GraphEdge(**e) for e in graph["edges"]],
        maxDepth=max_depth or 3,
        blastRadiusScope=graph.get("blast_radius_scope", "local blast radius within 3 levels"),
    )
