"""Unit and integration tests for dependency graph centrality and blast-radius metrics."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.centrality import (
    BLAST_RADIUS_SCOPE,
    compute_criticality_label,
    compute_graph_centrality,
)


def test_criticality_label_rules():
    """Verify criticality labels derived from in-degree and depth."""
    assert compute_criticality_label(in_degree=0, depth_in_tree=0) == "Root Package"
    assert compute_criticality_label(in_degree=0, depth_in_tree=1) == "Low"
    assert compute_criticality_label(in_degree=1, depth_in_tree=1) == "Low — 1 package depends on this"
    assert compute_criticality_label(in_degree=2, depth_in_tree=1) == "Medium — 2 packages depend on this"
    assert compute_criticality_label(in_degree=3, depth_in_tree=1) == "High — 3 packages depend on this"
    assert compute_criticality_label(in_degree=7, depth_in_tree=2) == "High — 7 packages depend on this"


def test_compute_graph_centrality_empty():
    """Empty nodes list should return empty list without errors."""
    assert compute_graph_centrality([], []) == []


def test_compute_graph_centrality_single_root():
    """Single root package has in_degree=0, depth=0, and root label."""
    nodes = [{"id": "n1", "packageName": "mypkg", "version": "1.0.0"}]
    edges = []

    result = compute_graph_centrality(nodes, edges, root_package="mypkg")
    assert len(result) == 1
    root = result[0]
    assert root["in_degree"] == 0
    assert root["depth_in_tree"] == 0
    assert root["criticality_label"] == "Root Package"
    assert root["blast_radius_scope"] == BLAST_RADIUS_SCOPE
    assert root["degree_centrality"] == 1.0


def test_compute_graph_centrality_multi_tier():
    """
    Test a 3-tier tree with diamond dependencies:
    root -> dep_a -> shared_lib
    root -> dep_b -> shared_lib
    root -> dep_c -> shared_lib
    """
    nodes = [
        {"id": "n1", "packageName": "root_app", "version": "1.0.0"},
        {"id": "n2", "packageName": "dep_a", "version": "1.0.0"},
        {"id": "n3", "packageName": "dep_b", "version": "1.0.0"},
        {"id": "n4", "packageName": "dep_c", "version": "1.0.0"},
        {"id": "n5", "packageName": "shared_lib", "version": "2.0.0"},
    ]
    edges = [
        {"source": "n1", "target": "n2"},
        {"source": "n1", "target": "n3"},
        {"source": "n1", "target": "n4"},
        {"source": "n2", "target": "n5"},
        {"source": "n3", "target": "n5"},
        {"source": "n4", "target": "n5"},
    ]

    result = compute_graph_centrality(nodes, edges, root_package="root_app")
    node_map = {n["packageName"]: n for n in result}

    # Root
    assert node_map["root_app"]["in_degree"] == 0
    assert node_map["root_app"]["depth_in_tree"] == 0
    assert node_map["root_app"]["criticality_label"] == "Root Package"

    # Direct dependencies (dep_a, dep_b, dep_c)
    for dep in ("dep_a", "dep_b", "dep_c"):
        assert node_map[dep]["in_degree"] == 1
        assert node_map[dep]["depth_in_tree"] == 1
        assert node_map[dep]["criticality_label"] == "Low — 1 package depends on this"
        assert node_map[dep]["blast_radius_scope"] == BLAST_RADIUS_SCOPE

    # Shared transitive dependency depended on by 3 packages
    shared = node_map["shared_lib"]
    assert shared["in_degree"] == 3
    assert shared["depth_in_tree"] == 2
    assert shared["criticality_label"] == "High — 3 packages depend on this"
    assert shared["degree_centrality"] > 0
    assert shared["blast_radius_scope"] == BLAST_RADIUS_SCOPE


def test_compute_graph_centrality_medium_label():
    """Verify Medium label when exactly 2 packages depend on a node."""
    nodes = [
        {"id": "n1", "packageName": "root_app", "version": "1.0.0"},
        {"id": "n2", "packageName": "dep_a", "version": "1.0.0"},
        {"id": "n3", "packageName": "dep_b", "version": "1.0.0"},
        {"id": "n4", "packageName": "shared_lib", "version": "2.0.0"},
    ]
    edges = [
        {"source": "n1", "target": "n2"},
        {"source": "n1", "target": "n3"},
        {"source": "n2", "target": "n4"},
        {"source": "n3", "target": "n4"},
    ]

    result = compute_graph_centrality(nodes, edges, root_package="root_app")
    node_map = {n["packageName"]: n for n in result}

    shared = node_map["shared_lib"]
    assert shared["in_degree"] == 2
    assert shared["depth_in_tree"] == 2
    assert shared["criticality_label"] == "Medium — 2 packages depend on this"


def test_dependency_graph_endpoint_response_shape(client, auth_headers):
    """Verify the endpoint returns per-node centrality data and top-level blastRadiusScope."""
    mock_graph_data = {
        "graph_id": "testgraph123",
        "root_package": "demo-pkg",
        "root_version": "1.0.0",
        "nodes": [
            {
                "id": "n1",
                "label": "demo-pkg",
                "packageName": "demo-pkg",
                "version": "1.0.0",
                "riskLevel": "safe",
                "riskScore": 10.0,
                "risk_color": "#00FF9C",
                "inDegree": 0,
                "degreeCentrality": 0.5,
                "depthInTree": 0,
                "criticalityLabel": "Root Package",
                "blastRadiusScope": BLAST_RADIUS_SCOPE,
            },
            {
                "id": "n2",
                "label": "dep-common",
                "packageName": "dep-common",
                "version": "0.9.0",
                "riskLevel": "suspicious",
                "riskScore": 45.0,
                "risk_color": "#FFB020",
                "inDegree": 3,
                "degreeCentrality": 0.8,
                "depthInTree": 1,
                "criticalityLabel": "High — 3 packages depend on this",
                "blastRadiusScope": BLAST_RADIUS_SCOPE,
            },
        ],
        "edges": [{"source": "n1", "target": "n2"}],
        "blast_radius_scope": BLAST_RADIUS_SCOPE,
    }

    with patch(
        "app.services.dependency_graph_builder.DependencyGraphBuilder.build_graph",
        new=AsyncMock(return_value=mock_graph_data),
    ):
        response = client.get(
            "/api/v1/scan/dependency-graph/demo-pkg",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()

        assert data["rootPackage"] == "demo-pkg"
        assert data["blastRadiusScope"] == BLAST_RADIUS_SCOPE
        assert len(data["nodes"]) == 2

        root_node = data["nodes"][0]
        assert root_node["inDegree"] == 0
        assert root_node["depthInTree"] == 0
        assert root_node["criticalityLabel"] == "Root Package"
        assert root_node["blastRadiusScope"] == BLAST_RADIUS_SCOPE

        dep_node = data["nodes"][1]
        assert dep_node["inDegree"] == 3
        assert dep_node["depthInTree"] == 1
        assert dep_node["criticalityLabel"] == "High — 3 packages depend on this"
        assert dep_node["degreeCentrality"] == 0.8
        assert dep_node["blastRadiusScope"] == BLAST_RADIUS_SCOPE
