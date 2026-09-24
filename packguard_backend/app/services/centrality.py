"""
Graph centrality and blast-radius analysis for dependency graphs.

Computes in-degree, NetworkX degree centrality, tree depth, and criticality labels.
NOTE: Since the dependency tree is depth-capped at 3, all computed metrics
represent the "local blast radius within 3 levels" and do NOT represent
the full transitive PyPI ecosystem graph.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import networkx as nx

logger = logging.getLogger(__name__)

BLAST_RADIUS_SCOPE: str = "local blast radius within 3 levels"


def compute_criticality_label(in_degree: int, depth_in_tree: Optional[int] = None) -> str:
    """
    Derive a criticality label based on in-degree and depth within the dependency tree.

    Note: Represents local blast radius within 3 levels; not full ecosystem graph.

    - Depth 0 (root package): "Root Package"
    - In-degree >= 3: "High — N packages depend on this"
    - In-degree == 2: "Medium — 2 packages depend on this"
    - In-degree == 1: "Low — 1 package depends on this"
    - In-degree == 0: "Low"
    """
    if depth_in_tree == 0:
        return "Root Package"
    if in_degree >= 3:
        return f"High — {in_degree} packages depend on this"
    if in_degree == 2:
        return "Medium — 2 packages depend on this"
    if in_degree == 1:
        return "Low — 1 package depends on this"
    return "Low"


def build_directed_graph(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> nx.DiGraph:
    """Build a NetworkX DiGraph from node and edge dictionaries."""
    graph = nx.DiGraph()
    for node in nodes:
        node_id = str(node.get("id"))
        graph.add_node(node_id, **node)
    for edge in edges:
        source = str(edge.get("source") or edge.get("from"))
        target = str(edge.get("target") or edge.get("to"))
        if source and target:
            graph.add_edge(source, target)
    return graph


def compute_graph_centrality(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    root_package: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Compute graph centrality and blast radius metrics for all nodes in the tree.

    Calculates:
    - in_degree: Number of packages in the tree that depend on this node.
    - degree_centrality: Degree centrality computed via networkx.degree_centrality().
    - depth_in_tree: Shortest-path distance from the root node in the tree.
    - criticality_label: Derived severity label (Root, High, Medium, Low).
    - blast_radius_scope: Constant "local blast radius within 3 levels".

    Updates each node dictionary in-place and returns the list of nodes.
    """
    if not nodes:
        return nodes

    graph = build_directed_graph(nodes, edges)

    # Compute degree centrality using networkx.degree_centrality()
    try:
        deg_centrality = nx.degree_centrality(graph)
    except Exception:
        logger.exception("Failed computing networkx degree centrality")
        deg_centrality = {str(n["id"]): 0.0 for n in nodes}

    # Identify the root node
    root_node_id: Optional[str] = None
    if root_package:
        root_pkg_lower = root_package.strip().lower()
        for node in nodes:
            pkg_name = (
                node.get("packageName")
                or node.get("package_name")
                or node.get("label", "")
            )
            if str(pkg_name).strip().lower() == root_pkg_lower:
                root_node_id = str(node["id"])
                break

    # If root_node_id is not found by name, default to node with 0 in-degree or first node
    if not root_node_id and nodes:
        in_degrees = dict(graph.in_degree())
        zero_in_nodes = [str(n["id"]) for n in nodes if in_degrees.get(str(n["id"]), 0) == 0]
        root_node_id = zero_in_nodes[0] if zero_in_nodes else str(nodes[0]["id"])

    # Compute shortest path depths from root
    depths: Dict[str, int] = {}
    if root_node_id and root_node_id in graph:
        try:
            depths = dict(nx.shortest_path_length(graph, source=root_node_id))
        except Exception:
            logger.exception("Failed computing shortest path depths")

    # Enrich each node
    for node in nodes:
        nid = str(node.get("id"))
        in_deg = int(graph.in_degree(nid)) if nid in graph else 0
        cent = float(deg_centrality.get(nid, 0.0))

        if nid == root_node_id:
            depth = 0
        elif nid in depths:
            depth = depths[nid]
        else:
            # Fallback depth for disconnected nodes
            depth = 1

        label = compute_criticality_label(in_deg, depth)

        # Populate both snake_case and camelCase for schema and consumer flexibility
        node["in_degree"] = in_deg
        node["inDegree"] = in_deg
        node["degree_centrality"] = round(cent, 4)
        node["degreeCentrality"] = round(cent, 4)
        node["depth_in_tree"] = depth
        node["depthInTree"] = depth
        node["criticality_label"] = label
        node["criticalityLabel"] = label
        node["blast_radius_scope"] = BLAST_RADIUS_SCOPE
        node["blastRadiusScope"] = BLAST_RADIUS_SCOPE

    return nodes
