"""Dependency-risk graph construction for the Lazarus dashboard.

Implements the graph contract from INTERFACES.md::

    build_graph(findings: list[dict]) -> dict

Returns ``{"nodes": [{"id", "type", "label", "risk"}],
"edges": [{"source", "target", "label"}]}``.

Node types: "domain", "maintainer", "package". Edges:
  domain -> maintainer  "hosts email"
  maintainer -> package "maintains"

Risk propagation: a finding's risk score flows down the chain, so a package
backing a high-risk domain is visibly high-risk. When several findings touch
the same node (shared domain, shared maintainer, shared package), the node
takes the MAXIMUM risk of all findings it participates in — the worst case
dominates, which is what the dashboard triage needs.

Findings missing a "risk" key are scored on the fly via scorer.score_finding,
so the graph is self-contained for tests.
"""

from __future__ import annotations

EDGE_DOMAIN_MAINTAINER = "hosts email"
EDGE_MAINTAINER_PACKAGE = "maintains"


def _finding_risk(finding: dict) -> int:
    """Risk score of a finding; scores it if not already scored."""
    risk = finding.get("risk")
    if isinstance(risk, int):
        return risk
    # Imported lazily to keep graph importable even without scorer present.
    from scorer import score_finding

    return score_finding(finding)["risk"]


def build_graph(findings: list[dict]) -> dict:
    """Build a nodes/edges graph from scored (or raw) findings.

    Node ids are namespaced by type ("domain:<name>", "maintainer:<name>",
    "package:<name>") so the same string can never collide across types.
    Nodes and edges are de-duplicated; node risk is the max over all
    findings touching that node.
    """
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def add_node(node_id: str, node_type: str, label: str, risk: int) -> None:
        node = nodes.get(node_id)
        if node is None:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "risk": risk,
            }
        elif risk > node["risk"]:
            node["risk"] = risk

    def add_edge(source: str, target: str, label: str) -> None:
        edges.setdefault(
            (source, target, label),
            {"source": source, "target": target, "label": label},
        )

    for finding in findings or []:
        risk = _finding_risk(finding)
        domain = finding.get("domain")
        domain_id = None

        if domain:
            domain_id = f"domain:{domain}"
            add_node(domain_id, "domain", domain, risk)

        maintainer_ids = []
        for maintainer in finding.get("maintainers") or []:
            maintainer_id = f"maintainer:{maintainer}"
            add_node(maintainer_id, "maintainer", maintainer, risk)
            maintainer_ids.append(maintainer_id)
            if domain_id is not None:
                add_edge(domain_id, maintainer_id, EDGE_DOMAIN_MAINTAINER)

        for package in finding.get("packages") or []:
            package_id = f"package:{package}"
            add_node(package_id, "package", package, risk)
            for maintainer_id in maintainer_ids:
                add_edge(maintainer_id, package_id, EDGE_MAINTAINER_PACKAGE)

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}
