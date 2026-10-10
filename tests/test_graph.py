"""Tests for graph.build_graph.

Covers node/edge construction, namespaced ids, de-duplication, and risk
propagation (max-risk-wins across findings touching the same node).
"""

import unittest

import graph
from scorer import score_finding

ATTACK_NOW_RDAP = {
    "domain": "atlantis-software.net",
    "registered": True,
    "created": "2026-05-07",
    "expires": "2027-05-07",
    "status": ["client transfer prohibited"],
    "error": None,
}


def scored_finding(domain, packages, maintainers, dependents=0,
                   downloads=0, dormant=False, mx=False, rdap=None):
    """Build a finding already carrying a risk score."""
    finding = {
        "domain": domain,
        "packages": packages,
        "maintainers": maintainers,
        "dependents": dependents,
        "downloads_week": downloads,
        "rdap": rdap or {"registered": True, "created": "2015-01-01",
                         "expires": "2030-01-01", "status": [],
                         "error": None},
        "maintainer_dormant": dormant,
        "mx_present": mx,
    }
    scored = score_finding(finding, now=graph_datetime())
    finding["risk"] = scored["risk"]
    finding["severity"] = scored["severity"]
    return finding


def graph_datetime():
    from datetime import datetime, timezone
    return datetime(2026, 10, 10, tzinfo=timezone.utc)


def node_map(result):
    return {node["id"]: node for node in result["nodes"]}


def edge_set(result):
    return {(e["source"], e["target"], e["label"]) for e in result["edges"]}


class TestNodeConstruction(unittest.TestCase):
    def test_empty_findings(self):
        result = graph.build_graph([])
        self.assertEqual(result, {"nodes": [], "edges": []})

    def test_single_finding_node_and_edge_types(self):
        result = graph.build_graph(
            [scored_finding("evil.example", ["evil-pkg"],
                            ["m@evil.example"])]
        )
        nodes = node_map(result)
        self.assertEqual(
            set(nodes), {"domain:evil.example", "maintainer:m@evil.example",
                         "package:evil-pkg"}
        )
        self.assertEqual(nodes["domain:evil.example"]["type"], "domain")
        self.assertEqual(nodes["maintainer:m@evil.example"]["type"],
                         "maintainer")
        self.assertEqual(nodes["package:evil-pkg"]["type"], "package")

        self.assertEqual(
            edge_set(result),
            {
                ("domain:evil.example", "maintainer:m@evil.example",
                 "hosts email"),
                ("maintainer:m@evil.example", "package:evil-pkg",
                 "maintains"),
            },
        )

    def test_node_shape(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["p"], ["m@a.example"])]
        )
        for node in result["nodes"]:
            self.assertEqual(
                sorted(node.keys()), ["id", "label", "risk", "type"]
            )
        for edge in result["edges"]:
            self.assertEqual(
                sorted(edge.keys()), ["label", "source", "target"]
            )

    def test_label_matches_human_name(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["my-pkg"], ["dev@a.example"])]
        )
        nodes = node_map(result)
        self.assertEqual(nodes["domain:a.example"]["label"], "a.example")
        self.assertEqual(nodes["maintainer:dev@a.example"]["label"],
                         "dev@a.example")
        self.assertEqual(nodes["package:my-pkg"]["label"], "my-pkg")

    def test_multiple_packages_and_maintainers(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["p1", "p2"],
                            ["m1@a.example", "m2@a.example"])]
        )
        # 1 domain + 2 maintainers + 2 packages
        self.assertEqual(len(result["nodes"]), 5)
        # 2 domain->maintainer + 4 maintainer->package (2x2)
        self.assertEqual(len(result["edges"]), 6)

    def test_finding_without_domain(self):
        result = graph.build_graph(
            [scored_finding(None, ["p"], ["m@x.example"])]
        )
        self.assertEqual(
            set(node_map(result)),
            {"maintainer:m@x.example", "package:p"},
        )
        self.assertEqual(len(result["edges"]), 1)

    def test_finding_without_maintainers(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["p"], [])]
        )
        self.assertEqual(set(node_map(result)),
                         {"domain:a.example", "package:p"})
        # No maintainer to hang the edge off of.
        self.assertEqual(result["edges"], [])

    def test_missing_lists_do_not_crash(self):
        result = graph.build_graph([{"domain": "d.example"}])
        self.assertEqual(set(node_map(result)), {"domain:d.example"})
        self.assertEqual(result["edges"], [])


class TestDeduplication(unittest.TestCase):
    def test_same_domain_two_findings_merges(self):
        result = graph.build_graph(
            [
                scored_finding("a.example", ["p1"], ["m1@a.example"]),
                scored_finding("a.example", ["p2"], ["m2@a.example"]),
            ]
        )
        self.assertEqual(len(result["nodes"]), 5)
        self.assertEqual(len(result["edges"]), 4)

    def test_same_edge_not_duplicated(self):
        finding = scored_finding("a.example", ["p"],
                                 ["m@a.example", "m@a.example"])
        result = graph.build_graph([finding])
        self.assertEqual(len(result["edges"]), 2)

    def test_ids_namespaced_by_type(self):
        # A package named exactly like the domain must not collide.
        result = graph.build_graph(
            [scored_finding("x", ["x"], ["x"])]
        )
        self.assertEqual(len(result["nodes"]), 3)
        self.assertEqual(
            set(node_map(result)),
            {"domain:x", "maintainer:x", "package:x"},
        )


class TestRiskPropagation(unittest.TestCase):
    def test_domain_risk_propagates_to_nodes(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["p"], ["m@a.example"])]
        )
        nodes = node_map(result)
        self.assertEqual(nodes["domain:a.example"]["risk"],
                         nodes["maintainer:m@a.example"]["risk"])
        self.assertEqual(nodes["maintainer:m@a.example"]["risk"],
                         nodes["package:p"]["risk"])

    def test_high_risk_finding_propagates(self):
        result = graph.build_graph(
            [
                scored_finding(
                    "atlantis-software.net", ["node-ipc"],
                    ["m@atlantis-software.net"],
                    dependents=50000, downloads=2_000_000,
                    dormant=True, mx=True, rdap=ATTACK_NOW_RDAP,
                )
            ]
        )
        nodes = node_map(result)
        self.assertEqual(nodes["domain:atlantis-software.net"]["risk"], 100)
        self.assertEqual(nodes["package:node-ipc"]["risk"], 100)
        self.assertEqual(nodes["maintainer:m@atlantis-software.net"]["risk"],
                         100)

    def test_shared_node_takes_max_risk(self):
        # One maintainer keeps packages under a clean domain and a dirty one.
        result = graph.build_graph(
            [
                scored_finding("clean.example", ["safe-pkg"],
                               ["shared@clean.example"]),
                scored_finding(
                    "dirty.example", ["risky-pkg"],
                    ["shared@clean.example"],
                    dependents=5000, downloads=1_000_000,
                    dormant=True, mx=True,
                    rdap={"registered": True, "created": "2026-09-01",
                          "expires": "2027-09-01", "status": [],
                          "error": None},
                ),
            ]
        )
        nodes = node_map(result)
        self.assertGreater(
            nodes["domain:dirty.example"]["risk"],
            nodes["domain:clean.example"]["risk"],
        )
        # The shared maintainer node must show the WORST of the two domains.
        self.assertEqual(nodes["maintainer:shared@clean.example"]["risk"],
                         nodes["domain:dirty.example"]["risk"])

    def test_shared_package_takes_max_risk(self):
        result = graph.build_graph(
            [
                scored_finding("a.example", ["shared-pkg"], ["m@a.example"]),
                scored_finding(
                    "b.example", ["shared-pkg"], ["m@b.example"],
                    dependents=5000,
                ),
            ]
        )
        nodes = node_map(result)
        self.assertEqual(nodes["package:shared-pkg"]["risk"],
                         nodes["domain:b.example"]["risk"])

    def test_unscored_finding_is_scored_on_the_fly(self):
        # Findings straight from the scan (no "risk" key yet) must still graph.
        finding = {
            "domain": "atlantis-software.net",
            "packages": ["node-ipc"],
            "maintainers": ["m@atlantis-software.net"],
            "dependents": 50000,
            "downloads_week": 2_000_000,
            "rdap": ATTACK_NOW_RDAP,
            "maintainer_dormant": True,
            "mx_present": True,
        }
        result = graph.build_graph([finding])
        nodes = node_map(result)
        self.assertEqual(nodes["domain:atlantis-software.net"]["risk"], 100)

    def test_zero_risk_finding_all_zero(self):
        result = graph.build_graph(
            [scored_finding("a.example", ["p"], ["m@a.example"])]
        )
        for node in result["nodes"]:
            self.assertEqual(node["risk"], 0)


if __name__ == "__main__":
    unittest.main()
