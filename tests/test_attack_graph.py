import unittest

from scan_engine.helpers.attack_graph import AttackGraphBuilder


class AttackGraphTests(unittest.TestCase):
    def test_attack_graph_contains_required_nodes_and_edges(self):
        graph = AttackGraphBuilder().build(
            {
                "target": "example.com",
                "findings": [
                    {"id_stable": "f1", "category": "asset_discovery", "endpoint": "app.example.com", "metadata": {"discovered_asset": "app.example.com"}},
                    {"id_stable": "f2", "category": "cloud_asset", "endpoint": "bucket.s3.amazonaws.com", "metadata": {"discovered_asset": "bucket.s3.amazonaws.com"}},
                    {"id_stable": "f3", "category": "api_surface", "endpoint": "/api/v1/users"},
                    {"id_stable": "f4", "category": "parameter_surface", "parameter": "token", "endpoint": "/api/v1/users"},
                    {"id_stable": "f5", "category": "secret_exposure", "endpoint": "/api/v1/users", "metadata": {"secret_type": "github_token"}},
                    {"id_stable": "f6", "category": "attack_chain", "endpoint": "/api/v1/users", "metadata": {"chain": ["js_api", "auth_parameter", "token"]}},
                ],
                "phases": {"recon": {"open_ports": []}, "enum": {}, "vuln": {}},
            }
        )
        node_types = {n.get("type") for n in graph["nodes"]}
        edge_types = {e.get("type") for e in graph["edges"]}

        self.assertIn("asset", node_types)
        self.assertIn("cloud_resource", node_types)
        self.assertIn("secret", node_types)
        self.assertIn("api_endpoint", node_types)
        self.assertIn("parameter", node_types)

        self.assertIn("exposes_asset", edge_types)
        self.assertIn("leaks_secret", edge_types)
        self.assertIn("depends_on", edge_types)
        self.assertIn("leads_to_attack", edge_types)
        self.assertIn("reachable_from", edge_types)


if __name__ == "__main__":
    unittest.main()
