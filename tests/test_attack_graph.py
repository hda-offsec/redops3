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
                    {
                        "id_stable": "f7",
                        "category": "auth",
                        "title": "Bounded validation on export route",
                        "endpoint": "/api/v1/export",
                        "result_state": "validation",
                        "repro_command": "curl -isk https://example.com/api/v1/export",
                        "request": "GET /api/v1/export HTTP/1.1",
                        "response": "HTTP/1.1 403 Forbidden",
                        "metadata": {"validation": {"status": "uncertain", "artifact": "HTTP/1.1 403 Forbidden"}},
                    },
                    {
                        "id_stable": "f8",
                        "category": "ssrf",
                        "title": "Confirmed metadata SSRF",
                        "description": "A bounded SSRF replay reached the metadata service and returned a controlled response.",
                        "endpoint": "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
                        "result_state": "confirmed",
                        "repro_command": "curl -isk https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
                        "request": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
                        "response": "HTTP/1.1 200 OK\nmetadata-token: canary",
                        "metadata": {"validation": {"status": "success", "artifact": "HTTP/1.1 200 OK\nmetadata-token: canary"}},
                    },
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
        self.assertIn("validation", node_types)

        self.assertIn("exposes_asset", edge_types)
        self.assertIn("leaks_secret", edge_types)
        self.assertIn("depends_on", edge_types)
        self.assertIn("leads_to_attack", edge_types)
        self.assertIn("reachable_from", edge_types)
        self.assertIn("validated_by_execution", edge_types)

    def test_attack_graph_node_ids_normalized(self):
        graph = AttackGraphBuilder().build(
            {
                "target": "EXAMPLE.com",
                "findings": [
                    {"id_stable": "f1", "category": "asset_discovery", "endpoint": "API.Example.com", "metadata": {"discovered_asset": "API.Example.com"}},
                    {"id_stable": "f2", "category": "asset_discovery", "endpoint": "api.example.com", "metadata": {"discovered_asset": "api.example.com"}},
                ],
                "phases": {"recon": {"open_ports": []}, "enum": {}, "vuln": {}},
            }
        )
        ids = {n.get("id") for n in graph["nodes"]}
        self.assertIn("target:example.com", ids)
        self.assertIn("asset:api.example.com", ids)


if __name__ == "__main__":
    unittest.main()
