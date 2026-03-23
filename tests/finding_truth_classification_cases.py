import unittest

from scan_engine.helpers.attack_graph import AttackGraphBuilder
from scan_engine.helpers.decision_cortex import suggest_actions
from scan_engine.helpers.finding_schema import (
    apply_finding_quality_gates,
    classify_visible_truth,
    normalize_finding_shape,
)


class FindingTruthClassificationTests(unittest.TestCase):
    def test_visible_truth_classifies_observation_suspicion_recommendation_and_confirmed(self):
        observation = normalize_finding_shape(
            {
                "title": "Missing Strict-Transport-Security header",
                "category": "header_observation",
                "severity": "low",
                "result_state": "observation",
            },
            source="unit_test",
        )
        suspicion = normalize_finding_shape(
            {
                "title": "Probable authorization bypass correlation",
                "category": "attack_chain",
                "result_state": "correlation",
                "metadata": {"validation": {"status": "uncertain"}},
            },
            source="unit_test",
        )
        recommendation = {
            "title": "Recommendation: review JWT handling on port 443",
            "reason": "Token telemetry was observed on an authenticated surface.",
            "family": "jwt_audit",
            "internal_priority": 88,
            "metadata": {"analysis_tier": "signal_supported_correlation"},
        }
        confirmed = normalize_finding_shape(
            {
                "title": "Confirmed SSRF to metadata endpoint",
                "category": "ssrf",
                "severity": "high",
                "result_state": "confirmed",
                "description": "Bounded SSRF replay reached the metadata service with a controlled canary request.",
                "endpoint": "https://example.org/fetch?url=http://169.254.169.254/latest/meta-data/",
                "repro_command": "curl -isk 'https://example.org/fetch?url=http://169.254.169.254/latest/meta-data/'",
                "request": "GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
                "response": "HTTP/1.1 200 OK\nmetadata-token: canary",
                "metadata": {"validation": {"status": "success", "artifact": "metadata-token: canary"}},
            },
            source="unit_test",
        )

        self.assertEqual(classify_visible_truth(observation), "observation")
        self.assertEqual(classify_visible_truth(suspicion), "suspicion")
        self.assertEqual(classify_visible_truth(recommendation), "recommendation")
        self.assertEqual(classify_visible_truth(confirmed), "confirmed_vulnerability")

    def test_quality_gates_downgrade_weak_high_and_weak_confirmed(self):
        weak_high = apply_finding_quality_gates(
            {
                "title": "Generic Finding",
                "severity": "high",
                "result_state": "observation",
                "description": "Interesting telemetry.",
                "metadata": {"validation": {"status": "not_run"}},
            }
        )
        weak_confirmed = normalize_finding_shape(
            {
                "title": "Placeholder confirmed",
                "result_state": "confirmed",
                "severity": "high",
                "evidence": "manual verification required",
                "repro_command": "N/A",
                "metadata": {"validation": {"status": "not_run"}},
            },
            source="unit_test",
        )

        self.assertEqual(weak_high["severity"], "medium")
        self.assertEqual(
            weak_high["metadata"]["quality_gate"]["reasons"][0],
            "high_requires_endpoint_command_and_proof",
        )
        self.assertEqual(weak_confirmed["result_state"], "correlation")
        self.assertEqual(weak_confirmed["metadata"]["validation"]["status"], "uncertain")
        self.assertEqual(
            weak_confirmed["metadata"]["validation"]["downgrade_reason"],
            "confirmed_requires_validated_reproducible_proof",
        )

    def test_decision_cortex_exposes_recommendation_wording_and_capped_confidence(self):
        results = {
            "phases": {
                "recon": {"open_ports": [{"port": 443, "service": "https"}]},
                "enum": {
                    "targets": {
                        "443": [
                            "https://example.org/auth/login",
                            "https://example.org/api/token/refresh?api_key=abc",
                        ]
                    },
                    "api": {},
                    "injection_points": {},
                    "katana": {},
                    "attack_profile": {},
                    "waf": {},
                    "http_methods": {},
                    "derived": {},
                },
                "vuln": {},
                "osint": {},
            },
            "findings": [],
        }

        suggestions = suggest_actions(results)
        jwt = next(item for item in suggestions if item["family"] == "auth_token_session_controls")

        self.assertTrue(jwt["title"].startswith("Recommendation:"))
        self.assertLessEqual(jwt["confidence"], 74)
        self.assertEqual(jwt["metadata"]["kind"], "recommendation")
        self.assertEqual(jwt["metadata"]["visible_truth"], "recommendation")
        self.assertIn("requested_confidence", jwt["metadata"])

    def test_attack_graph_marks_non_confirmed_items_as_suspicion_or_recommendation(self):
        graph = AttackGraphBuilder().build(
            {
                "target": "example.org",
                "phases": {"recon": {"open_ports": []}, "enum": {}, "vuln": {}},
                "findings": [
                    {
                        "id_stable": "corr-1",
                        "title": "Correlated attack path hypothesis",
                        "category": "attack_chain",
                        "result_state": "correlation",
                        "metadata": {"validation": {"status": "uncertain"}},
                    },
                    {
                        "id_stable": "obs-1",
                        "title": "Exposed admin route",
                        "category": "route_discovery",
                        "endpoint": "https://example.org/admin",
                        "result_state": "observation",
                    },
                    {
                        "id_stable": "conf-1",
                        "title": "Confirmed SSRF",
                        "category": "ssrf",
                        "endpoint": "https://example.org/fetch?url=http://169.254.169.254/latest/meta-data/",
                        "result_state": "confirmed",
                        "request": "GET /fetch?... HTTP/1.1",
                        "response": "HTTP/1.1 200 OK",
                        "repro_command": "curl -isk 'https://example.org/fetch?url=http://169.254.169.254/latest/meta-data/'",
                        "metadata": {"validation": {"status": "success", "artifact": "HTTP/1.1 200 OK"}},
                    },
                ],
            }
        )

        node_types = {node["id"]: node["type"] for node in graph["nodes"]}
        edge_types = {(edge["from"], edge["to"]): edge["type"] for edge in graph["edges"]}

        self.assertEqual(node_types["finding:db:corr-1"], "suspicion")
        self.assertEqual(node_types["attack_chain:corr-1"], "attack_hypothesis")
        self.assertEqual(node_types["finding:db:obs-1"], "observation")
        self.assertEqual(node_types["finding:db:conf-1"], "vulnerability")
        self.assertEqual(
            edge_types[("endpoint:derived:https://example.org/admin", "finding:db:obs-1")],
            "supports_assessment",
        )


if __name__ == "__main__":
    unittest.main()
