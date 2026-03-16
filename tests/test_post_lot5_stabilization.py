import unittest

from core.quality_metrics import build_quality_metrics, classify_finding_family
from core.replay_vault import compare_replay_artifacts, normalize_replay_artifact
from scan_engine.helpers.finding_schema import normalize_finding_shape


class PostLot5StabilizationTests(unittest.TestCase):
    def test_normalize_finding_shape_is_deterministic_and_keeps_lineage(self):
        payload = {
            "title": "GraphQL schema leak",
            "severity": "warning",
            "confidence": "HIGH",
            "tool": "graphql_scanner",
            "endpoint": "https://example.org/graphql",
            "param": "query",
            "evidence": {"sample": "type Query"},
            "metadata": {
                "field_sources": {"endpoint": "graphql_scanner"},
                "score_factors": {"severity": 0.8},
            },
            "signal_ids": [3, 2, 3],
        }

        first = normalize_finding_shape(payload, source="unit_test")
        second = normalize_finding_shape(payload, source="unit_test")

        self.assertEqual(first["id_stable"], second["id_stable"])
        self.assertEqual(first["signal_ids"], [3, 2])
        self.assertEqual(first["severity"], "medium")
        self.assertEqual(first["confidence"], "high")
        self.assertIn("field_sources", first["metadata"])
        self.assertEqual(first["metadata"]["field_sources"]["endpoint"], "graphql_scanner")

    def test_replay_diff_is_deterministic_for_same_payload(self):
        replay = {
            "method": "get",
            "url": "https://example.org/api/users?id=7",
            "request_headers": {"Authorization": "Bearer aaa.bbb.ccc"},
            "response_headers": {"Content-Type": "application/json"},
            "response_body": {"ok": True, "id": 7},
        }

        normalized = normalize_replay_artifact(replay)
        diff = compare_replay_artifacts(normalized, normalized)

        self.assertTrue(diff["same_status"])
        self.assertTrue(diff["same_shape"])
        self.assertTrue(diff["same_body_hash"])
        self.assertEqual(diff["significance_score"], 0)

    def test_quality_metrics_contract_and_determinism(self):
        findings = [
            {
                "title": "Cloud metadata exposure",
                "category": "ssrf",
                "confidence": "low",
                "signal_ids": [10],
                "module": "cloud_metadata_scanner",
                "metadata": {
                    "validation_profile": "safe_probe",
                    "field_sources": {"endpoint": "ssrf_scanner"},
                    "heuristic_family": "cloud_heuristics",
                    "evidence_confidence": "medium",
                },
            },
            {
                "title": "Upload form detected",
                "category": "upload_surface",
                "confidence": "high",
                "signal_ids": [],
                "module": "upload_scanner",
                "metadata": {},
            },
        ]
        actions = [
            {"status": "suggested", "objective_type": "cloud_credential_access"},
            {"status": "invalidated", "objective_type": "cloud_credential_access"},
        ]
        objective_paths = [{"objective_type": "cloud_credential_access"}]
        next_steps = [{"objective_type": "cloud_credential_access"}]

        first = build_quality_metrics(
            findings=findings,
            operator_actions=actions,
            objectives=[{"objective_type": "cloud_credential_access"}],
            objective_paths=objective_paths,
            next_steps=next_steps,
        )
        second = build_quality_metrics(
            findings=findings,
            operator_actions=actions,
            objectives=[{"objective_type": "cloud_credential_access"}],
            objective_paths=objective_paths,
            next_steps=next_steps,
        )

        self.assertEqual(first, second)
        self.assertEqual(first["artifact_volume"]["findings"], 2)
        self.assertIn("cloud_pivot_candidates", first["findings_by_family"])
        self.assertEqual(first["operator_feedback"]["false_positive_like_actions"], 1)
        self.assertIn("safe_probe", first["validation_profiles"])
        self.assertEqual(classify_finding_family(findings[1]), "upload_retrieval_assessments")

    def test_quality_metrics_handles_malformed_empty_inputs(self):
        payload = build_quality_metrics(
            findings=None,
            operator_actions=[{"status": None}, {"status": "SKIPPED"}],
            objectives=None,
            objective_paths=[{"objective_type": "identity_privilege_path"}, "bad-entry"],
            next_steps=[{"objective_type": "identity_privilege_path"}],
        )

        self.assertEqual(payload["artifact_volume"]["findings"], 0)
        self.assertEqual(payload["operator_feedback"]["false_positive_like_actions"], 1)
        self.assertEqual(payload["coverage_hints"]["objectives_with_paths"], 1)

    def test_finding_schema_additive_reproducibility_fields(self):
        normalized = normalize_finding_shape(
            {
                "title": "API probe",
                "endpoint": "https://example.org/api",
                "repro_command": "curl -i https://example.org/api",
                "validation": {"status": "failed"},
            },
            source="unit_test",
        )

        self.assertIn("metadata", normalized)
        self.assertIn("validation", normalized["metadata"])
        self.assertIn("reproducibility", normalized["metadata"])
        self.assertEqual(normalized["metadata"]["validation"]["status"], "failed")
        self.assertEqual(normalized["metadata"]["reproducibility"]["url"], "https://example.org/api")


if __name__ == "__main__":
    unittest.main()
