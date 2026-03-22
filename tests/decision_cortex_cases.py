import unittest

from scan_engine.helpers.decision_cortex import suggest_actions


def _base_results(open_ports, *, findings=None):
    return {
        "phases": {
            "recon": {
                "open_ports": open_ports,
            },
            "enum": {
                "targets": {},
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
        "findings": findings or [],
    }


def _suggestion_by_family(suggestions, family):
    return next((item for item in suggestions if item.get("family") == family), None)


class DecisionCortexTests(unittest.TestCase):
    def test_auth_surface_and_token_surface_emit_structured_session_control_suggestion(self):
        results = _base_results([{"port": 443, "service": "https"}])
        results["phases"]["enum"]["targets"]["443"] = [
            "https://example.org/auth/login",
            "https://example.org/api/token/refresh?api_key=abc",
        ]

        suggestions = suggest_actions(results)
        auth_token = _suggestion_by_family(suggestions, "auth_token_session_controls")

        self.assertIsNotNone(auth_token)
        self.assertEqual(auth_token["metadata"]["analysis_tier"], "signal_supported_correlation")
        self.assertIn("auth_surface", auth_token["trigger_signals"])
        self.assertIn("token_surface", auth_token["trigger_signals"])

    def test_ssrf_surface_and_metadata_service_emit_structured_cloud_suggestion(self):
        results = _base_results([{"port": 443, "service": "https"}])
        results["phases"]["vuln"]["ssrf"] = [
            {
                "url": "https://example.org/fetch?url=http://169.254.169.254/latest/meta-data/",
                "title": "SSRF metadata reachability",
                "category": "ssrf",
                "description": "Cloud metadata service 169.254.169.254 responded.",
            }
        ]

        suggestions = suggest_actions(results)
        ssrf = _suggestion_by_family(suggestions, "ssrf_metadata_controls")

        self.assertIsNotNone(ssrf)
        self.assertEqual(ssrf["metadata"]["analysis_tier"], "signal_supported_correlation")
        self.assertIn("metadata_service", ssrf["trigger_signals"])

    def test_api_object_reference_and_auth_context_emit_bola_suggestion(self):
        results = _base_results([{"port": 443, "service": "https"}])
        results["phases"]["enum"]["targets"]["443"] = [
            "https://example.org/api/v1/users/123?account_id=7",
            "https://example.org/auth/login",
            "https://example.org/admin/dashboard",
        ]

        suggestions = suggest_actions(results)
        bola = _suggestion_by_family(suggestions, "object_access_authorization")

        self.assertIsNotNone(bola)
        self.assertIn("api_surface", bola["trigger_signals"])
        self.assertIn("object_reference_surface", bola["trigger_signals"])

    def test_oauth_surface_and_token_surface_emit_oauth_audit(self):
        results = _base_results([{"port": 443, "service": "https"}])
        results["phases"]["enum"]["targets"]["443"] = [
            "https://example.org/oauth/authorize",
            "https://example.org/callback?token=abc",
        ]

        suggestions = suggest_actions(results)
        oauth = _suggestion_by_family(suggestions, "oauth_oidc")

        self.assertIsNotNone(oauth)
        self.assertIn("oauth_surface", oauth["trigger_signals"])

    def test_validated_findings_promote_analysis_tier_without_changing_family(self):
        findings = [
            {
                "title": "Validated auth token replay",
                "endpoint": "https://example.org/api/token/refresh",
                "category": "auth",
                "metadata": {"validation": {"status": "success"}},
                "result_state": "confirmed",
            }
        ]
        results = _base_results([{"port": 443, "service": "https"}], findings=findings)
        results["phases"]["enum"]["targets"]["443"] = [
            "https://example.org/auth/login",
            "https://example.org/api/token/refresh?api_key=abc",
        ]

        suggestions = suggest_actions(results)
        auth_token = _suggestion_by_family(suggestions, "auth_token_session_controls")

        self.assertIsNotNone(auth_token)
        self.assertEqual(auth_token["metadata"]["analysis_tier"], "validated_signal")

    def test_non_http_without_supporting_markers_emits_no_suggestions(self):
        results = _base_results([{"port": 22, "service": "ssh"}])

        suggestions = suggest_actions(results)

        self.assertEqual(suggestions, [])

    def test_suggest_actions_keeps_dedup_budget_order_and_observability_stable(self):
        results = _base_results(
            [
                {"port": 443, "service": "https"},
                {"port": 443, "service": "https"},
                {"port": 8443, "service": "https"},
            ]
        )
        results["phases"]["enum"]["targets"]["443"] = [
            "https://example.org/auth/login",
            "https://example.org/api/token/refresh?api_key=abc",
            "https://example.org/api/v1/users/123?account_id=7",
        ]
        results["phases"]["enum"]["targets"]["8443"] = [
            "https://example.org:8443/auth/login",
            "https://example.org:8443/api/token/refresh?api_key=abc",
            "https://example.org:8443/api/v1/users/123?account_id=7",
        ]

        first = suggest_actions(results, max_suggestions=2, max_suggestions_per_port=1)
        second = suggest_actions(results, max_suggestions=2, max_suggestions_per_port=1)

        self.assertEqual([item["id"] for item in first], [item["id"] for item in second])
        self.assertEqual(len(first), 2)
        self.assertEqual(len({item.get("port") for item in first}), 2)

        observability = results["phases"]["enum"]["derived"]["cortex_observability"]
        self.assertGreater(observability["raw_count"], observability["deduped_count"])
        self.assertEqual(observability["budgeted_count"], 2)
        self.assertEqual(observability["selected_by_port"], {"443": 1, "8443": 1})


if __name__ == "__main__":
    unittest.main()
