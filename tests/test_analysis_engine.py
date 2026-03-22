import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import sys
import types


if "flask_login" not in sys.modules:
    flask_login_stub = types.ModuleType("flask_login")

    class _UserMixin:
        pass

    class _LoginManager:
        def __init__(self, *args, **kwargs):
            pass

    flask_login_stub.UserMixin = _UserMixin
    flask_login_stub.LoginManager = _LoginManager
    sys.modules["flask_login"] = flask_login_stub

from core import analysis


class AnalysisEngineTests(unittest.TestCase):
    def test_analyze_nmap_results_replaces_legacy_suggestions_and_sorts_ports(self):
        open_ports = [
            {"port": 445, "service_name": "microsoft-ds"},
            {"port": 443, "service_name": "https"},
            {"port": 22, "service_name": "ssh"},
        ]
        created = []
        added_findings = []

        with patch.object(analysis.db.session, "add", side_effect=added_findings.append), patch.object(
            analysis.db.session, "commit"
        ), patch.object(
            analysis.SuggestionEngine,
            "create",
            side_effect=lambda scan_id, tool, command, reason: created.append(
                {
                    "scan_id": scan_id,
                    "tool": tool,
                    "command": command,
                    "reason": reason,
                }
            ),
        ):
            analysis.AnalysisEngine.analyze_nmap_results(scan_id=7, open_ports=open_ports)

        self.assertEqual(len(added_findings), 1)
        finding = added_findings[0]
        self.assertEqual(finding.title, "Open Ports Detected: 22, 443, 445")
        self.assertIn("'port': 22", finding.description)
        self.assertLess(finding.description.index("'port': 22"), finding.description.index("'port': 443"))
        self.assertEqual([item["tool"] for item in created], ["ssh_review", "http_review", "route_review", "smb_review"])
        self.assertNotIn("whatweb", [item["tool"] for item in created])
        self.assertNotIn("gobuster", [item["tool"] for item in created])
        self.assertNotIn("enum4linux", [item["tool"] for item in created])
        self.assertNotIn("hydra", [item["tool"] for item in created])
        self.assertFalse(any("rockyou" in item["command"] for item in created))

    def test_analyze_nmap_results_deduplicates_http_suggestions_for_duplicate_port_records(self):
        created = []
        open_ports = [
            {"port": 443, "service_name": "https"},
            {"port": 443, "service_name": "http-proxy"},
        ]

        with patch.object(analysis.db.session, "add"), patch.object(analysis.db.session, "commit"), patch.object(
            analysis.SuggestionEngine,
            "create",
            side_effect=lambda scan_id, tool, command, reason: created.append((tool, command, reason)),
        ):
            analysis.AnalysisEngine.analyze_nmap_results(scan_id=8, open_ports=open_ports)

        self.assertEqual(
            created,
            [
                (
                    "http_review",
                    "curl -isk https://<target>:443/",
                    "HTTP service detected. Capture headers, redirects, and auth hints before active probing.",
                ),
                (
                    "route_review",
                    "Review observed auth, admin, and API routes on https://<target>:443/ before adding active enumeration.",
                    "Web surface detected. Prioritize contextual route validation over generic directory brute force.",
                ),
            ],
        )


class CortexEngineTests(unittest.TestCase):
    def test_derive_attack_paths_requires_metadata_signal_for_ssrf_next_step(self):
        findings = [
            SimpleNamespace(
                id=11,
                title="SSRF candidate",
                description="Potential SSRF on url parameter",
                category="ssrf_surface",
                signal_ids=[5],
                metadata_json={},
            )
        ]

        paths = analysis.CortexEngine.derive_attack_paths(findings)

        titles = [item["title"] for item in paths]
        self.assertNotIn("Cortex Next Step: Probe SSRF Metadata Path", titles)

    def test_derive_attack_paths_keeps_js_plan_deterministic_and_non_duplicated(self):
        findings = [
            SimpleNamespace(
                id=3,
                title="Hidden JavaScript route",
                description="JavaScript bundle references /admin/api/users",
                category="js_intelligence",
                signal_ids=[8, 8, 9],
                metadata_json={"field_sources": {"endpoint": "js"}},
            ),
            SimpleNamespace(
                id=4,
                title="Hidden API endpoint",
                description="Hidden API route /admin/api/users discovered",
                category="api_surface",
                signal_ids=[10],
                metadata_json={},
            ),
        ]

        first = analysis.CortexEngine.derive_attack_paths(findings)
        second = analysis.CortexEngine.derive_attack_paths(list(reversed(findings)))

        self.assertEqual(first, second)
        js_plan = next(item for item in first if item["title"] == "Cortex Attack Plan: Investigate JS-Derived Routes")
        self.assertEqual(js_plan["metadata"]["chain"], ["javascript_surface", "route_validation"])
        self.assertEqual(js_plan["metadata"]["related_signal_ids"], [8, 9, 10])
        self.assertEqual(js_plan["metadata"]["reason_tags"], ["api_surface", "javascript_surface"])


class RiskScoringEngineTests(unittest.TestCase):
    def test_score_finding_does_not_promote_low_evidence_chain_to_high_priority(self):
        finding = SimpleNamespace(
            id=21,
            id_stable="finding-21",
            severity="low",
            confidence="low",
            title="Heuristic chain",
            description="Weakly correlated chain without validation",
            tool_source="correlation_engine",
            category="attack_path",
            signal_ids=[],
            metadata_json={"chain_length": 3},
        )

        exploit_score, risk_level, attack_priority, chain_length, signal_count, dependency_risk = analysis.RiskScoringEngine.score_finding(
            finding
        )

        self.assertEqual(exploit_score, 28.75)
        self.assertEqual(risk_level, "low")
        self.assertEqual(chain_length, 3)
        self.assertEqual(signal_count, 0)
        self.assertEqual(dependency_risk, 0.0)
        self.assertEqual(attack_priority, "low")

    def test_apply_risk_scores_preserves_existing_metadata_and_contract_fields(self):
        finding = SimpleNamespace(
            id=22,
            id_stable="stable-22",
            scan_id=5,
            severity="high",
            confidence="medium",
            title="Validated route chain",
            description="Exploit validation confirmed object access drift",
            tool_source="exploit_validation_engine",
            category="attack_path",
            signal_ids=[9, 7],
            metadata_json={
                "chain": ["auth_surface", "object_reference_surface", "authorization_drift"],
                "field_sources": {"provenance": "unit_test"},
                "score_factors": {"legacy": 0.2},
                "provenance": {"source": "unit_test"},
            },
        )
        fake_query = MagicMock()
        fake_query.filter_by.return_value.all.return_value = [finding]

        with patch.object(analysis, "Finding", SimpleNamespace(query=fake_query)), patch.object(
            analysis.db.session, "commit"
        ) as commit:
            updated = analysis.apply_risk_scores(scan_id=5, graph={"nodes": [{"id": "finding:db:stable-22"}]})

        self.assertEqual(updated, 1)
        self.assertEqual(finding.metadata_json["risk_level"], "critical")
        self.assertEqual(finding.metadata_json["attack_priority"], "critical")
        self.assertEqual(finding.metadata_json["signal_count"], 2)
        self.assertEqual(finding.metadata_json["chain_length"], 3)
        self.assertEqual(finding.metadata_json["attack_complexity"], "medium")
        self.assertEqual(finding.metadata_json["field_sources"]["provenance"], "unit_test")
        self.assertEqual(finding.metadata_json["field_sources"]["exploit_score"], "risk_scoring_engine")
        self.assertEqual(finding.metadata_json["score_factors"]["legacy"], 0.2)
        self.assertIn("attack_graph_bonus", finding.metadata_json["score_factors"])
        self.assertEqual(finding.metadata_json["provenance"], {"source": "unit_test"})
        commit.assert_called_once()


class PipelineIntegrationTests(unittest.TestCase):
    def test_run_cortex_attack_reasoning_adds_only_new_titles_and_keeps_metadata(self):
        findings = [
            SimpleNamespace(
                id=31,
                title="Login page detected",
                description="Authentication surface present",
                category="auth_surface",
                signal_ids=[1],
                metadata_json={},
            ),
            SimpleNamespace(
                id=32,
                title="API token leak",
                description="Bearer token observed in JavaScript response",
                category="token_leakage",
                signal_ids=[2],
                metadata_json={"field_sources": {"evidence": "unit_test"}},
            ),
            SimpleNamespace(
                id=33,
                title="Cortex Attack Path: Auth Surface + Token Material -> Authenticated API Access",
                description="Existing reasoning finding",
                category="attack_path",
                signal_ids=[],
                metadata_json={},
            ),
        ]
        fake_query = MagicMock()
        fake_query.filter_by.return_value.all.return_value = findings
        created = []

        with patch.object(analysis, "Finding", SimpleNamespace(query=fake_query)):
            created_count = analysis.run_cortex_attack_reasoning(
                scan_id=12,
                add_finding_cb=lambda **payload: created.append(payload),
            )

        self.assertEqual(created_count, 1)
        self.assertEqual([item["title"] for item in created], ["Cortex Attack Plan: Investigate JS-Derived Routes"])
        self.assertEqual(created[0]["metadata"]["related_finding_ids"], [32])
        self.assertEqual(created[0]["metadata"]["related_signal_ids"], [2])

    def test_run_cortex_attack_reasoning_emits_expected_payload_for_new_path(self):
        findings = [
            SimpleNamespace(
                id=41,
                title="Login page detected",
                description="Authentication surface present",
                category="auth_surface",
                signal_ids=[1],
                metadata_json={},
            ),
            SimpleNamespace(
                id=42,
                title="API token leak",
                description="Bearer token observed in JavaScript response",
                category="token_leakage",
                signal_ids=[2],
                metadata_json={"provenance": {"source": "unit_test"}},
            ),
        ]
        fake_query = MagicMock()
        fake_query.filter_by.return_value.all.return_value = findings
        created = []

        with patch.object(analysis, "Finding", SimpleNamespace(query=fake_query)):
            created_count = analysis.run_cortex_attack_reasoning(
                scan_id=13,
                add_finding_cb=lambda **payload: created.append(payload),
            )

        self.assertEqual(created_count, 2)
        self.assertEqual(
            [item["title"] for item in created],
            [
                "Cortex Attack Path: Auth Surface + Token Material -> Authenticated API Access",
                "Cortex Attack Plan: Investigate JS-Derived Routes",
            ],
        )
        payload = created[0]
        self.assertEqual(payload["category"], "attack_path")
        self.assertEqual(payload["tool_source"], "cortex_engine")
        self.assertEqual(payload["metadata"]["related_finding_ids"], [41, 42])
        self.assertEqual(payload["metadata"]["related_signal_ids"], [1, 2])
        self.assertEqual(
            payload["metadata"]["chain_explanation"]["likely_next_action"],
            "Validate token scope and replay controls on authenticated endpoints already discovered.",
        )
        self.assertIn("Trace prerequisite findings", payload["reproduction"])


if __name__ == "__main__":
    unittest.main()
