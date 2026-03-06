import unittest
from types import SimpleNamespace

from scan_engine.helpers.passive_intel_engine import PassiveIntelligenceEngine, AssetDiscoveryEngine, SecretsIntelligenceEngine
from core.analysis import RiskScoringEngine
from adapters.detection_adapter import DetectionAdapter


class IntelligenceEngineTests(unittest.TestCase):
    def setUp(self):
        self.results = {
            "target": "example.com",
            "phases": {
                "dns": {"subdomains": ["api.example.com", "cdn.example.com"]},
                "enum": {
                    "targets": {
                        "443": [
                            "https://api.example.com/auth/login",
                            "https://cdn.example.com/assets/app.js",
                            "https://internal.example.local/admin",
                        ]
                    },
                    "headers": {
                        "443": {
                            "server": {"value": "nginx"},
                            "x-powered-by": {"value": "Express"},
                        }
                    },
                    "api": {
                        "discovered_endpoints": [
                            "https://api.example.com/v1/users",
                            "https://bucket.s3.amazonaws.com/public",
                        ]
                    },
                    "js_deep_mining": {
                        "discovered_endpoints": ["https://portal.azurewebsites.net/admin"],
                    },
                },
                "dirbusting": {
                    "ffuf": {
                        "endpoints": ["https://d111111abcdef8.cloudfront.net/static"]
                    }
                },
                "vuln": {},
            },
            "raw": "token='ghp_abcdefghijklmnopqrstuvwxyz123456' and key='AKIAABCDEFGHIJKLMNOP' and -----BEGIN PRIVATE KEY-----",
        }

    def test_asset_discovery_detection(self):
        findings = AssetDiscoveryEngine.derive_findings(self.results, "example.com")
        categories = {f.get("category") for f in findings}
        endpoints = {f.get("endpoint") for f in findings}
        self.assertIn("asset_discovery", categories)
        self.assertIn("cloud_asset", categories)
        self.assertIn("api.example.com", endpoints)

    def test_secret_detection_patterns(self):
        findings = SecretsIntelligenceEngine.derive_findings(self.results, "example.com")
        types = {f.get("metadata", {}).get("secret_type") for f in findings}
        self.assertIn("github_token", types)
        self.assertIn("aws_access_key_id", types)
        self.assertIn("private_key", types)

    def test_risk_scoring_calculation(self):
        finding = SimpleNamespace(
            severity="high",
            confidence="high",
            endpoint="https://api.example.com/auth/login",
            target="example.com",
            metadata_json={"exploit_validated": True},
            id_stable="abc",
            title="Validated exploit",
            description="Exploit validation succeeded",
            tool_source="exploit_validation_engine",
        )
        score, level, priority, chain_length, signal_count, dependency_risk = RiskScoringEngine.score_finding(finding, {"finding:db:abc"})
        self.assertGreaterEqual(score, 80)
        self.assertEqual(level, "critical")
        self.assertEqual(priority, "critical")
        self.assertEqual(chain_length, 0)
        self.assertEqual(signal_count, 0)
        self.assertGreaterEqual(dependency_risk, 0.0)

    def test_attack_path_prioritization_fields_in_adapter(self):
        finding = SimpleNamespace(
            id=1,
            id_stable="path-1",
            title="Cortex Attack Path",
            severity="high",
            confidence="high",
            description="attack path",
            tool_source="cortex_engine",
            target="example.com",
            endpoint="https://api.example.com/auth/login",
            parameter=None,
            payload=None,
            request=None,
            response=None,
            repro_command=None,
            screenshot_path=None,
            raw_output=None,
            signal_ids=[1, 2],
            category="attack_path",
            evidence="evidence",
            reproduction="repro",
            module="cortex_reasoning",
            metadata_json={
                "exploit_score": 91.2,
                "risk_level": "critical",
                "attack_priority": "critical",
                "chain_length": 3,
                "attack_complexity": "medium",
            },
        )
        normalized = DetectionAdapter.normalize_findings([finding], {"phases": {}})
        self.assertEqual(len(normalized), 1)
        item = normalized[0]
        self.assertEqual(item.get("exploit_score"), 91.2)
        self.assertEqual(item.get("attack_priority"), "critical")
        self.assertEqual(item.get("chain_length"), 3)
        self.assertEqual(item.get("signal_count"), 2)

    def test_passive_engine_contains_git_exposure(self):
        local = dict(self.results)
        local["git_path"] = "https://example.com/.git/config"
        findings = PassiveIntelligenceEngine.derive_findings(local, "example.com")
        categories = {f.get("category") for f in findings}
        self.assertIn("git_exposure", categories)


if __name__ == "__main__":
    unittest.main()
