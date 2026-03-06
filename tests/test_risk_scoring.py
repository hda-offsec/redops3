import unittest
from types import SimpleNamespace

from core.analysis import RiskScoringEngine


class RiskScoringTests(unittest.TestCase):
    def test_scoring_is_deterministic_and_uses_chain_inputs(self):
        finding = SimpleNamespace(
            severity="high",
            confidence="high",
            endpoint="https://example.com/api/v1/users",
            target="example.com",
            metadata_json={"chain": ["js_api", "auth_parameter", "token"], "exploit_validated": True},
            signal_ids=[1, 2, 3, 4],
            id_stable="risk-1",
            title="Attack chain finding",
            description="validated",
            tool_source="exploit_validation_engine",
        )
        score_1 = RiskScoringEngine.score_finding(finding, {"finding:db:risk-1"})
        score_2 = RiskScoringEngine.score_finding(finding, {"finding:db:risk-1"})
        self.assertEqual(score_1, score_2)
        exploit_score, risk_level, attack_priority, chain_length, signal_count, dependency_risk = score_1
        self.assertGreaterEqual(exploit_score, 70)
        self.assertEqual(chain_length, 3)
        self.assertEqual(signal_count, 4)
        self.assertGreaterEqual(dependency_risk, 0.0)
        self.assertIn(risk_level, {"high", "critical"})
        self.assertIn(attack_priority, {"high", "critical"})


if __name__ == "__main__":
    unittest.main()
