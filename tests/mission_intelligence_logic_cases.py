import importlib
import sys
import types
import unittest
from types import SimpleNamespace


def _install_mission_test_stubs():
    passive_module = types.ModuleType("scan_engine.helpers.passive_intel_engine")
    passive_module.AssetDiscoveryEngine = object
    passive_module.SecretsIntelligenceEngine = object
    passive_module.PassiveIntelligenceEngine = object
    sys.modules["scan_engine.helpers.passive_intel_engine"] = passive_module

    models_module = types.ModuleType("core.models")

    class _StubQuery:
        def filter_by(self, **kwargs):
            return self

        def filter(self, *args, **kwargs):
            return self

        def order_by(self, *args, **kwargs):
            return self

        def limit(self, *args, **kwargs):
            return self

        def all(self):
            return []

        def first(self):
            return None

        def get_or_404(self, _id):
            raise AssertionError("DB-backed queries should not run in this unit test")

    class _StubModel:
        query = _StubQuery()

    for name in [
        "Asset",
        "AssetTargetLink",
        "AuthIdentityMap",
        "Finding",
        "Mission",
        "OperatorAction",
        "ReplayVaultEntry",
        "Scan",
        "Signal",
        "Target",
    ]:
        setattr(models_module, name, type(name, (_StubModel,), {}))

    models_module.db = SimpleNamespace(
        session=SimpleNamespace(add=lambda *args, **kwargs: None, flush=lambda: None, commit=lambda: None)
    )
    sys.modules["core.models"] = models_module


_install_mission_test_stubs()
mission_intelligence = importlib.import_module("core.mission_intelligence")


class MissionIntelligenceLogicTests(unittest.TestCase):
    def test_derive_operator_actions_stays_blocked_without_supporting_findings(self):
        objective = {
            "objective_type": "cloud_credential_path",
            "confidence": 0.91,
            "recommended_next_steps": ["Validate IMDS reachability safely"],
            "required_conditions": ["network_path_verified"],
        }

        actions = mission_intelligence.derive_operator_actions([objective], [])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["status"], "blocked")
        self.assertEqual(actions[0]["related_finding_ids"], [])
        self.assertIn("no_supporting_findings", actions[0]["blocker_summary"]["reasons"])
        self.assertIn("missing_signal_lineage", actions[0]["blocker_summary"]["reasons"])

    def test_cross_asset_paths_require_shared_lineage_before_correlation(self):
        unrelated_findings = [
            SimpleNamespace(id=1, severity="high", title="Asset A secret", category="secret", signal_ids=[11], scan=None),
            SimpleNamespace(id=2, severity="high", title="Asset B schema", category="schema", signal_ids=[22], scan=None),
        ]

        self.assertEqual(mission_intelligence._derive_cross_asset_paths(unrelated_findings), [])

        correlated_findings = [
            SimpleNamespace(id=3, severity="high", title="Token leak", category="token_leakage", signal_ids=[77], scan=None),
            SimpleNamespace(id=4, severity="medium", title="Auth surface", category="auth_surface", signal_ids=[77], scan=None),
        ]

        paths = mission_intelligence._derive_cross_asset_paths(correlated_findings)

        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["objective_type"], "authenticated_api_path")
        self.assertEqual(paths[0]["metadata"]["shared_signal_ids"], [77])


if __name__ == "__main__":
    unittest.main()
