import unittest

from scan_engine.helpers.passive_intel_engine import PassiveIntelligenceEngine


class PassiveIntelTests(unittest.TestCase):
    def test_subdomain_api_and_parameter_surface_discovery(self):
        results = {
            "target": "example.com",
            "phases": {
                "enum": {
                    "targets": {
                        "443": [
                            "https://app.example.com/home?user_id=1&token=abc",
                            "https://example.com/api/v1/users",
                        ]
                    }
                }
            },
            "artifact": "fetch('/api/v2/orders?account_id=9'); const u='https://api.example.com/graphql?token=';",
        }

        findings = PassiveIntelligenceEngine.derive_findings(results, "example.com")
        categories = {f.get("category") for f in findings}
        discovered_assets = {f.get("metadata", {}).get("discovered_asset") for f in findings if isinstance(f.get("metadata"), dict)}
        parameters = {f.get("parameter") for f in findings if f.get("category") == "parameter_surface"}

        self.assertIn("asset_discovery", categories)
        self.assertIn("api_surface", categories)
        self.assertIn("parameter_surface", categories)
        self.assertIn("api.example.com", discovered_assets)
        self.assertIn("user_id", parameters)
        self.assertIn("token", parameters)


if __name__ == "__main__":
    unittest.main()
