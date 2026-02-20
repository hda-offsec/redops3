import unittest

from scan_engine.helpers.execution_hints import derive_execution_hints
from scan_engine.helpers.safety_checks import validate_results_schema
from scan_engine.helpers.surface_expander import derive_surface_expansion


class TestSurfaceExpansionAndHints(unittest.TestCase):
    def test_caps_and_schema_warnings_empty(self):
        sample = {
            "target": "example.com",
            "phases": {
                "recon": {"open_ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]},
                "enum": {
                    "injection_points": {"80": ["http://example.com:80/search?q=1"]},
                    "targets": {"80": ["http://example.com:80/"]},
                    "api": {"discovered_endpoints": ["http://example.com:80/api/v1/users"]},
                    "js_secrets": {"80": [{"type": "token"}]},
                    "attack_profile": {"80": {"stack": ["react", "spa"]}},
                    "mutation_strategy": {"80": {"xss": "default"}},
                    "waf": {},
                    "derived": {},
                    "whatweb": {"summary": {"80": "nginx"}},
                },
                "vuln": {"wordpress": {"80": {"vulns": []}, "443": {"vulns": []}}, "graphql": []},
            },
            "scan_id": 1,
            "status": "running",
            "timestamp": "2026-01-01T00:00:00",
            "commands": [],
            "modules": {},
            "timeline": [],
            "target_info": {},
            "attack_plan": [],
            "task_status": {},
            "progress": 0,
            "metrics": {},
            "harmless_top_key": "ok",
        }

        surface = derive_surface_expansion(sample)
        sample["phases"]["enum"]["derived"]["surface_expansion"] = surface
        hints = derive_execution_hints(sample)
        sample["phases"]["enum"]["derived"]["execution_hints"] = hints

        self.assertLessEqual(len(surface["global"]["derived_endpoints"]), 30)
        self.assertLessEqual(len(hints["dalfox"]["seed_priority"]), 200)
        self.assertLessEqual(len(hints["nuclei"]["extra_tags"]), 3)
        self.assertTrue(any(u.startswith("https://example.com/") and ":443" not in u for u in hints["dalfox"]["seed_priority"]))

        warnings = validate_results_schema(sample)
        self.assertEqual([], warnings)


if __name__ == "__main__":
    unittest.main()
