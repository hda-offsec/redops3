import unittest

from scan_engine.helpers.passive_intel_engine import SecretsIntelligenceEngine


class SecretDetectionTests(unittest.TestCase):
    def test_secret_patterns_include_required_types(self):
        telemetry = {
            "js": "AKIAABCDEFGHIJKLMNOP and AIzaSyD3hL5Qx7s4xvA0QwM0l4QJm9aAbCdEfGh and ghp_abcdefghijklmnopqrstuvwxyz123456",
            "auth": "Authorization: Basic YWRtaW46c2VjcmV0MTIz",
            "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaa.bbbbbbbbbbbb",
            "pem": "-----BEGIN PRIVATE KEY-----",
        }
        findings = SecretsIntelligenceEngine.derive_findings(telemetry, "example.com")
        found = {f.get("metadata", {}).get("secret_type") for f in findings}
        severities = {f.get("severity") for f in findings}

        self.assertIn("aws_access_key_id", found)
        self.assertIn("gcp_api_key", found)
        self.assertIn("github_token", found)
        self.assertIn("jwt_token", found)
        self.assertIn("private_key", found)
        self.assertIn("basic_auth", found)
        self.assertEqual(severities, {"high"})


if __name__ == "__main__":
    unittest.main()
