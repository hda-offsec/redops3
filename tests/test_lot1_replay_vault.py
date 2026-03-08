import unittest

from core.replay_vault import (
    compare_replay_artifacts,
    extract_auth_identity_observations,
    normalize_replay_artifact,
)


class ReplayVaultNormalizationTests(unittest.TestCase):
    def test_normalization_redacts_sensitive_headers_and_summarizes_body(self):
        payload = {
            "method": "post",
            "url": "https://example.org/api/login?next=/admin",
            "request_headers": {
                "Authorization": "Bearer secret.jwt.token",
                "User-Agent": "UA",
            },
            "request_cookies": {"sessionid": "abcdef"},
            "request_body": {"username": "alice", "password": "p@ss"},
            "status_code": "200",
            "response_headers": {"Content-Type": "application/json"},
            "response_body": {"token": "x", "role": "admin"},
        }

        normalized = normalize_replay_artifact(payload)

        self.assertEqual(normalized["method"], "POST")
        self.assertEqual(normalized["status_code"], 200)
        self.assertEqual(normalized["request_headers"]["Authorization"], "[redacted]")
        self.assertEqual(normalized["request_cookies"]["sessionid"], "[present]")
        self.assertEqual(normalized["request_body_summary"]["kind"], "json")
        self.assertIn("sha256", normalized["response_body_summary"])
        self.assertEqual(normalized["query_params"].get("next"), "/admin")



    def test_normalization_handles_empty_or_malformed_payload(self):
        normalized = normalize_replay_artifact({"status_code": "bad-int", "request_headers": "oops"})
        self.assertEqual(normalized["method"], "GET")
        self.assertIsNone(normalized["status_code"])
        self.assertEqual(normalized["request_headers"], {})
        self.assertEqual(normalized["request_cookies"], {})


class DifferentialAnalysisTests(unittest.TestCase):
    def test_differential_engine_detects_status_headers_and_json_shape_changes(self):
        left = {
            "method": "GET",
            "url": "https://example.org/api/me",
            "status_code": 200,
            "response_headers": {"Content-Type": "application/json", "X-Frame-Options": "DENY"},
            "response_body": {"id": 1, "name": "alice"},
        }
        right = {
            "method": "GET",
            "url": "https://example.org/api/me",
            "status_code": 403,
            "response_headers": {"Content-Type": "application/json", "X-Frame-Options": "SAMEORIGIN"},
            "response_body": {"error": "forbidden"},
        }

        diff = compare_replay_artifacts(left, right)

        self.assertFalse(diff["same_status"])
        self.assertFalse(diff["same_shape"])
        self.assertIn("error", diff["added_fields"])
        self.assertIn("id", diff["removed_fields"])
        self.assertIn("X-Frame-Options", diff["header_differences"])
        self.assertGreaterEqual(diff["significance_score"], 5)


class AuthIdentityTests(unittest.TestCase):
    def test_auth_identity_observation_is_prudent_and_observation_only(self):
        artifact = {
            "method": "POST",
            "url": "https://example.org/auth/login",
            "request_headers": {
                "Authorization": "Bearer aaa.bbb.ccc",
            },
            "request_cookies": {"session": "opaque"},
            "response_headers": {"Set-Cookie": "session=abc; HttpOnly"},
            "response_body": {"claims": ["user"], "scope": "read"},
        }

        obs = extract_auth_identity_observations(artifact)

        self.assertIn("login", obs["route_auth_hints"])
        self.assertIn("session", obs["session_cookie_names"])
        self.assertTrue(obs["bearer_token_present"])
        self.assertTrue(obs["jwt_like_token"])
        self.assertIn("scope", obs["role_scope_claim_hints"])
        self.assertTrue(obs["observation_only"])


if __name__ == "__main__":
    unittest.main()
