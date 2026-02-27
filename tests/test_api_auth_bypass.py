
import unittest
from unittest.mock import MagicMock, patch
from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner

class MockResponse:
    def __init__(self, status_code, text, headers=None, content=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.content = content or text.encode()
        self.reason = "OK" if status_code == 200 else "Error"

class TestAPIAuthBypass(unittest.TestCase):
    def setUp(self):
        self.scanner = APIExpertScanner("https://example.com")
        self.target_url = "https://example.com/api/login"

    @patch('scan_engine.helpers.http_client.post')
    @patch('scan_engine.step03_vuln.api_expert_scanner.get_session')
    def test_login_page_200_no_detect(self, mock_get_session, mock_post):
        """1. Login page returns 200 but identical to baseline (Static page) -> No Detection"""
        static_html = "<html><body>Login Page</body></html>"
        
        # Baseline response
        mock_post.return_value = MockResponse(200, static_html)
        
        # Attack response (identical to baseline)
        mock_session = MagicMock()
        mock_session.post.return_value = MockResponse(200, static_html)
        mock_get_session.return_value = mock_session

        findings = self.scanner.auth_bypass_check(self.target_url)
        self.assertEqual(len(findings), 0, "Should suppress findings identical to baseline")

    @patch('scan_engine.helpers.http_client.post')
    def test_login_401_no_detect(self, mock_post):
        """2. Login returns 401 -> No Detection"""
        mock_post.return_value = MockResponse(401, "Unauthorized")
        
        findings = self.scanner.auth_bypass_check(self.target_url)
        self.assertEqual(len(findings), 0)

    @patch('scan_engine.helpers.http_client.post')
    @patch('scan_engine.step03_vuln.api_expert_scanner.get_session')
    def test_jwt_no_privilege_medium(self, mock_get_session, mock_post):
        """3. V10: JWT but no privilege → MEDIUM (not HIGH). HIGH requires privilege."""
        # Baseline
        mock_post.return_value = MockResponse(401, "Invalid")
        
        # Attack
        jwt_body = '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoyNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
        mock_session = MagicMock()
        mock_session.post.return_value = MockResponse(200, jwt_body)
        
        # Privilege check fails (403)
        mock_session.get.return_value = MockResponse(403, "Forbidden")
        mock_get_session.return_value = mock_session

        findings = self.scanner.auth_bypass_check(self.target_url)
        self.assertGreaterEqual(len(findings), 1)
        # V10: JWT alone = score 2 → MEDIUM (not HIGH)
        self.assertEqual(findings[0]['severity'], 'medium')
        self.assertIn("MEDIUM", findings[0]['title'])

    @patch('scan_engine.helpers.http_client.post')
    @patch('scan_engine.step03_vuln.api_expert_scanner.get_session')
    def test_full_bypass_critical(self, mock_get_session, mock_post):
        """4. V10: Real auth session cookie + privilege access → CRITICAL"""
        # Baseline
        mock_post.return_value = MockResponse(401, "Invalid")
        
        # Attack returns real auth cookie
        mock_session = MagicMock()
        mock_session.post.return_value = MockResponse(200, "Welcome Admin", headers={"Set-Cookie": "session=xyz123"})
        
        # Privilege check succeeds
        mock_session.get.return_value = MockResponse(200, "<html><body>Admin Dashboard</body></html>")
        mock_get_session.return_value = mock_session

        findings = self.scanner.auth_bypass_check(self.target_url)
        # V10: Multiple payloads may each produce a finding
        critical_findings = [f for f in findings if f['severity'] == 'critical']
        self.assertGreaterEqual(len(critical_findings), 1,
                                "Real auth cookie + privilege must produce CRITICAL")
        self.assertIn("CRITICAL", critical_findings[0]['title'])

if __name__ == '__main__':
    unittest.main()
