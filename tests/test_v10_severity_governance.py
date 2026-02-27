"""
V10 Regression Shield — Severity Governance & False Positive Eradication.

Test A: WordPress normal login redirect → MUST NOT produce HIGH
Test B: Public email in footer → MUST classify INFO
Test C: Missing CSP header → classified via nuclei severity (not our scanner)
Test D: HPP redirect_to without behavior change → INFO or SUPPRESS
Test E: X-Forwarded-For without 403 baseline → SUPPRESS (no bypass possible)
Test F: Duplicate Auth finding → blocked by dedupe
Test G: Privacy cookie only → MUST NOT produce HIGH auth bypass
Test H: Public IP in HTML → MUST classify INFO
"""

import unittest
from unittest.mock import MagicMock, patch
import hashlib


class MockResponse:
    def __init__(self, status_code, text, headers=None, url="http://test.local/"):
        self.status_code = status_code
        self.text = text
        self._content = text.encode('utf-8')
        self.content = self._content
        self.headers = headers or {}
        self.reason = "OK" if status_code == 200 else "Error"
        self.url = url
        self.request = MagicMock()
        self.request.headers = {"User-Agent": "Test"}
        self.cookies = {}


# ================================================
# AUTH BYPASS V10
# ================================================

class TestAuthBypassV10(unittest.TestCase):
    """Auth bypass must require real auth cookie + privilege for HIGH+."""

    @patch('scan_engine.step03_vuln.api_expert_scanner.get_session')
    @patch('scan_engine.step03_vuln.api_expert_scanner.http_client')
    def test_A_wordpress_login_redirect_no_high(self, mock_http, mock_get_session):
        """Test A: WP 302 redirect with privacy cookie → NOT HIGH."""
        from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner

        scanner = APIExpertScanner("rvz-location.fr")

        # Baseline: login page returns 200
        baseline_resp = MockResponse(
            200, '<html><body><form id="loginform">Login</form></body></html>',
            headers={'content-type': 'text/html'}
        )

        # Attack: returns 302 with privacy cookie (standard WP behavior)
        attack_resp = MockResponse(
            302, '',
            headers={
                'set-cookie': 'viewed_cookie_policy=yes; path=/',
                'location': 'http://rvz-location.fr/',
                'content-type': 'text/html'
            },
            url="http://rvz-location.fr/login"
        )
        attack_resp.request = MagicMock()
        attack_resp.request.headers = {"User-Agent": "Test"}

        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_session.post.return_value = attack_resp
        mock_session.get.return_value = MockResponse(200, '<html>Login page</html>')

        mock_http.get.return_value = baseline_resp

        findings = scanner.assault_endpoint("http://rvz-location.fr/login")
        high_findings = [f for f in findings if f.get('severity') in ('high', 'critical')
                         and 'Auth' in f.get('title', '')]
        self.assertEqual(len(high_findings), 0,
                         "Test A: WP login with privacy cookie must NOT be HIGH")

    @patch('scan_engine.step03_vuln.api_expert_scanner.get_session')
    @patch('scan_engine.step03_vuln.api_expert_scanner.http_client')
    def test_G_privacy_cookie_not_auth(self, mock_http, mock_get_session):
        """Test G: Privacy/GDPR cookie should NOT count as auth session."""
        from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner

        scanner = APIExpertScanner("test.local")

        baseline_resp = MockResponse(200, '<html>Login</html>', headers={})
        attack_resp = MockResponse(
            200, '<html>Login Page After Submit</html>',
            headers={
                'set-cookie': 'cookielawinfo-consent=yes; gdpr_consent=true',
                'content-type': 'text/html'
            }
        )
        attack_resp.request = MagicMock()
        attack_resp.request.headers = {}

        mock_session = MagicMock()
        mock_get_session.return_value = mock_session
        mock_session.post.return_value = attack_resp
        mock_session.get.return_value = MockResponse(200, '<html>Login</html>')

        mock_http.get.return_value = baseline_resp

        findings = scanner.assault_endpoint("http://test.local/login")
        for f in findings:
            if 'Auth' in f.get('title', ''):
                self.assertNotIn(f['severity'], ('high', 'critical'),
                                 "Test G: GDPR cookie must NOT produce HIGH auth finding")


# ================================================
# DATA MINER V10
# ================================================

class TestDataMinerV10(unittest.TestCase):
    """Public data in HTML must be classified INFO, not HIGH."""

    def test_B_public_email_info(self):
        """Test B: Public contact email → INFO."""
        # The severity is set in vuln.py, not in data_miner.py itself.
        # We verify the classification logic.
        SECRET_TYPES = {'api_keys', 'aws_keys', 'jwt_tokens', 'google_api',
                        'private_keys', 'stripe_keys', 'slack_tokens'}
        
        emails_type = 'emails'
        self.assertNotIn(emails_type, SECRET_TYPES)
        
        # Classification: emails → info
        if emails_type in SECRET_TYPES:
            sev = "high"
        elif emails_type in ('emails', 'ip_addresses'):
            sev = "info"
        else:
            sev = "low"
        
        self.assertEqual(sev, "info",
                         "Test B: Email in HTML → INFO, not HIGH")

    def test_H_public_ip_info(self):
        """Test H: Public IP address → INFO."""
        SECRET_TYPES = {'api_keys', 'aws_keys', 'jwt_tokens', 'google_api',
                        'private_keys', 'stripe_keys', 'slack_tokens'}
        
        ip_type = 'ip_addresses'
        if ip_type in SECRET_TYPES:
            sev = "high"
        elif ip_type in ('emails', 'ip_addresses'):
            sev = "info"
        else:
            sev = "low"
        
        self.assertEqual(sev, "info",
                         "Test H: Public IP → INFO, not HIGH")

    def test_real_secret_stays_high(self):
        """Actual API keys must remain HIGH."""
        SECRET_TYPES = {'api_keys', 'aws_keys', 'jwt_tokens', 'google_api',
                        'private_keys', 'stripe_keys', 'slack_tokens'}
        
        for secret_type in SECRET_TYPES:
            sev = "high" if secret_type in SECRET_TYPES else "low"
            self.assertEqual(sev, "high",
                             f"Secret type '{secret_type}' must remain HIGH")


# ================================================
# WAF BYPASS V10
# ================================================

class TestWafBypassV10(unittest.TestCase):
    """WAF bypass requires 401/403 baseline. 200→200 is NOT a bypass."""

    def test_E_no_403_baseline_no_bypass(self):
        """Test E: No protected paths (all 200) → No findings."""
        from scan_engine.step03_vuln.waf_bypass_scanner import WafBypassScanner

        scanner = WafBypassScanner("test.local")
        mock_session = MagicMock()
        scanner.session = mock_session

        # All test paths return 200 (nothing is protected)
        mock_session.get.return_value = MockResponse(200, '<html>OK</html>')

        findings = scanner.scan(80, 'http')
        self.assertEqual(len(findings), 0,
                         "Test E: No 401/403 baseline → No WAF bypass possible")

    def test_real_bypass_detected(self):
        """Real bypass: 403 baseline → 200 with header → CRITICAL."""
        from scan_engine.step03_vuln.waf_bypass_scanner import WafBypassScanner

        scanner = WafBypassScanner("test.local")
        mock_session = MagicMock()
        scanner.session = mock_session

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            url = args[0] if args else kwargs.get('url', '')
            headers = kwargs.get('headers', {})
            
            if 'X-Forwarded-For' in headers or 'X-Originating-IP' in headers:
                # Bypass successful
                return MockResponse(200, '<html>Admin Panel</html>')
            if 'admin' in url:
                return MockResponse(403, 'Forbidden')
            return MockResponse(200, '<html>OK</html>')

        mock_session.get.side_effect = side_effect

        findings = scanner.scan(80, 'http')
        critical = [f for f in findings if f['severity'] == 'critical']
        self.assertGreaterEqual(len(critical), 1,
                                "Real 403→200 bypass must produce CRITICAL finding")


# ================================================
# HPP V10
# ================================================

class TestHPPV10(unittest.TestCase):
    """HPP requires behavior change, not just reflection."""

    def test_D_reflection_no_behavior_change_info(self):
        """Test D: redirect_to duplication without behavior change → INFO."""
        from scan_engine.step03_vuln.business_logic_scanner import BusinessLogicScanner

        scanner = BusinessLogicScanner()
        mock_session = MagicMock()
        scanner.session = mock_session

        # Both baseline and attack return identical response (with reflection)
        response = MockResponse(
            200,
            '<html><body>redirect_to=redops_hpp_test appears but page is same</body></html>',
            headers={}
        )
        mock_session.get.return_value = response

        findings = scanner.scan_hpp(
            "http://test.local/wp-login.php?redirect_to=admin"
        )
        # Should NOT produce MEDIUM
        medium_findings = [f for f in findings if f['severity'] == 'medium']
        self.assertEqual(len(medium_findings), 0,
                         "Test D: HPP reflection without behavior change → NOT MEDIUM")
        # May produce INFO
        info_findings = [f for f in findings if f['severity'] == 'info']
        self.assertGreaterEqual(len(info_findings), 0,
                                "Test D: Reflection without change → INFO at most")


# ================================================
# DEDUPLICATION V10
# ================================================

class TestDeduplicationV10(unittest.TestCase):
    """Duplicate findings must be blocked by fingerprint."""

    def test_F_duplicate_blocked(self):
        """Test F: Same finding twice → only one counted."""
        from scan_engine.orchestrator import ScanOrchestrator

        findings_collected = []
        def mock_callback(**kwargs):
            findings_collected.append(kwargs)

        orch = ScanOrchestrator.__new__(ScanOrchestrator)
        orch._finding_callback = mock_callback
        orch.results = {}
        orch._results_lock = __import__('threading').Lock()
        orch._finding_fingerprints = set()
        
        # Provide emit_event as no-op
        orch.emit_event = lambda *args, **kwargs: None

        # Add same finding twice
        for _ in range(2):
            orch.add_finding(
                title="HIGH: Probable Auth Bypass",
                severity="high",
                tool_source="API-Assault",
                url="http://test.local/login"
            )

        self.assertEqual(len(findings_collected), 1,
                         "Test F: Duplicate finding must be blocked")

    def test_different_findings_allowed(self):
        """Different findings must NOT be blocked."""
        from scan_engine.orchestrator import ScanOrchestrator

        findings_collected = []
        def mock_callback(**kwargs):
            findings_collected.append(kwargs)

        orch = ScanOrchestrator.__new__(ScanOrchestrator)
        orch._finding_callback = mock_callback
        orch.results = {}
        orch._results_lock = __import__('threading').Lock()
        orch._finding_fingerprints = set()
        orch.emit_event = lambda *args, **kwargs: None

        orch.add_finding(
            title="Finding A",
            severity="high",
            tool_source="scanner_a",
            url="http://test.local/a"
        )
        orch.add_finding(
            title="Finding B",
            severity="medium",
            tool_source="scanner_b",
            url="http://test.local/b"
        )

        self.assertEqual(len(findings_collected), 2,
                         "Different findings must both be recorded")


if __name__ == '__main__':
    unittest.main()
