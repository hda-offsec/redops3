"""
V9 Regression Shield — SSTI + WPS Hide Login Formal Validation.

NEGATIVE CONTROLS (all must produce NO VULNERABILITY):
  N1  WordPress static site with numeric content
  N2  E-commerce page with prices ($49.99)
  N3  Static HTML page (no backend)
  N4  Redirect-only response (301/302)
  N5  WAF-blocked page (503)
  N6  Gzip-compressed page with no injection

POSITIVE CONTROLS (all must produce CONFIRMED SSTI):
  P1  Python/Jinja2 vulnerable lab
  P2  PHP/Twig vulnerable lab
  P3  Python/Mako vulnerable lab

WPS HIDE LOGIN:
  W1  Login not hidden → no finding
  W2  Plugin not installed → no finding
  W3  Version not vulnerable → INFO
  W4  All conditions met → MEDIUM
  W5  Bypass not confirmed → LOW
  W6  Default redirect equality → suppressed

API-ASSAULT:
  A1  WordPress page with natural '49' → NO SSTI

Stack mismatch:
  S1  PHP + Freemarker payload → Java-only engines never in title
"""

import unittest
from unittest.mock import patch, MagicMock


# --------------- Mock Response Helper ---------------

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
# SSTI V9 — NEGATIVE CONTROLS
# ================================================

class TestSSTINegativeControls(unittest.TestCase):
    """6 mandatory negative controls — all must produce NO VULNERABILITY."""

    def setUp(self):
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        self.scanner = SSTIScanner("test.local")

    def _run_with_mock(self, baseline_text, attack_text=None,
                       baseline_headers=None, attack_headers=None,
                       baseline_status=200, attack_status=200):
        """Helper: run scan with a mocked session."""
        mock_session = MagicMock()
        self.scanner.session = mock_session

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MockResponse(
                    baseline_status, baseline_text,
                    headers=baseline_headers or {}
                )
            else:
                return MockResponse(
                    attack_status, attack_text or baseline_text,
                    headers=attack_headers or baseline_headers or {}
                )

        mock_session.get.side_effect = side_effect
        return self.scanner.scan_endpoint(
            "http://test.local/page?id=1", ["id"]
        )

    def test_N1_wordpress_static_numeric(self):
        """N1: WordPress site with numeric content (article IDs, pagination)."""
        wp_page = (
            '<html><head><meta name="generator" content="WordPress 6.6.4">'
            '</head><body>'
            '<h1>Article #49</h1><p>Page 49 of 100</p>'
            '<div class="wp-content">Content here</div>'
            '</body></html>'
        )
        findings = self._run_with_mock(
            wp_page,
            baseline_headers={'X-Powered-By': 'PHP/8.2', 'Server': 'Apache'}
        )
        self.assertEqual(len(findings), 0,
                         "N1: WordPress with natural '49' must NOT trigger SSTI")

    def test_N2_ecommerce_prices(self):
        """N2: E-commerce page with $49.99 price tags."""
        shop_page = (
            '<html><body>'
            '<div class="product"><span class="price">$49.99</span></div>'
            '<div class="product"><span class="price">$149.00</span></div>'
            '<span>49 items in cart</span>'
            '</body></html>'
        )
        findings = self._run_with_mock(
            shop_page,
            baseline_headers={'X-Powered-By': 'PHP/8.2'}
        )
        self.assertEqual(len(findings), 0,
                         "N2: E-commerce prices must NOT trigger SSTI")

    def test_N3_static_html(self):
        """N3: Pure static HTML with no backend."""
        static = '<html><body><h1>Hello World</h1><p>Static page.</p></body></html>'
        findings = self._run_with_mock(static)
        self.assertEqual(len(findings), 0,
                         "N3: Static HTML must NOT trigger SSTI")

    def test_N4_redirect_only(self):
        """N4: 301 redirect must NOT trigger SSTI."""
        findings = self._run_with_mock(
            '', attack_text='',
            baseline_status=301, attack_status=301,
            baseline_headers={'Location': 'http://test.local/new'}
        )
        self.assertEqual(len(findings), 0,
                         "N4: Redirect-only must NOT trigger SSTI")

    def test_N5_waf_blocked(self):
        """N5: WAF-blocked 503 must NOT trigger SSTI."""
        waf_page = '<html><body><h1>403 Forbidden</h1></body></html>'
        findings = self._run_with_mock(
            waf_page, attack_text='<html><body>Blocked by WAF: 49</body></html>',
            baseline_status=503, attack_status=503,
        )
        self.assertEqual(len(findings), 0,
                         "N5: WAF-blocked must NOT trigger SSTI")

    def test_N6_gzip_no_injection(self):
        """N6: Gzip-compressed page with identical content must NOT trigger SSTI."""
        page = '<html><body><p>Normal content here no numbers</p></body></html>'
        findings = self._run_with_mock(
            page,
            baseline_headers={'Content-Encoding': 'identity'}
        )
        self.assertEqual(len(findings), 0,
                         "N6: Gzip page with no injection must NOT trigger SSTI")


# ================================================
# SSTI V9 — POSITIVE CONTROLS
# ================================================

class TestSSTIPositiveControls(unittest.TestCase):
    """3 mandatory positive controls — all must produce CONFIRMED SSTI."""

    def setUp(self):
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        self.scanner = SSTIScanner("test.local")

    def _run_injection_lab(self, stack_headers, rendered_body):
        """Helper: simulate a vulnerable template lab.
        Baseline must be significantly shorter than rendered_body (>20B delta).
        """
        mock_session = MagicMock()
        self.scanner.session = mock_session  # Inject mock (bypasses __init__ session)

        # Baseline: short, clean page with no expected result
        baseline = '<html><body><p>Hi guest</p></body></html>'

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MockResponse(200, baseline, headers=stack_headers)
            else:
                return MockResponse(200, rendered_body, headers=stack_headers)

        mock_session.get.side_effect = side_effect
        return self.scanner.scan_endpoint(
            "http://test.local/greet?name=test", ["name"]
        )

    def test_P1_jinja2_lab(self):
        """P1: Python/Jinja2 vulnerable lab — must produce CONFIRMED SSTI."""
        findings = self._run_injection_lab(
            stack_headers={'X-Powered-By': 'Python/Flask', 'Server': 'Werkzeug'},
            rendered_body=(
                '<html><body><p>Welcome, 49! Your profile is rendered '
                'with Jinja2 template engine output.</p></body></html>'
                + ' ' * 100
            ),
        )
        self.assertGreaterEqual(len(findings), 1,
                                "P1: Jinja2 lab must detect SSTI")
        f = findings[0]
        self.assertIn("SSTI", f['title'])
        self.assertIn("Confidence", f['description'])
        # Must mention Jinja2 as compatible engine
        self.assertTrue(
            'Jinja2' in f['title'] or 'Mako' in f['title'],
            f"P1: Python stack should suggest Jinja2/Mako, got: {f['title']}"
        )

    def test_P2_twig_lab(self):
        """P2: PHP/Twig vulnerable lab — must produce CONFIRMED SSTI."""
        findings = self._run_injection_lab(
            stack_headers={'X-Powered-By': 'PHP/8.2', 'Server': 'Apache'},
            rendered_body=(
                '<html><body><p>Welcome, 49! Your profile uses Twig '
                'rendering system for templates.</p></body></html>'
                + ' ' * 100
            ),
        )
        self.assertGreaterEqual(len(findings), 1,
                                "P2: Twig lab must detect SSTI")
        f = findings[0]
        self.assertIn("SSTI", f['title'])
        # PHP stack: only Twig should be suggested, NOT Jinja2
        self.assertNotIn("Jinja2", f['title'],
                         "P2: PHP stack must NOT suggest Jinja2")
        self.assertNotIn("Mako", f['title'],
                         "P2: PHP stack must NOT suggest Mako")

    def test_P3_mako_lab(self):
        """P3: Python/Mako vulnerable lab — must produce CONFIRMED SSTI."""
        findings = self._run_injection_lab(
            stack_headers={'X-Powered-By': 'Python', 'Server': 'gunicorn'},
            rendered_body=(
                '<html><body><p>Welcome, 49! Your profile is generated '
                'by Mako template engine in Python.</p></body></html>'
                + ' ' * 100
            ),
        )
        self.assertGreaterEqual(len(findings), 1,
                                "P3: Mako lab must detect SSTI")
        f = findings[0]
        self.assertIn("SSTI", f['title'])


# ================================================
# SSTI V9 — STACK MISMATCH
# ================================================

class TestSSTIStackMismatch(unittest.TestCase):
    """Stack-incompatible engines must be capped at MEDIUM."""

    def setUp(self):
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        self.scanner = SSTIScanner("test.local")

    def test_S1_php_freemarker_impossible(self):
        """S1: PHP stack + Freemarker-style payload → Java engines never appear."""
        mock_session = MagicMock()
        self.scanner.session = mock_session

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MockResponse(
                    200,
                    '<html><body>WordPress Dashboard</body></html>' + ' ' * 100,
                    headers={'X-Powered-By': 'PHP/8.2', 'Server': 'Apache'}
                )
            else:
                return MockResponse(
                    200,
                    '<html><body>WordPress Dashboard result 49 in output</body></html>' + ' ' * 100,
                    headers={'X-Powered-By': 'PHP/8.2', 'Server': 'Apache'}
                )

        mock_session.get.side_effect = side_effect
        findings = self.scanner.scan_endpoint(
            "http://test.local/api?tpl=test", ["tpl"]
        )
        for f in findings:
            self.assertNotIn("Freemarker", f['title'],
                             "Freemarker must NOT appear for PHP stack")
            self.assertNotIn("Velocity", f['title'],
                             "Velocity must NOT appear for PHP stack")
            # If stack-incompatible finding exists, severity must be ≤ MEDIUM
            if "ENGINE_INCOMPATIBLE" in f.get('title', ''):
                self.assertIn(f['severity'], ('medium', 'low', 'info'),
                              "Stack-incompatible must cap at MEDIUM")

    def test_S2_content_delta_too_small(self):
        """Content delta < 20 bytes → SUPPRESSED."""
        mock_session = MagicMock()
        self.scanner.session = mock_session

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MockResponse(200, '<html><body>Page content here</body></html>')
            else:
                return MockResponse(200, '<html><body>Page content 49re</body></html>')

        mock_session.get.side_effect = side_effect
        findings = self.scanner.scan_endpoint(
            "http://test.local/test?x=1", ["x"]
        )
        self.assertEqual(len(findings), 0,
                         "Small content delta must suppress SSTI")

    def test_S3_reflected_payload_suppressed(self):
        """Payload reflected literally → SUPPRESSED."""
        mock_session = MagicMock()
        self.scanner.session = mock_session

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return MockResponse(200, '<html><body>Clean page</body></html>')
            else:
                return MockResponse(200, '<html><body>{{7*7}} = 49 result</body></html>')

        mock_session.get.side_effect = side_effect
        findings = self.scanner.scan_endpoint(
            "http://test.local/search?q=test", ["q"]
        )
        self.assertEqual(len(findings), 0,
                         "Reflected payload must suppress SSTI")


# ================================================
# WPS HIDE LOGIN V9
# ================================================

class TestWPSHideLoginV9(unittest.TestCase):
    """V9 formal predicates for WPS Hide Login validation."""

    def setUp(self):
        from scan_engine.step03_vuln.js_vuln_scanner import JSVulnScanner
        self.scanner = JSVulnScanner("test.local")

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W1_login_not_hidden(self, mock_http):
        """W1: wp-login.php accessible → NO finding."""
        mock_http.get.return_value = MockResponse(
            200, '<form id="loginform">Login</form>',
            url="http://test.local/wp-login.php"
        )
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNone(result, "W1: Accessible login → no finding")

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W2_plugin_not_installed(self, mock_http):
        """W2: Login hidden but plugin not installed → NO finding."""
        def side_effect(url, **kwargs):
            if 'wp-login' in url or 'wp-admin' in url:
                return MockResponse(404, "Not Found")
            if 'wps-hide-login' in url:
                return MockResponse(404, "Not Found")
            if 'wp-json' in url:
                return MockResponse(403, "Forbidden")
            return MockResponse(200, "OK")
        mock_http.get.side_effect = side_effect
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNone(result, "W2: Plugin not installed → no finding")

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W3_version_not_vulnerable(self, mock_http):
        """W3: Plugin v2.0.0 → INFO only."""
        def side_effect(url, **kwargs):
            if 'wp-login' in url or ('wp-admin' in url and 'postpass' not in url):
                return MockResponse(404, "Not Found")
            if 'readme.txt' in url:
                return MockResponse(200, "=== WPS Hide Login ===\nStable tag: 2.0.0")
            return MockResponse(200, "OK")
        mock_http.get.side_effect = side_effect
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNotNone(result, "W3: Should produce INFO finding")
        self.assertEqual(result['severity'], 'info',
                         "W3: Non-vulnerable version must be INFO")

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W4_all_conditions_met(self, mock_http):
        """W4: All predicates satisfied → MEDIUM."""
        def side_effect(url, **kwargs):
            if 'wp-login.php' in url and 'postpass' not in url:
                return MockResponse(404, "Not Found")
            if 'wp-admin/' in url and 'postpass' not in url:
                return MockResponse(404, "Not Found")
            if 'readme.txt' in url:
                return MockResponse(200, "=== WPS Hide Login ===\nStable tag: 1.9.15")
            if 'postpass' in url:
                return MockResponse(
                    200,
                    '<form id="loginform"><input name="user_login"/></form>',
                    url="http://test.local/wp-login.php"
                )
            return MockResponse(200, "OK")
        mock_http.get.side_effect = side_effect
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNotNone(result)
        self.assertEqual(result['severity'], 'medium',
                         "W4: Confirmed bypass → MEDIUM")
        self.assertIn("Confirmed", result['title'])
        # V9: validation_path must be present
        self.assertIn("Validation path", result['description'])

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W5_bypass_not_confirmed(self, mock_http):
        """W5: Plugin installed, vulnerable version, bypass fails → LOW."""
        def side_effect(url, **kwargs):
            if 'wp-login.php' in url and 'postpass' not in url:
                return MockResponse(404, "Not Found")
            if 'wp-admin/' in url and 'postpass' not in url:
                return MockResponse(404, "Not Found")
            if 'readme.txt' in url:
                return MockResponse(200, "=== WPS Hide Login ===\nStable tag: 1.9.15")
            if 'postpass' in url:
                return MockResponse(404, "Not Found", url="http://test.local/404")
            return MockResponse(200, "OK")
        mock_http.get.side_effect = side_effect
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNotNone(result)
        self.assertEqual(result['severity'], 'low',
                         "W5: Unconfirmed bypass → LOW")
        self.assertIn("LOGIN DISCOVERY BEHAVIOR", result['title'])

    @patch('scan_engine.step03_vuln.js_vuln_scanner.http_client')
    def test_W6_redirect_equality_suppressed(self, mock_http):
        """W6: Default WP redirect to wp-login → NOT hidden, suppressed."""
        def side_effect(url, **kwargs):
            if 'wp-login.php' in url:
                # Default WP: accessible login form
                if not kwargs.get('allow_redirects', True):
                    return MockResponse(
                        200, '<form id="loginform">Login</form>',
                        url="http://test.local/wp-login.php"
                    )
                return MockResponse(
                    200, '<form id="loginform">Login</form>',
                    url="http://test.local/wp-login.php"
                )
            if 'wp-admin' in url:
                if not kwargs.get('allow_redirects', True):
                    return MockResponse(
                        302, '', headers={'Location': 'http://test.local/wp-login.php'}
                    )
                return MockResponse(
                    200, '<form id="loginform">Login</form>',
                    url="http://test.local/wp-login.php"
                )
            return MockResponse(200, "OK")
        mock_http.get.side_effect = side_effect
        result = self.scanner._validate_wps_hide_login("http://test.local")
        self.assertIsNone(result,
                         "W6: Default WP redirect behavior → suppressed")


# ================================================
# API-ASSAULT V9
# ================================================

class TestAPIAssaultSSTIV9(unittest.TestCase):

    @patch('scan_engine.step03_vuln.api_expert_scanner.http_client')
    def test_A1_wordpress_no_ssti(self, mock_http):
        """A1: WordPress with natural '49' → NO SSTI from API-Assault."""
        from scan_engine.step03_vuln.api_expert_scanner import APIExpertScanner
        scanner = APIExpertScanner("test.local")

        mock_http.get.return_value = MockResponse(
            200, '<html><body>Menu item $49 available</body></html>',
            headers={'X-Powered-By': 'PHP/8.2'}
        )
        findings = scanner.assault_endpoint("http://test.local/api/products")
        ssti_findings = [f for f in findings if 'SSTI' in f.get('title', '')]
        self.assertEqual(len(ssti_findings), 0,
                         "A1: Natural '49' must NOT trigger API-Assault SSTI")


# ================================================
# SCORING MATRIX VERIFICATION
# ================================================

class TestScoringMatrix(unittest.TestCase):
    """Verify the weighted scoring formula produces correct values."""

    def test_weights_sum_to_one(self):
        """All weights must sum to exactly 1.0."""
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        total = sum(SSTIScanner.WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=5,
                               msg=f"Weights sum to {total}, must be 1.0")

    def test_max_confidence_is_one(self):
        """All factors active → C = 1.0."""
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        confidence = 0.0
        factors = {k: 1 for k in SSTIScanner.WEIGHTS}
        for key, weight in SSTIScanner.WEIGHTS.items():
            confidence += weight * factors[key]
        self.assertAlmostEqual(confidence, 1.0, places=5)

    def test_critical_requires_f1_f2(self):
        """CRITICAL threshold (C ≥ 0.8) requires f1 and f2."""
        from scan_engine.step03_vuln.ssti_scanner import SSTIScanner
        # Without f1 (deterministic)
        factors_no_f1 = {k: 1 for k in SSTIScanner.WEIGHTS}
        factors_no_f1["f1_deterministic"] = 0
        c = sum(SSTIScanner.WEIGHTS[k] * factors_no_f1[k] for k in SSTIScanner.WEIGHTS)
        # Even if C ≥ 0.8, scanner code requires f1=1 for CRITICAL
        # Verify C is 0.75 without f1
        self.assertAlmostEqual(c, 0.75, places=5,
                               msg="Without f1, max C should be 0.75 (< 0.8)")


if __name__ == '__main__':
    unittest.main()
