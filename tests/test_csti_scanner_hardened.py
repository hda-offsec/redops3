import pytest
from unittest.mock import MagicMock, patch
from scan_engine.step03_vuln.csti_scanner import CSTIScanner

class MockResponse:
    def __init__(self, text, status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = {}

@pytest.fixture
def scanner():
    with patch('scan_engine.step03_vuln.csti_scanner.get_session') as mock_session:
        session = MagicMock()
        mock_session.return_value = session
        s = CSTIScanner()
        s.session = session
        yield s

def test_csti_wordpress_reflection_low(scanner):
    """Test 1: Site WordPress simple reflet -> DOIT retourner LOW ou MEDIUM (pas HIGH)"""
    # Baseline: Typical WordPress page
    scanner.session.get.side_effect = [
        MockResponse("<html><body>Welcome to WordPress</body></html>"), # Baseline
        MockResponse("<html><body>Reflected: {{7*7}}</body></html>"),    # Attack 1
        MockResponse("<html><body>Reflected: {{8*8}}</body></html>"),    # Attack 2
    ]
    
    findings = scanner.scan_endpoint("http://wp.local/", ["q"])
    assert len(findings) > 0
    assert findings[0]["severity"] in ["medium", "low"]
    assert findings[0]["confidence_score"] < 0.8

def test_csti_static_page_pattern_info(scanner):
    """Test 2: Page HTML statique avec {{7*7}} -> DOIT retourner INFO ou rien si pas de réflexion dynamique"""
    # Baseline already contains the pattern
    scanner.session.get.side_effect = [
        MockResponse("<html><body>Static Content {{7*7}}</body></html>"), # Baseline
        MockResponse("<html><body>Static Content {{7*7}}</body></html>"), # Attack
        MockResponse("<html><body>Static Content {{7*7}}</body></html>"), # Attack
    ]
    
    findings = scanner.scan_endpoint("http://static.local/", ["q"])
    # Should not produce a finding because it's in baseline or doesn't change
    assert len(findings) == 0

def test_csti_angularjs_vulnerable_high(scanner):
    """Test 3: Simulation AngularJS vulnérable -> DOIT retourner HIGH"""
    # Baseline: Contains angular.js script
    scanner.session.get.side_effect = [
        MockResponse("<html><script src='angular.js'></script><body>App</body></html>"), # Baseline
        MockResponse("<html><script src='angular.js'></script><body>Reflected: {{7*7}}</body></html>"), # Attack 1
        MockResponse("<html><script src='angular.js'></script><body>Reflected: {{8*8}}</body></html>"), # Attack 2
    ]
    
    findings = scanner.scan_endpoint("http://angular.local/", ["q"])
    assert len(findings) > 0
    assert findings[0]["severity"] == "high"
    assert findings[0]["framework_detected"] == ["angular"]
    assert findings[0]["confidence_score"] >= 0.8

def test_csti_numeric_collision_prevention(scanner):
    """Test 4: Page contenant nombre 49 baseline -> DOIT PAS confirmer"""
    # Baseline contains 49
    scanner.session.get.side_effect = [
        MockResponse("<html><body>Price: 49 USD</body></html>"), # Baseline
        MockResponse("<html><body>Price: 49 USD. Query: {{7*7}}</body></html>"), # Attack 1
        MockResponse("<html><body>Price: 49 USD. Query: {{8*8}}</body></html>"), # Attack 2
    ]
    
    findings = scanner.scan_endpoint("http://collision.local/", ["q"])
    # It should detect reflection but NOT evaluation to 49 because 49 was in baseline
    # Actually, my code skips numeric collision detection if '49' is in baseline.
    for f in findings:
        assert f["title"] != "Server-Side Template Injection (SSTI) Confirmed"
        if "differential_confirmed" in f:
            # It might still detect reflection if {{7*7}} is in response
            assert f["severity"] != "high" # Because no framework detected
