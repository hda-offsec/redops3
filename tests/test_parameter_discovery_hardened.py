import pytest
import json
import os
from unittest.mock import MagicMock, patch
from scan_engine.step02_enum.arjun_scanner import ArjunScanner

class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}

@pytest.fixture
def scanner():
    with patch('scan_engine.step02_enum.arjun_scanner.get_session') as mock_session, \
         patch('uuid.uuid4') as mock_uuid:
        # Fixed token for testing
        mock_uuid.return_value.hex = "12345678"
        session = MagicMock()
        mock_session.return_value = session
        s = ArjunScanner("target.com")
        s.session = session
        yield s

def test_arjun_wordpress_uncode_is_info(scanner):
    """Test 1: WordPress + Uncode -> majorité INFO / CMS_FRONTEND_CONFIG"""
    baseline = {"status": 200, "length": 1000, "body": "WordPress Site"}
    
    # Mock validation for a WP nonce
    # Should be low score because of CMS-aware minus
    # reflected (+0.2), cms_related (-0.5) -> score 0
    scanner.session.get.return_value = MockResponse("<html><body>Reflected REDOPS_TEST_12345678</body></html>")
    
    res = scanner._validate_param("http://target.com", "nonce_login", baseline)
    assert res["classification"] == "CMS_FRONTEND_CONFIG"
    assert res["severity"] == "INFO"
    assert res["cms_related"] is True

def test_arjun_active_parameter_success(scanner):
    """Test 2: Paramètre backend réel (ex: id=1) -> ACTIVE"""
    baseline = {"status": 200, "length": 1000, "body": "Product Page"}
    
    # Mock result that changes length significantly (Influences Response +0.3)
    # And reflects (+0.2)
    # Total score 0.5 -> MEDIUM
    scanner.session.get.return_value = MockResponse("<html><body>New Product Data REDOPS_TEST_12345678" + ("A" * 100) + "</body></html>")
    
    res = scanner._validate_param("http://target.com", "id", baseline)
    assert res["classification"] == "ACTIVE_PARAMETER"
    assert res["influences_response"] is True
    assert res["severity"] in ["MEDIUM", "HIGH"]

def test_arjun_sqli_high_severity(scanner):
    """Test 3: Paramètre qui modifie SQL (triggers error) -> HIGH"""
    baseline = {"status": 200, "length": 1000, "body": "User Profile"}
    
    # Mock result that triggers 500 error (+0.2)
    # Alters logic (status changed) (+0.3)
    # Influences response (+0.3)
    # Total score 0.8 -> HIGH
    scanner.session.get.return_value = MockResponse("Internal Server Error", status_code=500)
    
    res = scanner._validate_param("http://target.com", "id", baseline)
    assert res["severity"] == "HIGH"
    assert res["triggers_error"] is True
    assert res["exploitable_score"] >= 0.75

def test_arjun_simple_reflection_medium(scanner):
    """Test 4: Paramètre reflet simple -> MEDIUM/LOW"""
    baseline = {"status": 200, "length": 1000, "body": "Search results"}
    
    # Mock reflection (+0.2) but no other influence
    # Make length close to baseline to avoid 'influence' tag
    padding = "A" * (1000 - len("<html><body>You searched for REDOPS_TEST_12345678</body></html>"))
    scanner.session.get.return_value = MockResponse(f"<html><body>You searched for REDOPS_TEST_12345678</body></html>{padding}")
    
    res = scanner._validate_param("http://target.com", "q", baseline)
    assert res["reflected"] is True
    assert res["influences_response"] is False
    assert res["severity"] == "LOW"

def test_arjun_js_config_is_info(scanner):
    """Test 5: Paramètre JS config -> INFO"""
    baseline = {"status": 200, "length": 1000, "body": "App Config"}
    
    # ajax_url is a known noise pattern
    scanner.session.get.return_value = MockResponse("<html><body>Config set REDOPS_TEST_12345678</body></html>")
    
    res = scanner._validate_param("http://target.com", "ajax_url", baseline)
    assert res["classification"] == "CMS_FRONTEND_CONFIG"
    assert res["severity"] == "INFO"
