import pytest
import time
from unittest.mock import MagicMock, patch
from scan_engine.helpers.js_mining_expert import JSDeepMiningExpert

@pytest.fixture
def expert():
    return JSDeepMiningExpert("example.com")

def test_js_expert_no_js_files(expert):
    """Test 1: Site sans JS → doit COMPLETED proprement"""
    res = expert.mine_endpoints([])
    assert res["status"] == "COMPLETED"
    assert res["js_files_scanned"] == 0
    assert res["secrets_found"] == 0

def test_js_expert_simple_js(expert):
    """Test 2: Site avec JS simple → doit COMPLETED"""
    with patch('scan_engine.helpers.http_client.get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "console.log('hello world');"
        mock_get.return_value = mock_resp
        
        res = expert.mine_endpoints(["http://example.com/main.js"])
        assert res["status"] == "COMPLETED"
        assert res["js_files_scanned"] == 1
        assert res["secrets_found"] == 0

def test_js_expert_with_secrets(expert):
    """Test 3: Site contenant faux secret → doit détecter"""
    with patch('scan_engine.helpers.http_client.get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'const api_key = "AIzaSyA12345678901234567890123456789012";'
        mock_get.return_value = mock_resp
        
        res = expert.mine_endpoints(["http://example.com/app.js"])
        assert res["status"] == "COMPLETED"
        assert res["secrets_found"] > 0
        assert "Firebase" in [f['details']['secrets'][0]['type'] for f in res['findings'] if f['details']['secrets']]

def test_js_expert_crash_handling(expert):
    """Test 4: Simulation crash moteur → doit FAILED proprement"""
    with patch('scan_engine.helpers.http_client.get') as mock_get:
        mock_get.side_effect = Exception("Network is down")
        
        res = expert.mine_endpoints(["http://example.com/broken.js"])
        # Individual file error should not fail the whole expert (it continues to next file)
        assert res["status"] == "COMPLETED"
        assert len(res["errors"]) > 0
        
    # Test global failure (passing invalid input to the motor)
    res = expert.mine_endpoints(None)
    assert res["status"] == "FAILED"
    assert "Global expert failure" in str(res["errors"])

def test_js_expert_timeout(expert):
    """Test 5: Simulation freeze → doit TIMEOUT"""
    with patch('scan_engine.helpers.http_client.get') as mock_get:
        # Mocking http_client.get to simulate a delay
        def slow_get(*args, **kwargs):
            time.sleep(0.2)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "var x = 1;"
            return mock_resp
        
        mock_get.side_effect = slow_get
        
        # Run with very short timeout
        res = expert.mine_endpoints(["http://1.js", "http://2.js", "http://3.js"], timeout=0.1)
        assert res["status"] == "TIMEOUT"
        assert res["execution_time"] >= 0.1
