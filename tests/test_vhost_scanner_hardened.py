import pytest
from unittest.mock import MagicMock, patch
from scan_engine.step03_vuln.vhost_scanner import VhostScanner

class MockResponse:
    def __init__(self, content, status_code=200):
        self.content = content.encode() if isinstance(content, str) else content
        self.status_code = status_code
        self.headers = {}

@pytest.fixture
def scanner():
    with patch('scan_engine.step03_vuln.vhost_scanner.get_session') as mock_session:
        session = MagicMock()
        mock_session.return_value = session
        s = VhostScanner("target.com")
        s.session = session
        yield s

def test_vhost_run_quick(scanner):
    """Test 1: run(target, quick) → no crash"""
    scanner.session.get.return_value = MockResponse("Baseline", 200)
    
    res = scanner.run(80, "http", scan_mode="quick")
    assert res["status"] in ["COMPLETED", "TIMEOUT"]
    assert "findings" in res
    assert res["error"] is None

def test_vhost_run_full(scanner):
    """Test 2: run(target, full) → no crash"""
    scanner.session.get.return_value = MockResponse("Baseline", 200)
    
    res = scanner.run(80, "http", scan_mode="full")
    assert res["status"] in ["COMPLETED", "TIMEOUT"]
    assert "findings" in res

def test_vhost_default_mode(scanner):
    """Test 3: mode non fourni → default full (par via run signature)"""
    scanner.session.get.return_value = MockResponse("Baseline", 200)
    
    # La signature est def run(self, port, protocol='http', scan_mode="full", logger=None)
    res = scanner.run(80) 
    assert res["status"] in ["COMPLETED", "TIMEOUT"]

def test_vhost_discovery_success(scanner):
    """Test discovery: diff status and diff length"""
    # 1. Baseline
    # 2. Fuzzing
    
    responses = [
        MockResponse("Baseline", 200), # Baseline
        MockResponse("Secret Page", 200), # vhost1 (diff content)
        MockResponse("Forbidden", 403),   # vhost2 (diff status)
    ]
    scanner.session.get.side_effect = responses + ([MockResponse("Baseline", 200)] * 100)
    
    res = scanner.run(80, scan_mode="quick")
    assert len(res["findings"]) >= 2
    assert res["findings"][0]["severity"] == "medium"

def test_vhost_error_handling(scanner):
    """Test 4: simulation erreur → retourne FAILED"""
    scanner.session.get.side_effect = Exception("Network Down")
    
    res = scanner.run(80)
    assert res["status"] == "FAILED"
    assert "error" in res

def test_vhost_no_nameerror(scanner):
    """Test 5: variable non définie → jamais NameError"""
    # On teste que le code n'utilise pas de variables globales comme is_quick indéfinies
    # Ici on l'appelle normalement, mais on vérifie la robustesse interne
    try:
        scanner.run(80, scan_mode="quick")
    except NameError:
        pytest.fail("NameError was raised!")
    except Exception:
        pass # Other exceptions are fine for this specific check
