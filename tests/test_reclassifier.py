import unittest
import sys
import os

# Ensure core is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.models import Finding
from core.evidence import EvidenceModel, EvidenceLevel, compute_body_hash
from core.reclassifier import PostDetectionReclassifier

class DummyFinding(Finding):
    """Mock Finding without DB dependencies for unit testing."""
    def __init__(self, **kwargs):
        self.id = kwargs.pop('id', 1)
        self.scan_id = kwargs.pop('scan_id', 1)
        for k, v in kwargs.items():
            setattr(self, k, v)
            
        # Defaults if missing
        if not hasattr(self, 'title'): self.title = "Test Finding"
        if not hasattr(self, 'severity'): self.severity = "info"
        if not hasattr(self, 'description'): self.description = ""
        if not hasattr(self, 'tool_source'): self.tool_source = "test"
        if not hasattr(self, 'request'): self.request = ""
        if not hasattr(self, 'response'): self.response = ""
        if not hasattr(self, 'repro_command'): self.repro_command = ""

class TestReclassifier(unittest.TestCase):
    def setUp(self):
        self.reclassifier = PostDetectionReclassifier(scan_id=1)
        
    def test_ssti_single_probe(self):
        f = DummyFinding(
            title="SSTI Freemarker Detected",
            severity="critical",
            response="HTTP/1.1 200 OK\r\n\r\nResult is 49"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.PROBABLE)
        self.assertTrue(ev.verification_required)
        self.assertEqual(f.severity, "high")
        self.assertNotIn("Freemarker", f.title)
        self.assertIn("UNKNOWN_ENGINE", f.title)

    def test_ssti_confirmed_via_signature(self):
        f = DummyFinding(
            title="SSTI Jinja2",
            severity="critical",
            response="HTTP/1.1 500 Internal Error\r\n\r\nException in jinja2.environment"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.CONFIRMED)
        self.assertFalse(ev.verification_required)
        self.assertEqual(f.severity, "critical")
        self.assertIn("Jinja2", f.title) # Not stripped

    def test_waf_bypass_no_change(self):
        f = DummyFinding(
            title="WAF Bypass Detected",
            severity="critical",
            response="HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied by Cloudflare"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.HEURISTIC)
        self.assertEqual(f.severity, "info")

    def test_waf_bypass_confirmed(self):
        f = DummyFinding(
            title="WAF Bypass via X-Forwarded-For",
            severity="high",
            response="HTTP/1.1 200 OK\r\n\r\nWelcome to the admin dashboard!"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.CONFIRMED)
        self.assertIn("Welcome", ev.proof.markers)
        self.assertEqual(f.severity, "high")

    def test_wp_config_blocked(self):
        f = DummyFinding(
            title="wp-config.php exposed",
            severity="critical",
            response="HTTP/1.1 403 Forbidden\r\n\r\nnginx 403"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.HEURISTIC)
        self.assertEqual(f.severity, "info")

    def test_wp_config_confirmed(self):
        f = DummyFinding(
            title="wp-config.php exposed",
            severity="high",
            response="HTTP/1.1 200 OK\r\n\r\ndefine('DB_PASSWORD', 'supersecret');"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.CONFIRMED)
        self.assertEqual(f.severity, "critical")
        self.assertIn("DB_PASSWORD", ev.proof.markers)

    def test_cfide_unconfirmed(self):
        f = DummyFinding(
            title="CFIDE path found",
            severity="high",
            response="HTTP/1.1 200 OK\r\n\r\nJust a blank page"
        )
        ev = EvidenceModel()
        self.reclassifier._apply_rules(f, ev)
        
        self.assertEqual(ev.level, EvidenceLevel.HEURISTIC)
        self.assertEqual(f.severity, "info")

    def test_deduplication(self):
        # Two identical WAF bypasses with same structural request/response
        f1 = DummyFinding(
            id=1,
            title="WAF Bypass",
            severity="high",
            request="GET / HTTP/1.1\r\nHost: example.com",
            response="HTTP/1.1 200 OK\r\n\r\nadmin dashboard"
        )
        f2 = DummyFinding(
            id=2,
            title="WAF Bypass",
            severity="high",
            request="GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: payload",
            response="HTTP/1.1 200 OK\r\n\r\nadmin dashboard"
        )
        
        ev1 = EvidenceModel()
        ev2 = EvidenceModel()
        self.reclassifier._apply_rules(f1, ev1)
        self.reclassifier._apply_rules(f2, ev2)
        
        # Deduplicate
        final = self.reclassifier._deduplicate([(f1, ev1), (f2, ev2)])
        self.assertEqual(len(final), 1)
        # Verify description was enriched with occurrence data
        self.assertIn("Deduplicated 1 similar occurrences", final[0].description)

if __name__ == '__main__':
    unittest.main()
