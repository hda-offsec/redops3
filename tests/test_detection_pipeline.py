import unittest
import sys
import types

if "flask_login" not in sys.modules:
    fake = types.ModuleType("flask_login")
    class _UserMixin:
        pass
    class _LoginManager:
        def init_app(self, app):
            return None
    fake.UserMixin = _UserMixin
    fake.LoginManager = _LoginManager
    sys.modules["flask_login"] = fake

from flask import Flask

from core.extensions import db
from core.models import Scan, Target, Mission, Finding
from scan_engine.helpers.finding_normalizer import FindingNormalizer
from adapters.detection_adapter import DetectionAdapter
from core.correlation import run_attack_chain_correlation


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        db.init_app(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

        mission = Mission(name="m1")
        db.session.add(mission)
        db.session.flush()
        target = Target(identifier="example.com", mission_id=mission.id)
        db.session.add(target)
        db.session.flush()
        self.scan = Scan(target_id=target.id, scan_type="quick", status="completed")
        db.session.add(self.scan)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_normalizer_preserves_raw_output_and_param_payload(self):
        src = {
            "url": "https://example.com/search?q=1",
            "title": "Reflected XSS",
            "severity": "high",
            "category": "xss",
            "param": "q",
            "poison": "<svg/onload=alert(1)>",
            "response": "...<svg/onload=alert(1)>...",
            "evidence": "payload reflected",
        }
        f = FindingNormalizer.normalize(src, "dalfox")
        self.assertEqual(f["parameter"], "q")
        self.assertIn("alert(1)", f["payload"])
        self.assertTrue(f.get("raw_output"))
        self.assertIn(f["confidence"], {"low", "medium", "high"})

    def test_adapter_maps_extended_fields(self):
        finding = Finding(
            scan_id=self.scan.id,
            title="Test",
            severity="medium",
            confidence="medium",
            tool_source="unit",
            target="https://example.com",
            endpoint="https://example.com/a",
            parameter="id",
            payload="1 OR 1=1",
            evidence="sql error",
            reproduction="curl ...",
            raw_output="HTTP/1.1 500"
        )
        db.session.add(finding)
        db.session.commit()

        out = DetectionAdapter.normalize_findings([finding], {"phases": {}})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["parameter"], "id")
        self.assertIn("1 OR 1=1", out[0]["payload"])
        self.assertTrue(out[0]["raw_output"])

    def test_correlation_creates_attack_chain_finding(self):
        db.session.add(Finding(scan_id=self.scan.id, title="Directory Listing Enabled", severity="medium", tool_source="nuclei", signal_ids=[11]))
        db.session.add(Finding(scan_id=self.scan.id, title="Backup file found: backup.zip", severity="high", tool_source="ffuf", signal_ids=[12]))
        db.session.commit()

        created = run_attack_chain_correlation(self.scan.id)
        self.assertGreaterEqual(created, 1)
        chain = Finding.query.filter_by(scan_id=self.scan.id, category="attack_chain").all()
        self.assertTrue(chain)
        self.assertIn(11, chain[0].signal_ids)

    def test_correlation_detects_secret_internal_chain(self):
        db.session.add(Finding(scan_id=self.scan.id, title="Secret Found: API token", severity="high", tool_source="secret_scanner", signal_ids=[31]))
        db.session.add(Finding(scan_id=self.scan.id, title="Internal API endpoint exposed via swagger", severity="medium", tool_source="api_scanner", signal_ids=[32]))
        db.session.commit()

        created = run_attack_chain_correlation(self.scan.id)
        self.assertGreaterEqual(created, 1)
        chain = Finding.query.filter_by(scan_id=self.scan.id, title="Attack Chain: Secret Exposure + Internal API Surface").first()
        self.assertIsNotNone(chain)
        self.assertEqual(chain.confidence, "high")
        self.assertIn(31, chain.signal_ids)
        self.assertIn(32, chain.signal_ids)

    def test_adapter_synthesizes_wordpress_osint_intel_leaks(self):
        """Verify new synthesizers produce findings from structured JSON data."""
        json_results = {
            "phases": {
                "recon": {
                    "open_ports": [],
                    "nse_results": {
                        "21": {"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"},
                        "3306": {"mysql-empty-password": "root password is empty!"},
                        "80": {"http-title": "My Blog"}
                    }
                },
                "enum": {
                    "derived": {
                        "cortex_recommendations": [
                            {"id": 1, "title": "HTTP Smuggling Audit on port 80", "reason": "Apache detected", "confidence": 80, "port": "80", "category": "audit"},
                        ],
                    },
                    "api": {
                        "endpoints": [
                            {"url": "http://example.com/admin", "status": 200, "path": "admin"},
                            {"url": "http://example.com/health", "status": 200, "path": "health"},
                        ],
                    },
                    "injection_points": {
                        "443": ["https://example.com/?q=test", "https://example.com/?s=foo"],
                    },
                },
                "vuln": {
                    "wordpress": {
                        "80": {
                            "version": "6.6.4",
                            "theme": "twentytwentyfour",
                            "wordfence_detected": False,
                            "users": ["admin"],
                            "plugins": ["wordfence", "akismet"],
                            "vulns": [
                                {"title": "WP Core RCE", "severity": "critical", "description": "RCE via upload"},
                            ],
                        }
                    },
                    "data_leaks": [
                        {"type": "emails", "count": 2, "matches": ["a@b.com", "c@d.com"], "url": "http://example.com"},
                        {"type": "api_keys", "count": 1, "matches": ["sk-1234"], "url": "http://example.com/js"},
                    ],
                },
                "intel": {
                    "attack_vectors": [
                        {"category": "WEB", "risk": "HIGH", "score": 70, "name": "Web Surface", "description": "Web detected", "action": "Run nikto"},
                    ]
                },
                "osint": {
                    "origin_ips": [{"ip": "1.2.3.4", "confidence": "high", "reason": "Direct DNS"}],
                    "dorks": [{"query": "site:example.com ext:sql"}],
                    "historic_urls": ["http://example.com/old"] * 100,
                    "favicon": {"hash": -12345, "url": "http://example.com/favicon.ico", "shodan_query": "http.hash:-12345"},
                },
            }
        }

        out = DetectionAdapter.normalize_findings([], json_results)
        titles = {f["title"] for f in out}
        categories = {f.get("category") for f in out}

        # WordPress synthesizer
        self.assertTrue(any("WordPress 6.6.4" in t for t in titles), f"Missing WP detection, got: {titles}")
        self.assertIn("WP Core RCE", titles)
        self.assertIn("wordpress", categories)
        self.assertIn("wordpress_vuln", categories)

        # Data leaks synthesizer
        self.assertTrue(any("Data Leak: Emails" in t for t in titles))
        self.assertTrue(any("Data Leak: Api Keys" in t for t in titles))
        # api_keys should be promoted to high by governance (title contains "api key")
        api_key_finding = next(f for f in out if "Api Keys" in f["title"])
        self.assertEqual(api_key_finding["severity"], "high")

        # Intel vectors synthesizer
        self.assertTrue(any("Intel: Web Surface" in t for t in titles))
        self.assertIn("intel_vector", categories)

        # OSINT synthesizer
        self.assertTrue(any("Origin IP Detected: 1.2.3.4" in t for t in titles))
        self.assertTrue(any("Google Dork" in t for t in titles))
        self.assertTrue(any("Historic Wayback" in t for t in titles))
        self.assertIn("osint_origin", categories)
        self.assertIn("osint_dorks", categories)
        self.assertIn("osint_historic", categories)

        # Cortex recommendations synthesizer
        self.assertTrue(any("Cortex: HTTP Smuggling Audit" in t for t in titles))
        self.assertIn("cortex_recommendation", categories)

        # API endpoints synthesizer
        self.assertTrue(any("/admin" in t for t in titles))
        admin_f = next(f for f in out if "/admin" in f["title"])
        self.assertEqual(admin_f["severity"], "medium")  # admin is sensitive
        self.assertIn("api_endpoint", categories)

        # Injection points synthesizer
        self.assertTrue(any("Injection Points" in t for t in titles))
        self.assertIn("injection_surface", categories)

        # Favicon hash synthesizer
        self.assertTrue(any("Favicon Hash" in t for t in titles))
        self.assertIn("osint_favicon", categories)

        # NSE synthesizer
        self.assertTrue(any("NSE: ftp-anon (port 21)" in t for t in titles))
        self.assertTrue(any("NSE: mysql-empty-password (port 3306)" in t for t in titles))
        self.assertTrue(any("NSE: http-title (port 80)" in t for t in titles))
        
        # Check severity of NSE findings
        ftp_f = next(f for f in out if "ftp-anon" in f["title"])
        self.assertEqual(ftp_f["severity"], "medium")
        
        mysql_f = next(f for f in out if "mysql-empty-password" in f["title"])
        self.assertEqual(mysql_f["severity"], "high")

if __name__ == "__main__":
    unittest.main()
