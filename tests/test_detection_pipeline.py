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
        db.session.add(Finding(scan_id=self.scan.id, title="Directory Listing Enabled", severity="medium", tool_source="nuclei"))
        db.session.add(Finding(scan_id=self.scan.id, title="Backup file found: backup.zip", severity="high", tool_source="ffuf"))
        db.session.commit()

        created = run_attack_chain_correlation(self.scan.id)
        self.assertGreaterEqual(created, 1)
        chain = Finding.query.filter_by(scan_id=self.scan.id, category="attack_chain").all()
        self.assertTrue(chain)


if __name__ == "__main__":
    unittest.main()
