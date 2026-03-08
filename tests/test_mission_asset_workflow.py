import os
import unittest

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"

from app import create_app
from core.extensions import db
from core.models import Mission, Target, Scan, Finding, Asset, AssetTargetLink
from core.mission_intelligence import aggregate_mission_intelligence
from scan_engine.helpers.attack_graph import AttackGraphBuilder


class MissionAssetWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.drop_all()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_asset_attachment_and_target_link(self):
        mission = Mission(name="m1", description="desc")
        db.session.add(mission)
        db.session.commit()

        target = Target(mission_id=mission.id, identifier="api.example.com")
        db.session.add(target)
        db.session.commit()

        res = self.client.post(
            f"/api/missions/{mission.id}/assets",
            json={
                "identifier": "api.example.com",
                "type": "api_host",
                "source": "operator",
                "target_ids": [target.id],
                "tags": ["external_recon"],
            },
        )
        self.assertIn(res.status_code, (200, 201))
        asset = Asset.query.filter_by(mission_id=mission.id, identifier="api.example.com").first()
        self.assertIsNotNone(asset)
        link = AssetTargetLink.query.filter_by(asset_id=asset.id, target_id=target.id).first()
        self.assertIsNotNone(link)

    def test_mission_overview_aggregation_and_graph(self):
        mission = Mission(name="m2", description="desc", objectives_json=["authenticated_api_access"])
        db.session.add(mission)
        db.session.commit()

        t1 = Target(mission_id=mission.id, identifier="a.example.com")
        t2 = Target(mission_id=mission.id, identifier="b.example.com")
        db.session.add_all([t1, t2])
        db.session.commit()

        for idx, t in enumerate((t1, t2), start=1):
            asset = Asset(
                mission_id=mission.id,
                type="domain",
                identifier=t.identifier,
                label=t.identifier,
                source="seed",
                tags=["target_linked"],
            )
            db.session.add(asset)
            db.session.flush()
            db.session.add(AssetTargetLink(asset_id=asset.id, target_id=t.id, source="seed"))

            scan = Scan(target_id=t.id, scan_type="pipeline", status="completed")
            db.session.add(scan)
            db.session.flush()

            if idx == 1:
                db.session.add(Finding(
                    scan_id=scan.id,
                    title="Token leakage in JS",
                    description="api token exposed",
                    severity="high",
                    confidence="high",
                    category="token_leakage",
                    signal_ids=[101],
                    evidence="token=abc",
                    raw_output="token",
                    metadata_json={"objective_type": "authenticated_api_access"},
                ))
            else:
                db.session.add(Finding(
                    scan_id=scan.id,
                    title="Authentication surface discovered",
                    description="admin auth endpoint",
                    severity="medium",
                    confidence="medium",
                    category="auth_surface",
                    signal_ids=[202],
                    evidence="/admin/login",
                    raw_output="auth endpoint",
                ))
        db.session.commit()

        payload = aggregate_mission_intelligence(mission.id)
        self.assertEqual(payload["mission"]["id"], mission.id)
        self.assertEqual(len(payload["assets"]), 2)
        self.assertEqual(len(payload["targets"]), 2)
        self.assertGreaterEqual(payload["findings_total"], 2)
        self.assertTrue(payload["cross_asset_paths"])
        first_path = payload["cross_asset_paths"][0]
        self.assertTrue(first_path["related_asset_ids"])
        self.assertTrue(first_path["related_target_ids"])
        self.assertTrue(first_path["related_finding_ids"])
        self.assertIn("rationale", first_path)

        graph = AttackGraphBuilder().build_mission_graph(payload)
        self.assertTrue(graph["nodes"])
        self.assertTrue(graph["edges"])


if __name__ == "__main__":
    unittest.main()
