
import time
import unittest
from app import create_app, db
from core.models import Mission, Target, Scan, Finding
from sqlalchemy import event

class BenchmarkMissionMap(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()
        db.create_all()

        # Create data
        self.mission = Mission(name="Benchmark Mission")
        db.session.add(self.mission)
        db.session.commit()

        # Create N targets
        self.num_targets = 50
        self.targets = []
        for i in range(self.num_targets):
            t = Target(mission_id=self.mission.id, identifier=f"target-{i}.com")
            db.session.add(t)
            self.targets.append(t)
        db.session.commit()

        # Create Scans and Findings for each target
        for t in self.targets:
            # Create a few scans
            for j in range(3):
                s = Scan(target_id=t.id, scan_type="quick", status="completed", geolocation_data={"country": "US", "isp": "Cloudflare"})
                db.session.add(s)
                db.session.commit()

                # Add findings to the latest scan
                if j == 2:
                    for k in range(5):
                        f = Finding(scan_id=s.id, title=f"Finding {k}", severity="high")
                        db.session.add(f)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_mission_map_performance(self):
        mission_id = self.mission.id

        # Reset query count
        self.query_count = 0

        @event.listens_for(db.engine, 'before_cursor_execute')
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            self.query_count += 1

        start_time = time.time()

        # Call the endpoint
        response = self.client.get(f"/mission/{mission_id}/map")

        end_time = time.time()
        duration = end_time - start_time

        # Remove listener
        event.remove(db.engine, 'before_cursor_execute', receive_before_cursor_execute)

        print(f"\nBenchmark Results (via Endpoint):")
        print(f"Targets: {self.num_targets}")
        print(f"Duration: {duration:.4f}s")
        print(f"Query Count: {self.query_count}")

        self.assertEqual(response.status_code, 200)
        content = response.data.decode('utf-8')

        # Verify data is present
        self.assertIn("Benchmark Mission", content)
        self.assertIn("target-0.com", content)
        self.assertIn("US", content) # Geolocation country
        self.assertIn("ISP: Cloudflare", content) # Geolocation ISP
        self.assertIn("Finding 0", content) # Findings

if __name__ == '__main__':
    unittest.main()
