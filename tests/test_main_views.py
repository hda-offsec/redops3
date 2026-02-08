import unittest
import sys
import os

# Add root directory to sys.path to resolve imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from core.extensions import db

class TestMainViews(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        # Use in-memory DB for tests
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_check_dependencies(self):
        """Test the /api/dependencies endpoint returns correct tool status structure."""
        response = self.client.get('/api/dependencies')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIsInstance(data, dict)

        expected_tools = ["nmap", "nuclei", "ffuf", "whatweb", "subfinder", "katana", "sqlmap", "dnsrecon"]
        for tool in expected_tools:
            self.assertIn(tool, data)
            self.assertIn("found", data[tool])
            self.assertIn("path", data[tool])

            # Basic sanity check: found is boolean, path is string
            self.assertIsInstance(data[tool]["found"], bool)
            self.assertIsInstance(data[tool]["path"], str)

if __name__ == '__main__':
    unittest.main()
