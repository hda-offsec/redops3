import unittest
from unittest.mock import patch
from app import create_app, db

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    @patch('core.tasks.run_scan_task.delay')
    def test_scan_new_requires_auth(self, mock_delay):
        # Attempt to create a scan without login
        response = self.client.post('/scan/new', data={
            'target': 'example.com',
            'scan_type': 'quick',
            'confirm_auth': 'on'
        }, follow_redirects=False)

        # Expectation: Should be redirected to login
        if response.status_code == 302:
            location = response.headers['Location']
            if 'login' not in location:
                self.fail(f"Expected redirect to login, got {location}")
        else:
             self.fail(f"Expected 302 Redirect to login, got {response.status_code}")

    @patch('core.tasks.run_scan_task.delay')
    def test_scan_new_authenticated_success(self, mock_delay):
        # Create user
        from core.models import User
        with self.app.app_context():
            u = User(username='testuser')
            u.set_password('password')
            db.session.add(u)
            db.session.commit()

        # Login
        self.client.post('/login', data={'username': 'testuser', 'password': 'password'}, follow_redirects=True)

        # Attempt to create a scan WITH login
        response = self.client.post('/scan/new', data={
            'target': 'example.com',
            'scan_type': 'quick',
            'confirm_auth': 'on'
        }, follow_redirects=False)

        # Expectation: Should succeed and redirect to scan detail
        self.assertEqual(response.status_code, 302)
        location = response.headers['Location']
        self.assertIn('/scan/', location)
        self.assertNotIn('login', location)

if __name__ == '__main__':
    unittest.main()
