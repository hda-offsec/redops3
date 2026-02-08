import unittest
from app import create_app
from core.models import User
from core.extensions import db

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            user = User(username='admin')
            user.set_password('redops3_admin')
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_unauthorized_access(self):
        print("Testing unauthorized access to /api/dependencies...")
        # Try to access sensitive endpoint
        response = self.client.get('/api/dependencies', follow_redirects=True)
        # Should redirect to login
        # Verify we landed on login page
        self.assertIn(b'Operator ID', response.data)
        print("Successfully redirected to login page.")

    def test_login(self):
        print("Testing login...")
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'redops3_admin'
        }, follow_redirects=True)
        self.assertIn(b'Mission Control', response.data)
        print("Login successful.")

    def test_authorized_access(self):
        print("Testing authorized access to /api/dependencies...")
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'redops3_admin'
        }, follow_redirects=True)

        response = self.client.get('/api/dependencies')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'nmap', response.data)
        print("Access granted.")

if __name__ == '__main__':
    unittest.main()
