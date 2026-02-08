import unittest
from unittest.mock import patch, MagicMock
from app import create_app
from ui.web.views import main
import shlex

class TestSecurityFix(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_injection_prevention(self):
        # Test that injection attempt is parsed correctly and shell=False is used
        # Mock socketio.start_background_task so we can capture the function and args
        with patch('ui.web.views.main.socketio.start_background_task') as mock_start_background_task:
            response = self.client.post('/scan/verify', json={
                'scan_id': 1,
                'command': 'nmap localhost; whoami'
            })

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['status'], 'success')

            # Get the arguments passed to start_background_task
            mock_start_background_task.assert_called()
            args = mock_start_background_task.call_args[0]

            run_verification_func = args[0]
            scan_id = args[1]
            cmd = args[2]
            app_obj = args[3]

            # We need to execute the inner function run_verification
            # But we must mock Popen to avoid actual execution and verify arguments
            with patch('ui.web.views.main.Popen') as mock_popen:
                process_mock = MagicMock()
                process_mock.stdout = []
                process_mock.wait.return_value = None
                mock_popen.return_value = process_mock

                run_verification_func(scan_id, cmd, app_obj)

                mock_popen.assert_called()
                call_args = mock_popen.call_args

                # Check call arguments
                # call_args[0] is positional args (args list)
                # call_args[1] is keyword args (shell=False, etc.)
                command_args = call_args[0][0]
                shell_arg = call_args[1].get('shell', None)

                print(f"Command executed: {command_args}")
                print(f"Shell argument: {shell_arg}")

                self.assertIsInstance(command_args, list)
                self.assertEqual(command_args[0], 'nmap')
                # 'nmap' is in ALLOWED_TOOLS, so it proceeds.
                # However, the command is parsed as list.

                # Verify shell is False
                self.assertFalse(shell_arg, "shell=False ensures no shell injection")

                # Verify command parsing: 'nmap localhost; whoami' -> ['nmap', 'localhost;', 'whoami']
                # or ['nmap', 'localhost', ';', 'whoami'] depending on shlex rules.
                # In either case, 'whoami' is an argument to nmap (or ;), not executed.

    def test_disallowed_tool(self):
        # Test that a tool not in ALLOWED_TOOLS is blocked
        with patch('ui.web.views.main.socketio.start_background_task') as mock_start_background_task:
            response = self.client.post('/scan/verify', json={
                'scan_id': 1,
                'command': 'ls -la'
            })

            self.assertEqual(response.status_code, 200)

            args = mock_start_background_task.call_args[0]
            run_verification_func = args[0]
            scan_id = args[1]
            cmd = args[2]
            app_obj = args[3]

            with patch('ui.web.views.main.Popen') as mock_popen:
                run_verification_func(scan_id, cmd, app_obj)

                # Popen should NOT be called because 'ls' is not allowed
                mock_popen.assert_not_called()

    def test_allowed_tool(self):
        # Test that an allowed tool is executed
        with patch('ui.web.views.main.socketio.start_background_task') as mock_start_background_task:
            response = self.client.post('/scan/verify', json={
                'scan_id': 1,
                'command': 'ping -c 4 localhost'
            })

            self.assertEqual(response.status_code, 200)

            args = mock_start_background_task.call_args[0]
            run_verification_func = args[0]
            scan_id = args[1]
            cmd = args[2]
            app_obj = args[3]

            with patch('ui.web.views.main.Popen') as mock_popen:
                process_mock = MagicMock()
                process_mock.stdout = []
                process_mock.wait.return_value = None
                mock_popen.return_value = process_mock

                run_verification_func(scan_id, cmd, app_obj)

                mock_popen.assert_called()
                command_args = mock_popen.call_args[0][0]
                self.assertEqual(command_args[0], 'ping')
                self.assertFalse(mock_popen.call_args[1].get('shell'))

if __name__ == '__main__':
    unittest.main()
