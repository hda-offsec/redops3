import unittest
import subprocess
import os
import time
import sys

class TestAppSecurity(unittest.TestCase):
    def run_app_and_check(self, env, expected_debug, expected_error=False, expected_running=True):
        # Ensure we run from project root
        cwd = os.getcwd()
        if os.path.basename(cwd) == "tests":
            cwd = os.path.dirname(cwd)

        process = subprocess.Popen(
            ['python3', 'app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **(env or {})},
            cwd=cwd,
            text=True,
            bufsize=1
        )

        stdout_buf = []
        stderr_buf = []

        try:
            # Wait for app to start
            time.sleep(5)
        finally:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=2)
                stdout_buf.append(stdout)
                stderr_buf.append(stderr)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                stdout_buf.append(stdout)
                stderr_buf.append(stderr)

        full_stdout = "".join(stdout_buf)
        full_stderr = "".join(stderr_buf)

        debug_active = "Debugger is active!" in full_stdout or "Debugger is active!" in full_stderr
        runtime_error = "RuntimeError" in full_stderr
        # Check for standard Flask/Werkzeug startup messages
        running = "Serving Flask app" in full_stdout or "Running on" in full_stderr or "Running on" in full_stdout

        if expected_error:
            self.assertTrue(runtime_error, "RuntimeError should have occurred (Werkzeug unsafe check) but didn't.")
        else:
            self.assertFalse(runtime_error, f"RuntimeError occurred unexpectedly: {full_stderr[:500]}...")

        if expected_debug:
            self.assertTrue(debug_active, "Debugger should be active but wasn't found in output.")
        else:
            self.assertFalse(debug_active, "Debugger was active but shouldn't have been.")

        if expected_running:
            self.assertTrue(running, "App did not seem to be running (no startup message found).")

    def test_default_behavior(self):
        """Test default behavior (no env vars). Should be secure (debug=False) and fail safely."""
        # Default: Debug=False, AllowUnsafe=False -> RuntimeError because we use socketio.run with Werkzeug
        self.run_app_and_check({}, expected_debug=False, expected_error=True, expected_running=False)

    def test_flask_debug_true(self):
        """Test with FLASK_DEBUG=True. Should enable debug mode and allow unsafe werkzeug."""
        # FLASK_DEBUG=True -> Debug=True, AllowUnsafe=True -> Running
        self.run_app_and_check({"FLASK_DEBUG": "True"}, expected_debug=True, expected_running=True)

    def test_flask_debug_false_explicit(self):
        """Test with explicit FLASK_DEBUG=False. Should behave like default."""
        # FLASK_DEBUG=False -> Debug=False, AllowUnsafe=False -> RuntimeError
        self.run_app_and_check({"FLASK_DEBUG": "False"}, expected_debug=False, expected_error=True, expected_running=False)

    def test_allow_unsafe_werkzeug(self):
        """Test with ALLOW_UNSAFE_WERKZEUG=True. Should run without debug mode."""
        # FLASK_DEBUG=False, ALLOW_UNSAFE_WERKZEUG=True -> Debug=False, AllowUnsafe=True -> Running
        self.run_app_and_check({"FLASK_DEBUG": "False", "ALLOW_UNSAFE_WERKZEUG": "True"}, expected_debug=False, expected_running=True)

if __name__ == '__main__':
    unittest.main()
