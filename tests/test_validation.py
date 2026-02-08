import sys
import os
import unittest

# Ensure we can import from the root
sys.path.append(os.getcwd())

from scan_engine.helpers.target_utils import validate_target

class TestTargetValidation(unittest.TestCase):
    def test_valid_targets(self):
        valid_targets = [
            "8.8.8.8",
            "1.1.1.1",
            "google.com",
            "example.com",
            "http://google.com",
            "https://example.com:443",
        ]
        for t in valid_targets:
            try:
                self.assertTrue(validate_target(t), f"Target {t} should be valid")
            except Exception as e:
                self.fail(f"Target {t} raised exception: {e}")

    def test_invalid_targets(self):
        invalid_targets = [
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", # Link-local / Cloud metadata
            "::1", # IPv6 loopback
            "http://127.0.0.1",
            "https://localhost:8080",
        ]
        for t in invalid_targets:
            with self.assertRaises(ValueError, msg=f"Target {t} should be invalid"):
                validate_target(t)

if __name__ == '__main__':
    unittest.main()
