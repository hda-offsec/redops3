import unittest
import sys
import os
import time
import threading

# Add the project root to sys.path so we can import 'core'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.intelligence import AttackVectorMapper

class TestAttackVectorMapper(unittest.TestCase):
    def test_analyze_service_apache_match(self):
        # Apache 2.4.49 matches CVE-2021-41773
        vectors = AttackVectorMapper.analyze_service("Apache httpd", "2.4.49", 80)
        cve_vector = next((v for v in vectors if v["name"] == "CVE-2021-41773"), None)
        self.assertIsNotNone(cve_vector, "Should have found CVE-2021-41773 for Apache 2.4.49")
        self.assertEqual(cve_vector["risk"], "CRITICAL")

    def test_analyze_service_smb_all_match(self):
        vectors = AttackVectorMapper.analyze_service("microsoft-ds (smb)", "", 445)
        smb_vector = next((v for v in vectors if v["name"] == "SMB Signing Disabled"), None)
        self.assertIsNotNone(smb_vector, "Should have found SMB Signing Disabled vector")

    def test_analyze_service_general_tip(self):
        vectors = AttackVectorMapper.analyze_service("OpenSSH", "8.2p1", 22)
        ssh_tip = next((v for v in vectors if v["name"] == "Offensive Tip (Port 22)"), None)
        self.assertIsNotNone(ssh_tip, "Should have found general tip for port 22")

    def test_web_fallback(self):
        vectors = AttackVectorMapper.analyze_service("http-alt", "", 8080)
        web_vector = next((v for v in vectors if v["category"] == "WEB"), None)
        self.assertIsNotNone(web_vector, "Should have found WEB fallback vector")

    def test_no_match(self):
        vectors = AttackVectorMapper.analyze_service("unknown-service", "1.0", 12345)
        self.assertEqual(len(vectors), 0)

    def test_async_geolocation(self):
        target = "8.8.8.8"
        result_container = {}
        done_event = threading.Event()

        def my_callback(result):
            result_container['data'] = result
            done_event.set()

        start_time = time.time()
        t = AttackVectorMapper.get_ip_geolocation(target, callback=my_callback)
        end_time = time.time()

        dispatch_duration = end_time - start_time
        # Ensure it's not blocking - usually < 1ms on local thread start
        self.assertLess(dispatch_duration, 0.1, "Dispatch should be non-blocking")
        self.assertIsNotNone(t, "Should return a thread object")

        if not done_event.wait(timeout=5):
            self.fail("Geolocation callback timed out")

        self.assertIsNotNone(result_container.get('data'), "Callback should return data")

if __name__ == '__main__':
    unittest.main()
