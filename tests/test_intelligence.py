import unittest
import sys
import os

# Add the project root to sys.path so we can import 'core'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.intelligence import AttackVectorMapper

class TestAttackVectorMapper(unittest.TestCase):
    def test_analyze_service_apache_match(self):
        # Apache 2.4.49 matches CVE-2021-41773
        # In KB: "apache": [{"match": "2.4.49", ...}]
        # Subcat "apache" must be in service_name or version.
        vectors = AttackVectorMapper.analyze_service("Apache httpd", "2.4.49", 80)

        # Search for the specific CVE
        cve_vector = next((v for v in vectors if v["name"] == "CVE-2021-41773"), None)
        self.assertIsNotNone(cve_vector, "Should have found CVE-2021-41773 for Apache 2.4.49")
        self.assertEqual(cve_vector["risk"], "CRITICAL")

    def test_analyze_service_smb_all_match(self):
        # SMB matches "all" rules in KB: "smb": [{"match": "all", ...}]
        # "smb" must be in service_name
        vectors = AttackVectorMapper.analyze_service("microsoft-ds (smb)", "", 445)

        # Search for one of the SMB vectors
        smb_vector = next((v for v in vectors if v["name"] == "SMB Signing Disabled"), None)
        self.assertIsNotNone(smb_vector, "Should have found SMB Signing Disabled vector")

    def test_analyze_service_general_tip(self):
        # Port 22 should return SSH tip from GENERAL_TIPS
        vectors = AttackVectorMapper.analyze_service("OpenSSH", "8.2p1", 22)
        ssh_tip = next((v for v in vectors if v["name"] == "Offensive Tip (Port 22)"), None)
        self.assertIsNotNone(ssh_tip, "Should have found general tip for port 22")

    def test_web_fallback(self):
        # HTTP service on 8080 - should trigger default web fallback
        # "http" in service_name or port 8080 triggers it.
        vectors = AttackVectorMapper.analyze_service("http-alt", "", 8080)
        web_vector = next((v for v in vectors if v["category"] == "WEB"), None)
        self.assertIsNotNone(web_vector, "Should have found WEB fallback vector")
        self.assertEqual(web_vector["name"], "Web Application Surface")

    def test_no_match(self):
        # A service that matches nothing in KB and no tips for port 12345
        vectors = AttackVectorMapper.analyze_service("unknown-service", "1.0", 12345)
        self.assertEqual(len(vectors), 0, "Should have found no vectors for unknown service on port 12345")

if __name__ == '__main__':
    unittest.main()
