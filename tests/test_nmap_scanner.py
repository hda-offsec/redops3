import unittest
import sys
import os

# Add the project root to the python path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine.step01_recon.nmap_scanner import NmapScanner

class TestNmapScanner(unittest.TestCase):
    def setUp(self):
        self.target = "127.0.0.1"
        self.scanner = NmapScanner(self.target)

    def test_command_for_profile_quick(self):
        expected_command = ["nmap", "-n", "-v", "-T4", "-F", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("quick"), expected_command)

    def test_command_for_profile_deep(self):
        expected_command = ["nmap", "-n", "-v", "-sC", "-sV", "--top-ports", "3000", "--open", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("deep"), expected_command)

    def test_command_for_profile_full(self):
        expected_command = ["nmap", "-n", "-v", "-sC", "-sV", "-p-", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("full"), expected_command)

    def test_command_for_profile_udp(self):
        expected_command = ["nmap", "-v", "-sU", "--top-ports", "100", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("udp"), expected_command)

    def test_command_for_profile_vuln(self):
        expected_command = ["nmap", "-v", "--script", "vuln", "-sV", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("vuln"), expected_command)

    def test_command_for_profile_os(self):
        expected_command = ["nmap", "-v", "-O", "-sV", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("os"), expected_command)

    def test_command_for_profile_discovery(self):
        expected_command = ["nmap", "-v", "-sn", "-T4", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("discovery"), expected_command)

    def test_command_for_profile_stealth(self):
        expected_command = ["nmap", "-v", "-sS", "-sV", "-T2", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("stealth"), expected_command)

    def test_command_for_profile_web(self):
        expected_command = [
            "nmap",
            "-v",
            "-sV",
            "-p",
            "80,443,8000,8080,8443",
            "--script",
            "http-title,http-headers,http-methods",
            "-T4",
            "--stats-every",
            "10s",
            self.target
        ]
        self.assertEqual(self.scanner.command_for_profile("web"), expected_command)

    def test_command_for_profile_unknown_defaults_to_quick(self):
        expected_command = ["nmap", "-n", "-v", "-T4", "-F", "--stats-every", "10s", self.target]
        self.assertEqual(self.scanner.command_for_profile("unknown_profile"), expected_command)

if __name__ == '__main__':
    unittest.main()
