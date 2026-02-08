import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine.step01_recon.dns_scanner import DNSScanner

class TestDNSScanner(unittest.TestCase):
    @patch('scan_engine.step01_recon.dns_scanner.ProcessManager')
    def test_enumerate_all_parses_results(self, mock_pm):
        # Setup
        target = "example.com"
        scanner = DNSScanner(target)

        # Mock ProcessManager.run_command for subfinder (first call)
        # and dnsrecon (second call)

        def run_command_side_effect(command):
            cmd_str = " ".join(command)
            if "subfinder" in cmd_str:
                return True, "sub1.example.com\nsub2.example.com", "", 0
            elif "dnsrecon" in cmd_str:
                # Create dummy result file
                try:
                    output_file_index = command.index('--json') + 1
                    output_file = command[output_file_index]
                except (ValueError, IndexError):
                    output_file = f"data/results/dns_{target}.json"

                # Ensure dir exists
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump([
                        {"type": "A", "name": "example.com", "address": "1.2.3.4"},
                        {"type": "NS", "name": "example.com", "target": "ns1.example.com"}
                    ], f)
                return True, "", "", 0
            return False, "", "Unknown command", 1

        mock_pm.run_command.side_effect = run_command_side_effect

        # Run
        logger = MagicMock()

        # We need to ensure check_tools passes.
        # But check_tools is called before enumerate_all? No.
        # check_tools is likely called by orchestrator.
        # DNSScanner.enumerate_all calls run_subfinder and run_dnsrecon directly.

        # However, run_subfinder checks for shutil.which inside.
        with patch('shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/subfinder"
            results = scanner.enumerate_all(logger)

        # Assert
        self.assertIn("sub1.example.com", results["subdomains"])

        # This assertion is expected to FAIL before fix
        self.assertEqual(len(results["records"]), 2, f"Should have parsed 2 records from dnsrecon, got {len(results['records'])}")
        self.assertEqual(results["records"][0]["address"], "1.2.3.4")

    def tearDown(self):
        # Cleanup
        target = "example.com"
        output_file = f"data/results/dns_{target}.json"
        if os.path.exists(output_file):
            os.remove(output_file)
            # Try to remove dir if empty
            try:
                os.rmdir(os.path.dirname(output_file))
            except OSError:
                pass

if __name__ == '__main__':
    unittest.main()
