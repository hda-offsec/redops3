import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine.orchestrator import ScanOrchestrator
from scan_engine.phases.utils import extract_wp_data

class TestOrchestratorPipeline(unittest.TestCase):
    
    @patch('scan_engine.orchestrator.run_recon')
    @patch('scan_engine.orchestrator.run_dns_osint')
    @patch('scan_engine.orchestrator.run_intel')
    @patch('scan_engine.orchestrator.run_enum')
    @patch('scan_engine.orchestrator.run_vuln_scans')
    @patch('scan_engine.orchestrator.run_global_vuln_scans')
    def test_pipeline_execution_flow(self, mock_global_vuln, mock_vuln, mock_enum, mock_intel, mock_dns, mock_recon):
        # Setup Mocks
        mock_logger = MagicMock()
        mock_recon.return_value = [{'port': 80, 'service_name': 'http', 'protocol': 'tcp'}] # Simulate open port
        
        # Initialize Orchestrator
        orch = ScanOrchestrator(
            scan_id=1,
            target='127.0.0.1',
            logger_func=mock_logger,
            finding_func=MagicMock(),
            suggestion_func=MagicMock(),
            results_func=MagicMock()
        )
        
        # Run Pipeline
        success = orch.run_pipeline(profile='quick')
        
        # Verify Calls
        mock_recon.assert_called_once()
        mock_dns.assert_called_once()
        mock_intel.assert_called_once()
        mock_enum.assert_called() # Called per port
        mock_vuln.assert_called() # Called per port
        mock_global_vuln.assert_called_once()
        
        # Verify Results Structure Matches Checklist
        results = orch.results
        self.assertIn('recon', results['phases'])
        self.assertIn('intel', results['phases'])
        self.assertIn('enum', results['phases'])
        self.assertIn('vuln', results['phases'])
        self.assertIn('whatweb', results['phases']['enum'])
        self.assertIn('headers', results['phases']['enum'])
        self.assertIsInstance(results['phases']['enum']['js_secrets'], list, "JS Secrets must be a list for UI compatibility")
        self.assertIn('nuclei', results['phases']['vuln'])
        
        print("Pipeline flow verified successfully.")

    def test_wp_data_extraction(self):
        # Test the utility function for UI compliance
        mock_stream = [
            {"type": "stdout", "line": "API Response: WordPress version 6.0 identified"},
            {"type": "stdout", "line": "[+] plugin-slug"},
            {"type": "stdout", "line": "    Location: wp-content/plugins/plugin-slug"},
            {"type": "stdout", "line": "[!] Title: SQL Injection"},
            {"type": "exit", "code": 0}
        ]
        
        data, full_log = extract_wp_data(mock_stream, 80, MagicMock())
        
        self.assertEqual(data['version'], '6.0')
        self.assertEqual(len(data['plugins']), 1)
        self.assertEqual(data['plugins'][0]['slug'], 'plugin-slug')
        self.assertEqual(len(data['vulns']), 1)
        self.assertEqual(data['vulns'][0]['title'], 'Title: SQL Injection')
        
        print("WPScan data extraction verified successfully.")

if __name__ == '__main__':
    unittest.main()
