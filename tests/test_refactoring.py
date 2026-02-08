import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Add project root to path so we can import scan_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine.helpers.process_manager import ProcessManager
from scan_engine.step02_enum.katana_scanner import KatanaScanner
from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
from scan_engine.step01_recon.dns_scanner import DNSScanner

class TestProcessManager(unittest.TestCase):
    @patch('scan_engine.helpers.process_manager.shutil.which')
    def test_find_binary_path_system(self, mock_which):
        # Case 1: Binary in system PATH
        mock_which.return_value = '/usr/bin/tool'
        path = ProcessManager.find_binary_path('tool')
        self.assertEqual(path, '/usr/bin/tool')
        mock_which.assert_called_with('tool')

    @patch('scan_engine.helpers.process_manager.shutil.which')
    @patch('scan_engine.helpers.process_manager.os.path.exists')
    @patch('scan_engine.helpers.process_manager.os.path.expanduser')
    def test_find_binary_path_go(self, mock_expanduser, mock_exists, mock_which):
        # Case 2: Binary not in PATH, but in ~/go/bin
        mock_which.return_value = None
        mock_expanduser.side_effect = lambda x: x.replace('~', '/home/user')
        mock_exists.return_value = True

        path = ProcessManager.find_binary_path('tool')
        self.assertEqual(path, '/home/user/go/bin/tool')
        mock_exists.assert_called_with('/home/user/go/bin/tool')

    @patch('scan_engine.helpers.process_manager.shutil.which')
    @patch('scan_engine.helpers.process_manager.os.path.exists')
    def test_find_binary_path_none(self, mock_exists, mock_which):
        # Case 3: Binary nowhere
        mock_which.return_value = None
        mock_exists.return_value = False

        path = ProcessManager.find_binary_path('tool')
        self.assertIsNone(path)

class TestScanners(unittest.TestCase):
    @patch('scan_engine.helpers.process_manager.ProcessManager.find_binary_path')
    def test_katana_check_tools(self, mock_find):
        mock_find.return_value = '/usr/bin/katana'
        scanner = KatanaScanner('target')
        self.assertTrue(scanner.check_tools())
        mock_find.assert_called_with('katana')

        mock_find.return_value = None
        self.assertFalse(scanner.check_tools())

    @patch('scan_engine.helpers.process_manager.ProcessManager.find_binary_path')
    def test_nuclei_check_tools(self, mock_find):
        mock_find.return_value = '/usr/bin/nuclei'
        scanner = NucleiScanner('target')
        self.assertTrue(scanner.check_tools())
        mock_find.assert_called_with('nuclei')

    @patch('scan_engine.helpers.process_manager.ProcessManager.find_binary_path')
    def test_dns_check_tools(self, mock_find):
        mock_find.return_value = '/usr/bin/dnsrecon'
        scanner = DNSScanner('target')
        self.assertTrue(scanner.check_tools())
        mock_find.assert_called_with('dnsrecon')

if __name__ == '__main__':
    unittest.main()
