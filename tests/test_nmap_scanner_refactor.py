import unittest
from unittest.mock import patch, MagicMock
from scan_engine.step01_recon.nmap_scanner import NmapScanner

class TestNmapScannerRefactor(unittest.TestCase):
    def test_stream_scan_command_construction(self):
        scanner = NmapScanner("127.0.0.1")

        with patch('scan_engine.helpers.process_manager.ProcessManager.stream_command') as mock_stream:
            mock_stream.return_value = []

            # Test case 1: Standard args
            args = ["-T4", "-F"]
            scanner.stream_scan(args)

            # Verify call args
            mock_stream.assert_called()
            call_args = mock_stream.call_args[0][0]

            self.assertEqual(call_args[0], "nmap")
            self.assertIn("-T4", call_args)
            self.assertIn("-F", call_args)
            self.assertIn("127.0.0.1", call_args)
            self.assertIn("-v", call_args) # Added by default
            self.assertIn("--stats-every", call_args) # Added by default

    def test_stream_scan_no_duplication(self):
        scanner = NmapScanner("127.0.0.1")

        with patch('scan_engine.helpers.process_manager.ProcessManager.stream_command') as mock_stream:
            mock_stream.return_value = []

            # Test case 2: Args already contain target or nmap?

            args = ["-p", "80"]
            scanner.stream_scan(args)

            call_args = mock_stream.call_args[0][0]
            self.assertEqual(call_args.count("nmap"), 1)
            self.assertEqual(call_args.count("127.0.0.1"), 1)

    def test_stream_scan_with_nmap_prefix(self):
        scanner = NmapScanner("127.0.0.1")

        with patch('scan_engine.helpers.process_manager.ProcessManager.stream_command') as mock_stream:
            mock_stream.return_value = []

            # Test case: args starting with nmap
            args = ["nmap", "-sS", "127.0.0.1"]
            scanner.stream_scan(args)

            call_args = mock_stream.call_args[0][0]
            self.assertEqual(call_args.count("nmap"), 1)
            self.assertEqual(call_args.count("127.0.0.1"), 1)
            self.assertEqual(call_args[0], "nmap")

    def test_stream_scan_with_target_in_args(self):
        scanner = NmapScanner("127.0.0.1")

        with patch('scan_engine.helpers.process_manager.ProcessManager.stream_command') as mock_stream:
            mock_stream.return_value = []

            # Test case: args containing target
            args = ["-sS", "127.0.0.1"]
            scanner.stream_scan(args)

            call_args = mock_stream.call_args[0][0]
            self.assertEqual(call_args.count("127.0.0.1"), 1)

if __name__ == '__main__':
    unittest.main()
