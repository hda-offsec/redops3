import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add the project root to the python path so we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner

class TestFfufScanner(unittest.TestCase):

    @patch('scan_engine.step05_dirbusting.ffuf_scanner.ProcessManager.stream_command')
    def test_stream_fuzz_with_full_url(self, mock_stream_command):
        """
        Test that stream_fuzz correctly handles self.target being a full URL.
        """
        # Scenario: target is already a URL (e.g. from orchestrator)
        scanner = FfufScanner("http://example.com:80")

        # We call stream_fuzz with port 80 (as legacy code might)
        # We expect the URL to remain "http://example.com:80/FUZZ"
        # and NOT become "http://http://example.com:80:80/FUZZ"

        # Since stream_fuzz currently requires port, we must provide it.
        scanner.stream_fuzz(80)

        # Verify the command passed to stream_command
        args, _ = mock_stream_command.call_args
        command = args[0]

        # command is a list: ["ffuf", "-u", url, ...]
        self.assertIn("-u", command)
        url_index = command.index("-u") + 1
        url = command[url_index]

        expected_url = "http://example.com:80/FUZZ"
        self.assertEqual(url, expected_url, f"Expected URL {expected_url}, but got {url}")

    @patch('scan_engine.step05_dirbusting.ffuf_scanner.ProcessManager.stream_command')
    def test_stream_fuzz_legacy_behavior(self, mock_stream_command):
        """
        Test that stream_fuzz still works for legacy/simple hostname targets.
        """
        # Scenario: target is just a hostname
        scanner = FfufScanner("example.com")

        # Call stream_fuzz with port 8080 and protocol https
        scanner.stream_fuzz(8080, protocol='https')

        # Verify the command passed to stream_command
        args, _ = mock_stream_command.call_args
        command = args[0]

        self.assertIn("-u", command)
        url_index = command.index("-u") + 1
        url = command[url_index]

        expected_url = "https://example.com:8080/FUZZ"
        self.assertEqual(url, expected_url, f"Expected URL {expected_url}, but got {url}")

    @patch('scan_engine.step05_dirbusting.ffuf_scanner.ProcessManager.stream_command')
    def test_stream_scan_delegates_to_stream_fuzz(self, mock_stream_command):
        """
        Test that stream_scan properly delegates to stream_fuzz.
        """
        scanner = FfufScanner("http://example.com:80")
        scanner.stream_scan()

        args, _ = mock_stream_command.call_args
        command = args[0]
        self.assertIn("-u", command)
        url_index = command.index("-u") + 1
        url = command[url_index]
        expected_url = "http://example.com:80/FUZZ"
        self.assertEqual(url, expected_url)

if __name__ == '__main__':
    unittest.main()
