import unittest
from scan_engine.helpers.target_utils import normalize_target_url

class TestTargetUtils(unittest.TestCase):
    def test_target_with_existing_scheme(self):
        """Test that targets starting with http:// or https:// are returned as is."""
        self.assertEqual(normalize_target_url("http://example.com"), "http://example.com")
        self.assertEqual(normalize_target_url("https://example.com"), "https://example.com")
        # Even if port/scheme args are provided, existing scheme should take precedence
        self.assertEqual(normalize_target_url("http://example.com", port=443), "http://example.com")
        self.assertEqual(normalize_target_url("https://example.com", scheme="http"), "https://example.com")

    def test_default_scheme_http(self):
        """Test that without port or scheme, it defaults to http."""
        self.assertEqual(normalize_target_url("example.com"), "http://example.com")

    def test_port_implies_https(self):
        """Test that ports 443 and 8443 imply https."""
        self.assertEqual(normalize_target_url("example.com", port=443), "https://example.com")
        self.assertEqual(normalize_target_url("example.com", port=8443), "https://example.com:8443")

    def test_explicit_scheme(self):
        """Test that providing a scheme overrides the default logic."""
        self.assertEqual(normalize_target_url("example.com", scheme="https"), "https://example.com")
        self.assertEqual(normalize_target_url("example.com", scheme="http"), "http://example.com")
        self.assertEqual(normalize_target_url("example.com", scheme="ftp"), "ftp://example.com")

    def test_port_handling(self):
        """Test port handling logic."""
        # Standard ports (80, 443) are omitted from the URL string
        self.assertEqual(normalize_target_url("example.com", port=80), "http://example.com")
        self.assertEqual(normalize_target_url("example.com", port=443), "https://example.com")

        # Non-standard ports are appended
        self.assertEqual(normalize_target_url("example.com", port=8080), "http://example.com:8080")
        self.assertEqual(normalize_target_url("example.com", port=8443), "https://example.com:8443")
        self.assertEqual(normalize_target_url("example.com", port=22), "http://example.com:22")

    def test_mixed_scheme_and_port(self):
        """Test behavior when both scheme and port are provided."""
        # Scheme provided, port is standard for that scheme -> check code behavior
        # If scheme="https", port=443. resolved_scheme="https". port in (80, 443) -> port omitted.
        self.assertEqual(normalize_target_url("example.com", port=443, scheme="https"), "https://example.com")

        # If scheme="http", port=80. resolved_scheme="http". port in (80, 443) -> port omitted.
        self.assertEqual(normalize_target_url("example.com", port=80, scheme="http"), "http://example.com")

        # If scheme="http", port=443. resolved_scheme="http". port (443) in (80, 443) -> port omitted.
        self.assertEqual(normalize_target_url("example.com", port=443, scheme="http"), "http://example.com")

        # If scheme="https", port=80. resolved_scheme="https". port (80) in (80, 443) -> port omitted.
        self.assertEqual(normalize_target_url("example.com", port=80, scheme="https"), "https://example.com")

        # Scheme provided, non-standard port
        self.assertEqual(normalize_target_url("example.com", port=8080, scheme="https"), "https://example.com:8080")

if __name__ == "__main__":
    unittest.main()
