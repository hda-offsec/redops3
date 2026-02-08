import pytest
from scan_engine.helpers.target_utils import normalize_target_url

def test_target_already_has_scheme():
    """Test that targets with existing schemes are returned as-is."""
    assert normalize_target_url("http://example.com") == "http://example.com"
    assert normalize_target_url("https://example.com") == "https://example.com"
    # Even if port is provided, existing scheme takes precedence and returns original string
    assert normalize_target_url("http://example.com", port=8080) == "http://example.com"

def test_target_no_scheme_defaults():
    """Test default behavior for target without scheme."""
    # Default scheme is http
    assert normalize_target_url("example.com") == "http://example.com"

def test_target_with_specific_ports():
    """Test scheme resolution based on port."""
    # Port 80 -> http, port omitted
    assert normalize_target_url("example.com", port=80) == "http://example.com"

    # Port 443 -> https, port omitted
    assert normalize_target_url("example.com", port=443) == "https://example.com"

    # Port 8443 -> https, port included
    assert normalize_target_url("example.com", port=8443) == "https://example.com:8443"

    # Other ports -> http, port included
    assert normalize_target_url("example.com", port=8080) == "http://example.com:8080"
    assert normalize_target_url("example.com", port=21) == "http://example.com:21"

def test_target_with_explicit_scheme():
    """Test that explicit scheme overrides default logic."""
    assert normalize_target_url("example.com", scheme="https") == "https://example.com"
    assert normalize_target_url("example.com", scheme="ftp") == "ftp://example.com"

    # Explicit scheme with port
    assert normalize_target_url("example.com", scheme="https", port=8443) == "https://example.com:8443"
    assert normalize_target_url("example.com", scheme="ftp", port=21) == "ftp://example.com:21"

def test_port_omission_logic():
    """Test that standard ports are omitted from output."""
    # 80 and 443 are omitted
    assert normalize_target_url("example.com", port=80) == "http://example.com"
    assert normalize_target_url("example.com", port=443) == "https://example.com"

    # Non-standard are included
    assert normalize_target_url("example.com", port=8080) == "http://example.com:8080"

def test_scheme_argument_precedence():
    """Test scheme argument behavior when port also implies a scheme."""
    # Port 443 implies https, but if we pass http?
    # Logic: resolved_scheme = scheme (if provided).
    # So if scheme="http", it stays "http".
    # And port 443 is omitted? Code: `if port and port not in (80, 443)`
    # So `http://example.com` (no port).
    assert normalize_target_url("example.com", port=443, scheme="http") == "http://example.com"

    # Port 80 implies http, pass https
    # resolved_scheme = "https"
    # port 80 is omitted.
    # Result: https://example.com
    assert normalize_target_url("example.com", port=80, scheme="https") == "https://example.com"
