import requests
import urllib3
from flask import current_app, request
from urllib.parse import urlparse

# Globally suppress warnings for the defensive tool's scanning activities
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_verify_ssl():
    """Returns the SSL verification setting from the app config or default to True."""
    try:
        # Default to True for security unless explicitly overridden
        return current_app.config.get('HTTP_VERIFY', True)
    except:
        return True

def safe_requests_get(url, **kwargs):
    if 'verify' not in kwargs:
        kwargs['verify'] = get_verify_ssl()
    return requests.get(url, **kwargs)

def safe_requests_post(url, **kwargs):
    if 'verify' not in kwargs:
        kwargs['verify'] = get_verify_ssl()
    return requests.post(url, **kwargs)

def safe_requests_head(url, **kwargs):
    if 'verify' not in kwargs:
        kwargs['verify'] = get_verify_ssl()
    return requests.head(url, **kwargs)

def is_safe_url(target):
    """
    Robust Open Redirect Protection.
    Ensures URL is either relative or belongs to the same host/domain.
    """
    if not target:
        return False
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        # Check scheme and netloc for safety
        if test_url.scheme and test_url.scheme not in ('http', 'https'):
            return False
        # If absolute, must match ref_url netloc. If relative, must have no netloc.
        return (not test_url.netloc) or (test_url.netloc == ref_url.netloc)
    except Exception:
        return False
