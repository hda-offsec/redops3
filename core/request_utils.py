import requests
import urllib3
from flask import current_app

# Globally suppress warnings for the defensive tool's scanning activities
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_verify_ssl():
    """Returns the SSL verification setting from the app config or default to False for red-teaming."""
    try:
        # If we have an app context, check config. Otherwise default to False.
        return current_app.config.get('HTTP_VERIFY', False)
    except Exception:
        return False

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
