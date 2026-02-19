import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.process_manager import ProcessManager

class OpenRedirectScanner:
    def __init__(self, target):
        self.target = target
        # Parameters often associated with redirects
        self.redirect_params = [
            'url', 'next', 'redirect', 'dest', 'destination', 'out', 'view', 'to', 
            'from', 'move', 'path', 'uri', 'url_callback', 'return', 'r', 'u'
        ]
        self.bypass_payloads = [
            '//google.com',
            'https://google.com',
            '/%2fgoogle.com',
            '/%5cgoogle.com',
            '/%2f%2fgoogle.com'
        ]

    def scan_endpoints(self, endpoints, logger=None):
        """
        Takes a list of endpoints (from Katana) and tests those with redirect parameters.
        """
        vulnerable = []
        # Filter for endpoints with parameters
        target_endpoints = [ep for ep in endpoints if '?' in ep]
        
        if logger: logger(f"Advanced: Testing {len(target_endpoints)} endpoints for Open Redirects...", "INFO")
        
        for ep in target_endpoints:
            try:
                parsed = urlparse(ep)
                query = parse_qs(parsed.query, keep_blank_values=True)

                # Find redirect-related params
                redirect_keys = [
                    k for k in query if k.lower() in self.redirect_params
                ]
                if not redirect_keys:
                    continue

                for p_name in redirect_keys:
                    for payload in self.bypass_payloads:
                        # Build test URL with proper query reconstruction
                        test_query = {k: v for k, v in query.items()}
                        test_query[p_name] = [payload]
                        # Flatten single-value lists for clean encoding
                        flat_pairs = []
                        for k in sorted(test_query.keys()):
                            for val in test_query[k]:
                                flat_pairs.append((k, val))
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(flat_pairs), ""
                        ))

                        try:
                            r = requests.get(test_url, timeout=5, verify=True, allow_redirects=False)
                            loc = r.headers.get('Location', '')
                            if loc.startswith('//google.com') or 'google.com' in loc:
                                if logger: logger(f"🔥 Open Redirect Found: {test_url} -> {loc}", "CRITICAL")
                                vulnerable.append({"url": test_url, "destination": loc})
                                break  # Next param
                        except Exception:
                            continue
            except Exception:
                continue
        
        return vulnerable

