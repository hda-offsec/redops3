import requests
import re
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
            # Extract parameters
            try:
                base_url, params_str = ep.split('?', 1)
                # Quick and dirty param check
                for p_pair in params_str.split('&'):
                    if '=' in p_pair:
                        p_name = p_pair.split('=')[0].lower()
                        if p_name in self.redirect_params:
                            # Test this parameter
                            for payload in self.bypass_payloads:
                                # Reconstruct URL with payload
                                # Replace the value of the parameter with our payload
                                test_params = params_str.replace(p_pair, f"{p_name}={payload}")
                                test_url = f"{base_url}?{test_params}"
                                
                                try:
                                    # We don't want to follow redirects automatically to check the Location header
                                    r = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                                    loc = r.headers.get('Location', '')
                                    if loc.startswith('//google.com') or 'google.com' in loc:
                                        if logger: logger(f"🔥 Open Redirect Found: {test_url} -> {loc}", "CRITICAL")
                                        vulnerable.append({"url": test_url, "destination": loc})
                                        break # Next endpoint
                                except:
                                    continue
            except Exception:
                continue
        
        return vulnerable
