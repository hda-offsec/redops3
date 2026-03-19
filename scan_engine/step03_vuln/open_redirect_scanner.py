import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.process_manager import ProcessManager

class OpenRedirectScanner:
    def __init__(self, target, options=None):
        self.options = options
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
                    # 0. Get baseline
                    try:
                        baseline_resp = http_client.get(ep, options=getattr(self, "options", None), timeout=5, allow_redirects=False)
                        baseline_loc = baseline_resp.headers.get('Location', '')
                    except Exception:
                        baseline_loc = ""

                    for payload in self.bypass_payloads:
                        # Build test URL with proper query reconstruction
                        # ... (encoding logic)
                        test_query = {k: v for k, v in query.items()}
                        test_query[p_name] = [payload]
                        flat_pairs = []
                        for k in sorted(test_query.keys()):
                            for val in test_query[k]:
                                flat_pairs.append((k, val))
                        
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(flat_pairs), ""
                        ))

                        try:
                            r = http_client.get(test_url, options=getattr(self, "options", None), timeout=5, allow_redirects=False)
                            loc = r.headers.get('Location', '')
                            
                            # Validates if:
                            # 1. Location matches our payload (google.com)
                            # 2. Location is DIFFERENT from baseline (proves the parameter matters)
                            if (loc.startswith('//google.com') or 'google.com' in loc) and loc != baseline_loc:
                                if logger: logger(f"🔥 Open Redirect Found: {test_url} -> {loc}", "CRITICAL")
                                from scan_engine.helpers.finding_normalizer import FindingNormalizer
                                vulnerable.append(FindingNormalizer.from_response(
                                    r,
                                    title="Open Redirect Detected",
                                    description=f"URL: {test_url}\nRedirects to: {loc}\nConfirmed via baseline comparison.",
                                    severity="medium",
                                    tool_source="open_redirect_scanner",
                                    category="redirect",
                                    payload=payload
                                ))
                                break  # Next param
                        except Exception:
                            continue
            except Exception:
                continue
        
        return vulnerable

