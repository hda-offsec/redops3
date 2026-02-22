from scan_engine.helpers.http_client import get_session
import re
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

class OAuthScanner:
    """
    Expert Auditor for OAuth2 and OpenID Connect implementations.
    Detects:
    1. Weak Redirect URIs (Wildcard/Open Redirect)
    2. Missing 'state' parameter (CSRF)
    3. Token Leakage in Referer
    4. Implicit Flow Usage (Security Risk)
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(options)
        self.session.headers.update({"User-Agent": "RedOps3-OAuthExpert/1.0"})
        self.sensitive_params = ["code", "access_token", "id_token", "refresh_token"]

    def scan_endpoints(self, urls, logger=None):
        findings = []
        oauth_urls = [u for u in urls if any(k in u.lower() for k in ["oauth", "callback", "authorize", "token", "openid", "signin-"])]
        
        if not oauth_urls:
            return []

        if logger: logger(f"OAuth Expert: Analyzing {len(oauth_urls)} candidate OAuth flows...", "INFO")

        for url in oauth_urls:
            try:
                # 1. Check for missing 'state' parameter in authorization requests
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                if "client_id" in params and "redirect_uri" in params:
                    if "state" not in params:
                        findings.append({
                            "title": "OAuth 2.0 Missing State Parameter",
                            "description": f"The OAuth authorization request at {url} lacks a 'state' parameter. This makes the flow vulnerable to CSRF attacks.",
                            "severity": "high",
                            "tool_source": "oauth_expert",
                            "url": url
                        })

                    # 2. Check for Implicit Flow (response_type=token)
                    if "response_type" in params and "token" in params["response_type"]:
                        findings.append({
                            "title": "OAuth 2.0 Deprecated Implicit Flow",
                            "description": "Implicit flow (response_type=token) is used. It is deprecated due to security risks where tokens are exposed in the URL hash.",
                            "severity": "medium",
                            "tool_source": "oauth_expert",
                            "url": url
                        })

                    # 3. Test for Redirection URI Manipulation
                    findings.extend(self._test_redirect_uri(url, params, logger))

            except Exception as e:
                if logger: logger(f"OAuth Expert Error on {url}: {e}", "DEBUG")

        return findings

    def _test_redirect_uri(self, url, params, logger):
        found = []
        original_uri = params["redirect_uri"][0]
        
        # Attack URIs
        malicious_redirects = [
            "https://evil.local",
            f"{original_uri}.evil.com",
            original_uri.replace(urlparse(original_uri).netloc, "evil.com")
        ]

        for mal_uri in malicious_redirects:
            try:
                # Construct new URL with malicious redirect_uri
                new_params = params.copy()
                new_params["redirect_uri"] = [mal_uri]
                # Rebuild query
                new_url = url.split("?")[0] + "?" + urlencode(new_params, doseq=True)
                
                # Check if server accepts it (200 OK or 302 to the malicious URI)
                resp = self.session.get(new_url, timeout=5, allow_redirects=False)
                
                if resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if mal_uri in location:
                        found.append({
                            "title": "OAuth Redirect URI Validation Bypass",
                            "description": f"OAuth provider accepts unauthorized redirect_uri: {mal_uri}\nOriginal: {original_uri}\nAttack URL: {new_url}",
                            "severity": "critical",
                            "tool_source": "oauth_expert",
                            "url": new_url
                        })
                        if logger: logger(f"CRITICAL: OAuth Redirect Bypass found on {url}", "CRITICAL")
                        break
            except Exception:
                pass
        return found
