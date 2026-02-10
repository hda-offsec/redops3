import requests
import json
import re

class APIExpertScanner:
    def __init__(self, target):
        self.target = target

    def is_api_spec(self, content):
        """Checks if content is a valid Swagger/OpenAPI specification."""
        try:
            # Check JSON
            data = json.loads(content)
            if any(k in data for k in ["swagger", "openapi", "paths", "info"]):
                return True
        except:
            # Check for common strings in non-JSON (YAML/HTML doc)
            if any(x in content for x in ["openapi:", "swagger:", "swagger-ui", "redoc-container"]):
                return True
        return False

    def audit_endpoints(self, api_endpoints, logger=None):
        """
        Expert Logic: Analyzes discovered endpoints for security misconfigurations, 
        exposed documentation, and sensitive leakage.
        """
        findings = []
        if not api_endpoints:
            return findings

        if logger: logger(f"API Expert: Performing deep inspection on {len(api_endpoints)} potential endpoints...", "INFO")

        for ep in api_endpoints:
            path = ep['path'].lower().lstrip('/')
            url = ep['url']
            status = int(ep['status'])

            # Helper for verification
            def verify_exposure(target_url):
                try:
                    r = requests.get(target_url, timeout=5, verify=False, allow_redirects=True)
                    # If redirected to a login page or generic root, it's not a hit
                    if r.status_code == 200:
                        # Simple heuristic: if the URL changed significantly or contains login keywords
                        if any(x in r.url.lower() for x in ['login', 'signin', 'auth', 'authorize']):
                            return False, r.url, r.text
                        return True, r.url, r.text
                except: pass
                return False, None, None

            # 1. SPECIFICATION EXPOSURE (Highest Risk)
            spec_keywords = ['swagger.json', 'openapi.json', 'swagger.yaml', 'swagger.yml', 'api-docs', 'v2/api-docs', 'v3/api-docs']
            if any(x in path for x in spec_keywords):
                hit, final_url, content = verify_exposure(url)
                if hit and self.is_api_spec(content):
                    findings.append({
                        "title": "CRITICAL: Exposed API Specification",
                        "description": (
                            f"A live API specification was found at `{final_url}`.\n\n"
                            f"Impact: This document exposes the entire API design, including hidden endpoints, "
                            f"required parameters, and authentication logic. It serves as a blueprint for automated exploitation."
                        ),
                        "severity": "critical",
                        "tool_source": "api_expert"
                    })
                    if logger: logger(f"🔥 API BREACH: Valid spec found at {final_url}", "CRITICAL")

            # 2. SENSITIVE ACTUATOR / DEBUG (High Risk)
            sensitive_paths = {
                'actuator/env': 'Leaked Environment Variables (including secrets)',
                'actuator/heapdump': 'JVM Heap Dump Exposure (Critical data leak)',
                'actuator/configprops': 'Application Configuration Properties',
                'actuator/mappings': 'Endpoint Routing Mappings',
                'prometheus': 'Internal System Metrics',
                '.env': 'Plaintext Environment File',
                '.git/config': 'Git Repository Metadata (Source code leak)',
                'phpinfo': 'PHP Information Disclosure'
            }
            
            for p_match, desc in sensitive_paths.items():
                if p_match in path:
                    hit, final_url, content = verify_exposure(url)
                    if hit:
                        # Extra check for .env to avoid landing pages
                        if '.env' in p_match and ('=' not in content or '<html' in content.lower()):
                            continue
                        
                        findings.append({
                            "title": f"CRITICAL: Sensitive Endpoint `{p_match}` Exposed",
                            "description": f"The endpoint `{final_url}` is accessible and reveals: {desc}.",
                            "severity": "critical" if any(x in p_match for x in ['env', 'git', 'heapdump']) else "high",
                            "tool_source": "api_expert",
                            "raw_loot": content if len(content) < 5000 else content[:5000],
                            "loot_type": "Sensitive File" if '.env' in p_match else "Actuator Data"
                        })
                        if logger: logger(f"🎯 SENSITIVE DATA: {p_match} exposed on {final_url}", "CRITICAL")

            # 3. AUTHENTICATION GAPS (Medium/High)
            if any(x in path for x in ['login', 'auth', 'signup', 'register']) and status == 200:
                findings.append({
                    "title": "Risk: Public Auth Endpoint Discovery",
                    "description": f"An authentication endpoint was discovered at `{url}`. This should be audited for brute-force resistance and lack of MFA.",
                    "severity": "medium",
                    "tool_source": "api_expert"
                })

        return findings
