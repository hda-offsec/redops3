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

            # 1. SPECIFICATION EXPOSURE (Highest Risk)
            spec_keywords = ['swagger.json', 'openapi.json', 'swagger.yaml', 'swagger.yml', 'api-docs', 'v2/api-docs', 'v3/api-docs']
            if any(x in path for x in spec_keywords) and status == 200:
                try:
                    r = requests.get(url, timeout=5, verify=False)
                    if self.is_api_spec(r.text):
                        findings.append({
                            "title": "CRITICAL: Exposed API Specification",
                            "description": (
                                f"A live API specification was found at `{url}`.\n\n"
                                f"Impact: This document exposes the entire API design, including hidden endpoints, "
                                f"required parameters, and authentication logic. It serves as a blueprint for automated exploitation."
                            ),
                            "severity": "critical",
                            "tool_source": "api_expert"
                        })
                        if logger: logger(f"🔥 API BREACH: Valid spec found at {url}", "CRITICAL")
                except: pass

            # 2. SENSITIVE ACTUATOR / DEBUG (High Risk)
            sensitive_paths = {
                'actuator/env': 'Leaked Environment Variables (including secrets)',
                'actuator/heapdump': 'JVM Heap Dump Exposure (Critical data leak)',
                'actuator/configprops': 'Application Configuration Properties',
                'actuator/mappings': 'Endpoint Routing Mappings',
                'prometheus': 'Internal System Metrics',
                '.env': 'Plaintext Environment File',
                '.git/config': 'Git Repository Metadata (Source code leak)'
            }
            
            for p_match, desc in sensitive_paths.items():
                if p_match in path and status == 200:
                    findings.append({
                        "title": f"CRITICAL: Sensitive Debug Endpoint `{p_match}`",
                        "description": f"The endpoint `{url}` is accessible and reveals: {desc}.",
                        "severity": "critical" if 'env' in p_match or 'git' in p_match else "high",
                        "tool_source": "api_expert"
                    })
                    if logger: logger(f"🎯 SENSITIVE DATA: {p_match} exposed on {url}", "CRITICAL")

            # 3. AUTHENTICATION GAPS (Medium/High)
            if any(x in path for x in ['login', 'auth', 'signup', 'register']) and status == 200:
                # Check for "Basic" or no-auth indications
                findings.append({
                    "title": "Risk: Public Auth Endpoint Discovery",
                    "description": f"An authentication endpoint was discovered at `{url}`. This should be audited for brute-force resistance and lack of MFA.",
                    "severity": "medium",
                    "tool_source": "api_expert"
                })

        return findings
