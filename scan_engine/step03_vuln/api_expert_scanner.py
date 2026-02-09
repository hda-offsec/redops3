import requests
import json

class APIExpertScanner:
    def __init__(self, target):
        self.target = target

    def audit_endpoints(self, api_endpoints, logger=None):
        """
        Analyzes discovered endpoints for high-value API assets.
        api_endpoints is a list of dicts: {'path': ..., 'status': ..., 'url': ...}
        """
        findings = []
        if not api_endpoints:
            return findings

        if logger: logger(f"API Expert: Analyzing {len(api_endpoints)} discovered endpoints for high-value assets...", "INFO")

        for ep in api_endpoints:
            path = ep['path'].lower()
            url = ep['url']
            status = int(ep['status'])

            # 1. Documentation Exposure (CRITICAL/HIGH)
            if any(x in path for x in ['swagger.json', 'openapi.json', 'api-docs']) and status == 200:
                try:
                    r = requests.get(url, timeout=5, verify=False)
                    if '"swagger":' in r.text or '"openapi":' in r.text:
                        findings.append({
                            "title": "CRITICAL: Exposed API Documentation (Swagger/OpenAPI)",
                            "description": f"The full API specification is publicly accessible at `{url}`. This reveals all endpoints, parameters, and authentication methods, drastically increasing the attack surface.",
                            "severity": "critical",
                            "tool_source": "api_expert"
                        })
                        if logger: logger(f"🔥 API BREACH: Swagger/OpenAPI spec found at {url}", "CRITICAL")
                except: pass

            # 2. Administrative/Debug Endpoints (HIGH)
            elif any(x in path for x in ['actuator', 'env', 'config', 'metrics', 'prometheus', 'health']) and status == 200:
                 findings.append({
                    "title": "High: Exposed Internal API/Metrics Endpoint",
                    "description": f"An internal administrative or monitoring endpoint was found at `{url}` (Status: {status}). This may leak environment variables, system configuration, or internal metrics.",
                    "severity": "high",
                    "tool_source": "api_expert"
                })
                 if logger: logger(f"🎯 SENSITIVE API: Found {path} at {url}", "WARN")

            # 3. Postman Collection/Env Leak (MEDIUM)
            elif "postman" in path and status == 200:
                 findings.append({
                    "title": "Medium: Exposed Postman Collection/Environment",
                    "description": f"A Postman-related file was found at `{url}`. These files often contain sample requests and sometimes hardcoded credentials.",
                    "severity": "medium",
                    "tool_source": "api_expert"
                })

        return findings
