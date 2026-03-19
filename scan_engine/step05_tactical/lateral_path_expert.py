import re
import json
from urllib.parse import urlparse

class LateralPathExpert:
    """
    Expert for identifying Lateral Movement Paths.
    Correlates findings to suggest how an attacker could pivot from one asset to another.
    """
    def __init__(self, scan_id, results_loader):
        self.scan_id = scan_id
        self.results_loader = results_loader

    def analyze(self, logger=None):
        if logger: logger("Lateral Path: Analyzing discovered assets for pivot vectors...", "INFO")
        
        results = self.results_loader(self.scan_id)
        if not results: return []

        paths = []
        findings = self._extract_findings(results)
        endpoints = self._extract_endpoints(results)

        # 1. Identity Bridges (Leaks -> Auth)
        # If we found secrets/tokens, where can they be reused?
        leaks = [f for f in findings if "secret" in f.get('title', '').lower() or "token" in f.get('title', '').lower()]
        auth_pages = [e for e in endpoints if any(x in e.lower() for x in ['login', 'signin', 'auth', 'admin'])]

        for leak in leaks:
            for auth in auth_pages:
                paths.append({
                    "title": "Lateral Path: Credential Reuse Vector",
                    "description": f"Secrets found in '{leak['title']}' might be valid on the authentication endpoint {auth}.",
                    "source": leak.get('endpoint', 'Unknown'),
                    "destination": auth,
                    "severity": "high",
                    "type": "lateral_pivot"
                })

        # 2. Infrastructure Bridges (Admin Panels -> Internal)
        admin_panels = [f for f in findings if "admin" in f.get('title', '').lower() and f.get('severity') in ['high', 'critical']]
        for admin in admin_panels:
            paths.append({
                "title": "Lateral Path: Management Pivot",
                "description": f"Compromising the admin panel at {admin.get('endpoint')} could provide a direct path into internal systems/databases.",
                "source": admin.get('endpoint'),
                "destination": "Internal Infrastructure",
                "severity": "high",
                "type": "lateral_pivot"
            })

        return paths

    def _extract_findings(self, results):
        findings = []
        # Support flattened findings in results or nested in phases
        if 'findings' in results:
            findings.extend(results['findings'])
        
        phases = results.get('phases', {})
        for phase_name, tools in phases.items():
            for tool_name, tool_data in tools.items():
                if isinstance(tool_data, dict) and 'findings' in tool_data:
                    findings.extend(tool_data['findings'])
                elif isinstance(tool_data, list):
                    # Check if items look like findings
                    for item in tool_data:
                        if isinstance(item, dict) and ('title' in item or 'severity' in item):
                            findings.append(item)
        return findings

    def _extract_endpoints(self, results):
        urls = set()
        phases = results.get('phases', {})
        for phase in ["enum", "dirbusting", "recon"]:
            data = phases.get(phase, {})
            for tool, tool_data in data.items():
                if isinstance(tool_data, dict) and "endpoints" in tool_data:
                    for ep in tool_data["endpoints"]: urls.add(ep.get("url"))
                elif isinstance(tool_data, list):
                    for item in tool_data:
                        if isinstance(item, str): urls.add(item)
                        elif isinstance(item, dict) and "url" in item: urls.add(item["url"])
        return list(urls)
