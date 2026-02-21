import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode

class BusinessLogicScanner:
    """
    Expert Auditor for Business Logic Flaws.
    1. Mass Assignment (Auto-binding abuse)
    2. HTTP Parameter Pollution (HPP)
    """
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RedOps3-LogicExpert/1.0"})
        # Dangerous fields often vulnerable to mass assignment
        self.priv_fields = ["is_admin", "is_staff", "role", "permissions", "privilege", "superuser", "org_id", "plan_id"]

    def scan_mass_assignment(self, url, json_baseline=None, logger=None):
        findings = []
        if not json_baseline: return []

        if logger: logger(f"Logic Expert: Testing Mass Assignment on {url}...", "INFO")

        # Attack: Try to add privileged fields to a POST/PUT request
        for field in self.priv_fields:
            try:
                # Build malicious JSON
                payload = json_baseline.copy() if isinstance(json_baseline, dict) else {}
                payload[field] = True # or "admin" or 1
                
                resp = self.session.post(url, json=payload, timeout=5)
                # Success indicator: 200/204 and the field appearing in response (reflection of merged state)
                if resp.status_code in [200, 201] and f'"{field}":true' in resp.text.replace(" ", ""):
                    findings.append({
                        "title": "Mass Assignment Vulnerability",
                        "description": f"Successfully injected privileged field '{field}' into object via POST request.\nURL: {url}\nPayload: {payload}",
                        "severity": "critical",
                        "tool_source": "business_logic_expert",
                        "url": url
                    })
                    if logger: logger(f"CRITICAL: Mass Assignment on {field} at {url}", "CRITICAL")
            except Exception:
                pass
        return findings

    def scan_hpp(self, url, logger=None):
        findings = []
        # Logic: ?user=1&user=2 -> Does the server use the first, last, or both?
        # Useful for bypassing WAFs or logic checks
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return []

        for param in params:
            try:
                # Original
                orig = self.session.get(url, timeout=5)
                
                # Malicious (Double parameter)
                # new_qs = ?param=val&param=attack
                new_url = url + f"&{param}=redops_hpp_test"
                resp = self.session.get(new_url, timeout=5)
                
                if resp.status_code == 200 and "redops_hpp_test" in resp.text:
                     findings.append({
                        "title": "HTTP Parameter Pollution (HPP)",
                        "description": f"Server processed secondary occurrence of parameter '{param}'. This can be used to bypass security filters or manipulate internal logic.\nURL: {new_url}",
                        "severity": "medium",
                        "tool_source": "business_logic_expert",
                        "url": new_url
                    })
            except Exception:
                pass
        return findings
