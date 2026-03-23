from scan_engine.helpers.http_client import get_session
import json
from urllib.parse import urlparse, parse_qs, urlencode

class BusinessLogicScanner:
    """
    Expert Auditor for Business Logic Flaws.
    1. Mass Assignment (Auto-binding abuse)
    2. HTTP Parameter Pollution (HPP)
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
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
                        "url": url,
                        "result_state": "validation",
                        "validation_status": "success",
                        "metadata": {
                            "validation": {
                                "status": "success",
                                "target": url,
                                "command": f"curl -ik -X POST '{url}' -H 'Content-Type: application/json' --data '{json.dumps(payload, sort_keys=True)}'",
                                "artifact": resp.text[:500],
                            },
                            "mass_assignment_field": field,
                        },
                    })
                    if logger: logger(f"CRITICAL: Mass Assignment on {field} at {url}", "CRITICAL")
            except Exception:
                pass
        return findings

    def scan_hpp(self, url, logger=None):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return []

        for param in params:
            try:
                # Baseline request
                orig = self.session.get(url, timeout=5)
                orig_status = orig.status_code
                orig_len = len(orig.content)
                
                # V10: Duplicate parameter injection
                new_url = url + f"&{param}=redops_hpp_test"
                resp = self.session.get(new_url, timeout=5)
                
                # V10 HPP Hard Gate: ALL must be true
                # H1: Test value must be reflected (server processes it)
                reflected = "redops_hpp_test" in resp.text
                # H2: Server behavior must actually change
                #     (status code change OR significant body diff)
                status_changed = resp.status_code != orig_status
                body_diff = abs(len(resp.content) - orig_len) > 100
                # H3: Access control or redirect altered
                redirect_altered = (
                    resp.status_code in [301, 302, 303, 307]
                    and resp.headers.get('Location', '') != orig.headers.get('Location', '')
                )
                
                behavior_changed = status_changed or redirect_altered or body_diff
                
                if reflected and behavior_changed:
                    findings.append({
                        "title": "HTTP Parameter Pollution (HPP)",
                        "description": (
                            f"Server processed secondary occurrence of parameter '{param}' "
                            f"AND behavior changed.\n"
                            f"Status: {orig_status} → {resp.status_code}\n"
                            f"Body delta: {abs(len(resp.content) - orig_len)}B\n"
                            f"URL: {new_url}"
                        ),
                        "severity": "medium",
                        "tool_source": "business_logic_expert",
                        "url": new_url,
                        "result_state": "validation",
                        "validation_status": "success",
                        "metadata": {
                            "validation": {
                                "status": "success",
                                "target": new_url,
                                "command": f"curl -ik '{new_url}'",
                                "artifact": resp.text[:500],
                            }
                        },
                    })
                elif reflected:
                    # V10: Reflection without behavior change → INFO
                    findings.append({
                        "title": "HTTP Parameter Reflection (Informational)",
                        "description": (
                            f"Server reflects secondary parameter '{param}' value "
                            f"but behavior is identical to baseline.\n"
                            f"No exploitable logic change detected.\n"
                            f"URL: {new_url}"
                        ),
                        "severity": "info",
                        "tool_source": "business_logic_expert",
                        "url": new_url,
                        "result_state": "observation",
                        "validation_status": "uncertain",
                    })
            except Exception:
                pass
        return findings
