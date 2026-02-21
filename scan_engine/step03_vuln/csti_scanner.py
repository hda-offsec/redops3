import requests
from urllib.parse import quote

class CSTIScanner:
    """
    Expert Auditor for Client-Side Template Injection (CSTI).
    Targets: AngularJS, Vue.js, Moustache, Handlebars.
    """
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RedOps3-CSTIExpert/1.0"})
        # Simple mathematical payloads for evaluation detection
        self.payloads = {
            "angular": "{{7*7}}",        # Expected: 49
            "vue": "{{7*7}}",            # Expected: 49
            "moustouche": "{{7*7}}",    # Expected: 49
            "handlebars": "{{7*7}}"     # Expected: 49
        }

    def scan_endpoint(self, url, params, logger=None):
        findings = []
        if logger: logger(f"CSTI Expert: Auditing {url} for Client-Side Template Injection...", "INFO")

        for param in params:
            for engine, payload in self.payloads.items():
                try:
                    # Inject payload
                    attack_url = f"{url}?{param}={quote(payload)}" if "?" not in url else f"{url}&{param}={quote(payload)}"
                    resp = self.session.get(attack_url, timeout=5, verify=False)
                    
                    # Look for evaluated output "49" in the response body
                    # BUT it must NOT be the literal payload "{{7*7}}"
                    if "49" in resp.text and payload not in resp.text:
                        findings.append({
                            "title": f"Confirmed Client-Side Template Injection ({engine.upper()})",
                            "description": f"Successfully executed mathematical expression '{payload}' on client-side. The server returned '49'.\nURL: {attack_url}\nThis allows for XSS-like attacks and client-side logic manipulation.",
                            "severity": "high",
                            "tool_source": "csti_expert",
                            "url": attack_url,
                            "repro_payload": payload
                        })
                        if logger: logger(f"HIGH: CSTI found on {url} using {engine} payload", "SUCCESS")
                        break # Found for this param
                except Exception:
                    pass
        return findings
