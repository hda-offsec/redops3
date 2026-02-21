import requests
from urllib.parse import urljoin

class PrototypePollutionScanner:
    """
    V6 EXPERT: Advanced Prototype Pollution Auditor.
    Scans for client-side and server-side object prototype injections.
    """
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-PP-Expert)"})

    def scan_prototype(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # Payloads for both Server-Side (Node.js) and Client-Side detection
        # We look for behavioral changes or reflection
        payloads = [
            {"p": "__proto__[redops_pp]=true", "key": "redops_pp"},
            {"p": "constructor.prototype.redops_pp=true", "key": "redops_pp"},
            {"p": "__proto__%5Bpolluted%5D=polluted", "key": "polluted"},
        ]

        if logger: logger(f"🧬 Prototype Expert: Auditing {base_url} for object injections...", "INFO")

        # 1. Parameter Pollution Check
        params = ["q", "id", "data", "config", "settings", "options"]
        
        for param in params:
            for item in payloads:
                payload = item["p"]
                try:
                    # Test via Query String
                    target_url = f"{base_url}/?{param}[{payload}]"
                    r = self.session.get(target_url, timeout=3, verify=False)
                    
                    # Heuristic: If we send a PP payload and the server starts behaving differently
                    # or reflects the key-value in a way that suggests object merger.
                    # Real PP detection is better with JS execution, but we check for "object" reflections.
                    if r.status_code == 500:
                        # Some servers crash when prototype is polluted with junk
                        findings.append({
                            "title": "Low: Potential Prototype Pollution (Behavioral)",
                            "description": f"Server returned 500 error when receiving PP payload on `{param}`: `{payload}`. This might indicate a server-side crash during object merger.",
                            "severity": "low",
                            "tool_source": "prototype_expert",
                            "url": target_url
                        })
                except Exception: pass

        # 2. JSON Body Pollution (Common in APIs)
        try:
            target_url = f"{base_url}/"
            # Attempt to pollute via JSON if endpoint accepts it
            json_payload = {"__proto__": {"redops_json_pp": "true"}}
            r = self.session.post(target_url, json=json_payload, timeout=3, verify=False)
            if r.status_code == 200 and "redops_json_pp" in r.text:
                 findings.append({
                    "title": "High: Server-Side Prototype Pollution (JSON Injection)",
                    "description": f"The server reflected the injected prototype key in the response. This strongly suggests a vulnerable object merger (e.g., `lodash.merge` or `extend`).",
                    "severity": "high",
                    "tool_source": "prototype_expert",
                    "url": target_url
                })
        except Exception: pass

        return findings
