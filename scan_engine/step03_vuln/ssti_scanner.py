import requests
from urllib.parse import urljoin

class SSTIScanner:
    def __init__(self, target):
        self.target = target

    def scan_ssti(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        # Polyglot-ish payload for {{7*7}} in different engines
        # Polyglot-ish payload for {{1337*1337}} in different engines
        payloads = [
            ("{{1337*1337}}", "1787569"),
            ("${1337*1337}", "1787569"),
            ("<%= 1337*1337 %>", "1787569")
        ]
        
        # Fuzz common params
        params = ["q", "s", "search", "id", "name", "view"]

        if logger: logger(f"💉 SSTi Expert: Fuzzing {len(params)} params on {base_url}...", "INFO")

        for param in params:
            for payload, expected in payloads:
                try:
                    target_url = f"{base_url}/?{param}={payload}"
                    r = requests.get(target_url, timeout=3)
                    
                    if expected in r.text and payload not in r.text:
                        # If result is there but payload isn't (rendered) -> Vulnerable
                        findings.append({
                            "title": f"CRITICAL: SSTi Detected on param `{param}`",
                            "description": f"Server Rendered `{payload}` as `{expected}`. Confirmed Server-Side Template Injection.",
                            "severity": "critical",
                            "tool_source": "ssti_scanner",
                            "raw_loot": target_url,
                            "method": "GET",
                            "payload": payload,
                            "status_code": r.status_code,
                            "response_snippet": r.text[:200] if len(r.text) > 200 else r.text
                        })
                        if logger: logger(f"💀 SSTV RCE CONFIRMED: {target_url}", "CRITICAL")
                        return findings # Return early on confirm
                except:
                    pass
        return findings
