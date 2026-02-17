import requests
from urllib.parse import urljoin

class PrototypePollutionScanner:
    def __init__(self, target):
        self.target = target

    def scan_prototype(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        payloads = [
            "__proto__[vulnerable]=true",
            "constructor[prototype][vulnerable]=true"
        ]

        if logger: logger(f"🧬 Prototype Logic: Probing {base_url}...", "INFO")

        try:
            # Simple check: Does reflected parameter appear specifically in context?
            # Real PP detection is Client-Side (Puppeteer), but we can check for
            # specific server-side reflections or known vulnerable query handling.
            # Here we check if the server accepts the payload without error (blind) 
            # or reflects it directly.
            
            for payload in payloads:
                target_url = f"{base_url}/?{payload}"
                r = requests.get(target_url, timeout=3, allow_redirects=False)
                
                # If we get a 500, it MIGHT look like the server struggled with the object injection
                if r.status_code == 500:
                     findings.append({
                        "title": "Low: Potential Server-Side Prototype Pollution",
                        "description": f"Server returned 500 Error when receiving PP payload: `{payload}`. This warrants manual investigation.",
                        "severity": "low",
                        "tool_source": "prototype_scanner",
                        "raw_loot": target_url
                    })
        except:
            pass
            
        return findings
