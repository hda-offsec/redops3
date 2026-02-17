import requests

class CRLFScanner:
    def __init__(self, target):
        self.target = target

    def scan_crlf(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # CRLF Injection: Try to inject a Set-Cookie header
        # Using %0d%0a (CRLF) URL encoded equivalent
        payload = "/%0d%0aSet-Cookie:crlf=injection"
        target_url = base_url + payload

        if logger: logger(f"🕸️ CRLF Audit: Probing {base_url}...", "INFO")

        try:
            r = requests.get(target_url, timeout=3, allow_redirects=False)
            
            # Check headers for our injected cookie
            for h, v in r.headers.items():
                if h.lower() == 'set-cookie' and 'crlf=injection' in v:
                    findings.append({
                        "title": "Medium: CRLF Injection Detected",
                        "description": f"Server is vulnerable to HTTP Response Splitting via CRLF injection at `{target_url}`.",
                        "severity": "medium",
                        "tool_source": "crlf_scanner",
                        "raw_loot": target_url
                    })
                    break
        except:
            pass
        return findings
