from scan_engine.helpers.http_client import get_session

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

    def __init__(self, target, options=None):
        self.target = target
        self.options = options
        self.session = get_session(self.options)

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
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [401, 403]:
                    protected_paths.append((path, r.status_code, len(r.content)))
            except Exception:
                continue

        if not protected_paths:
            if logger: logger(f"WAF Bypass: No protected paths (401/403) found on port {port}. Nothing to bypass.", "DEBUG")
            return findings  # V10: No protected path → no bypass possible

        # 2. Bypass Probing
        for path, orig_status, orig_len in protected_paths:
            url = base_url + path
            for header in self.BYPASS_HEADERS:
                for val in self.BYPASS_VALUES:
                    try:
                        headers = {header: val}
                        r = self.session.get(url, headers=headers, timeout=5, allow_redirects=False)
                        
                        # Detection Logic: 
                        # - Critical: Transition from 403/401 to 200
                        # - Medium: Massive content length change on 200 (still risky, better evidence needed)
                        is_bypass = False
                        sev = "info"
                        
                        if orig_status in [401, 403] and r.status_code == 200:
                            is_bypass = True
                            sev = "critical"
                        # V10: Content-length diff on 200→200 is NOT a bypass
                        # Only status code transitions from restricted to accessible count

                        if is_bypass:
                            if logger: logger(f"🚩 WAF BYPASS DETECTED ({sev.upper()}): {url} via {header}: {val}", "SUCCESS")
                            
                            # Build detailed request/response evidence
                            req_dump = f"GET {url} HTTP/1.1\n"
                            req_dump += f"Host: {self.target}\n"
                            req_dump += f"{header}: {val}\n"
                            
                            res_dump = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                            for k, v in r.headers.items():
                                res_dump += f"{k}: {v}\n"
                            res_dump += f"\n{r.text[:2000]}..." # Snippet

                            findings.append({
                                "title": f"{sev.capitalize()}: WAF/ACL Bypass via HTTP Header",
                                "description": (
                                    f"Potential access control bypass on `{url}` using the `{header}` header.\n"
                                    f"Original Status: {orig_status} ({orig_len} bytes)\n"
                                    f"Bypass Status: {r.status_code} ({len(r.content)} bytes)\n\n"
                                    f"**Validation Evidence**:\n"
                                    f"- Header `{header}: {val}` caused the server to respond differently.\n"
                                    f"- This often indicates the server trusts this header for internal IP validation or virtual host routing."
                                ),
                                "severity": sev,
                                "tool_source": "waf_bypass_expert",
                                "url": url,
                                "request": req_dump,
                                "response": res_dump,
                                "repro_command": f"curl -v -H '{header}: {val}' '{url}'"
                            })
                            break # Found one for this path
                    except Exception:
                        continue
        
        return findings
