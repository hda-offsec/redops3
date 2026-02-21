import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class AccessControlScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def scan_403_bypass(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        protected_path = "/admin" # We assume /admin is protected or doesn't exist, we test behavior
        
        target_url = base_url + protected_path
        
        if logger: logger(f"🚫 403 Bypass: Fuzzing ACLs on {target_url}...", "INFO")

        try:
            # Baseline
            r_base = http_client.get(target_url, options=getattr(self, "options", None), timeout=3, allow_redirects=False)
            if r_base.status_code in [401, 403]:
                # Attempt bypass techniques
                # 1. Headers
                headers_bypass = {
                    "X-Custom-IP-Authorization": "127.0.0.1",
                    "X-Original-URL": protected_path,
                    "X-Rewrite-URL": protected_path,
                    "X-Forwarded-For": "127.0.0.1"
                }
                
                for h, v in headers_bypass.items():
                    try:
                        # Test: Request to ROOT but with Header pointing to ADMIN
                        # Or Request to ADMIN with IP Spoof
                        r_test = http_client.get(target_url, options=getattr(self, "options", None), headers={h: v}, timeout=3, allow_redirects=False)
                        if r_test.status_code == 200:
                            findings.append({
                                "title": "CRITICAL: 403 Bypass Successful",
                                "description": f"Accessed protected resource `{protected_path}` (originally {r_base.status_code}) using header `{h}: {v}`. Status: 200 OK.",
                                "severity": "critical",
                                "tool_source": "acl_scanner",
                                "raw_loot": target_url
                            })
                            return findings # Return on first success
                    except Exception:
                        continue
                    
                # 2. URL Methods
                # /%2e/admin, /admin/., /admin?
                variations = ["/%2e/admin", "/admin/.", "/admin?", "/admin;"]
                for v in variations:
                    url_var = f"{protocol}://{self.target}:{port}{v}"
                    try:
                        r_var = http_client.get(url_var, options=getattr(self, "options", None), timeout=3, allow_redirects=False)
                        if r_var.status_code == 200:
                             findings.append({
                                "title": "High: ACL Bypass via URL Encoding",
                                "description": f"Bypassed Access Control on `{protected_path}` using variation `{v}`. Status: 200 OK.",
                                "severity": "high",
                                "tool_source": "acl_scanner",
                                "raw_loot": url_var
                            })
                    except Exception:
                        continue

        except Exception:
            pass
        return findings

    # Alias for orchestrator compatibility
    def scan_acl(self, port, protocol='http', logger=None):
        return self.scan_403_bypass(port, protocol, logger=logger)
