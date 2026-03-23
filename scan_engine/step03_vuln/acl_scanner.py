import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class AccessControlScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def _candidate_paths(self, candidate_urls=None):
        paths = ["/admin"]
        for candidate in candidate_urls or []:
            if not isinstance(candidate, str):
                continue
            try:
                from urllib.parse import urlparse
                parsed = urlparse(candidate)
                path = parsed.path or "/"
            except Exception:
                path = str(candidate or "").strip()
            if not path.startswith("/") or path == "/":
                continue
            if path not in paths:
                paths.append(path)
        return paths[:12]

    def scan_403_bypass(self, port, protocol='http', logger=None, candidate_urls=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        protected_paths = self._candidate_paths(candidate_urls)
        if logger:
            logger(f"🚫 403 Bypass: Fuzzing ACLs on {len(protected_paths)} protected-path candidates...", "INFO")

        for protected_path in protected_paths:
            target_url = base_url + protected_path
            try:
                # Baseline
                r_base = http_client.get(target_url, options=getattr(self, "options", None), timeout=3, allow_redirects=False)
                if r_base.status_code not in [401, 403]:
                    continue
                # Attempt bypass techniques
                headers_bypass = {
                    "X-Custom-IP-Authorization": "127.0.0.1",
                    "X-Original-URL": protected_path,
                    "X-Rewrite-URL": protected_path,
                    "X-Forwarded-For": "127.0.0.1"
                }

                for h, v in headers_bypass.items():
                    try:
                        r_test = http_client.get(target_url, options=getattr(self, "options", None), headers={h: v}, timeout=3, allow_redirects=False)
                        if r_test.status_code == 200:
                            from scan_engine.helpers.finding_normalizer import FindingNormalizer
                            findings.append(FindingNormalizer.from_response(
                                r_test,
                                title="CRITICAL: 403 Bypass Successful",
                                description=f"Accessed protected resource `{protected_path}` (originally {r_base.status_code}) using header `{h}: {v}`. Status: 200 OK.",
                                severity="critical",
                                tool_source="acl_scanner",
                                category="access_control",
                                method="GET",
                                metadata={"bypass_header": f"{h}: {v}", "baseline_status": r_base.status_code}
                            ))
                            return findings
                    except Exception:
                        continue

                variations = [f"/%2e{protected_path}", f"{protected_path}/.", f"{protected_path}?", f"{protected_path};"]
                for v in variations:
                    url_var = f"{protocol}://{self.target}:{port}{v}"
                    try:
                        r_var = http_client.get(url_var, options=getattr(self, "options", None), timeout=3, allow_redirects=False)
                        if r_var.status_code == 200:
                             from scan_engine.helpers.finding_normalizer import FindingNormalizer
                             findings.append(FindingNormalizer.from_response(
                                 r_var,
                                 title="High: ACL Bypass via URL Encoding",
                                 description=f"Bypassed Access Control on `{protected_path}` using variation `{v}`. Status: 200 OK.",
                                 severity="high",
                                 tool_source="acl_scanner",
                                 category="access_control",
                                 method="GET",
                                 metadata={"variation": v, "baseline_status": r_base.status_code}
                             ))
                    except Exception:
                        continue

            except Exception:
                continue
        return findings

    # Alias for orchestrator compatibility
    def scan_acl(self, port, protocol='http', logger=None, candidate_urls=None):
        return self.scan_403_bypass(port, protocol, logger=logger, candidate_urls=candidate_urls)
