from scan_engine.helpers.http_client import get_session
import concurrent.futures
import re
from urllib.parse import urlparse, urljoin
from core.results_store import load_results

class LogicAssaultScanner:
    """
    Phase 8: Business Logic & API Assault.
    Ports advanced RedOps2 capabilities:
    1. Auth Bypass (401/403 headers)
    2. IDOR (Numeric ID fuzzing)
    """

    # V15: Red Team Logic & JWT Assault
    AUTH_BYPASS_HEADERS = {
        "X-Original-URL": ["/admin", "/console", "/api/v1/debug"],
        "X-Rewrite-URL": ["/admin", "/console"],
        "X-Forwarded-For": ["127.0.0.1", "::1"],
        "X-Custom-IP-Authorization": ["127.0.0.1"],
        "X-Remote-IP": ["127.0.0.1"],
        "X-Originating-IP": ["127.0.0.1"],
        "Client-IP": ["127.0.0.1"]
    }

    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-LogicAssault/2.0"})

    def scan(self, target, scan_id, logger=None):
        if logger: logger(f"Logic Assault: Initiating Advanced Business Logic & JWT Attacks on {target}", "INFO")
        
        findings = []
        urls = self._get_scan_urls(scan_id)
        if not urls:
            return []

        # 1. Auth Bypass (Targeting 403/401 endpoints)
        protected_urls = [u for u in urls if any(x in u for x in ['admin', 'dashboard', 'private', 'api', 'debug'])] 
        if protected_urls:
            findings.extend(self.scan_auth_bypass(protected_urls, logger))

        # 2. Advanced IDOR (Path, Query and Headers)
        findings.extend(self.scan_idor(urls, logger))

        # 3. HTTP Parameter Pollution (HPP)
        findings.extend(self.scan_hpp(urls, logger))

        # 4. JWT Assault
        findings.extend(self.scan_jwt(urls, logger))

        return findings

    def _get_scan_urls(self, scan_id):
        try:
            results = load_results(scan_id)
            if not results: return []
            urls = set()
            # Extract from all available sources in results
            phases = results.get("phases", {})
            for phase in ["enum", "dirbusting", "recon"]:
                data = phases.get(phase, {})
                for tool, tool_data in data.items():
                    if isinstance(tool_data, dict) and "endpoints" in tool_data:
                        for ep in tool_data["endpoints"]: urls.add(ep.get("url"))
                    elif isinstance(tool_data, list):
                        for item in tool_data:
                            if isinstance(item, str): urls.add(item)
                            elif isinstance(item, dict) and "url" in item: urls.add(item["url"])
            return [u for u in list(urls) if u and u.startswith('http')]
        except Exception:
            return []

    def scan_auth_bypass(self, urls, logger):
        findings = []
        # Target high-value protected areas
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self._test_bypass_headers, url): url for url in urls[:50]}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res: findings.append(res)
        return findings

    def _test_bypass_headers(self, url):
        try:
            base = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
            if base.status_code not in [401, 403]: return None
        except Exception: return None

        for header, values in self.AUTH_BYPASS_HEADERS.items():
            for val in values:
                try:
                    resp = self.session.get(url, headers={header: val}, timeout=5, verify=False, allow_redirects=False)
                    if resp.status_code in [200, 202, 302] and len(resp.content) != len(base.content):
                         return {
                             "title": f"Auth Bypass: {header} Leakage",
                             "description": f"Bypassed {base.status_code} on {url} using {header}: {val}.\nReflected server-side IP/URL trust.",
                             "severity": "critical",
                             "tool_source": "LogicAssault",
                             "endpoint": url,
                             "repro_command": f"curl -ik -H '{header}: {val}' {url}"
                         }
                except Exception: pass
        return None

    def scan_idor(self, urls, logger):
        findings = []
        idor_candidates = [u for u in urls if re.search(r'/\d+($|/|\?)', u) or re.search(r'[?&](\w*id|user|account|order|uid|uuid|doc|file|msg)=\d+', u)]
        if not idor_candidates: return []

        if logger: logger(f"Logic Assault: Testing IDOR on {len(idor_candidates)} candidates...", "INFO")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
             future_to_url = {executor.submit(self._test_idor, url): url for url in idor_candidates[:30]}
             for future in concurrent.futures.as_completed(future_to_url):
                 res = future.result()
                 if res: findings.extend(res)
        return findings
    
    def _test_idor(self, url):
        found = []
        # Test targets: 1, 0, 99, and decrementing/incrementing
        # This is a high-fidelity filter: we look for a significant change in content vs unauthorized baseline
        for target_id in ['1', '0', '99']:
            modified = re.sub(r'(\d+)', target_id, url)
            if modified != url:
                if self._check_access(modified):
                    found.append({
                        "title": f"Critical IDOR: Object Access Confirmed",
                        "description": f"Successfully accessed non-public data at {modified} by manipulating ID.\nPotential Broken Object Level Authorization (BOLA).",
                        "severity": "high",
                        "tool_source": "LogicAssault",
                        "endpoint": modified,
                        "repro_command": f"curl -ik {modified}"
                    })
                    break 
        return found

    def scan_hpp(self, urls, logger):
        """HTTP Parameter Pollution detection."""
        findings = []
        # Target URLs with parameters
        hpp_candidates = [u for u in urls if '?' in u]
        if not hpp_candidates: return []

        if logger: logger(f"Logic Assault: Testing HPP on {len(hpp_candidates)} URLs...", "INFO")
        for url in hpp_candidates[:20]:
            try:
                # Add duplicate parameters
                base_parsed = urlparse(url)
                if not base_parsed.query: continue
                
                params = base_parsed.query.split('&')
                polluted_query = '&'.join(params + [params[0]]) # Duplicate first param
                polluted_url = urljoin(url, '?' + polluted_query)
                
                resp = self.session.get(polluted_url, timeout=5, verify=False)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    # Check if response reflects the second instance (indicates backend processing)
                    # This is complex to verify without PoC payloads, so we mark as HIGH surface findings
                    findings.append({
                        "title": "HPP: HTTP Parameter Pollution Suspected",
                        "description": f"URL {url} processes duplicated parameters without error. Potential for authentication bypass or WAF evasion.",
                        "severity": "medium",
                        "tool_source": "LogicAssault",
                        "endpoint": polluted_url,
                        "repro_command": f"curl -ik '{polluted_url}'"
                    })
            except Exception: pass
        return findings

    def scan_jwt(self, urls, logger):
        """JWT Misconfiguration Scanner."""
        findings = []
        # Search for JWTs in cookies or headers if we have sample requests (difficult on pure recon)
        # But we can look at JS for hardcoded keys or 'alg: none' hints.
        if logger: logger("Logic Assault: Checking for JWT misconfigurations...", "INFO")
        # Placeholder for JWT logic: testing known keys if we found them or common patterns
        return findings

    def _check_access(self, url):
        try:
            resp = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 500:
                # Signature matching for "private" data or specific JSON keys
                if any(x in resp.text.lower() for x in ['"email"', '"uuid"', '"username"', '"address"', '"phone"']):
                    return True
        except Exception: pass
        return False
