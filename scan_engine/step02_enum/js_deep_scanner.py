import re
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JSDeepScanner:
    def __init__(self, target):
        self.target = target
        
        # 1. Secret Patterns (Based on TruffleHog / GitLeaks / RedOps legacy)
        self.secret_patterns = {
            "Generic API Key": r'(?i)(api[_-]?key|api[_-]?token|auth[_-]?token|secret[_-]?key|access[_-]?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
            "Google API": r'AIza[0-9A-Za-z-_]{35}',
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret": r'(?i)aws[_-]?secret[_-]?key["\']\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
            "Slack Token": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
            "Stripe Key": r'(?:r|s)k_live_[0-9a-zA-Z]{24}',
            "Twilio": r'SK[0-9a-fA-F]{32}',
            "GitHub PAT": r'ghp_[a-zA-Z0-9]{36}',
            "Private Key": r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
            "JWT Token": r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        }

        # 2. Endpoint Patterns (Based on LinkFinder / xnLinkFinder)
        # Catches relative paths, API endpoints, etc.
        self.endpoint_regex = r"""
          (?:"|')                               # Start quote
          (
            ((?:[a-zA-Z]{1,10}://|//)           # Absolute URLs (http://...)
            [^"'/]{1,}\.                        # Domain
            [a-zA-Z]{2,}                        # TLD
            [^"']{0,})                          # Rest of URL
            |
            ((?:/|\.\./|\./)                    # Relative paths starting with / or ../ or ./
            [^"'><,;| *()(%%$^/\\\[\]]          # No invalid chars
            [^"'><,;|()]{1,})                   # Rest of path
            |
            ([a-zA-Z0-9_\-/]{1,}/               # Path like foo/bar
            [a-zA-Z0-9_\-/]{1,}                 # bar
            \.(?:[a-zA-Z]{1,4}|action)          # Extension or action
            (?:[\?|#][^"|']{0,}|))              # Query params
          )
          (?:"|')                               # End quote
        """
        self.compiled_endpoint_re = re.compile(self.endpoint_regex, re.VERBOSE)

    def scan_url(self, url, logger=None):
        results = {"secrets": [], "endpoints": [], "raw_size": 0}
        try:
            r = requests.get(url, timeout=10, verify=True)
            if r.status_code != 200:
                return results
                
            content = r.text
            results["raw_size"] = len(content)

            # A. Find Secrets
            for name, pattern in self.secret_patterns.items():
                for match in re.finditer(pattern, content):
                    full_match = match.group(0)
                    snip = content[max(0, match.start()-20):min(len(content), match.end()+20)].replace("\n", " ").strip()
                    results["secrets"].append({
                        "type": name,
                        "match": full_match[:50] + "..." if len(full_match) > 50 else full_match,
                        "secret": full_match, # Full secret for analysis
                        "context": snip
                    })
            
            # B. Find Endpoints
            # Use regex to find potential paths
            found = self.compiled_endpoint_re.findall(content)
            
            # The regex returns tuples because of groups. We flatten and filter.
            # Group 0 is the full match usually, but here we have alternatives.
            # Actually findall returns tuples of groups.
            # We explicitly want the full capture of the "OR" chunks.
            
            cleaned_endpoints = set()
            for group in found:
                # filter empty groups
                match_str = next((g for g in group if g), None)
                if match_str:
                    # Filter junk
                    if len(match_str) < 4: continue
                    if any(x in match_str for x in ["text/javascript", "application/", "<", ">", "function("]): continue
                    
                    # Heuristics for "good" endpoints
                    if any(x in match_str for x in ["/", "http", "api", ".php", ".json"]):
                        cleaned_endpoints.add(match_str)

            results["endpoints"] = list(cleaned_endpoints)
            
        except Exception as e:
            if logger: logger(f"JS Scan Error ({url}): {e}", "DEBUG")
            
        return results

    def scan_list(self, urls, logger=None):
        """
        Main entry point for scanning a list of JS URLs
        """
        aggregated = {
            "secrets": [],
            "endpoints": [],
            "processed_urls": []
        }
        
        # Filter duplicates and ensure JS extension (soft check)
        target_urls = list(set([u for u in urls if u and "jquery" not in u.lower()])) # Skip jquery broadly
        
        if logger: logger(f"JS Deep Scan: Analyzing {len(target_urls)} unique JS files...", "INFO")
        
        for url in target_urls:
            res = self.scan_url(url, logger)
            if res["raw_size"] > 0:
                aggregated["processed_urls"].append(url)
            
            if res["secrets"]:
                for s in res["secrets"]:
                    s["source"] = url
                    aggregated["secrets"].append(s)
                    
            if res["endpoints"]:
                for ep in res["endpoints"]:
                    # Relative to absolute conversion could happen here but we keep raw for now
                    aggregated["endpoints"].append({"url": ep, "source": url})

        return aggregated
