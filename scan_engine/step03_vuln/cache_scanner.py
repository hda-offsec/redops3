import requests
import time
import random

class CacheExpertScanner:
    """
    Expert Auditor for Web Cache vulnerabilities.
    1. Web Cache Poisoning (Unkeyed header injection)
    2. Web Cache Deception (Static extension path confusion)
    """
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.unkeyed_headers = [
            "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", 
            "X-Rewrite-URL", "X-Host", "X-Forwarded-Proto"
        ]

    def scan_cache_poisoning(self, url, logger=None):
        findings = []
        if logger: logger(f"Cache Expert: Testing poisoning on {url}...", "INFO")

        # 1. Identify unkeyed headers reflected in response
        canary = f"redops-poison-{random.randint(1000, 9999)}"
        for header in self.unkeyed_headers:
            try:
                # Add a cache buster to ensure we get a fresh miss initially
                buster = f"?cb={random.randint(1, 1000000)}"
                test_url = url + buster if "?" not in url else url + "&cb=" + str(random.randint(1, 1000000))
                
                resp = self.session.get(test_url, headers={header: canary}, timeout=5)
                
                # Check for reflection
                if canary in resp.text:
                    # Check if the response is cached? (Look for X-Cache: HIT or Age header)
                    is_cached = any(h in resp.headers for h in ["X-Cache", "CF-Cache-Status", "Age", "Cache-Control"])
                    
                    if is_cached:
                        # Verify poisoning: request AGAIN WITHOUT the header
                        # Must wait a tiny bit or just send again
                        resp2 = self.session.get(test_url, timeout=5)
                        if canary in resp2.text:
                            findings.append({
                                "title": "Web Cache Poisoning Confirmed",
                                "description": f"Successfully poisoned cache at {url} using unkeyed header: {header}\nReflection observed: {canary}",
                                "severity": "critical",
                                "tool_source": "cache_expert",
                                "url": url
                            })
                            if logger: logger(f"CRITICAL: Web Cache Poisoning on {url} via {header}", "CRITICAL")
                            break # Found a hit
            except Exception:
                pass
        return findings

    def scan_cache_deception(self, url, logger=None):
        findings = []
        # Logic: /profile.jpg (if it returns user data and is cached)
        if "/api/" in url or "/profile" in url or "/account" in url:
            try:
                # Append a fake static extension
                deception_url = url + "/test.css" if url.endswith('/') else url + ".css"
                resp = self.session.get(deception_url, timeout=5)
                
                # If it returns 200 OK and looks like JSON/sensitive content
                if resp.status_code == 200 and ("application/json" in resp.headers.get("Content-Type", "") or "{" in resp.text[:10]):
                    # Check if it's cached
                    val_cache = resp.headers.get("X-Cache", "").upper()
                    if "HIT" in val_cache or resp.headers.get("Age"):
                         findings.append({
                            "title": "Web Cache Deception Potential",
                            "description": f"Sensitive data returned at extension-cloaked URL: {deception_url}\nThe response is being cached by the server/CDN, potentially exposing private data.",
                            "severity": "high",
                            "tool_source": "cache_expert",
                            "url": deception_url
                        })
            except Exception:
                pass
        return findings
