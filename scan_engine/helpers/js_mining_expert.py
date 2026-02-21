import re
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import json
import traceback
from urllib.parse import urlparse, urljoin

class JSDeepMiningExpert:
    """
    V6 EXPERT: Performs deep extraction of secrets and endpoints from JS files.
    Specifically designed for SPAs (React, Vue, Angular).
    """
    def __init__(self, target_domain, options=None):
        self.options = options
        self.target_domain = target_domain
        self.patterns = {
            "Secret/Key": r'(?i)(?:key|token|auth|secret|access|pwd|password|passwd|credential)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{12,})["\']',
            "Firebase": r'AIza[0-9A-Za-z-_]{35}',
            "Cloud Bucket": r'(?:s3|storage|blob)\.?(?:[a-z0-9\.-]+)?\.?(?:amazonaws|google|windows|digitalocean)\.com/[a-z0-9\.-]+',
            "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            "Internal Path": r'["\']((?:/|[a-z]+://)(?:[a-z0-9_-]+/){1,}[a-z0-9_-]+)["\']',
            "GraphQL Query": r'(?i)(?:query|mutation)\s*[A-Z_]*\s*\{'
        }
        # SPA Route common patterns
        self.route_patterns = [
            r'path:["\']([^"\']+)["\']',
            r'route\(["\']([^"\']+)["\']',
            r'component\s*:\s*[a-zA-Z0-9]+'
        ]

    def _should_ignore(self, url):
        ignores = ['jquery', 'bootstrap', 'wp-includes', 'wp-content/plugins', 'google-analytics', 'tagmanager']
        return any(x in url.lower() for x in ignores)

    def extract_from_content(self, content, source_url):
        findings = {"secrets": [], "endpoints": [], "routes": []}
        
        # 1. Regex Mining
        for name, pattern in self.patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                val = match.group(1) if match.groups() else match.group(0)
                findings["secrets" if "Secret" in name or "Firebase" in name else "endpoints"].append({
                    "type": name,
                    "value": val,
                    "context": content[max(0, match.start()-40):min(len(content), match.end()+40)].replace('\n', ' ').strip()
                })

        # 2. SPA Route Mining
        for p in self.route_patterns:
            matches = re.findall(p, content)
            for m in matches:
                if len(m) > 1 and '/' in m:
                    findings["routes"].append(m)

        return findings

    def mine_endpoints(self, js_urls, logger=None):
        results = {"total_files": len(js_urls), "findings": [], "discovered_endpoints": []}
        
        processed_count = 0
        for url in js_urls:
            if self._should_ignore(url): continue
            
            try:
                if logger: logger(f"JS Expert: Mining {url}...", "DEBUG")
                resp = http_client.get(url, options=getattr(self, "options", None), timeout=10)
                if resp.status_code == 200:
                    data = self.extract_from_content(resp.text, url)
                    if data["secrets"] or data["endpoints"] or data["routes"]:
                        results["findings"].append({
                            "source": url,
                            "secrets_count": len(data["secrets"]),
                            "endpoints_count": len(data["endpoints"]),
                            "routes_count": len(data["routes"]),
                            "details": data
                        })
                        for ep in data["endpoints"]:
                            if isinstance(ep, dict): results["discovered_endpoints"].append(ep["value"])
                        for r in data["routes"]:
                            results["discovered_endpoints"].append(r)
                processed_count += 1
                if processed_count > 20: break # Budget limit for deep mining
            except Exception:
                continue

        results["discovered_endpoints"] = list(set(results["discovered_endpoints"]))
        return results
