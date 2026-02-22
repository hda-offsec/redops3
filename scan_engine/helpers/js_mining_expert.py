import re
import time
import json
import traceback
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class JSDeepMiningExpert:
    """
    V7 HARDENED EXPERT: Performs deep extraction of secrets and endpoints from JS files.
    Specifically designed for SPAs (React, Vue, Angular).
    Implements mandatory state machine, global timeouts, and watchdog protection.
    """
    
    # States
    INIT = "INIT"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"

    def __init__(self, target_domain, options=None):
        self.options = options or {}
        self.target_domain = target_domain
        self.status = self.INIT
        self.start_time = None
        self.last_activity = None
        self.js_files_scanned = 0
        self.secrets_count = 0
        self.errors = []
        
        # Expert Patterns
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
            try:
                matches = re.finditer(pattern, content)
                for match in matches:
                    val = match.group(1) if match.groups() else match.group(0)
                    findings["secrets" if "Secret" in name or "Firebase" in name else "endpoints"].append({
                        "type": name,
                        "value": val,
                        "context": content[max(0, match.start()-40):min(len(content), match.end()+40)].replace('\n', ' ').strip()
                    })
            except Exception as e:
                self.errors.append(f"Regex error in {name}: {str(e)}")

        # 2. SPA Route Mining
        for p in self.route_patterns:
            try:
                matches = re.findall(p, content)
                for m in matches:
                    if isinstance(m, str) and len(m) > 1 and '/' in m:
                        findings["routes"].append(m)
            except Exception:
                pass

        return findings

    def _update_activity(self):
        self.last_activity = time.time()

    def mine_endpoints(self, js_urls, timeout=60, logger=None):
        """
        Main entry point with strict timeout and watchdog.
        Garantit que le module termine toujours.
        """
        self.start_time = time.time()
        self._update_activity()
        self.status = self.RUNNING
        self.js_files_scanned = 0
        self.secrets_count = 0
        self.errors = []
        
        # Global hard cap at 120s
        hard_cap = min(timeout, 120)
        
        results = {
            "status": self.INIT,
            "execution_time": 0,
            "js_files_scanned": 0,
            "secrets_found": 0,
            "findings": [],
            "discovered_endpoints": [],
            "errors": [],
            "confidence_score": 0.0
        }

        if logger: logger(f"JS Expert: Starting hardened scan on {len(js_urls)} files (Timeout: {hard_cap}s)", "INFO")

        try:
            for url in js_urls:
                # Watchdog Check
                elapsed = time.time() - self.start_time
                if elapsed > hard_cap:
                    self.status = self.TIMEOUT
                    if logger: logger(f"JS Expert: Global timeout reached ({hard_cap}s). Aborting.", "ERROR")
                    break

                if self._should_ignore(url): continue
                
                try:
                    self._update_activity()
                    if logger: logger(f"JS Expert: Mining {url}...", "DEBUG")
                    
                    # http_client already has internal timeout, but we wrap it
                    resp = http_client.get(url, options=self.options, timeout=10)
                    
                    if resp.status_code == 200:
                        data = self.extract_from_content(resp.text, url)
                        if data["secrets"] or data["endpoints"] or data["routes"]:
                            self.secrets_count += len(data["secrets"])
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
                                
                        self.js_files_scanned += 1
                        
                    # Budget limit to avoid blocking too long even if within timeout
                    if self.js_files_scanned >= 50: 
                        if logger: logger("JS Expert: Reached maximum file budget (50).", "WARN")
                        break
                        
                except Exception as ex:
                    self.errors.append(f"Error scanning {url}: {str(ex)}")
                    continue

            if self.status != self.TIMEOUT:
                self.status = self.COMPLETED

        except Exception as e:
            self.status = self.FAILED
            self.errors.append(f"Global expert failure: {str(e)}")
            if logger: logger(f"JS Expert Critical Error: {traceback.format_exc()}", "ERROR")

        # Finalize Results
        total_time = time.time() - self.start_time
        results.update({
            "status": self.status,
            "execution_time": round(total_time, 2),
            "js_files_scanned": self.js_files_scanned,
            "secrets_found": self.secrets_count,
            "errors": self.errors,
            "confidence_score": 0.9 if self.status == self.COMPLETED else 0.5
        })
        
        results["discovered_endpoints"] = list(set(results["discovered_endpoints"]))
        
        if logger: logger(f"JS Expert finished with status: {self.status} in {results['execution_time']}s", "SUCCESS" if self.status == self.COMPLETED else "WARN")
        
        return results
