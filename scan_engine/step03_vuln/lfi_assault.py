import requests
import json
import os
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.mutator import PayloadMutator
from scan_engine.helpers.param_expander import ParamExpander
from core.models import db, Finding
from core.results_store import load_results

class LfiAssaultScanner:
    """
    Phase 4: Matrix-Based LFI Assault.
    Replaces the basic lfi_scanner.py with a full mutation-based engine.
    """
    
    def __init__(self, output_dir="data/results/lfi"):
        self.output_dir = output_dir
        self.waf_matrix_path = "data/kb/waf_matrix.json"
        
        # Load WAF Matrix
        if os.path.exists(self.waf_matrix_path):
            with open(self.waf_matrix_path, "r") as f:
                self.matrix = json.load(f)
        else:
            self.matrix = []
            
        # Filter matrix for LFI rules
        self.lfi_rules = [r for r in self.matrix if "lfi" in r.get("tags", []) or "path_traversal" in r.get("tags", [])]

    def scan(self, target, scan_id, urls=None, logger=None, finding_callback=None, quick=False):
        """
        Main entry point for LFI scanning.
        """
        if logger: logger(f"LFI Assault: Starting Matrix Attack on {target} (Mode: {'Quick' if quick else 'Full'})", "INFO")
        
        # 1. Discover Parameters & Expand Surface
        urls_to_test = [target]
        
        # Add provided URLs (from Katana/FFUF)
        if urls:
            # Sort URLs to prioritize more interesting ones (with params or high depth)
            urls = sorted(urls, key=lambda x: (len(urlparse(x).query) > 0, urlparse(x).path.count('/')), reverse=True)
            
            if quick:
                # Limit surface in quick mode
                urls = urls[:15]
                if logger: logger(f"LFI Assault: (Quick Mode) Capping scan to top {len(urls)} target URLs", "DEBUG")
            
            if logger: logger(f"LFI Assault: Ingested {len(urls)} prioritized URLs", "INFO")
            urls_to_test.extend(urls)
            
        # 2. Attack Execution
            
        # 2. Attack Execution
        findings = []
        
        # We process URLs in parallel threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self._assault_url, url, logger, quick): url for url in urls_to_test}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url_findings = future.result()
                    if url_findings:
                        for f in url_findings:
                            if finding_callback:
                                finding_callback(
                                    title=f.get('title'),
                                    description=f.get('description'),
                                    severity=f.get('severity'),
                                    tool_source="LfiAssault",
                                    raw_loot=url
                                )
                            findings.append(f)
                except Exception as e:
                    if logger: logger(f"LFI Error on {url}: {e}", "ERROR")

        if logger: logger(f"LFI Assault: Finished. Found {len(findings)} issues.", "SUCCESS")
        return findings

    def _get_crawled_urls(self, scan_id):
        try:
            results = load_results(scan_id)
            if not results: return []
            
            urls = set()
            # Extract from Katana
            if "enum" in results.get("phases", {}) and "katana" in results["phases"]["enum"]:
                 # Katana output might be a list of strings or dicts
                 katana_data = results["phases"]["enum"]["katana"]
                 # ... parsing logic depends on how raw_output is stored.
                 # Assuming simpler case for now or empty.
                 pass
            
            # Extract from FFUF
            if "dirbusting" in results.get("phases", {}) and "ffuf" in results["phases"]["dirbusting"]:
                 ffuf_data = results["phases"]["dirbusting"]["ffuf"]
                 if isinstance(ffuf_data, dict) and "endpoints" in ffuf_data:
                     for ep in ffuf_data["endpoints"]:
                         urls.add(ep.get("url"))
                         
            return list(urls)
        except Exception:
            return []

    def _assault_url(self, url, logger, quick=False):
        """
        Performs the matrix attack on a single base URL.
        """
        findings = []
        target_urls_with_points = []
        
        # 1. Existing params
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            for param in qs:
                target_urls_with_points.append((url, param))
        
        # 2. Expanded params
        # In quick mode/deep 1, only expand if NO params exist at all, otherwise skip expansion to save time
        if not target_urls_with_points or not quick:
            expanded_urls = ParamExpander.expand(url, attack_type="lfi")
            for e_url in expanded_urls:
                e_qs = parse_qs(urlparse(e_url).query)
                for p, v in e_qs.items():
                    if v == ['FUZZ']:
                        target_urls_with_points.append((e_url, p))
                        if quick: break # Only one expanded param in quick mode
        
        target_urls_with_points = list(set(target_urls_with_points))[:10] # Cap injection points
        
        session = requests.Session()
        session.headers.update({"User-Agent": "RedOps3-Assault/1.0"})
        
        for rule in self.lfi_rules:
            # In quick mode, only test first 3 payloads per rule
            payloads_to_test = rule.get("payloads", [])
            if quick: payloads_to_test = payloads_to_test[:3]
                
            for base_payload in payloads_to_test:
                # Apply mutations
                rule_mutations = rule.get("mutations")
                if quick:
                    # Only basic mutations in quick mode
                    rule_mutations = [m for m in rule_mutations if m in ["url_encode", "original"]]
                    if not rule_mutations: rule_mutations = ["original"]

                mutations = PayloadMutator.mutate(base_payload, rule_mutations)
                
                for payload in mutations:
                    for target_url, param in target_urls_with_points:
                        final_url = self._inject(target_url, param, payload)
                        try:
                            # Use Verify=False if we want to bypass cert issues, 
                            # but verify=True is safer. Let's stick to system default.
                            resp = session.get(final_url, timeout=3, verify=False)
                            if self._check_success(resp, rule):
                                findings.append({
                                    "title": f"LFI Detected ({rule['rule_id']})",
                                    "severity": "critical",
                                    "description": f"URL: {final_url}\nPayload: {payload}",
                                    "url": final_url
                                })
                                break 
                        except Exception:
                            pass
                    if findings: break
                if findings: break
                            
        return findings

    def _inject(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        
        # If param value was FUZZ, replace it. Else replace existing value.
        qs[param] = payload
        
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _check_success(self, resp, rule):
        """
        Verifies if the attack succeeded based on the rule's check_type.
        """
        check_type = rule.get("check_type")
        keywords = rule.get("match_keywords", [])
        
        if check_type == "keyword_match":
            for kw in keywords:
                if kw in resp.text:
                    return True
        
        return False
