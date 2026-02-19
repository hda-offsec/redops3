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

    def scan(self, target, scan_id, urls=None, logger=None, finding_callback=None):
        """
        Main entry point for LFI scanning.
        """
        if logger: logger(f"LFI Assault: Starting Matrix Attack on {target}", "INFO")
        
        # 1. Discover Parameters & Expand Surface
        urls_to_test = [target]
        
        # Add provided URLs (from Katana/FFUF)
        if urls:
            if logger: logger(f"LFI Assault: Ingested {len(urls)} crawled URLs", "INFO")
            urls_to_test.extend(urls)
            
        # 2. Attack Execution
            
        # 2. Attack Execution
        findings = []
        
        # We process URLs in parallel threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self._assault_url, url, logger): url for url in urls_to_test}
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

    def _assault_url(self, url, logger):
        """
        Performs the matrix attack on a single base URL.
        1. Expands params (guess LFI params).
        2. Injects payloads + mutations.
        """
        findings = []
        
        # Get injection points (existing + expanded)
        # We start with the raw URL.
        # If it has no params, we use ParamExpander to add standard LFI params.
        
        target_urls_with_points = []
        
        # 1. Existing params
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            for param in qs:
                target_urls_with_points.append((url, param))
        
        # 2. Expanded params (only if few params or aggressive mode)
        # Always try to inject 'file'/'path' if not present
        expanded_urls = ParamExpander.expand(url, attack_type="lfi")
        for e_url in expanded_urls:
            # ParamExpander puts "FUZZ" in the value. We need to identify the param name.
            e_parsed = urlparse(e_url)
            e_qs = parse_qs(e_parsed.query)
            for p, v in e_qs.items():
                if v == ['FUZZ']:
                    target_urls_with_points.append((e_url, p))

        # Remove duplicates
        target_urls_with_points = list(set(target_urls_with_points))
        
        session = requests.Session()
        session.headers.update({"User-Agent": "RedOps3-Assault/1.0"})
        
        for rule in self.lfi_rules:
            for base_payload in rule.get("payloads", []):
                # Apply mutations defined in the rule
                mutations = PayloadMutator.mutate(base_payload, rule.get("mutations"))
                
                for payload in mutations:
                    for target_url, param in target_urls_with_points:
                        # Inject payload
                        # Handle the "FUZZ" placeholder if present, otherwise replace value
                        final_url = self._inject(target_url, param, payload)
                        
                        try:
                            resp = session.get(final_url, timeout=5, verify=True)
                            if self._check_success(resp, rule):
                                findings.append({
                                    "title": f"LFI Detected ({rule['rule_id']})",
                                    "severity": "critical",
                                    "description": f"URL: {final_url}\nPayload: {payload}\nRule: {rule['description']}",
                                    "url": final_url
                                })
                                # Stop after first valid finding for this URL/Rule combo to avoid spam
                                break 
                        except requests.exceptions.RequestException:
                            pass
                            
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
