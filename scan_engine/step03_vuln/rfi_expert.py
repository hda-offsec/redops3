import json
import os
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.http_client import get_session
from scan_engine.helpers.mutator import PayloadMutator
from scan_engine.helpers.param_expander import ParamExpander

class RFIExpert:
    """
    Wave 5: Remote File Inclusion (RFI) Expert.
    Focuses on detecting and verifying RFI vulnerabilities with a focus on bypasses.
    """
    
    def __init__(self, options=None):
        self.options = options or {}
        self.waf_matrix_path = "data/kb/waf_matrix.json"
        
        # Load WAF Matrix
        if os.path.exists(self.waf_matrix_path):
            with open(self.waf_matrix_path, "r") as f:
                self.matrix = json.load(f)
        else:
            self.matrix = []
            
        # Filter matrix for RFI rules
        self.rfi_rules = [r for r in self.matrix if "rfi" in r.get("tags", [])]

    def scan(self, target, scan_id, urls=None, logger=None, quick=False):
        """
        Scans for RFI on prioritized endpoints.
        """
        if logger: logger(f"RFI Expert: Starting audit on {target}", "INFO")
        
        urls_to_test = [target]
        if urls:
            # Prioritize URLs with query parameters
            urls = sorted(urls, key=lambda x: len(urlparse(x).query) > 0, reverse=True)
            if quick:
                urls = urls[:10]
            else:
                if logger: logger(f"RFI Expert: (Exhaustive) Ingested {len(urls)} prioritized URLs", "INFO")
            urls_to_test.extend(urls)

        findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self._audit_url, url, logger, quick): url for url in urls_to_test}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    res = future.result()
                    if res: findings.extend(res)
                except Exception as e:
                    if logger: logger(f"RFI Expert Error on {future_to_url[future]}: {e}", "DEBUG")

        if logger: logger(f"RFI Expert: Finished. Found {len(findings)} confirmed issues.", "SUCCESS")
        return findings

    def _audit_url(self, url, logger, quick=False):
        findings = []
        points = []
        
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for p in qs: points.append((url, p))
        
        # Expand surface if no points found
        if not points or not quick:
            expanded = ParamExpander.expand(url, attack_type="lfi") # LFI expansion usually covers interesting params for RFI too
            for e_url in expanded:
                e_qs = parse_qs(urlparse(e_url).query)
                for p, v in e_qs.items():
                    if v == ['FUZZ']: points.append((e_url, p))
        
        points = list(set(points))
        if quick:
            points = points[:5]
        
        session = get_session(self.options)
        
        # 0. Baseline Analysis (Hardening)
        try:
            baseline_resp = session.get(url, timeout=5, verify=False)
            baseline_text = baseline_resp.text if baseline_resp.status_code == 200 else ""
        except:
            baseline_text = ""

        for rule in self.rfi_rules:
            payloads = rule.get("payloads", [])
            if quick: payloads = payloads[:2]
            
            for base_payload in payloads:
                mutations = PayloadMutator.mutate(base_payload, rule.get("mutations", ["original"]))
                for payload in mutations:
                    for t_url, param in points:
                        final_url = self._inject(t_url, param, payload)
                        try:
                            resp = session.get(final_url, timeout=5, verify=False)
                            if self._check_success(resp, rule, baseline_text, payload):
                                f = {
                                    "title": "Remote File Inclusion (RFI) Confirmed",
                                    "severity": "critical",
                                    "confidence": "certain",
                                    "description": f"Confirmed Remote File Inclusion via external payload inclusion.\nURL: {final_url}\nPayload: {payload}\nRule: {rule['rule_id']}",
                                    "remediation": "Disable 'allow_url_include' in php.ini and use strictly defined allow-lists for file inclusion logic.",
                                    "risk_scorecard": {"impact": "Critical", "complexity": "Low", "likelihood": "Medium"},
                                    "repro_command": f"curl -i '{final_url}'",
                                    "request": f"GET {final_url} HTTP/1.1\nHost: {urlparse(t_url).netloc}",
                                    "response": f"HTTP/1.1 {resp.status_code}\n\n{resp.text[:500]}",
                                    "metadata": {"validation_status": "confirmed_active"}
                                }
                                findings.append(f)
                                return findings # Found one for this URL, move on
                        except: pass
        return findings

    def _inject(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def _check_success(self, resp, rule, baseline_text="", payload=""):
        if resp.status_code != 200: return False
        keywords = rule.get("match_keywords", [])
        content = resp.text
        for kw in keywords:
            # 1. Keyword must be present
            # 2. Keyword must NOT be in baseline
            # 3. Keyword must NOT be part of the reflected payload URL (to avoid reflection FP)
            if kw in content and kw not in baseline_text:
                if kw not in payload:
                    return True
        return False
