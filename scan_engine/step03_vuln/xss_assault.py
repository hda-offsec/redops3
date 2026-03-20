import tempfile
import os
import json
import logging
from scan_engine.helpers.mutator import PayloadMutator
from scan_engine.helpers.param_expander import ParamExpander
from core.models import db, Finding
from scan_engine.helpers.process_manager import ProcessManager

class XssAssaultScanner:
    """
    Phase 4: XSS Assault.
    Combines Dalfox (Go) for speed with ParamExpander for surface discovery.
    MutationEngine is NOT used here — Phase 3 vuln already mutates seeds.
    Phase 4 consumes raw enum seeds / injection_points only.
    """
    
    def __init__(self, options=None):
        self.options = options
        self.mutator = PayloadMutator()
    
    def scan(self, target, scan_id, urls=None, logger=None, finding_callback=None):
        if logger: logger("XSS Assault: initializing...", "INFO")
        
        # 1. Gather URLs — deterministic order, deduped
        seen = set()
        target_urls = []
        for u in (urls or []):
            if u not in seen:
                target_urls.append(u)
                seen.add(u)
        if target not in seen:
            target_urls.append(target)
            seen.add(target)
        
        # 2. Expand Attack Surface (Param Expander)
        expanded_urls = ParamExpander.expand(target, attack_type="generic")
        for u in expanded_urls:
            if u not in seen:
                target_urls.append(u)
                seen.add(u)
        
        # Filter: Dalfox needs URLs with parameters
        param_urls = [u for u in target_urls if "?" in u]
        
        if not param_urls:
            if logger: logger("XSS Assault: No parameters found to fuzz.", "INFO")
            return []

        if logger: logger(f"XSS Assault: Feeding {len(param_urls)} URLs to Dalfox...", "INFO")
        
        findings = self._run_dalfox(param_urls, logger)
        
        # Report Findings
        for f in findings:
            if finding_callback:
                finding_callback(
                    title=f.get('title', 'XSS Found'),
                    description=f.get('description', ''),
                    severity=f.get('severity', 'high'),
                    tool_source="Dalfox [Assault]",
                    raw_loot=f.get('endpoint', f.get('url', ''))
                )
        
        return findings

    def _run_dalfox(self, urls, logger):
        findings = []
        
        # Create temp file for URLs
        fd, url_file = tempfile.mkstemp(suffix=".txt", prefix="redops_xss_")
        output_file = url_file + ".json"
        
        try:
            with os.fdopen(fd, 'w') as f:
                for u in urls:
                    f.write(u + "\n")
            
            dalfox_path = ProcessManager.find_binary_path("dalfox") or "dalfox"
            
            command = [
                dalfox_path, "file", url_file,
                "--format", "json",
                "-o", output_file,
                "--skip-bav",
                "--silence",
                "--no-color",
                "--worker", "40",
                "--follow-redirects",
            ]
            
            success, stdout, stderr, code = ProcessManager.run_command(command, timeout=600)
            
            # FIX #4 — Vérification tool_exit_code
            if code != 0:
                if logger: logger("external_tool_non_zero_exit_code", "DEBUG")
            
            if os.path.exists(output_file):
                 with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            vuln = json.loads(line)
                            url = vuln.get("url", "")
                            param = vuln.get("param", "unknown_param")
                            payload = vuln.get("payload", "")
                            method = vuln.get("method", "GET")
                            
                            from scan_engine.helpers.finding_normalizer import FindingNormalizer
                            findings.append(FindingNormalizer.normalize({
                                "title": f"Cross-Site Scripting (XSS) via '{param}' parameter",
                                "description": f"Dalfox successfully confirmed reflected Cross-Site Scripting (XSS) on the `{param}` parameter using `{method}`.\n\nArbitrary JavaScript can be executed in the context of the victim's browser session by tricking them into clicking a crafted link.",
                                "severity": "high",
                                "confidence": "certain",
                                "tool_source": "Dalfox [Assault]",
                                "category": "xss",
                                "endpoint": url,
                                "parameter": param,
                                "payload": payload,
                                "evidence": {
                                    "dalfox_proof": vuln.get('evidence', ''),
                                    "injection_point": vuln.get('inject_point', ''),
                                    "bav": vuln.get('bav', '')
                                },
                                "repro_command": f"curl -ik \"{url}\"",
                                "metadata": {
                                    "validation_status": "success",
                                    "technique": vuln.get('type', 'reflected'),
                                    "method": method
                                }
                            }))
                        except Exception:
                            continue
                        
        except Exception as e:
            if logger: logger(f"Dalfox Error: {e}", "ERROR")
        finally:
            if os.path.exists(url_file): os.remove(url_file)
            if os.path.exists(output_file): os.remove(output_file)
            
        return findings

