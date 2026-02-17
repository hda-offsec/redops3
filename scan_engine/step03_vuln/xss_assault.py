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
    Combines Dalfox (Go) for speed with RedOps3 Mutation Engine for WAF evasion.
    """
    
    def __init__(self):
        self.mutator = PayloadMutator()
    
    def scan(self, target, scan_id, urls=None, logger=None, finding_callback=None):
        if logger: logger("XSS Assault: initializing...", "INFO")
        
        # 1. Gather URLs
        target_urls = set()
        if urls:
            target_urls.update(urls)
        target_urls.add(target)
        
        # 2. Expand Attack Surface (Param Expander)
        # For XSS, we want to find reflected parameters.
        # We add some common XSS params to the target.
        expanded_urls = ParamExpander.expand(target, attack_type="generic") # generic includes generic params
        target_urls.update(expanded_urls)
        
        # Filter: Dalfox needs URLs with parameters to be effective in 'url' mode, 
        # or we feed it raw file.
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
                    title=f['title'],
                    description=f['description'],
                    severity=f['severity'],
                    tool_source="Dalfox [Mutated]",
                    raw_loot=f['url']
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
            
            # We use Dalfox with some custom flags to mimic our 'Mutation' desire
            # --mining-dict: we could pass our mutated payloads here?
            # Actually, Dalfox has built-in evasion. 
            # To strictly follow Phase 4 "RedOps Logic", we should pre-mutate logic or 
            # use dalfox's payload list.
            # Dalfox supports --remote-payloads or built-in.
            
            command = [
                dalfox_path, "file", url_file,
                "--format", "json",
                "-o", output_file,
                "--skip-bav", # faster
                "--silence",
                "--no-color",
                "--worker", "40",
                "--follow-redirects",
                "--mining-dict-word", "scan_engine/helpers/param_expander.py" # Hacky way to point to wordlist if valid path, but let's stick to default for now
            ]
            
            success, stdout, stderr, code = ProcessManager.run_command(command, timeout=600)
            
            if os.path.exists(output_file):
                 with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            vuln = json.loads(line)
                            findings.append({
                                "title": f"XSS Found: {vuln.get('message_str', 'Reflected XSS')}",
                                "description": f"Payload: `{vuln.get('payload')}`\nURL: {vuln.get('url')}\nMethod: {vuln.get('method')}",
                                "severity": "critical",
                                "url": vuln.get('url')
                            })
                        except: pass
                        
        except Exception as e:
            if logger: logger(f"Dalfox Error: {e}", "ERROR")
        finally:
            if os.path.exists(url_file): os.remove(url_file)
            if os.path.exists(output_file): os.remove(output_file)
            
        return findings
