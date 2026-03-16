import subprocess
import json
import os
import shutil
from core.utils import get_setting

class GitleaksScanner:
    def __init__(self, target_url, options=None):
        self.target_url = target_url
        self.options = options or {}
        self.gitleaks_path = get_setting("GITLEAKS_PATH", "gitleaks")

    def scan(self, logger=None):
        """
        Runs gitleaks against a git repository URL or local path.
        """
        if logger: logger(f"Gitleaks: Scanning {self.target_url} for secrets...", "INFO")
        
        if not shutil.which(self.gitleaks_path):
            if logger: logger(f"Gitleaks: Binary '{self.gitleaks_path}' not found. Skipping.", "WARN")
            return []

        findings = []
        temp_dir = f"/tmp/gitleaks_{os.urandom(4).hex()}"
        report_path = f"{temp_dir}_report.json"
        
        try:
            # Gitleaks can scan a remote repo directly or we clone it. 
            # Recent gitleaks versions support 'detect --repo <url>'
            # But to be safe and captured detailed info, we might want to clone or use 'detect'.
            
            cmd = [
                self.gitleaks_path,
                "detect",
                "--source", self.target_url,
                "--report-format", "json",
                "--report-path", report_path,
                "--redact", # Don't leak secrets in the report file if possible, though we want them for our loot
                "--no-git" if not self.target_url.endswith('.git') and not os.path.isdir(self.target_url) else ""
            ]
            # Filter out empty strings
            cmd = [c for c in cmd if c]

            if logger: logger(f"Gitleaks: Running command: {' '.join(cmd)}", "DEBUG")
            
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        findings.append({
                            "type": item.get("RuleID"),
                            "file": item.get("File"),
                            "line": item.get("StartLine"),
                            "secret": item.get("Secret"),
                            "match": item.get("Match"),
                            "commit": item.get("Commit"),
                            "author": item.get("Author"),
                            "date": item.get("Date")
                        })
            
            if logger:
                if findings:
                    logger(f"🚀 Gitleaks: Found {len(findings)} potential secrets in {self.target_url}!", "SUCCESS")
                else:
                    logger(f"Gitleaks: No secrets detected in {self.target_url}.", "INFO")
                    
        except Exception as e:
            if logger: logger(f"Gitleaks scan failed: {e}", "ERROR")
        finally:
            if os.path.exists(report_path):
                os.remove(report_path)
                
        return findings
