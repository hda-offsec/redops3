import subprocess
import json
import os
import shutil
from core.utils import get_setting

class GitrobScanner:
    def __init__(self, target_org, options=None):
        self.target_org = target_org
        self.options = options or {}
        self.gitrob_path = get_setting("GITROB_PATH", "gitrob")
        self.github_token = get_setting("GITHUB_TOKEN")

    def scan(self, logger=None):
        """
        Runs gitrob against a GitHub organization or user.
        """
        if logger: logger(f"Gitrob: Analyzing GitHub organization/user '{self.target_org}'...", "INFO")
        
        if not shutil.which(self.gitrob_path):
            if logger: logger(f"Gitrob: Binary '{self.gitrob_path}' not found. Skipping.", "WARN")
            return []

        if not self.github_token:
            if logger: logger("Gitrob: GITHUB_TOKEN not set in settings. Gitrob requires a token.", "WARN")
            return []

        findings = []
        # Gitrob saves to a file by default if specified or we capture stdout
        # However, gitrob's output is not always easy to parse directly if not using the web UI.
        # But we can try to use a save file if supported or use a wrapper.
        
        temp_file = f"/tmp/gitrob_{os.urandom(4).hex()}.json"
        
        try:
            # gitrob [options] target
            env = os.environ.copy()
            env["GITROB_ACCESS_TOKEN"] = self.github_token
            
            cmd = [
                self.gitrob_path,
                "-no-server", # Don't start the web server
                "-save", temp_file,
                self.target_org
            ]

            if logger: logger(f"Gitrob: Running command: {' '.join(cmd)}", "DEBUG")
            
            process = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
            
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as f:
                    data = json.load(f)
                    # Gitrob JSON format inclusion
                    # Data contains 'Findings', 'Repositories', etc.
                    items = data.get('Findings', [])
                    for item in items:
                        findings.append({
                            "repository": item.get('RepositoryName'),
                            "file": item.get('FilePath'),
                            "path": item.get('Action'),
                            "description": item.get('Description'),
                            "reason": item.get('Reason')
                        })
            
            if logger:
                if findings:
                    logger(f"🚀 Gitrob: Found {len(findings)} potential exposures in {self.target_org}!", "SUCCESS")
                else:
                    logger(f"Gitrob: No immediate exposures detected in {self.target_org}.", "INFO")
                    
        except Exception as e:
            if logger: logger(f"Gitrob scan failed: {e}", "ERROR")
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
                
        return findings
