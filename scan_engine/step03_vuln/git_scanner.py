import requests
import re

class GitExposureScanner:
    def __init__(self, target):
        self.target = target

    def audit_git(self, port, protocol='http', logger=None):
        """
        Scans for exposed .git directory and analyzes its configuration.
        """
        url = f"{protocol}://{self.target}:{port}/.git/config"
        findings = []
        
        try:
            if logger: logger(f"Advanced: Checking for .git exposure on {protocol}://{self.target}:{port}...", "INFO")
            
            # 1. Check for .git/config
            r = requests.get(url, timeout=7, verify=False, allow_redirects=False)
            if r.status_code == 200 and "[core]" in r.text:
                config_content = r.text
                
                # Extract interesting info from config
                # 1. Remotes (URLs)
                remotes = re.findall(r'url\s*=\s*(.*)', config_content)
                
                desc = "The .git directory is publicly accessible! This is a critical vulnerability that typically leads to full source code disclosure.\n\n"
                desc += "Exposed Config Content (Snippet):\n```ini\n" + config_content[:500] + "...\n```\n"
                
                if remotes:
                    desc += "\nDiscovered Remotes:\n" + "\n".join([f"- {url}" for url in remotes])
                    
                findings.append({
                    "title": f"CRITICAL: .git Directory Exposed ({port})",
                    "description": desc,
                    "severity": "critical",
                    "tool_source": "git_scanner"
                })
                
                if logger: logger(f"🔥 CRITICAL: Exposed .git directory found on port {port}!", "CRITICAL")

                # 2. Check for .git/HEAD to confirm
                r_head = requests.get(f"{protocol}://{self.target}:{port}/.git/HEAD", timeout=5, verify=False)
                if r_head.status_code == 200 and "ref:" in r_head.text:
                    if logger: logger(f"Confirmed: Valid .git/HEAD found: {r_head.text.strip()}", "SUCCESS")

        except Exception as e:
            if logger: logger(f"Git exposure check failed on {port}: {e}", "DEBUG")
            
        return findings
