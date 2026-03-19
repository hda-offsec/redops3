import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import re

class GitExposureScanner:
    def __init__(self, target, options=None):
        self.options = options
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
            r = http_client.get(url, options=getattr(self, "options", None), timeout=7, allow_redirects=False)
            if r.status_code == 200 and "[core]" in r.text:
                config_content = r.text
                
                # Extract interesting info from config
                # 1. Remotes (URLs)
                remotes = re.findall(r'url\s*=\s*(.*)', config_content)
                
                desc = "The .git directory is publicly accessible! This is a critical vulnerability that typically leads to full source code disclosure.\n\n"
                desc += "Exposed Config Content (Snippet):\n```ini\n" + config_content[:500] + "...\n```\n"
                
                if remotes:
                    desc += "\nDiscovered Remotes:\n" + "\n".join([f"- {url}" for url in remotes])
                    
                from scan_engine.helpers.finding_normalizer import FindingNormalizer
                findings.append(FindingNormalizer.from_response(
                    r,
                    title=f"CRITICAL: .git Directory Exposed ({port})",
                    description=desc,
                    severity="critical",
                    tool_source="git_scanner",
                    category="vuln"
                ))
                
                if logger: logger(f"🔥 CRITICAL: Exposed .git directory found on port {port}!", "CRITICAL")

                # 2. Check for .git/HEAD to confirm
                r_head = http_client.get(f"{protocol}://{self.target}:{port}/.git/HEAD", options=getattr(self, "options", None), timeout=5)
                if r_head.status_code == 200 and "ref:" in r_head.text:
                    if logger: logger(f"Confirmed: Valid .git/HEAD found: {r_head.text.strip()}", "SUCCESS")
                    
                    # 3. EXPERT: Auto-Looting (Git Dumper)
                    loot_path = f"data/loot/git_{self.target}_{port}"
                    if logger: logger(f"⚔️  Attempting to dump source code to {loot_path}...", "WARN")
                    self.dump_git(f"{protocol}://{self.target}:{port}/.git/", loot_path, logger)
                    
                    from scan_engine.helpers.finding_normalizer import FindingNormalizer
                    findings.append(FindingNormalizer.from_response(
                        r_head,
                        title="Git Source Code Dump Attempted",
                        description=f"RedOps3 attempted to dump the repository to `{loot_path}`.\nCheck the `data/loot` directory for extracted source code.",
                        severity="critical",
                        tool_source="git_dumper",
                        category="vuln"
                    ))

        except Exception as e:
            if logger: logger(f"Git exposure check failed on {port}: {e}", "DEBUG")
            
        return findings

    def dump_git(self, base_url, output_dir, logger=None):
        """
        Minimal Git Dumper implementation.
        Tries to fetch objects and reconstruct files.
        """
        import os
        import zlib
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        try:
            # Get HEAD to find current branch
            r_head = http_client.get(base_url + "HEAD", options=getattr(self, "options", None), timeout=10)
            if "ref:" not in r_head.text: return
            
            ref_path = r_head.text.split(" ")[1].strip()
            
            # Get the object hash of the last commit
            r_ref = http_client.get(base_url + ref_path, options=getattr(self, "options", None), timeout=10)
            if r_ref.status_code != 200: return
            
            commit_hash = r_ref.text.strip()
            if logger: logger(f"Git Dumper: HEAD is at {commit_hash}. Fetching objects...", "INFO")
            
            # Download basic objects (Proof of Concept level)
            # In a full dumper we would traverse the tree. 
            # Here we save proof: config, HEAD, logs/HEAD
            
            def save_url(url, dest):
                try:
                    r = http_client.get(url, options=getattr(self, "options", None), timeout=5)
                    if r.status_code == 200:
                        with open(dest, 'wb') as f: f.write(r.content)
                except Exception:
                    return

            save_url(base_url + "config", os.path.join(output_dir, "config"))
            save_url(base_url + "HEAD", os.path.join(output_dir, "HEAD"))
            save_url(base_url + "logs/HEAD", os.path.join(output_dir, "logs_HEAD"))
            save_url(base_url + "index", os.path.join(output_dir, "index"))
            
            if logger: logger(f"Git Dumper: Extracted core meta-files to {output_dir}. Use 'git-dumper' tool for full reconstruction.", "SUCCESS")
            
        except Exception as e:
            if logger: logger(f"Git Dump failed: {e}", "ERROR")
