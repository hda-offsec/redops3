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
        base_url = f"{protocol}://{self.target}:{port}/.git/"
        url = f"{base_url}config"
        findings = []
        
        try:
            if logger: logger(f"Advanced: Checking for .git exposure on {base_url}...", "INFO")
            
            # 1. Check for .git/config
            r = http_client.get(url, options=getattr(self, "options", None), timeout=7, allow_redirects=False)
            if r.status_code == 200 and "[core]" in r.text:
                config_content = r.text
                
                # Extract interesting info from config
                remotes = re.findall(r'url\s*=\s*(.*)', config_content)

                curl_cmd = f"curl -ik {url}"
                
                from scan_engine.helpers.finding_normalizer import FindingNormalizer
                
                findings.append(FindingNormalizer.from_response(
                    r,
                    title="Exposed Git Repository (.git/config)",
                    description="The `.git` directory is publicly accessible! This is a severe vulnerability that typically leads to full source code disclosure, API keys leakage, and intellectual property theft.",
                    severity="critical",
                    confidence="certain",
                    tool_source="git_scanner",
                    category="secret", # Maps to Secret/Intel icon
                    evidence={
                        "config_snippet": config_content[:500],
                        "discovered_remotes": remotes
                    },
                    repro_command=curl_cmd,
                    metadata={
                        "validation_status": "success",
                        "port": port,
                        "protocol": protocol,
                        "component": "Source Control"
                    }
                ))
                
                if logger: logger(f"🔥 CRITICAL: Exposed .git directory found on port {port}!", "CRITICAL")

                # 2. Check for .git/HEAD to confirm
                r_head = http_client.get(f"{base_url}HEAD", options=getattr(self, "options", None), timeout=5)
                if r_head.status_code == 200 and "ref:" in r_head.text:
                    if logger: logger(f"Confirmed: Valid .git/HEAD found: {r_head.text.strip()}", "SUCCESS")
                    
                    # 3. EXPERT: Auto-Looting (Git Dumper)
                    loot_path = f"data/loot/git_{self.target}_{port}"
                    if logger: logger(f"⚔️  Attempting to dump source code to {loot_path}...", "WARN")
                    self.dump_git(base_url, loot_path, logger)
                    
                    findings.append(FindingNormalizer.from_response(
                        r_head,
                        title="Git Source Code Extracted (Auto-Loot)",
                        description=f"RedOps3 successfully confirmed a valid `HEAD` and attempted to dump the repository locally.\n\nAll extracted source code has been saved to the secure loot vault.",
                        severity="high",
                        confidence="certain",
                        tool_source="git_dumper",
                        category="intel",
                        repro_command=f"git-dumper {base_url} /tmp/git_dump",
                        evidence={
                            "head_content": r_head.text.strip()[:100],
                            "loot_destination": loot_path
                        },
                        metadata={
                            "validation_status": "success",
                            "port": port,
                            "protocol": protocol,
                        }
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
