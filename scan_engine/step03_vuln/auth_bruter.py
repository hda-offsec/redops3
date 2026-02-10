import subprocess
import os
import tempfile

class AuthBruteScanner:
    def __init__(self, target):
        self.target = target
        # Expert Strategy: Base naming for target-specific brute forcing
        self.base_name = target.split('.')[0]
        self.short_name = self.base_name[:8] if len(self.base_name) > 8 else self.base_name

    def create_wordlists(self):
        """Generates hyper-targeted wordlists for the specific entity."""
        users = ["root", "admin", "administrator", "user", "guest", "backup", "operator", "webmaster", 
                 self.base_name, self.short_name, f"svc_{self.short_name}"]
        
        passwords = ["root", "admin", "password", "password123", "123456", "admin123", 
                     self.base_name, f"{self.base_name}123", f"{self.base_name}!", f"{self.base_name}2024",
                     self.short_name, f"{self.short_name}123", "manager", "support", "changeme"]
        
        # Write to temporary files
        user_fd, user_path = tempfile.mkstemp(suffix=".txt", prefix="redops_users_")
        pass_fd, pass_path = tempfile.mkstemp(suffix=".txt", prefix="redops_pass_")
        
        with os.fdopen(user_fd, 'w') as f:
            for u in sorted(list(set(users))): f.write(f"{u}\n")
        with os.fdopen(pass_fd, 'w') as f:
            for p in sorted(list(set(passwords))): f.write(f"{p}\n")
            
        return user_path, pass_path

    def audit_ssh(self, port=22, logger=None):
        """Audits SSH with high-performance targeted brute-force logic."""
        findings = []
        user_path, pass_path = None, None
        try:
            if logger: logger(f"Auth Expert: Launching targeted SSH probe on {self.target}:{port}...", "INFO")
            
            user_path, pass_path = self.create_wordlists()
            
            # Using Nmap's ssh-brute with our custom targeted dictionary
            cmd = [
                "nmap", "-p", str(port), 
                "--script", "ssh-brute", 
                "--script-args", f"userdb={user_path},passdb={pass_path},brute.threads=4",
                self.target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if "Accounts:" in result.stdout or "Valid credentials" in result.stdout:
                import re
                creds_match = re.search(r"Accounts:\s+([^\n-]+)", result.stdout)
                found_creds = creds_match.group(1).strip() if creds_match else "Credentials Found (check logs)"

                findings.append({
                    "title": f"CRITICAL: SSH AUTHENTICATION BYPASS",
                    "description": (
                        f"Valid SSH credentials were discovered on {self.target}:{port} using target-specific dictionaries.\n\n"
                        f"Impact: Fully compromised system access. Immediate session takeover is possible.\n\n"
                        f"Evidence:\n{result.stdout}"
                    ),
                    "severity": "critical",
                    "tool_source": "auth_expert",
                    "raw_loot": found_creds,
                    "loot_type": "SSH Credential"
                })
                if logger: logger(f"🔥 SSH BREACH: Credentials cracked for {self.target}!", "CRITICAL")
        except Exception as e:
            if logger: logger(f"SSH audit failed: {e}", "DEBUG")
        finally:
            for p in [user_path, pass_path]:
                if p and os.path.exists(p): os.remove(p)
        return findings

    def audit_ftp(self, port=21, logger=None):
        """Audits FTP for high-risk access (Anonymous + Targeted Brute)."""
        findings = []
        user_path, pass_path = None, None
        try:
            if logger: logger(f"Auth Expert: Auditing FTP on {self.target}:{port}...", "INFO")
            
            # 1. Anonymous Check
            cmd_anon = ["nmap", "-p", str(port), "--script", "ftp-anon", self.target]
            res_anon = subprocess.run(cmd_anon, capture_output=True, text=True, timeout=30)
            if "Anonymous FTP login allowed" in res_anon.stdout:
                findings.append({
                    "title": "High: FTP Anonymous Access Exposed",
                    "description": f"The FTP server at {self.target}:{port} allows identity-less login via 'anonymous'.",
                    "severity": "high",
                    "tool_source": "auth_expert"
                })

            # 2. Targeted Brute
            user_path, pass_path = self.create_wordlists()
            cmd_brute = [
                "nmap", "-p", str(port), 
                "--script", "ftp-brute", 
                "--script-args", f"userdb={user_path},passdb={pass_path}",
                self.target
            ]
            res_brute = subprocess.run(cmd_brute, capture_output=True, text=True, timeout=120)
            if "Accounts:" in res_brute.stdout or "Valid credentials" in res_brute.stdout:
                import re
                creds_match = re.search(r"Accounts:\s+([^\n-]+)", res_brute.stdout)
                found_creds = creds_match.group(1).strip() if creds_match else "Credentials Found (check logs)"

                findings.append({
                    "title": f"CRITICAL: FTP AUTHENTICATION BYPASS",
                    "description": f"Valid FTP credentials found via targeted analysis.\n\nEvidence:\n{res_brute.stdout}",
                    "severity": "critical",
                    "tool_source": "auth_expert",
                    "raw_loot": found_creds,
                    "loot_type": "FTP Credential"
                })
        except Exception: pass
        finally:
            for p in [user_path, pass_path]:
                if p and os.path.exists(p): os.remove(p)
        return findings

    def run_all(self, open_ports, logger=None):
        findings = []
        for p in open_ports:
            port = int(p['port'])
            svc = (p.get('service') or p.get('service_name') or '').lower()
            if port == 22 or "ssh" in svc: findings.extend(self.audit_ssh(port, logger))
            elif port == 21 or "ftp" in svc: findings.extend(self.audit_ftp(port, logger))
        return findings
