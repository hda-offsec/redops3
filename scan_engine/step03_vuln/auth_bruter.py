import subprocess
import os

class AuthBruteScanner:
    def __init__(self, target):
        self.target = target
        # Generates basic target-based credentials
        self.base_user = target.split('.')[0]
        self.default_creds = [
            ("root", "root"),
            ("admin", "admin"),
            ("admin", "password"),
            ("user", "user"),
            (self.base_user, self.base_user),
            (self.base_user, f"{self.base_user}123"),
            ("guest", "guest"),
            ("backup", "backup")
        ]

    def audit_ssh(self, port=22, logger=None):
        """Audits SSH for weak/default credentials using Nmap."""
        findings = []
        if logger: logger(f"Auth Audit: Starting SSH brute-force probe on {self.target}:{port}...", "INFO")
        
        # We can use nmap with a small user/password list generated on the fly as a string, 
        # or just use the nmap-ssh-brute which is fairly fast with its defaults.
        # But for Red Team, we want target-specific. 
        # For simplicity and reliability, we'll use nmap's scripts.
        try:
            cmd = ["nmap", "-p", str(port), "--script", "ssh-brute", "--script-args", "userdb=data/wordlists/users_small.txt,passdb=data/wordlists/pass_small.txt", self.target]
            # If wordlists don't exist, nmap uses its defaults. 
            # Let's try without custom list first to ensure it works.
            cmd = ["nmap", "-p", str(port), "--script", "ssh-brute", self.target]
            
            # Using timeout to avoid blocking forever
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if "Accounts:" in result.stdout or "Valid credentials" in result.stdout:
                findings.append({
                    "title": f"CRITICAL: SSH Weak Credentials detected ({port})",
                    "description": f"Valid SSH credentials discovered on {self.target}:{port}. Immediate action required.\n\nNmap Result:\n{result.stdout}",
                    "severity": "critical",
                    "tool_source": "auth_bruter"
                })
                if logger: logger(f"🔥 SSH BREACH: Valid credentials found on port {port}!", "CRITICAL")
        except Exception as e:
            if logger: logger(f"SSH brute-force failed: {e}", "DEBUG")
        return findings

    def audit_ftp(self, port=21, logger=None):
        """Audits FTP for anonymous access and weak credentials."""
        findings = []
        if logger: logger(f"Auth Audit: Probing FTP for anonymous/weak access on {self.target}:{port}...", "INFO")
        
        try:
            cmd = ["nmap", "-p", str(port), "--script", "ftp-anon,ftp-brute", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if "Anonymous FTP login allowed" in result.stdout:
                findings.append({
                    "title": f"High: FTP Anonymous Access ({port})",
                    "description": f"The FTP server on {self.target}:{port} allows anonymous login.",
                    "severity": "high",
                    "tool_source": "auth_bruter"
                })
                if logger: logger(f"🔥 FTP OPEN: Anonymous access allowed on port {port}!", "WARN")
            
            if "Valid credentials" in result.stdout or "root" in result.stdout and "brute" in result.stdout:
                 findings.append({
                    "title": f"CRITICAL: FTP Weak Credentials detected ({port})",
                    "description": f"Valid FTP credentials discovered on {self.target}:{port}.\n\nNmap Result:\n{result.stdout}",
                    "severity": "critical",
                    "tool_source": "auth_bruter"
                })
        except Exception:
            pass
        return findings

    def run_all(self, open_ports, logger=None):
        findings = []
        for p in open_ports:
            port = int(p['port'])
            svc = p['service'].lower()
            
            if port == 22 or "ssh" in svc:
                findings.extend(self.audit_ssh(port, logger))
            elif port == 21 or "ftp" in svc:
                findings.extend(self.audit_ftp(port, logger))
            elif port == 23 or "telnet" in svc:
                # Add telnet check if needed
                pass
        return findings
