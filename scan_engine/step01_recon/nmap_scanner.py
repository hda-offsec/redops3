import logging
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class NmapScanner:
    PROFILES = {
        "quick": {
            "label": "Quick Scan",
            "command": ["nmap", "-n", "-v", "-T4", "-F", "--stats-every", "10s"],
            "requires_root": False,
        },
        "deep": {
            "label": "Deep Audit (Red Team Standard)",
            "command": ["nmap", "-n", "-v", "-sC", "-sV", "--top-ports", "3000", "--open", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "full": {
            "label": "Full TCP Scan",
            "command": ["nmap", "-n", "-v", "-sC", "-sV", "-p-", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "udp": {
            "label": "Top UDP Ports",
            "command": ["nmap", "-v", "-sU", "--top-ports", "100", "-T4", "--stats-every", "10s"],
            "requires_root": True,
        },
        "vuln": {
            "label": "NSE Vuln Scan",
            "command": ["nmap", "-v", "--script", "vuln", "-sV", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "os": {
            "label": "OS Detection",
            "command": ["nmap", "-v", "-O", "-sV", "-T4", "--stats-every", "10s"],
            "requires_root": True,
        },
        "discovery": {
            "label": "Host Discovery",
            "command": ["nmap", "-v", "-sn", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "stealth": {
            "label": "Stealth Scan",
            "command": ["nmap", "-v", "-sS", "-sV", "-T2", "--stats-every", "10s"],
            "requires_root": True,
        },
        "web": {
            "label": "Web Recon",
            "command": [
                "nmap",
                "-v",
                "-sV",
                "-p",
                "80,443,8000,8080,8443",
                "--script",
                "http-title,http-headers,http-methods",
                "-T4",
                "--stats-every",
                "10s",
            ],
            "requires_root": False,
        },
        "smart": {
             "label": "Smart Adaptive Scan",
             # Top 2000 ports + Service Detect + No DNS resolution (-n) + JSON compatible stats
             "command": ["nmap", "-v", "-sS", "-sV", "--version-intensity", "5", "--top-ports", "2000", "--stats-every", "10s", "-n"],  
             "requires_root": True,
        },
    }

    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        import shutil
        return shutil.which("nmap") is not None

    def detect_best_timing(self):
        """
        Pings the target to measure RTT and returns an appropriate Nmap timing flag.
        """
        try:
            # Quick ping: 2 packets, 1s timeout
            # Use ProcessManager to run ping
            # Linux ping: -c count, -W timeout (seconds)
            cmd = ["ping", "-c", "2", "-W", "1", self.target]
            success, stdout, stderr, _ = ProcessManager.run_command(cmd)
            
            if not success or not stdout: return "-T3" # Fallback if ping fails/blocked
            
            output = stdout
            # Extract avg time using local import
            import re
            # pattern: time=14.3 ms
            match = re.search(r"time=([\d\.]+)\s*ms", output)
            if match:
                rtt = float(match.group(1))
                if rtt < 10: return "-T5" # Insane speed for local/low-latency
                if rtt < 60: return "-T4" # Aggressive for decent networks
                return "-T3" # Normal
            
            # Try parsing avg from summary line
            # rtt min/avg/max/mdev = 0.048/0.048/0.048/0.000 ms
            match_avg = re.search(r"min/avg/max/mdev = [\d\.]+/([\d\.]+)/", output)
            if match_avg:
                rtt = float(match_avg.group(1))
                if rtt < 10: return "-T5"
                if rtt < 60: return "-T4"
                return "-T3"

        except Exception as e:
            logger.warning(f"Timing detection failed: {e}")
        
        return "-T3" # Safe default

    def get_recommended_scripts(self, service):
        """
        Returns a list of Nmap scripts relevant to the discovered service.
        """
        service = service.lower()
        scripts = []
        
        # Web
        if any(s in service for s in ['http', 'ssl', 'www']):
            scripts.extend([
                "http-title", "http-headers", "http-methods", "http-enum", 
                "http-robots.txt", "http-waf-detect", "http-config-backup"
            ])
            # CMS Checks (lightweight)
            scripts.extend(["http-wordpress-enum", "http-generator"])
            
        # SMB / Windows
        if any(s in service for s in ['smb', 'microsoft-ds', 'netbios']):
            scripts.extend([
                "smb-os-discovery", "smb-enum-shares", "smb-enum-users", 
                "smb2-security-mode", "smb-vuln-ms17-010"
            ])
            
        # DNS
        if 'dns' in service or 'domain' in service:
            scripts.extend(["dns-recursion", "dns-service-discovery"])
            
        # FTP
        if 'ftp' in service:
            scripts.extend(["ftp-anon", "ftp-bounce", "ftp-syst"])
            
        # SSH
        if 'ssh' in service:
            scripts.extend(["ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods"])
            
        # Database
        if 'mysql' in service:
            scripts.extend(["mysql-info", "mysql-empty-password", "mysql-variables"])
        if 'postgresql' in service:
            scripts.extend(["pgsql-brute"]) # Careful with brute
        if 'mssql' in service:
            scripts.extend(["ms-sql-info", "ms-sql-ntlm-info", "ms-sql-config"])
            
        # Mail
        if 'smtp' in service:
            scripts.extend(["smtp-commands", "smtp-open-relay", "smtp-enum-users"])
        if 'imap' in service:
            scripts.extend(["imap-capabilities", "imap-ntlm-info"])
        if 'pop3' in service:
             scripts.extend(["pop3-capabilities", "pop3-ntlm-info"])
             
        # RDP
        if 'rdp' in service or 'ms-wbt-server' in service:
            scripts.extend(["rdp-ntlm-info", "rdp-enum-encryption", "rdp-vuln-ms12-020"])
            
        # Catch-All / Universal Fallback
        if not scripts:
            # If no specific scripts found, use a robust default set
            # "default" = standard safe scripts
            # "discovery" = try to learn more
            # "safe" = don't crash it
            # "vulners" = if installed, check CVEs
            scripts.extend(["default", "discovery", "safe", "vulners"])

        return list(set(scripts)) # De-dupe

    def command_for_profile(self, profile):
        profile_info = self.PROFILES.get(profile, self.PROFILES["quick"])
        base_cmd = profile_info["command"][:] # Copy list
        
        # Dynamic adjustments for Smart Profile
        if profile == "smart":
            timing = self.detect_best_timing()
            base_cmd.append(timing)
            logger.info(f"Smart Scan: Selected timing {timing} for {self.target}")
            
        return base_cmd + [self.target]

    def stream_profile(self, profile):
        command = self.command_for_profile(profile)
        logger.info("Starting %s Nmap scan for %s", profile, self.target)
        return ProcessManager.stream_command(command)

    @classmethod
    def requires_root(cls, profile):
        return cls.PROFILES.get(profile, {}).get("requires_root", False)

    @classmethod
    def profile_label(cls, profile):
        return cls.PROFILES.get(profile, {}).get("label", profile)

    def stream_scan(self, args):
        """
        Stream an arbitrary Nmap command.
        args: List of arguments (e.g. ['-sS', '-p80']) or a raw command string.
        """
        import shlex

        # Handle string input
        if isinstance(args, str):
            args = shlex.split(args)

        # Create a copy to avoid modifying original list if passed by reference
        cmd = list(args) if args else []

        # Ensure we have 'nmap' at the start
        if not cmd or cmd[0].lower() != "nmap":
            cmd.insert(0, "nmap")

        # Ensure target is present
        if self.target not in cmd:
            cmd.append(self.target)
            
        # Add basic formatting flags if not present
        if "-v" not in cmd: cmd.insert(1, "-v")

        # Check for stats flag (partially matching)
        has_stats = any("--stats-every" in c for c in cmd)
        if not has_stats:
            cmd.extend(["--stats-every", "10s"])
            
        logger.info("Starting Custom Nmap scan: %s", " ".join(cmd))
        return ProcessManager.stream_command(cmd)
