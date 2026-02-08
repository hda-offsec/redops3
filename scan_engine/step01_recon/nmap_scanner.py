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
    }

    def __init__(self, target):
        self.target = target

    def check_tools(self):
        import shutil
        return shutil.which("nmap") is not None

    def command_for_profile(self, profile):
        profile_info = self.PROFILES.get(profile, self.PROFILES["quick"])
        return profile_info["command"] + [self.target]

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
        args: List of arguments (e.g. ['-sS', '-p80'])
        Does NOT auto-append target, caller must include it or I will append it if missing?
        Actually standard is to append target at end.
        But 'args' from profile might not include target.
        Let's allow args to be the FULL command list EXCLUDING 'nmap' binary, 
        or just the flags.
        Steps:
        1. Prepend 'nmap' if not present.
        2. Append target if not present (risky if not checking).
        Let's assume args are just the flags.
        """
        # Ensure we don't have 'nmap' twice
        cmd = ["nmap"] + args
        if self.target not in cmd:
            cmd.append(self.target)
            
        # Add basic formatting flags if not present
        if "-v" not in cmd: cmd.insert(1, "-v")
        if "--stats-every" not in cmd: 
            cmd.extend(["--stats-every", "10s"])
            
        logger.info("Starting Custom Nmap scan: %s", " ".join(cmd))
        return ProcessManager.stream_command(cmd)
