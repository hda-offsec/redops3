import logging
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class NmapScanner:
    PROFILES = {
        "quick": {
            "label": "Quick Scan",
            "command": ["nmap", "-T4", "-F", "--stats-every", "10s"],
            "requires_root": False,
        },
        "quick": {
            "label": "Quick Scan",
            "command": ["nmap", "-T4", "-F", "--stats-every", "10s"],
            "requires_root": False,
        },
        "deep": {
            "label": "Deep Audit (Red Team Standard)",
            "command": ["nmap", "-sC", "-sV", "--top-ports", "3000", "--open", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "full": {
            "label": "Full TCP Scan",
            "command": ["nmap", "-sC", "-sV", "-p-", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "udp": {
            "label": "Top UDP Ports",
            "command": ["nmap", "-sU", "--top-ports", "100", "-T4", "--stats-every", "10s"],
            "requires_root": True,
        },
        "vuln": {
            "label": "NSE Vuln Scan",
            "command": ["nmap", "--script", "vuln", "-sV", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "os": {
            "label": "OS Detection",
            "command": ["nmap", "-O", "-sV", "-T4", "--stats-every", "10s"],
            "requires_root": True,
        },
        "discovery": {
            "label": "Host Discovery",
            "command": ["nmap", "-sn", "-T4", "--stats-every", "10s"],
            "requires_root": False,
        },
        "stealth": {
            "label": "Stealth Scan",
            "command": ["nmap", "-sS", "-sV", "-T2", "--stats-every", "10s"],
            "requires_root": True,
        },
        "web": {
            "label": "Web Recon",
            "command": [
                "nmap",
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
