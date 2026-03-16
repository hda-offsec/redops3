import subprocess
import re
from datetime import datetime

class WhoisScanner:
    """
    Advanced WHOIS scanner that parses domain registration data.
    Provides detailed insight into registrar, contacts, and domain lifecycle.
    """

    def __init__(self, target):
        self.target = target

    def scan(self, logger=None):
        if logger:
            logger(f"WHOIS: Analyzing domain registration for {self.target}...", "INFO")

        try:
            # We use the system 'whois' tool as it handles many TLDs and redirection automatically
            process = subprocess.Popen(
                ["whois", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                if logger:
                    logger(f"WHOIS tool returned error: {stderr.strip()}", "DEBUG")
                return None

            return self.parse_whois(stdout)
        except Exception as e:
            if logger:
                logger(f"WHOIS scan failed: {str(e)}", "DEBUG")
            return None

    def parse_whois(self, raw_data):
        """
        Parses raw WHOIS output into a structured dictionary.
        """
        data = {
            "registrar": "Unknown",
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "status": [],
            "nameservers": [],
            "registrant": {"name": "REDACTED", "org": "REDACTED", "email": "REDACTED", "phone": "REDACTED"},
            "admin": {"name": "REDACTED", "org": "REDACTED", "email": "REDACTED", "phone": "REDACTED"},
            "tech": {"name": "REDACTED", "org": "REDACTED", "email": "REDACTED", "phone": "REDACTED"},
            "raw": raw_data
        }

        # Regex patterns for common WHOIS formats
        patterns = {
            "registrar": [r"Registrar:\s*(.*)", r"registrar:\s*(.*)", r"Sponsoring Registrar:\s*(.*)"],
            "creation_date": [r"Creation Date:\s*(.*)", r"created:\s*(.*)", r"Registered on:\s*(.*)"],
            "expiration_date": [r"Registry Expiry Date:\s*(.*)", r"Expiration Date:\s*(.*)", r"free-date:\s*(.*)", r"expires:\s*(.*)"],
            "updated_date": [r"Updated Date:\s*(.*)", r"last-updated:\s*(.*)"],
            "nameservers": [r"Name Server:\s*(.*)", r"nserver:\s*(.*)"],
            "status": [r"Domain Status:\s*(.*)", r"status:\s*(.*)"],
            
            # Contact parsing (simplified)
            "registrant_name": [r"Registrant Name:\s*(.*)", r"registrant:\s*(.*)"],
            "registrant_org": [r"Registrant Organization:\s*(.*)"],
            "registrant_email": [r"Registrant Email:\s*(.*)"],
            "admin_name": [r"Admin Name:\s*(.*)", r"admin-c:\s*(.*)"],
            "tech_name": [r"Tech Name:\s*(.*)", r"tech-c:\s*(.*)"]
        }

        for line in raw_data.splitlines():
            line = line.strip()
            if not line or line.startswith("%") or line.startswith("#"):
                continue

            # Iterate over patterns to extract data
            for key, regexes in patterns.items():
                for regex in regexes:
                    match = re.search(regex, line, re.IGNORECASE)
                    if match:
                        val = match.group(1).strip()
                        if key == "nameservers":
                            if val.lower() not in [ns.lower() for ns in data["nameservers"]]:
                                data["nameservers"].append(val)
                        elif key == "status":
                            if val not in data["status"]:
                                data["status"].append(val)
                        elif key.startswith("registrant_"):
                            sub_key = key.split("_")[1]
                            data["registrant"][sub_key] = val
                        elif key.startswith("admin_"):
                            sub_key = key.split("_")[1]
                            data["admin"][sub_key] = val
                        elif key.startswith("tech_"):
                            sub_key = key.split("_")[1]
                            data["tech"][sub_key] = val
                        else:
                            data[key] = val
                        break

        # Post-processing: Normalize dates if possible
        for date_key in ["creation_date", "expiration_date", "updated_date"]:
            if data[date_key]:
                # Attempt to strip timezone/time if redundant
                data[date_key] = data[date_key].split("T")[0].split(" ")[0]

        return data
