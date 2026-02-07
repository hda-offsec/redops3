import subprocess
import json
import os
from scan_engine.helpers.process_manager import ProcessManager

class DNSScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        import shutil
        return shutil.which("dnsrecon") is not None

    def run_dnsrecon(self):
        """Run dnsrecon for standard enumeration"""
        output_file = f"data/results/dns_{self.target}.json"
        command = ["dnsrecon", "-d", self.target, "-t", "std", "--json", output_file]
        return ProcessManager.run_command(command)

    def run_subfinder(self):
        """Run subfinder for subdomain discovery"""
        # We check if subfinder is in path or in $HOME/go/bin
        subfinder_path = "subfinder"
        
        # Try finding in system path first
        import shutil
        if not shutil.which(subfinder_path):
            home_go = os.path.expanduser("~/go/bin/subfinder")
            if os.path.exists(home_go):
                subfinder_path = home_go
        
        command = [subfinder_path, "-d", self.target, "-silent"]
        return ProcessManager.run_command(command)

    def enumerate_all(self, logger=None):
        results = {
            "subdomains": [],
            "records": []
        }
        
        # Subfinder logic
        if logger: logger("Checking for subdomains via Subfinder...", "INFO")
        success, stdout, stderr, code = self.run_subfinder()
        if success:
            found = [line.strip() for line in stdout.splitlines() if line.strip()]
            results["subdomains"] = found
            if logger: logger(f"Subfinder finished. Found {len(found)} subdomains.", "SUCCESS")
        else:
            if logger: logger("Subfinder failed or find nothing.", "WARN")
            
        # DNSRecon
        if logger: logger("Enumerating DNS records via DNSRecon...", "INFO")
        success, stdout, stderr, code = self.run_dnsrecon()
        if success:
            if logger: logger("DNSRecon enumeration complete.", "SUCCESS")
        else:
            if logger: logger("DNSRecon enumeration skipped or failed.", "WARN")
            
        return results
