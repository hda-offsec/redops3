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
        command = ["dnsrecon", "-d", self.target, "-t", "std", "--json"]
        # dnsrecon output is often to a file or stdout, we'll try to capture it
        return ProcessManager.run_command(command)

    def run_subfinder(self):
        """Run subfinder for subdomain discovery"""
        # We check if subfinder is in path or in $HOME/go/bin
        subfinder_path = "subfinder"
        if not os.path.exists(subfinder_path):
            home_go = os.path.expanduser("~/go/bin/subfinder")
            if os.path.exists(home_go):
                subfinder_path = home_go
        
        command = [subfinder_path, "-d", self.target, "-silent"]
        return ProcessManager.run_command(command)

    def enumerate_all(self):
        results = {
            "subdomains": [],
            "records": []
        }
        
        # Subfinder
        success, stdout, stderr, code = self.run_subfinder()
        if success:
            results["subdomains"] = [line.strip() for line in stdout.splitlines() if line.strip()]
            
        # DNSRecon
        success, stdout, stderr, code = self.run_dnsrecon()
        if success:
            # DNSRecon often outputs a lot of text before/after JSON or in a file
            # For now we just log that it ran
            pass
            
        return results
