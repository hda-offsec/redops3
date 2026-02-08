from scan_engine.helpers.process_manager import ProcessManager

class TakeoverScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("nuclei") is not None

    def stream_takeover_scan(self, logger=None):
        """
        Runs nuclei specifically for subdomain takeover detection using all subdomains found
        """
        # We assume subdomains are passed or we use the main domain
        # For robustness, we will run it on the main domain first
        command = [
            "nuclei", 
            "-u", self.target,
            "-t", "takeovers/",
            "-jsonl",
            "-silent"
        ]
        
        if logger: logger(f"Vulnerability: Starting Subdomain Takeover audit with Nuclei...", "INFO")
        return ProcessManager.stream_command(command)
