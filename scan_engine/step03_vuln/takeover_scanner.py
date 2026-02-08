from scan_engine.helpers.process_manager import ProcessManager

class TakeoverScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("nuclei") is not None

    def stream_takeover_scan(self, logger=None):
        """
        Runs nuclei specifically for subdomain takeover detection.
        Attempts to update templates if they are missing.
        """
        command = [
            "nuclei", 
            "-u", self.target,
            "-tags", "takeover",
            "-jsonl",
            "-silent"
        ]
        
        if logger: logger(f"Vulnerability: Starting Subdomain Takeover audit with Nuclei...", "INFO")
        
        # We wrap the generator to detect the "no templates" error
        first_run = list(ProcessManager.stream_command(command))
        
        # Check if we hit the "no templates" error
        for event in first_run:
            if event['type'] == 'stdout' and "no templates provided" in event['line']:
                if logger: logger("Nuclei templates missing. Attempting automatic update (-ut)...", "WARN")
                ProcessManager.run_command(["nuclei", "-ut"])
                # Retry once
                return ProcessManager.stream_command(command)
        
        # If no error, just return the first run results as a generator
        def gen():
            for e in first_run:
                yield e
        return gen()
