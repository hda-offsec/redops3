from scan_engine.helpers.process_manager import ProcessManager

class TakeoverScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("nuclei") is not None

    def stream_takeover_scan(self, logger=None, targets=None):
        """
        Runs nuclei specifically for subdomain takeover detection.
        Attempts to update templates if they are missing.
        """
        import os
        import tempfile

        # Default to single target if none provided
        target_list = targets if targets else [self.target]
        
        # Nuclei -l for multiple targets
        target_file = None
        if len(target_list) > 1:
            fd, target_file = tempfile.mkstemp(suffix=".txt", prefix="redops_takeover_")
            with os.fdopen(fd, 'w') as f:
                for t in target_list:
                    f.write(f"{t}\n")
            
            command = [
                "nuclei", 
                "-l", target_file,
                "-tags", "takeover",
                "-jsonl",
                "-silent"
            ]
        else:
            command = [
                "nuclei", 
                "-u", target_list[0],
                "-tags", "takeover",
                "-jsonl",
                "-silent"
            ]
        
        if logger: logger(f"Vulnerability: Starting Takeover audit on {len(target_list)} targets...", "INFO")
        
        try:
            # We wrap the generator to detect the "no templates" error
            first_run = list(ProcessManager.stream_command(command))
            
            # Check if we hit the "no templates" error
            needs_update = False
            for event in first_run:
                if event['type'] == 'stdout' and "no templates provided" in event['line']:
                    needs_update = True
                    break
            
            def gen(stream, cleanup=False):
                try:
                    for e in stream:
                        yield e
                finally:
                    if cleanup and target_file and os.path.exists(target_file):
                        try:
                            os.remove(target_file)
                        except Exception:
                            pass

            if needs_update:
                if logger: logger("Nuclei templates missing. Attempting automatic update (-ut)...", "WARN")
                ProcessManager.run_command(["nuclei", "-ut"])
                # Retry once
                return gen(ProcessManager.stream_command(command), cleanup=True)
            
            return gen(first_run, cleanup=True)
        except Exception as e:
            if logger: logger(f"Takeover scan failed: {e}", "ERROR")
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass
            return []
