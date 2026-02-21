from scan_engine.helpers.process_manager import ProcessManager

class NucleiScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("nuclei") is not None

    def get_command(self, port, protocol='http', tags=None):
        path = ProcessManager.find_binary_path("nuclei") or "nuclei"
        url = f"{protocol}://{self.target}:{port}"
        
        # Expert Logic:
        # 1. Use -severity (long form) for better compatibility
        # 2. Increase -rl to 20 for faster execution without being too aggressive
        # 3. ONLY use -as (Automatic Scan) if no tags are specified. 
        #    Combining both leads to massive redundancy and slow scans.
        command = [
            path, 
            "-u", url, 
            "-severity", "critical,high,medium", 
            "-rl", "20",
            "-no-color",
            "-json",
            "-timeout", "5",
            "-stats",
            "-stats-interval", "30"
        ]
        
        if tags:
            # Targeted scan based on tags
            command.extend(["-tags", tags])
        else:
            # Fallback to smart automatic tech-based scan
            command.append("-as")
            
        return command

    def stream_vuln_scan(self, port, protocol='http', tags=None):
        """
        Runs Nuclei on the target
        """
        command = self.get_command(port, protocol, tags)
        return ProcessManager.stream_command(command)
