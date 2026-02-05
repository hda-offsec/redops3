import shutil
from scan_engine.helpers.process_manager import ProcessManager

class NucleiScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('nuclei') is not None

    def stream_vuln_scan(self, port, protocol='http'):
        """
        Runs Nuclei on the target
        """
        url = f"{protocol}://{self.target}:{port}"
        # We assume standard nuclei workflow: basic templates for cves/token-spray
        # -s critical,high will focus only on dangerous findings
        # -o /dev/stdout is default but we want json output for parsing ideally
        # For simplicity in Phase 1 styling, we stream text but nuclei has JSON output -j
        command = [
            "nuclei", 
            "-u", url, 
            "-s", "critical,high,medium", 
            "-no-color",
            "-silent"
        ]
        
        return ProcessManager.stream_command(command)
