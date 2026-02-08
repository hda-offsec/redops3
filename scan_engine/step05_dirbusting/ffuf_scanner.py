import shutil
from scan_engine.helpers.process_manager import ProcessManager

class FfufScanner:
    def __init__(self, target, wordlist=None):
        self.target = target
        self.wordlist = wordlist or '/usr/share/wordlists/common.txt'

    def check_tools(self):
        return shutil.which('ffuf') is not None

    def stream_scan(self):
        """Standard interface alias for stream_fuzz"""
        # Parse port/proto from target URL if possible, or assume simple target
        # The orchestrator passes a full URL like http://1.2.3.4:80
        # But stream_fuzz takes port/protocol. 
        # Let's adjust stream_fuzz to handle full URL or parse it here.
        
        # Orchestrator passes: target_url = f"{proto}://{self.target}:{port}" as 'target' to __init__
        # So self.target is "http://1.2.3.4:80"
        
        # We need to construct the ffuf command using this URL.
        # stream_fuzz implementation in this file constructs URL from protocol/target/port.
        # Let's rewrite stream_scan to use the full URL directly.
        
        url = f"{self.target}/FUZZ"
        
        command = [
            "ffuf", 
            "-u", url, 
            "-w", self.wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-noninteractive",
            "-s" 
        ]
        
        return ProcessManager.stream_command(command)

    def stream_fuzz(self, port, protocol='http', wordlist=None):
        """Legacy/granular method"""
        wlist = wordlist or self.wordlist
        url = f"{protocol}://{self.target}:{port}/FUZZ"
        
        command = [
            "ffuf", 
            "-u", url, 
            "-w", wlist,
            "-mc", "200,204,301,302,307,401,403",
            "-noninteractive",
            "-s" 
        ]
        
        return ProcessManager.stream_command(command)
