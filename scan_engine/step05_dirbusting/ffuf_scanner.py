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
        # The orchestrator passes a full URL like http://1.2.3.4:80
        # self.target is "http://1.2.3.4:80".
        # We delegate to stream_fuzz which now handles full URLs gracefully.
        return self.stream_fuzz(port=None)

    def stream_fuzz(self, port=None, protocol='http', wordlist=None):
        """Legacy/granular method"""
        wlist = wordlist or self.wordlist

        if self.target.startswith('http://') or self.target.startswith('https://'):
            url = f"{self.target}/FUZZ"
        else:
            if port is None:
                raise ValueError("Port is required when target is not a full URL")
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
