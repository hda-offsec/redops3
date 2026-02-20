import shutil
import os
from scan_engine.helpers.process_manager import ProcessManager

class FfufScanner:
    def __init__(self, target, wordlist=None):
        self.target = target
        self.wordlist = self._find_wordlist(wordlist)

    def _find_wordlist(self, user_wlist):
        if user_wlist and os.path.exists(user_wlist):
            return user_wlist
        
        # Kali Common Locations
        potential_paths = [
            '/usr/share/dirb/wordlists/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/common.txt'
        ]
        for p in potential_paths:
            if os.path.exists(p):
                return p
        return '/usr/share/dirb/wordlists/common.txt' # Fallback

    def check_tools(self):
        return shutil.which('ffuf') is not None

    def stream_scan(self):
        return self.stream_fuzz(port=None)

    def get_command(self, port=None, protocol='http', wordlist=None, quick=False):
        wlist = wordlist or self.wordlist

        if self.target.startswith('http://') or self.target.startswith('https://'):
            url = f"{self.target}/FUZZ"
        else:
            if port is None:
                raise ValueError("Port is required when target is not a full URL")
            url = f"{protocol}://{self.target}:{port}/FUZZ"
        
        cmd = [
            "ffuf", 
            "-u", url, 
            "-w", wlist,
            "-mc", "200,204,301,302,307,401,403,405",
            "-r",
            "-ac", # Autocalibration
            "-t", "40" if not quick else "20",
            "-timeout", "5",
            "-noninteractive",
            "-json" # Use JSON for robust parsing
        ]

        if not quick:
            cmd.extend([
                "-recursion",
                "-recursion-depth", "1",
                "-e", ".php,.html,.js,.txt,.bak,.zip",
            ])
        
        return cmd

    def stream_fuzz(self, port=None, protocol='http', wordlist=None, quick=False):
        """Legacy/granular method"""
        command = self.get_command(port, protocol, wordlist, quick=quick)
        return ProcessManager.stream_command(command)
