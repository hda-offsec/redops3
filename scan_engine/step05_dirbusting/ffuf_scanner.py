import shutil
from scan_engine.helpers.process_manager import ProcessManager

class FfufScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('ffuf') is not None

    def stream_fuzz(self, port, protocol='http', wordlist='/usr/share/wordlists/common.txt'):
        """
        Runs ffuf for directory discovery.
        """
        url = f"{protocol}://{self.target}:{port}/FUZZ"
        
        # Simplified common wordlist path or fallback
        # In a real environment, we'd want to check if the file exists
        command = [
            "ffuf", 
            "-u", url, 
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-noninteractive",
            "-s" # silent, only results
        ]
        
        return ProcessManager.stream_command(command)
