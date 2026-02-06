import os
from scan_engine.helpers.process_manager import ProcessManager

class KatanaScanner:
    def __init__(self, target):
        self.target = target

    def stream_katana(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        
        katana_path = "katana"
        home_go = os.path.expanduser("~/go/bin/katana")
        if os.path.exists(home_go):
            katana_path = home_go

        # -jc: crawl JS files, -kf: known files, -d 3: depth 3
        command = [
            katana_path,
            "-u", url,
            "-jc",
            "-kf", "all",
            "-d", "3",
            "-silent",
            "-nc" # no color
        ]
        
        return ProcessManager.stream_command(command)
