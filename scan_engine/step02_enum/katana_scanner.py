from scan_engine.helpers.process_manager import ProcessManager

class KatanaScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("katana") is not None

    def stream_katana(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        
        katana_path = ProcessManager.find_binary_path("katana") or "katana"

        # -jc: crawl JS files, -kf: known files, -d 3: depth 3
        command = [
            katana_path,
            "-u", url,
            "-jc",
            "-kf", "all",
            "-d", "3",
            "-fs", "fqdn", # restrict scope to FQDN
            "-silent",
            "-nc" # no color
        ]
        
        return ProcessManager.stream_command(command)
