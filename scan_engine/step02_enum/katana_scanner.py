from scan_engine.helpers.process_manager import ProcessManager

class KatanaScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("katana") is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        katana_path = ProcessManager.find_binary_path("katana") or "katana"
        return [
            katana_path,
            "-u", url,
            "-jc",
            "-jsl", 
            "-kf", "all",
            "-d", "3",
            "-fs", "fqdn", 
            "-ct", "10", 
            "-silent",
            "-nc" 
        ]

    def stream_katana(self, port, protocol='http'):
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)
