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
            "-jc",           # JSON output
            "-jsl",          # JS Library detection
            "-kf", "all",    # Keep all fields
            "-d", "3",       # Reduced depth slightly for speed
            "-fs", "fqdn",   # Filter scope
            "-ct", "10",     # Crawl duration
            "-silent",
            "-nc",
            
            # DEEP CRAWL FLAGS (Removed -headless as it causes issues)
            "-js-crawl",     # Enable JavaScript crawling
            "-xhr",          # Extract XHR requests
            "-aff",          # Automatic Form Filling
            "-dr",           # Disable redirect following (let katana handle it)
        ]

    def stream_katana(self, port, protocol='http'):
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)

    def stream_scan(self, port, protocol='http'):
        """Alias for stream_katana to satisfy enum.py contract"""
        return self.stream_katana(port, protocol)
