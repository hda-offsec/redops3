import os
from scan_engine.helpers.process_manager import ProcessManager

class DalfoxScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        import shutil
        return shutil.which("dalfox") is not None

    def scan_url(self, url):
        """Run dalfox against a specific URL"""
        command = ["dalfox", "url", url, "--silent", "--no-color"]
        return ProcessManager.stream_command(command)
