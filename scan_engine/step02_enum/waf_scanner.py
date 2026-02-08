import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WafScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('wafw00f') is not None

    def stream_wafw00f(self, port, protocol='http'):
        """
        Runs wafw00f against a specific port
        """
        url = f"{protocol}://{self.target}:{port}"
        # -a: check all WAFs
        command = ["wafw00f", "-a", url]
        
        return ProcessManager.stream_command(command)
