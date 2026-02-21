import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WafScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        return shutil.which('wafw00f') is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        return ["wafw00f", "-a", url]

    def stream_wafw00f(self, port, protocol='http'):
        """
        Runs wafw00f against a specific port
        """
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)
