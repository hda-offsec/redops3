import shutil
from scan_engine.helpers.process_manager import ProcessManager

class ArjunScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('arjun') is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        return ["arjun", "-u", url]

    def stream_arjun(self, port, protocol='http'):
        """
        Runs arjun for parameter discovery.
        """
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)
