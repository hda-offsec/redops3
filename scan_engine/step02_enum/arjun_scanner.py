import shutil
from scan_engine.helpers.process_manager import ProcessManager

class ArjunScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('arjun') is not None

    def stream_arjun(self, port, protocol='http'):
        """
        Runs arjun for parameter discovery.
        --fast for speed.
        """
        url = f"{protocol}://{self.target}:{port}"
        # Using --fast for quicker discovery
        command = ["arjun", "-u", url, "--fast"]
        
        return ProcessManager.stream_command(command)
