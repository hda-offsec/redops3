import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WebReconScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        return shutil.which('whatweb') is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        return ["whatweb", "--color=never", "--no-errors", "-a", "3", url]

    def stream_whatweb(self, port, protocol='http'):
        """
        Runs WhatWeb against a specific port
        """
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)
