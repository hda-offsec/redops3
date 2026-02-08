import shutil
from scan_engine.helpers.process_manager import ProcessManager

class WebReconScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return shutil.which('whatweb') is not None

    def stream_whatweb(self, port, protocol='http', aggression=1):
        """
        Runs WhatWeb against a specific port
        """
        url = f"{protocol}://{self.target}:{port}"
        # --color=never to avoid ANSI codes in output parsing
        # --log-json could be used, but let's stick to text stream for UI consistency first
        command = ["whatweb", "--color=never", "--no-errors", "-a", str(aggression), url]
        
        return ProcessManager.stream_command(command)
