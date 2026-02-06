from scan_engine.helpers.process_manager import ProcessManager

class SQLMapScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        import shutil
        return shutil.which("sqlmap") is not None

    def scan_url(self, url):
        """Run sqlmap against a specific URL in batch mode"""
        # --batch: no user input, --random-agent: avoid detection, --level 1: basic
        command = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level", "1", "--risk", "1", "--threads", "5"]
        return ProcessManager.stream_command(command)
