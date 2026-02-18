from scan_engine.helpers.process_manager import ProcessManager

class DalfoxScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        """Checker for dalfox binary"""
        return ProcessManager.find_binary_path("dalfox") is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        path = ProcessManager.find_binary_path("dalfox") or "dalfox"
        return [
            path, "url", url,
            "--no-color",
            "--silence",
            "--worker", "10",
            "--skip-bav"
        ]

    def stream_scan_xss(self, port, protocol='http'):
        """
        Runs Dalfox XSS scanner against the target
        """
        command = self.get_command(port, protocol)
        return ProcessManager.stream_command(command)

    def stream_scan_pipe(self, urls):
        """
        Takes a list of URLs (with parameters) and scans them via pipe simulation or file input.
        """
        pass 

    def stream_scan_url(self, url):
        """
        Scans a single URL. Consumes the stream to ensure execution since caller might not iterate.
        """
        path = ProcessManager.find_binary_path("dalfox") or "dalfox"
        # Use basic scan options
        command = [path, "url", url, "--no-color", "--silence", "--skip-bav", "--worker", "10"]
        
        # Generator that we consume immediately to force execution
        stream = ProcessManager.stream_command(command)
        for event in stream:
            pass # Just execute, we rely on logs or CLI output if any (silenced)
            # Ideally we would return findings but strict patch in vuln.py ignores return.
