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
        For simplicity, we might just loop "dalfox url" or write to a temp file then dalfox file.
        Using 'file' mode is safer for large lists.
        """
        pass # To implement if we feed it katana results
