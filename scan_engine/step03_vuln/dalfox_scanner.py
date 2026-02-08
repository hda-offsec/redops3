from scan_engine.helpers.process_manager import ProcessManager

class DalfoxScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        """Checker for dalfox binary"""
        return ProcessManager.find_binary_path("dalfox") is not None

    def stream_scan_xss(self, port, protocol='http'):
        """
        Runs Dalfox XSS scanner against the target by first crawling (or assuming) a parameter list.
        Dalfox works best when fed URLs with parameters.
        Since we might not have a URL list yet, we can try to point it at the base URL (pipe mode is better usually).
        """
        url = f"{protocol}://{self.target}:{port}"
        
        # dalfox url <Target> -S (silence)
        # --no-color because we parse text
        # --skip-mining-dom : faster
        # --skip-mining-dict : faster
        path = ProcessManager.find_binary_path("dalfox") or "dalfox"
        
        command = [
            path, "url", url,
            "--no-color",
            "--silence",
            "--worker", "10", # speed up
            "--skip-bav" # skip boolean analysis verifier for speed if needed, but let's keep basic checks
        ]
        
        return ProcessManager.stream_command(command)

    def stream_scan_pipe(self, urls):
        """
        Takes a list of URLs (with parameters) and scans them via pipe simulation or file input.
        For simplicity, we might just loop "dalfox url" or write to a temp file then dalfox file.
        Using 'file' mode is safer for large lists.
        """
        pass # To implement if we feed it katana results
