import tempfile
import os
from urllib.parse import urlparse
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
        Writes URLs to a temp file and runs dalfox in file mode for batch scanning.
        Returns a stream of events (same contract as stream_command).
        """
        if not urls:
            return iter([])

        # Scope enforcement: only allow URLs whose host matches/is subdomain of target
        target_host = self.target.lower()
        scoped_urls = []
        for u in urls:
            p = urlparse(u)
            if p.hostname and p.hostname.lower().endswith(target_host):
                scoped_urls.append(u)

        if not scoped_urls:
            return iter([])

        fd, url_file = tempfile.mkstemp(suffix=".txt", prefix="redops_dalfox_")
        try:
            with os.fdopen(fd, 'w') as f:
                for u in scoped_urls:
                    f.write(u + "\n")

            path = ProcessManager.find_binary_path("dalfox") or "dalfox"
            command = [
                path, "file", url_file,
                "--no-color", "--silence",
                "--skip-bav", "--worker", "4",
            ]
            yield from ProcessManager.stream_command(command)
        finally:
            if os.path.exists(url_file):
                os.remove(url_file)

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

