import tempfile
import os
import signal
import subprocess
import threading
from urllib.parse import urlparse
from scan_engine.helpers.process_manager import ProcessManager

# Maximum time (seconds) Dalfox may run for a batch scan before being killed.
DALFOX_GLOBAL_TIMEOUT = 900  # 15 minutes


class DalfoxScanner:
    def __init__(self, target, options=None):
        self.options = options
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
            "--skip-bav",
            "--timeout", "10",
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
        Includes a global timeout to prevent indefinite blocking on rate-limited sites.
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
                "--timeout", "10",
            ]

            # --- GLOBAL TIMEOUT: Kill dalfox if it exceeds DALFOX_GLOBAL_TIMEOUT ---
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Watchdog timer
            killed = threading.Event()

            def _kill_on_timeout():
                killed.set()
                try:
                    process.kill()
                except Exception:
                    pass

            timer = threading.Timer(DALFOX_GLOBAL_TIMEOUT, _kill_on_timeout)
            timer.daemon = True
            timer.start()

            try:
                for line in iter(process.stdout.readline, ''):
                    if line:
                        yield {"type": "stdout", "line": line.rstrip('\n\r')}
                process.stdout.close()
                return_code = process.wait()

                if killed.is_set():
                    yield {"type": "stdout", "line": f"[TIMEOUT] Dalfox killed after {DALFOX_GLOBAL_TIMEOUT}s global timeout."}
                    yield {"type": "exit", "code": -9}
                else:
                    yield {"type": "exit", "code": return_code}
            finally:
                timer.cancel()

        finally:
            if os.path.exists(url_file):
                os.remove(url_file)

    def stream_scan_url(self, url):
        """
        Scans a single URL.
        """
        path = ProcessManager.find_binary_path("dalfox") or "dalfox"
        command = [path, "url", url, "--no-color", "--silence", "--skip-bav", "--worker", "10", "--timeout", "10"]
        
        stream = ProcessManager.stream_command(command)
        for event in stream:
            pass

