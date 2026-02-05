import logging
import shutil
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class FfufScanner:
    def __init__(self, target_url, wordlist_path, threads=30):
        self.target_url = target_url.rstrip("/")
        self.wordlist_path = wordlist_path
        self.threads = threads

    def check_tools(self):
        return shutil.which("ffuf") is not None

    def stream_scan(self):
        # -s for silent mode to output only results
        # -of md is also an option but we parse stdout line by line
        command = [
            "ffuf",
            "-u",
            f"{self.target_url}/FUZZ",
            "-w",
            self.wordlist_path,
            "-t",
            str(self.threads),
            "-mc",
            "200,204,301,302,307,401,403",
            "-s" 
        ]
        logger.info("Starting ffuf scan: %s", " ".join(command))
        return ProcessManager.stream_command(command)

