import logging
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class NucleiScanner:
    def __init__(self, target_url, severity="low,medium,high,critical"):
        self.target_url = target_url
        self.severity = severity

    def stream_scan(self):
        command = ["nuclei", "-u", self.target_url, "-severity", self.severity]
        logger.info("Starting Nuclei scan for %s", self.target_url)
        return ProcessManager.stream_command(command)
