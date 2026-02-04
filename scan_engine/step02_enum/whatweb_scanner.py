import logging
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)


class WhatWebScanner:
    def __init__(self, target_url):
        self.target_url = target_url

    def stream_scan(self):
        command = ["whatweb", "-a", "3", self.target_url]
        logger.info("Starting WhatWeb scan for %s", self.target_url)
        return ProcessManager.stream_command(command)
