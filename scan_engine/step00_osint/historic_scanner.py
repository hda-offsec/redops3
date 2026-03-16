import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import time
from scan_engine.helpers.process_manager import ProcessManager

class HistoricScanner:
    """
    Expert Module: Fetches historic URLs from Wayback Machine API to expand attack surface.
    """
    def __init__(self, target, logger=None, options=None):
        self.options = options
        self.target = target
        self.logger = logger

    def fetch_historic_urls(self):
        urls = set()
        api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=text&fl=original&collapse=urlkey"
        
        if self.logger: self.logger(f"Fetching historic URLs from Wayback Machine for {self.target}...", "INFO")
        
        # Custom options for Wayback (notorious for timeouts/503)
        archive_opts = (self.options or {}).copy()
        archive_opts["read_timeout"] = 60.0 # 1 minute read timeout
        archive_opts["max_retries"] = 5
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if self.logger: self.logger(f"Wayback Query (Attempt {attempt+1}/{max_attempts}): {self.target}", "DEBUG")
                response = http_client.get(api_url, options=archive_opts, timeout=60)
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        u = line.strip()
                        if u:
                            urls.add(u)
                    if self.logger: self.logger(f"Discovered {len(urls)} historic URLs.", "SUCCESS")
                    break 
                elif response.status_code == 503:
                    if self.logger: self.logger(f"Wayback 503 (Busy). Retrying...", "WARN")
                    time.sleep(2)
                else:
                    if self.logger: self.logger(f"Wayback Machine returned status {response.status_code}", "WARN")
                    break 
            except Exception as e:
                if attempt == max_attempts - 1:
                    if self.logger: self.logger(f"Wayback fetch failed after {max_attempts} attempts: {e}", "ERROR")
                else:
                    if self.logger: self.logger(f"Wayback attempt {attempt+1} failed: {e}. Retrying...", "DEBUG")
                    time.sleep(2)

            
        return list(urls)

    def process_discovered_urls(self, urls):
        """
        Filters and normalizes URLs for downstream tools.
        """
        interesting_exts = ['.php', '.asp', '.aspx', '.jsp', '.jspx', '.cgi', '.pl', '.py', '.rb']
        interesting_keywords = ['admin', 'api', 'v1', 'v2', 'debug', 'config', 'setup', 'backup', 'db', 'sql', 'upload', 'download']
        
        candidates = []
        for u in urls:
            u_lower = u.lower()
            # Heuristic: keep if it has parameters or interesting extension/keyword
            if '?' in u or any(ext in u_lower for ext in interesting_exts) or any(key in u_lower for key in interesting_keywords):
                candidates.append(u)
        
        return candidates
