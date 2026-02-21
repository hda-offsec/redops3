import requests
import time
from scan_engine.helpers.process_manager import ProcessManager

class HistoricScanner:
    """
    Expert Module: Fetches historic URLs from Wayback Machine API to expand attack surface.
    """
    def __init__(self, target, logger=None):
        self.target = target
        self.logger = logger

    def fetch_historic_urls(self):
        urls = set()
        api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=text&fl=original&collapse=urlkey"
        
        if self.logger: self.logger(f"Fetching historic URLs from Wayback Machine for {self.target}...", "INFO")
        
        try:
            # We use a timeout to avoid hanging the scan if Archive.org is slow
            response = requests.get(api_url, timeout=30)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    u = line.strip()
                    if u:
                        urls.add(u)
                if self.logger: self.logger(f"Discovered {len(urls)} historic URLs.", "SUCCESS")
            else:
                if self.logger: self.logger(f"Wayback Machine returned status {response.status_code}", "WARN")
        except Exception as e:
            if self.logger: self.logger(f"Failed to fetch historic URLs: {e}", "DEBUG")
            
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
