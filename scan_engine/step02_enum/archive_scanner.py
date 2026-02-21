import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import urllib.parse

class ArchiveScanner:
    """
    Archive Intelligence Scanner.
    Fetches historical URLs from Wayback Machine, AlienVault, and CommonCrawl.
    Useful for finding forgotten parameters, old endpoints, and subdomains.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.seen_urls = set()

    def fetch_wayback(self):
        urls = set()
        print(f"[DEBUG] Querying Wayback Machine for {self.target}...")
        try:
             # cdx api
             api_url = f"http://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&collapse=urlkey"
             r = http_client.get(api_url, options=getattr(self, "options", None), timeout=10)
             if r.status_code == 200:
                 data = r.json()
                 # Skip header row
                 if data and len(data) > 0:
                     for row in data[1:]:
                         # row format varies, usually [urlkey, timestamp, original, mimetype, statuscode, digest, length]
                         original_url = row[2]
                         urls.add(original_url)
        except Exception as e:
            print(f"[ERROR] Wayback fetch failed: {e}")
            
        return urls

    def fetch_alienvault(self):
        urls = set()
        print(f"[DEBUG] Querying AlienVault OTX for {self.target}...")
        try:
            api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/url_list?limit=500&page=1"
            r = http_client.get(api_url, options=getattr(self, "options", None), timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("url_list", []):
                    urls.add(item.get("url"))
        except Exception as e:
            print(f"[ERROR] AlienVault fetch failed: {e}")
        return urls

    def scan_archive(self, logger=None):
        all_urls = set()
        
        if logger: logger(f"Archive Intel: Querying checking history for {self.target}...", "INFO")
        
        # 1. Wayback
        wb = self.fetch_wayback()
        if wb:
            if logger: logger(f"Wayback Machine returned {len(wb)} historical URLs.", "SUCCESS")
            all_urls.update(wb)
            
        # 2. AlienVault
        av = self.fetch_alienvault()
        if av:
            if logger: logger(f"AlienVault OTX returned {len(av)} URLs.", "SUCCESS")
            all_urls.update(av)
            
        # Filter interesting parameters
        interesting_params = []
        interesting_kw = ['admin', 'debug', 'test', 'auth', 'redirect', 'url', 'file', 'path', 'config']
        
        # Analyze results
        findings = []
        
        for url in all_urls:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                # distinct param names
                qs = urllib.parse.parse_qs(parsed.query)
                for q in qs.keys():
                    if any(k in q.lower() for k in interesting_kw):
                        interesting_params.append(url)
                        break

        # Output structure
        result = {
            "total_urls": len(all_urls),
            "urls": list(all_urls),
            "interesting_params": list(set(interesting_params))
        }
        
        return result
