import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import mmh3
import codecs
import base64

class FaviconScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def calculate_hash(self, url):
        try:
            response = http_client.get(url, options=getattr(self, "options", None), timeout=10)
            if response.status_code == 200:
                favicon = codecs.encode(response.content, 'base64')
                hash_val = mmh3.hash(favicon)
                return hash_val
        except Exception:
            pass
        return None

    def scan(self, port=80, protocol='http', logger=None):
        url = f"{protocol}://{self.target}:{port}/favicon.ico"
        if logger: logger(f"OSINT: Calculating Favicon Hash for {url}...", "INFO")
        
        hash_val = self.calculate_hash(url)
        if hash_val:
            shodan_query = f"http.component:\"favicon\" http.hash:{hash_val}"
            if logger: logger(f"🎯 Favicon Hash: {hash_val} (Shodan Query: {shodan_query})", "SUCCESS")
            return {
                "hash": hash_val,
                "shodan_query": shodan_query,
                "url": url
            }
        return None
