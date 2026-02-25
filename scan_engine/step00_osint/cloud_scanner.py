import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import threading

class CloudScanner:
    def __init__(self, target, options=None, dns_subdomains=None):
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        self.options = options or {}
        self.target = target
        # Cap DNS subdomains to top 50 to avoid hours-long hangs testing millions of permutations
        self.dns_subdomains = (dns_subdomains or [])[:50]

        
        # Extract keywords from domain parts
        parts = target.lower().split('.')
        self.keywords = [p for p in parts if len(p) > 2 and p not in ['com', 'org', 'net', 'io', 'cloud', 'app', 'gov', 'edu']]
        
        self.target_name = self.keywords[0] if self.keywords else target.split('.')[0]
        
        # Hardened session: ABSOLUTELY NO RETRIES to avoid log flooding with NameResolutionError
        self.session = get_session(self.options)
        no_retry_adapter = HTTPAdapter(max_retries=Retry(total=0, connect=0, read=0, status=0, raise_on_status=False), pool_connections=30, pool_maxsize=30)
        self.session.mount("http://", no_retry_adapter)
        self.session.mount("https://", no_retry_adapter)
        self.results = []

    def check_s3(self, bucket_name):
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            # Silence is golden: use self.session and suppress errors
            r = self.session.get(url, timeout=2)
            if r.status_code == 200:
                files = []
                try:
                    from xml.etree import ElementTree
                    root = ElementTree.fromstring(r.content)
                    ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                    contents = root.findall('s3:Contents', ns)
                    for item in contents[:10]:
                        key = item.find('s3:Key', ns)
                        if key is not None:
                            files.append(key.text)
                except Exception: pass
                
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "OPEN/PUBLIC", "files": files}
            elif r.status_code == 403:
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "PROTECTED"}
        except Exception: pass
        return None

    def check_azure(self, account_name):
        # Azure account names: 3-24 alphanumeric
        if not account_name.isalnum() or len(account_name) < 3 or len(account_name) > 24:
            return None
        url = f"https://{account_name}.blob.core.windows.net"
        try:
            r = self.session.get(url, timeout=2)
            if r.status_code in [400, 403]:
                return {"provider": "Azure Blob", "account": account_name, "url": url, "status": "EXISTS"}
        except Exception: pass
        return None

    def check_gcp(self, bucket_name):
        url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
        try:
            r = self.session.get(url, timeout=2)
            if r.status_code == 200:
                 return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "OPEN/PUBLIC"}
            elif r.status_code == 403:
                return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "EXISTS"}
        except Exception: pass
        return None

    def _load_patterns(self):
        import os
        patterns = ["dev", "stage", "prod", "test", "qa", "ops", "internal", "assets", "static", "media", "images", "files", "content", "public", "cdn", "data", "db", "sql", "backup", "archive", "logs", "config", "dump", "app", "web", "api", "core", "deploy", "build", "registry"]
        pattern_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data/wordlists/cloud_patterns.txt")
        if os.path.exists(pattern_file):
            try:
                with open(pattern_file, 'r') as f:
                    patterns = [line.strip() for line in f if line.strip()]
            except Exception: pass
        return list(set(patterns))

    def scan_all(self, logger=None):
        suffixes = self._load_patterns()
        patterns = set()
        
        # 1. Base Target
        target_exact = self.target.lower().strip()
        patterns.add(target_exact)
        
        # 2. Add DNS Intelligence Subdomains as explicit targets
        for sub in self.dns_subdomains:
            if sub and isinstance(sub, str):
                patterns.add(sub.lower().strip())
                
        # 3. UX Requested Mutations: pattern.target & pattern-target
        # Example: dev.datahub.navitia.io & dev-datahub.navitia.io
        for s in suffixes:
            patterns.add(f"{s}.{target_exact}")
            patterns.add(f"{s}-{target_exact}")
            # Also generate a purely alphanumeric slug for Azure (which rejects dots and dashes)
            slug = target_exact.replace('.', '').replace('-', '')
            patterns.add(f"{s}{slug}")
            
        if logger: logger(f"Cloud Audit: Checking patterns on target '{target_exact}' (+{len(self.dns_subdomains)} DNS subdomains). Testing {len(patterns)} variations.", "INFO")
        
        found = []
        from queue import Queue
        q = Queue()
        for p in patterns:
            q.put(p)

        def worker():
            while not q.empty():
                try:
                    p = q.get_nowait()
                except Exception: break
                
                # AWS S3
                s3 = self.check_s3(p)
                if s3: found.append(s3)
                # Azure Blob
                if len(p) <= 24:
                    az = self.check_azure(p)
                    if az: found.append(az)
                # Google GCP
                gcp = self.check_gcp(p)
                if gcp: found.append(gcp)
                q.task_done()

        threads = []
        thread_count = 15
        for i in range(thread_count):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
            
        return found
