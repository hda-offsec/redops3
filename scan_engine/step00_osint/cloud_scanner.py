import requests
import threading

class CloudScanner:
    def __init__(self, target):
        # target could be "example.com", we want "example"
        self.target_name = target.split('.')[0]
        self.results = []

    def check_s3(self, bucket_name):
        url = f"http://{bucket_name}.s3.amazonaws.com"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "OPEN/PUBLIC"}
            elif r.status_code == 403:
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "PROTECTED"}
        except:
            pass
        return None

    def check_azure(self, account_name):
        url = f"https://{account_name}.blob.core.windows.net"
        try:
            r = requests.get(url, timeout=5)
            # 400 or 403 on base URL usually means account exists
            if r.status_code in [400, 403]:
                return {"provider": "Azure Blob", "account": account_name, "url": url, "status": "EXISTS"}
        except:
            pass
        return None

    def check_gcp(self, bucket_name):
        url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                 return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "OPEN/PUBLIC"}
            elif r.status_code == 403:
                return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "EXISTS"}
        except:
            pass
        return None

    def scan_all(self, logger=None):
        # Professional Red Team Permutations
        bases = [self.target_name, self.target_name.replace('-', ''), self.target_name.replace('_', '')]
        suffixes = [
            # Environment
            "dev", "development", "staging", "stg", "prod", "production", "test", "demo",
            # Content
            "assets", "data", "static", "media", "images", "img", "files", "public", "private", "secret",
            # Technical
            "backup", "bak", "archive", "arc", "old", "new", "temp", "tmp", "db", "sql", "database",
            # Functional
            "logs", "logging", "audit", "internal", "corp", "admin", "management", "client", "customer",
            # Infrastructure
            "web", "app", "api", "infra", "kubernetes", "k8s", "docker", "registry", "mirror"
        ]
        
        patterns = set()
        for b in bases:
            patterns.add(b)
            for s in suffixes:
                patterns.add(f"{b}-{s}")
                patterns.add(f"{b}{s}")
                patterns.add(f"{s}-{b}")
        
        if logger: logger(f"Cloud Audit: Checking {len(patterns)*3} potential cloud storage buckets (aggressive mode)...", "INFO")
        
        found = []
        # Use simple threading to speed up the large number of checks
        import threading
        from queue import Queue

        q = Queue()
        for p in patterns:
            q.put(p)

        def worker():
            while not q.empty():
                p = q.get()
                # AWS
                s3 = self.check_s3(p)
                if s3: found.append(s3)
                # Azure
                az = self.check_azure(p)
                if az: found.append(az)
                # GCP
                gcp = self.check_gcp(p)
                if gcp: found.append(gcp)
                q.task_done()

        threads = []
        for i in range(10): # 10 threads for cloud discovery
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
            
        if logger and found:
            logger(f"Cloud Audit: Found {len(found)} cloud resources associated with target.", "SUCCESS")
        
        return found
