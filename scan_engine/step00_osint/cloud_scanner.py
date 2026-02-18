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
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                # RED TEAM: Attempt to list files for impact demonstration
                files = []
                try:
                    from xml.etree import ElementTree
                    root = ElementTree.fromstring(r.content)
                    # S3 XML namespace
                    ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                    contents = root.findall('s3:Contents', ns)
                    for item in contents[:10]: # List top 10 files
                        key = item.find('s3:Key', ns)
                        if key is not None:
                            files.append(key.text)
                except Exception:
                    files = []
                
                return {
                    "provider": "AWS S3", 
                    "bucket": bucket_name, 
                    "url": url, 
                    "status": "OPEN/PUBLIC",
                    "files": files
                }
            elif r.status_code == 403:
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": "PROTECTED"}
        except Exception:
            return None
        return None

    def check_azure(self, account_name):
        url = f"https://{account_name}.blob.core.windows.net"
        try:
            r = requests.get(url, timeout=1)
            # 400 or 403 on base URL usually means account exists
            if r.status_code in [400, 403]:
                return {"provider": "Azure Blob", "account": account_name, "url": url, "status": "EXISTS"}
        except Exception:
            return None
        return None

    def check_gcp(self, bucket_name):
        url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
        try:
            r = requests.get(url, timeout=1)
            if r.status_code == 200:
                 return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "OPEN/PUBLIC"}
            elif r.status_code == 403:
                return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "EXISTS"}
        except Exception:
            return None
        return None

    def scan_all(self, logger=None):
        # Professional Red Team Permutations (Expanded CloudEnum Style)
        bases = [self.target_name, self.target_name.replace('-', ''), self.target_name.replace('_', '')]
        
        # 1. Environment & Stage
        envs = ["dev", "development", "stage", "staging", "prod", "production", "test", "testing", "qa", "uat", "beta", "ops", "internal"]
        
        # 2. Content & Assets
        assets = ["assets", "static", "media", "images", "img", "css", "js", "files", "content", "upload", "uploads", "public", "cdn", "bucket"]
        
        # 3. Data & Sensitive
        sensitive = ["data", "db", "sql", "backup", "bak", "archive", "logs", "log", "audit", "private", "secret", "conf", "config", "dump"]
        
        # 4. Infrastructure & Tech
        infra = ["app", "web", "api", "core", "server", "infra", "deploy", "build", "ci", "cd", "k8s", "docker", "jenkins", "gitlab", "registry"]
        
        # 5. Business & Func
        biz = ["admin", "dashboard", "client", "customer", "user", "users", "corp", "finance", "hr", "sales", "marketing", "docs", "report", "reports"]

        suffixes = envs + assets + sensitive + infra + biz
        
        patterns = set()
        for b in bases:
            patterns.add(b)
            # Standard: target-suffix, targetsuffix, suffix-target
            for s in suffixes:
                patterns.add(f"{b}-{s}")
                patterns.add(f"{b}{s}")
                patterns.add(f"{s}-{b}")
                patterns.add(f"{s}{b}")
                
            # Double permutations for high value (e.g. dev-assets)
            for e in envs:
                for a in assets:
                     patterns.add(f"{b}-{e}-{a}")
                     patterns.add(f"{b}-{a}-{e}")

        if logger: logger(f"Cloud Audit: Checking {len(patterns)*3} potential cloud storage buckets (aggressive mode)...", "INFO")
        
        found = []
        import threading
        from queue import Queue

        q = Queue()
        for p in patterns:
            q.put(p)

        def worker():
            while not q.empty():
                try:
                    p = q.get_nowait()
                except:
                    break
                    
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
        for i in range(25): # Increased to 25 threads for larger wordlist
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
            
        if logger and found:
            logger(f"Cloud Audit: Found {len(found)} cloud resources associated with target.", "SUCCESS")
        
        return found
