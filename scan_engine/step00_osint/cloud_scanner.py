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
            if r.status_code != 404:
                # 200 = Open/Public, 403 = Protected but exists
                status = "PROTECTED" if r.status_code == 403 else "OPEN/PUBLIC"
                return {"provider": "AWS S3", "bucket": bucket_name, "url": url, "status": status}
        except:
            pass
        return None

    def check_azure(self, account_name):
        url = f"https://{account_name}.blob.core.windows.net"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 404:
                return {"provider": "Azure Blob", "account": account_name, "url": url, "status": "EXISTS"}
        except:
            pass
        return None

    def check_gcp(self, bucket_name):
        url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 404:
                return {"provider": "Google GCP", "bucket": bucket_name, "url": url, "status": "EXISTS"}
        except:
            pass
        return None

    def scan_all(self, logger=None):
        patterns = [
            self.target_name,
            f"{self.target_name}-data",
            f"{self.target_name}-backup",
            f"{self.target_name}-dev",
            f"{self.target_name}-staging",
            f"{self.target_name}-prod",
            f"{self.target_name}-assets",
            f"{self.target_name}-public"
        ]
        
        if logger: logger(f"Cloud Audit: Checking {len(patterns)*3} potential cloud storage buckets...", "INFO")
        
        found = []
        for p in patterns:
            # Simple synchronous for now for stability, can be threaded later
            s3 = self.check_s3(p)
            if s3: found.append(s3)
            
            az = self.check_azure(p)
            if az: found.append(az)
            
            gcp = self.check_gcp(p)
            if gcp: found.append(gcp)
            
        if logger and found:
            logger(f"Cloud Audit: Found {len(found)} cloud resources associated with target.", "SUCCESS")
        
        return found
