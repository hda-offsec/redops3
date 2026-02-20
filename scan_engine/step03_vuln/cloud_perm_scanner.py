import requests
import xml.etree.ElementTree as ET

class CloudPermScanner:
    """
    Expert Module: Checks for public permissions on discovered Cloud Buckets (S3, Azure).
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-CloudExpert)"})

    def check_s3_bucket(self, bucket_url, logger=None):
        """Checks if an S3 bucket is publicly listable or writable."""
        findings = []
        if logger: logger(f"Cloud Audit: Checking S3 permissions for {bucket_url}", "DEBUG")
        
        # 1. Test Listing
        try:
            r = self.session.get(bucket_url, timeout=5)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                if logger: logger(f"🔥 S3 BUCKET PUBLIC: {bucket_url}", "CRITICAL")
                
                # Extract some keys as proof
                keys = []
                try:
                    root = ET.fromstring(r.text)
                    for content in root.findall("{http://s3.amazonaws.com/doc/2006-03-01/}Contents")[:5]:
                        key = content.find("{http://s3.amazonaws.com/doc/2006-03-01/}Key").text
                        keys.append(key)
                except Exception: pass
                
                findings.append({
                    "title": "Critical: Publicly Listable S3 Bucket",
                    "description": (
                        f"The S3 bucket `{bucket_url}` is publicly accessible.\n"
                        f"Anyone can list the files in this bucket.\n\n"
                        f"Sample Files:\n- " + "\n- ".join(keys) if keys else "No files found (but listable)."
                    ),
                    "severity": "critical",
                    "tool_source": "cloud_perm_expert",
                    "url": bucket_url,
                    "raw_loot": bucket_url,
                    "loot_type": "Cloud Asset"
                })
        except Exception: pass
        
        # 2. Test Writable (HEAD check or small PUT if allowed?) - Keeping it safe with just metadata/listing for now
        return findings

    def check_azure_blob(self, storage_url, logger=None):
        """Checks for public access on Azure Blob Containers."""
        findings = []
        # Azure usually follows: https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
        if "?restype=container" not in storage_url:
            test_url = storage_url.rstrip('/') + "?restype=container&comp=list"
        else:
            test_url = storage_url

        try:
            r = self.session.get(test_url, timeout=5)
            if r.status_code == 200 and "EnumerationResults" in r.text:
                if logger: logger(f"🔥 AZURE BLOB PUBLIC: {storage_url}", "CRITICAL")
                findings.append({
                    "title": "Critical: Publicly Accessible Azure Storage Container",
                    "description": f"The Azure storage container at `{storage_url}` is publicly accessible without authentication.",
                    "severity": "critical",
                    "tool_source": "cloud_perm_expert",
                    "url": storage_url,
                    "raw_loot": storage_url,
                    "loot_type": "Cloud Asset"
                })
        except Exception: pass
        
        return findings

    def scan_all(self, assets, logger=None):
        all_findings = []
        if not assets: return []
        
        for asset in assets:
            url = asset.get('url', asset.get('bucket', ''))
            if not url: continue
            
            if "s3.amazonaws.com" in url or "s3://" in url:
                # Normalize s3:// to http
                if url.startswith("s3://"):
                    bucket_name = url.replace("s3://", "")
                    url = f"https://{bucket_name}.s3.amazonaws.com"
                all_findings.extend(self.check_s3_bucket(url, logger))
            elif "blob.core.windows.net" in url:
                all_findings.extend(self.check_azure_blob(url, logger))
                
        return all_findings
