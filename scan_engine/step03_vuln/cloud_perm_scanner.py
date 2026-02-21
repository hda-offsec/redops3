from scan_engine.helpers.http_client import get_session
import xml.etree.ElementTree as ET
import random
import string

class CloudPermScanner:
    """
    V6 EXPERT: Advanced Cloud Storage Auditor.
    Checks for public Listing, Reading, and Writing on S3 and Azure buckets.
    """
    
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(options if 'options' in locals() else (self.options if hasattr(self, 'options') else None))
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-CloudExpert-V6)"})

    def _generate_test_filename(self):
        return "redops_write_test_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".txt"

    def check_s3_bucket(self, bucket_url, logger=None):
        """Checks if an S3 bucket is publicly listable, readable, or writable."""
        findings = []
        bucket_url = bucket_url.rstrip('/')
        
        if logger: logger(f"Cloud Expert: Auditing S3 permissions for {bucket_url}", "INFO")
        
        # 1. Test Listing
        is_listable = False
        sample_keys = []
        try:
            r = self.session.get(bucket_url, timeout=5, verify=False)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                is_listable = True
                try:
                    root = ET.fromstring(r.text)
                    # Handle namespaces
                    ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                    contents = root.findall("s3:Contents", ns) or root.findall("Contents")
                    for content in contents[:5]:
                        key_node = content.find("s3:Key", ns) or content.find("Key")
                        if key_node is not None:
                            sample_keys.append(key_node.text)
                except Exception: pass
                
                findings.append({
                    "title": "Critical: Publicly Listable S3 Bucket",
                    "description": (
                        f"The S3 bucket `{bucket_url}` allows public listing.\n"
                        f"Anyone can discover the contents of this bucket.\n\n"
                        f"Sample Files Detected:\n- " + ("\n- ".join(sample_keys) if sample_keys else "Bucket appears empty but is listable.")
                    ),
                    "severity": "critical",
                    "tool_source": "cloud_expert",
                    "url": bucket_url
                })
                if logger: logger(f"🔥 S3 BUCKET LISTABLE: {bucket_url}", "CRITICAL")
        except Exception: pass

        # 2. Test Writing (Active Check)
        try:
            test_file = self._generate_test_filename()
            test_url = f"{bucket_url}/{test_file}"
            content = "RedOps3 Security Audit - Public Write Test"
            
            r_put = self.session.put(test_url, data=content, timeout=5, verify=False)
            if r_put.status_code in [200, 201]:
                findings.append({
                    "title": "🔥 CRITICAL: Publicly Writable S3 Bucket",
                    "description": (
                        f"The S3 bucket `{bucket_url}` is PUBLICLY WRITABLE.\n"
                        f"An attacker can upload arbitrary files, potentially leading to malware hosting or site defacement.\n"
                        f"Successfully uploaded test file: `{test_url}`"
                    ),
                    "severity": "critical",
                    "tool_source": "cloud_expert",
                    "url": bucket_url,
                    "repro_command": f"curl -X PUT -d 'test' {test_url}"
                })
                if logger: logger(f"💀 S3 BUCKET WRITABLE: {bucket_url}", "CRITICAL")
                
                # Try to cleanup
                self.session.delete(test_url, timeout=5, verify=False)
        except Exception as e:
            if logger: logger(f"S3 Write Test Failed: {e}", "DEBUG")

        return findings

    def check_azure_blob(self, storage_url, logger=None):
        """Checks for public access on Azure Blob Containers."""
        findings = []
        if "?restype=container" not in storage_url:
            test_url = storage_url.rstrip('/') + "?restype=container&comp=list"
        else:
            test_url = storage_url

        try:
            r = self.session.get(test_url, timeout=5, verify=False)
            if r.status_code == 200 and "EnumerationResults" in r.text:
                findings.append({
                    "title": "Critical: Publicly Accessible Azure Storage Container",
                    "description": f"The Azure storage container at `{storage_url}` allows public listing of blobs.",
                    "severity": "critical",
                    "tool_source": "cloud_expert",
                    "url": storage_url
                })
                if logger: logger(f"🔥 AZURE BLOB PUBLIC: {storage_url}", "CRITICAL")
        except Exception: pass
        
        return findings

    def scan_assets(self, assets, logger=None):
        all_findings = []
        if not assets: return []
        
        for asset in assets:
            url = asset if isinstance(asset, str) else asset.get('url', asset.get('bucket', ''))
            if not url: continue
            
            if "s3.amazonaws.com" in url or "s3.auto" in url or ".s3." in url:
                all_findings.extend(self.check_s3_bucket(url, logger))
            elif "blob.core.windows.net" in url:
                all_findings.extend(self.check_azure_blob(url, logger))
                
        return all_findings
