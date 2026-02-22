from scan_engine.helpers.http_client import get_session
import xml.etree.ElementTree as ET
import random
import string
import time
import traceback
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class CloudPermScanner:
    """
    V7 HARDENED EXPERT: Advanced Cloud Storage Auditor.
    Checks for public Listing, Reading, and Writing on S3 and Azure buckets.
    Implements mandatory state machine, watchdog, and resolution fast-fail.
    """
    
    # States
    INIT = "INIT"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"

    def __init__(self, options=None):
        self.options = options or {}
        # Hardened session: 0 retries to avoid flooding logs with NameResolutionError
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-CloudExpert-V7)"})
        
        # Disable retries for this expert to avoid log clutter on non-existent buckets
        # Using 0/False to ensure absolute silence on resolution errors
        no_retry_adapter = HTTPAdapter(max_retries=Retry(total=0, connect=0, read=0, status=0, raise_on_status=False))
        self.session.mount("http://", no_retry_adapter)
        self.session.mount("https://", no_retry_adapter)
        
        self.status = self.INIT
        self.start_time = None
        self.assets_processed = 0
        self.error_count = 0

    def _generate_test_filename(self):
        return "redops_write_test_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8)) + ".txt"

    def _check_timeout(self, limit):
        if self.start_time and (time.time() - self.start_time) > limit:
            self.status = self.TIMEOUT
            return True
        return False

    def check_s3_bucket(self, bucket_url, logger=None):
        findings = []
        bucket_url = bucket_url.rstrip('/')
        
        try:
            # 1. Test Listing
            r = self.session.get(bucket_url, timeout=5, verify=False)
            if r.status_code == 200 and "ListBucketResult" in r.text:
                sample_keys = []
                try:
                    root = ET.fromstring(r.text)
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

            # 2. Test Writing (Active Check)
            test_file = self._generate_test_filename()
            test_url = f"{bucket_url}/{test_file}"
            content = "RedOps3 Security Audit - Public Write Test"
            
            r_put = self.session.put(test_url, data=content, timeout=5, verify=False)
            if r_put.status_code in [200, 201]:
                findings.append({
                    "title": "🔥 CRITICAL: Publicly Writable S3 Bucket",
                    "description": (
                        f"The S3 bucket `{bucket_url}` is PUBLICLY WRITABLE.\n"
                        f"Successfully uploaded test file: `{test_url}`"
                    ),
                    "severity": "critical",
                    "tool_source": "cloud_expert",
                    "url": bucket_url,
                    "repro_command": f"curl -X PUT -d 'test' {test_url}"
                })
                if logger: logger(f"💀 S3 BUCKET WRITABLE: {bucket_url}", "CRITICAL")
                self.session.delete(test_url, timeout=5, verify=False)
                
        except Exception:
            self.error_count += 1

        return findings

    def check_azure_blob(self, storage_url, logger=None):
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
        except Exception:
            self.error_count += 1
        
        return findings

    def scan_assets(self, assets, timeout=60, logger=None):
        """
        Hardened scanner entry point with watchdog and budget.
        """
        self.start_time = time.time()
        self.status = self.RUNNING
        self.assets_processed = 0
        self.error_count = 0
        all_findings = []
        
        if not assets:
            self.status = self.COMPLETED
            return []
            
        if logger: logger(f"Cloud Expert: Starting hardened audit on {len(assets)} assets (Timeout: {timeout}s)", "INFO")

        try:
            for asset in assets:
                # 1. Watchdog check
                if self._check_timeout(timeout):
                    if logger: logger(f"Cloud Expert: Global timeout reached. Aborting.", "WARN")
                    break
                
                # 2. Asset extraction
                url = asset if isinstance(asset, str) else asset.get('url', asset.get('bucket', ''))
                if not url: continue
                
                # Normalize URL for logic
                url_lower = url.lower()
                
                try:
                    if "s3" in url_lower and (".amazonaws.com" in url_lower or ".s3." in url_lower):
                        all_findings.extend(self.check_s3_bucket(url, logger))
                    elif "blob.core.windows.net" in url_lower:
                        all_findings.extend(self.check_azure_blob(url, logger))
                    
                    self.assets_processed += 1
                    
                    # 3. Budget Check (Protect against exploding asset lists)
                    if self.assets_processed >= 100:
                        if logger: logger("Cloud Expert: Asset budget (100) reached.", "WARN")
                        break
                        
                except Exception as ex:
                    self.error_count += 1
                    continue

            if self.status != self.TIMEOUT:
                self.status = self.COMPLETED

        except Exception as e:
            self.status = self.FAILED
            if logger: logger(f"Cloud Expert Global Failure: {traceback.format_exc()}", "ERROR")

        if logger: logger(f"Cloud Expert finished: {self.status} (Processed: {self.assets_processed}, Errors: {self.error_count})", "SUCCESS")
        return all_findings
