import re
import requests
from datetime import datetime

class CloudStorageExpert:
    """
    Tactical module to identify and verify exposed cloud storage (S3/Azure/GCP).
    Scans targets for cloud resource patterns and checks for public accessibility.
    """
    
    BUCKET_PATTERNS = {
        "aws_s3": r"([a-z0-9\.-]+)\.s3[\.-]([a-z0-9-]+)?\.?amazonaws\.com",
        "gcp_storage": r"storage\.googleapis\.com/([a-z0-9\.-]+)",
        "azure_blob": r"([a-z0-9]+)\.blob\.core\.windows\.net",
    }

    def __init__(self, scan_id):
        self.scan_id = scan_id

    def scan(self, discovery_data, logger=None):
        """
        Scans discovery data (assets, endpoints) for cloud buckets.
        """
        findings = []
        # Convert discovery data to string for searching
        corpus = str(discovery_data)
        
        for cloud_type, pattern in self.BUCKET_PATTERNS.items():
            matches = re.finditer(pattern, corpus)
            for match in matches:
                bucket_name = match.group(1)
                full_url = match.group(0)
                if not full_url.startswith('http'):
                    full_url = f"https://{full_url}"
                
                if logger: logger(f"☁️ CloudStorageExpert: Inspecting potential {cloud_type} bucket: {bucket_name}", "INFO")
                
                status = self._verify_bucket(cloud_type, bucket_name, full_url)
                if status["exposed"]:
                    if logger: logger(f"🚨 CloudStorageExpert: Exposed {cloud_type} bucket found: {bucket_name}!", "WARNING")
                    findings.append({
                        "title": f"Exposed {cloud_type.replace('_', ' ').upper()} Bucket: {bucket_name}",
                        "description": f"The cloud storage bucket is publicly accessible.\n\n**Finding**: {status['reason']}\n**URL**: {full_url}",
                        "severity": "high",
                        "confidence": "high",
                        "category": "cloud_exposure",
                        "tool_source": "cloud_expert",
                        "endpoint": full_url,
                        "metadata": {
                            "bucket_name": bucket_name,
                            "cloud_provider": cloud_type,
                            "exposure_type": status["exposure_type"],
                            "check_timestamp": datetime.utcnow().isoformat()
                        },
                        "remediation": self._get_remediation(cloud_type)
                    })
        return findings

    def _verify_bucket(self, cloud_type, bucket_name, url):
        res = {"exposed": False, "reason": "", "exposure_type": "none"}
        
        try:
            if cloud_type == "aws_s3":
                # Check for public listing
                list_url = f"{url}?max-keys=1"
                r = requests.get(list_url, timeout=5)
                if r.status_code == 200 and "<ListBucketResult" in r.text:
                    res = {"exposed": True, "reason": "Public bucket listing is enabled.", "exposure_type": "listing_enabled"}
                elif r.status_code == 403:
                    # Check for direct file access if we had a filename, but for now we focus on listing
                    pass
            
            elif cloud_type == "gcp_storage":
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and "Items" in r.text:
                     res = {"exposed": True, "reason": "Public access to GCP bucket confirmed.", "exposure_type": "public_access"}

            elif cloud_type == "azure_blob":
                # Azure usually requires container name to list, but we can check if the account exists
                # For now, simplistic check
                pass
                
        except Exception:
            pass
            
        return res

    def _get_remediation(self, cloud_type):
        return (
            "1. **Enforce Public Access Block**: Enable 'Block all public access' at the bucket and account level.\n"
            "2. **IAM Policy Review**: Ensure bucket policies and ACLs follow the principle of least privilege.\n"
            "3. **Audit Content**: Review existing files for PII or sensitive secrets before re-securing."
        )
