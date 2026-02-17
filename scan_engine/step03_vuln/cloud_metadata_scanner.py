import re
import requests
from scan_engine.helpers.process_manager import ProcessManager

class CloudMetadataScanner:
    """
    Scans for Cloud Metadata Exposure via Reverse Proxy Misconfigurations.
    Checks for: AWS, Azure, GCP, DigitalOcean, Alibaba, Oracle.
    """
    def __init__(self, target):
        self.target = target
        self.metadata_paths = {
            "aws": ["/latest/meta-data/", "/latest/user-data/"],
            "azure": ["/metadata/instance?api-version=2021-02-01"],
            "gcp": ["/computeMetadata/v1/", "/computeMetadata/v1beta1/instance/service-accounts/default/token"],
            "digitalocean": ["/metadata/v1/"],
            "alibaba": ["/latest/meta-data/"],
            "oracle": ["/opc/v1/instance/"]
        }
        self.headers = {
            "Metadata": "true", # Required for Azure/GCP sometimes, but if proxy forwards it, it might work
            "X-Google-Metadata-Request": "True" 
        }

    def check_tools(self):
        return True # Uses requests

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        if logger: logger(f"Cloud Metadata: Probing {base_url} for proxy misconfigurations...", "INFO")

        for provider, paths in self.metadata_paths.items():
            for path in paths:
                url = f"{base_url}{path}"
                try:
                    # Short timeout because if it's not a proxy, it will likely 404 fast or timeout
                    r = requests.get(url, headers=self.headers, timeout=3, verify=False, allow_redirects=False)
                    
                    if r.status_code == 200:
                        # Validation logic to reduce false positives
                        content = r.text.lower()
                        is_vuln = False
                        
                        if provider == "aws" and "ami-id" in content: is_vuln = True
                        elif provider == "azure" and "compute" in content and "location" in content: is_vuln = True
                        elif provider == "gcp" and "instance" in content: is_vuln = True
                        elif provider == "digitalocean" and "droplet_id" in content: is_vuln = True
                        
                        if is_vuln:
                            findings.append({
                                "title": f"Critical Cloud Metadata Exposure ({provider.upper()})",
                                "description": f"The application appears to be proxying requests to the internal Cloud Metadata service.\n\nURL: {url}\n\nThis is a critical vulnerability allowing full cloud account compromise.",
                                "severity": "critical",
                                "tool_source": "cloud_metadata_scanner",
                                "raw_loot": r.text[:1000]
                            })
                            if logger: logger(f"CRITICAL: Found {provider.upper()} metadata at {url}", "CRITICAL")
                            return findings # Stop after first confirmed hit to avoid noise/alarms
                except:
                    pass
        
        return findings
