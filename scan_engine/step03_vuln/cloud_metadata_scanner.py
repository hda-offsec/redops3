import re
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
from scan_engine.helpers.process_manager import ProcessManager

class CloudMetadataScanner:
    """
    Scans for Cloud Metadata Exposure via Reverse Proxy Misconfigurations.
    Checks for: AWS, Azure, GCP, DigitalOcean, Alibaba, Oracle.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.metadata_paths = {
            "aws": [
                "/latest/meta-data/iam/security-credentials/",
                "/latest/meta-data/instance-id",
                "/latest/user-data/"
            ],
            "azure": [
                "/metadata/instance?api-version=2021-02-01",
                "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
            ],
            "gcp": [
                "/computeMetadata/v1/instance/service-accounts/default/token",
                "/computeMetadata/v1/project/project-id"
            ],
            "digitalocean": ["/metadata/v1.json", "/metadata/v1/user-data"],
            "alibaba": ["/latest/meta-data/ram/security-credentials/"],
            "oracle": ["/opc/v1/instance/"],
            "tencent": ["/latest/meta-data/iam/security-credentials/"]
        }
        self.headers = {
            "Metadata": "true", # Required for Azure/GCP
            "X-Google-Metadata-Request": "True",
            "X-Metadata-Request": "True" # Oracle
        }

    def check_tools(self):
        return True 

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        if logger: logger(f"Cloud Metadata: Probing {base_url} for high-fidelity IMDS leaks...", "INFO")

        # First, try to fetch AWS IMDSv2 token as a verification step if IMDSv1 is blocked
        aws_token = None
        try:
            token_r = http_client.put(f"{base_url}/latest/api/token", 
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                                     options=getattr(self, "options", None), timeout=2)
            if token_r.status_code == 200 and len(token_r.text) > 30:
                aws_token = token_r.text
                if logger: logger(f"🔥 IMDSv2 Token Obtained: AWS Infrastructure Confirmed via Proxy", "CRITICAL")
        except Exception:
            pass

        for provider, paths in self.metadata_paths.items():
            for path in paths:
                url = f"{base_url}{path}"
                headers = self.headers.copy()
                if provider == "aws" and aws_token:
                    headers["X-aws-ec2-metadata-token"] = aws_token

                try:
                    r = http_client.get(url, options=getattr(self, "options", None), headers=headers, timeout=3, allow_redirects=False)
                    
                    if r.status_code == 200:
                        content = r.text
                        is_verified = False
                        
                        # High Fidelity Signatures (Anti-Faux Positif)
                        if provider == "aws":
                            if any(x in content for x in ["ami-id", "instance-type", "local-hostname"]) or "/" in content: 
                                is_verified = True
                        elif provider == "azure":
                            if "compute" in content and "provider" in content: is_verified = True
                        elif provider == "gcp":
                            if "access_token" in content or "project-id" in content: is_verified = True
                        elif provider == "digitalocean":
                            if "droplet_id" in content or "region" in content: is_verified = True
                        elif provider == "alibaba" or provider == "tencent":
                            if len(content) > 2 and "/" not in content: is_verified = True # Usually returns role name
                        
                        if is_verified:
                            findings.append({
                                "title": f"Critical Cloud Metadata Leak: {provider.upper()} IMDS Exposed",
                                "description": (
                                    f"The server is misconfigured as a proxy or vulnerable to SSRF, exposing the internal {provider.upper()} Cloud Metadata Service.\n\n"
                                    f"**Vulnerable URL**: {url}\n"
                                    f"**Impact**: This allows an attacker to steal IAM credentials, instance metadata, and potentially compromise the entire cloud account."
                                ),
                                "severity": "critical",
                                "tool_source": "cloud_metadata_scanner",
                                "endpoint": url,
                                "repro_command": f"curl -ik -H 'Metadata: true' {url}",
                                "metadata": {
                                    "provider": provider,
                                    "imds_version": "v2" if aws_token else "v1",
                                    "leak_preview": content[:200]
                                }
                            })
                            if logger: logger(f"🔥 CONFIRMED: {provider.upper()} Metadata Leak at {url}", "CRITICAL")
                            # We keep scanning other providers/paths because we want 360 view, 
                            # but we stop for this provider if we found a verified hit.
                            break 
                except Exception:
                    continue
        
        return findings
