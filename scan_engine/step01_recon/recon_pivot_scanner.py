import ssl
import socket
import re
from urllib.parse import urlparse
import scan_engine.helpers.http_client as http_client

class ReconPivotScanner:
    """
    Advanced Identity & Infrastructure Recon.
    Pivots via SSL SANs and CSP records to discover hidden assets.
    """
    def __init__(self, target, options=None):
        self.target = target
        self.options = options

    def audit(self, port=443, protocol='https', logger=None):
        findings = []
        if logger: logger(f"Recon Pivot: Starting advanced infrastructure discovery on {self.target}:{port}", "INFO")

        # 1. SSL/TLS SAN Extraction
        if protocol == 'https':
            san_findings = self.get_ssl_sans(logger)
            findings.extend(san_findings)

        # 2. CSP Parsing
        csp_findings = self.parse_csp(port, protocol, logger)
        findings.extend(csp_findings)

        return findings

    def get_ssl_sans(self, logger):
        """Extract Subject Alternative Names from the SSL certificate."""
        found_domains = set()
        findings = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    # Use a more robust way to parse DER cert if needed, but for now simple regex on string
                    # Or use cryptography lib if available. 
                    # Let's try to get it from ssock.getpeercert() which works if we allow verification or use specific flags
                    
            # Re-try with verification enabled just to get the dict if possible
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_dict = ssock.getpeercert()
                    if cert_dict and 'subjectAltName' in cert_dict:
                        for entry in cert_dict['subjectAltName']:
                            if entry[0] == 'DNS':
                                found_domains.add(entry[1])
        except Exception as e:
            if logger: logger(f"Recon Pivot: SSL SAN extraction failed (expected if self-signed): {e}", "DEBUG")

        if found_domains:
            domain_list = sorted(list(found_domains))
            findings.append({
                "title": f"Infrastructure Pivot: {len(found_domains)} SANs Discovered",
                "description": f"Extracted Subject Alternative Names (SAN) from the SSL certificate. These domains likely share the same infrastructure:\n\n" + "\n".join([f"• {d}" for d in domain_list]),
                "severity": "info",
                "tool_source": "recon_pivot",
                "category": "recon",
                "metadata": {"discovered_domains": domain_list}
            })
            if logger: logger(f"Recon Pivot: Discovered {len(found_domains)} domains via SSL SANs", "SUCCESS")
        
        return findings

    def parse_csp(self, port, protocol, logger):
        """Parse Content-Security-Policy to find external integrations/buckets."""
        findings = []
        url = f"{protocol}://{self.target}:{port}/"
        try:
            r = http_client.get(url, options=getattr(self, "options", None), timeout=5, verify=False)
            csp = r.headers.get("Content-Security-Policy", "")
            if not csp:
                return []

            # Extract domains from CSP
            # Basic regex for domains/subdomains/buckets
            # Look for strings like *.s3.amazonaws.com, etc.
            external_refs = set(re.findall(r'([a-z0-9.-]+\.[a-z]{2,})', csp))
            
            # Filter out common junk and self
            filtered = {d for d in external_refs if d != self.target and len(d.split('.')) > 1}
            
            if filtered:
                ref_list = sorted(list(filtered))
                findings.append({
                    "title": f"Infrastructure Pivot: {len(filtered)} CSP External References",
                    "description": f"Parsed Content-Security-Policy (CSP) and identified authorized external domains/buckets. These reveal the extended 3rd-party attack surface:\n\n" + "\n".join([f"• {d}" for d in ref_list]),
                    "severity": "info",
                    "tool_source": "recon_pivot",
                    "category": "recon",
                    "metadata": {"csp_sources": ref_list}
                })
                if logger: logger(f"Recon Pivot: Discovered {len(filtered)} external sources via CSP", "SUCCESS")
        except Exception:
            pass
        return findings
