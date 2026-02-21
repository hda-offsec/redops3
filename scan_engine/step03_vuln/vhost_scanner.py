import requests
from urllib.parse import urlparse

class VhostScanner:
    """
    V6 EXPERT: Virtual Host (Vhost) Brute-forcer.
    Discovers hidden subdomains or sites co-located on the same IP by fuzzing the 'Host' header.
    """
    def __init__(self, target):
        self.target = target
        self.common_vhosts = [
            "dev", "test", "stage", "staging", "api", "v1", "v2", "beta",
            "admin", "internal", "corp", "m", "mobile", "static", "assets",
            "vpn", "mail", "blog", "shop", "git"
        ]

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        # 1. Get Baseline
        try:
            r_base = requests.get(base_url, timeout=5, verify=False, allow_redirects=False)
            base_len = len(r_base.content)
            base_status = r_base.status_code
        except Exception:
            return []

        if logger: logger(f"Vhost Expert: Fuzzing Vhosts on {base_url}...", "INFO")

        # Generate candidates based on target domain
        t_parts = self.target.split('.')
        domain = ".".join(t_parts[-2:]) if len(t_parts) >= 2 else self.target
        
        candidates = []
        for v in self.common_vhosts:
            candidates.append(f"{v}.{domain}")
            candidates.append(f"{v}-{domain}")

        for vhost in set(candidates):
            if vhost == self.target: continue
            
            try:
                headers = {"Host": vhost}
                r = requests.get(base_url, headers=headers, timeout=3, verify=False, allow_redirects=False)
                
                # Compare with baseline
                # Check for different status code or significantly different length
                is_different = False
                if r.status_code != base_status:
                    is_different = True
                elif abs(len(r.content) - base_len) > (base_len * 0.1): # 10% difference
                    is_different = True
                
                if is_different:
                    findings.append({
                        "title": f"Medium: Discovered Virtual Host ({vhost})",
                        "description": (
                            f"A unique response was detected when using the Host header `{vhost}`.\n\n"
                            f"**Status**: {r.status_code} (Base: {base_status})\n"
                            f"**Content Length**: {len(r.content)} (Base: {base_len})"
                        ),
                        "severity": "medium",
                        "tool_source": "vhost_expert",
                        "vhost": vhost,
                        "url": f"{protocol}://{vhost}:{port}"
                    })
                    if logger: logger(f"🌐 VHOST DISCOVERED: {vhost} (Port {port})", "SUCCESS")

            except Exception: pass
            
        return findings
